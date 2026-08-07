use std::collections::HashMap;
use std::io::{self, prelude::*, IsTerminal};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use tracing::{info, warn};

use crate::network::certs;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const PROMPT_TIMEOUT_SECS: u64 = 60;
/// After a prompt is declined or times out, reject that fingerprint silently
/// for this long instead of re-prompting on every automatic retry.
const REJECTION_COOLDOWN_SECS: u64 = 60;

pub fn rustls_client_config(
    verifier: Arc<MonuxCertVerification<'static>>,
) -> Result<Arc<dyn quinn::crypto::ClientConfig>> {
    let mut rustls_config = quinn::rustls::ClientConfig::builder_with_provider(verifier.crypto_provider.clone())
        .with_safe_default_protocol_versions().context("Failed to set client default protocol versions")?
        .dangerous().with_custom_certificate_verifier(verifier.clone())
        .with_client_auth_cert(
            vec![verifier.our_cert.clone()],
            verifier.our_privkey.clone_key(),
        ).context("Failed to assign client cert and privkey")?;
    rustls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    Ok(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
            .context("Failed to create QUIC client configuration")?
    ))
}

pub fn rustls_server_config(
    verifier: Arc<MonuxCertVerification<'static>>,
) -> Result<Arc<dyn quinn::crypto::ServerConfig>> {
    let mut rustls_config = quinn::rustls::ServerConfig::builder_with_provider(verifier.crypto_provider.clone())
        .with_safe_default_protocol_versions().context("Failed to set server default protocol versions")?
        .with_client_cert_verifier(verifier.clone())
        .with_single_cert(
            vec![verifier.our_cert.clone()],
            verifier.our_privkey.clone_key(),
        ).context("Failed to assign server cert and privkey")?;
    rustls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    rustls_config.max_early_data_size = u32::MAX; // required by QUIC
    Ok(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)
            .context("Failed to create QUIC server configuration")?
    ))
}

/// The fingerprint of a connection peer's certificate, read back from the
/// established connection. quinn's rustls session exposes the verified peer
/// chain via peer_identity (leaf first), so the server pairs each connection
/// with its own client's fingerprint directly — immune to the
/// simultaneous-reconnect mixups of the former global fingerprint slot.
pub fn connection_peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    peer_fingerprint_from_identity(conn.peer_identity()?)
}

/// The leaf fingerprint of a peer identity as quinn hands it over: the Any
/// downcasts to Vec<CertificateDer> for the rustls session (documented on
/// quinn::Connection::peer_identity). None for a foreign session type or an
/// empty chain.
fn peer_fingerprint_from_identity(identity: Box<dyn std::any::Any>) -> Option<String> {
    let chain = identity
        .downcast::<Vec<rustls_pki_types::CertificateDer>>()
        .ok()?;
    chain.first().map(certs::fingerprint)
}

#[derive(Debug)]
struct ApprovalState {
    /// Previously-approved certs: loaded from disk at startup, plus certs
    /// approved via the interactive prompt (pushed by the prompt thread, so
    /// the peer's retry passes the known-certs check without re-prompting).
    /// Owned so the state can be shared with the prompt thread.
    known_certs: Vec<rustls_pki_types::CertificateDer<'static>>,
    /// Whether an approval prompt thread is currently running.
    /// We only allow one prompt to be pending at a time, globally.
    prompt_active: bool,
    /// Fingerprint -> earliest time we may prompt for it again. Recorded when
    /// a prompt is declined or times out: the peer's reconnect loop retries
    /// every few seconds, and without this every attempt would retrigger the
    /// prompt.
    rejection_cooldowns: HashMap<String, Instant>,
}

#[derive(Debug)]
pub struct MonuxCertVerification<'a> {
    /// For storing certs to disk
    config_dir: PathBuf,
    /// Used for building rustls configs
    our_cert: rustls_pki_types::CertificateDer<'a>,
    /// Used for building rustls configs
    our_privkey: rustls_pki_types::PrivateKeyDer<'a>,
    /// Pre-approved cert fingerprints provided via commandline argument
    approved_cert_fingerprints: Vec<String>,
    /// Mutable certificate approval state, shared with the prompt thread
    approval_state: Arc<RwLock<ApprovalState>>,
    /// Whether unknown certs may be approved via an interactive prompt.
    /// Disabled for the server in --www mode, where internet-facing peers must
    /// be pre-approved instead of prompting on the console.
    allow_interactive_prompts: bool,
    /// Server name (client side only), shown in the approval prompt so the
    /// user can sanity-check which machine they are connecting to. Learned
    /// via mDNS discovery or the v15+ handshake; both are unauthenticated,
    /// so this is a hint, not proof.
    discovered_server_name: Mutex<Option<String>>,
    /// The server certificate's fingerprint as learned during the client-side
    /// handshake, read after a successful connect for the remembered-servers
    /// store (known_servers.rs). Server side, the client's fingerprint is
    /// instead derived from the established connection after the handshake
    /// (see connection_peer_fingerprint).
    peer_fingerprint: Mutex<Option<String>>,
    /// For rustls verify calls
    crypto_provider: Arc<rustls::crypto::CryptoProvider>,
    /// How long a declined/timed-out fingerprint is rejected silently before
    /// we may prompt for it again. Injectable for tests.
    rejection_cooldown: Duration,
    /// Stdin-TTY check, injectable so tests can exercise the prompt path.
    stdin_is_tty: fn() -> bool,
    /// Prompt-thread spawner, injectable so tests can observe spawns without
    /// touching stdin/stdout.
    prompt_spawner: fn(PromptJob),
}

impl<'a> MonuxCertVerification<'a> {
    /// The fingerprint of our own certificate, for display so that peers can
    /// verify or pre-approve us.
    pub fn our_fingerprint(&self) -> String {
        certs::fingerprint(&self.our_cert)
    }

    /// Records the mDNS-discovered server instance name, for display in the
    /// client-side approval prompt.
    pub fn set_discovered_server_name(&self, name: String) {
        if let Ok(mut slot) = self.discovered_server_name.lock() {
            *slot = Some(name);
        }
    }

    /// Records the server's hostname learned from the v15+ handshake, for the
    /// approval prompt — but only when no mDNS-discovered name exists (mDNS
    /// was there first and says the same thing).
    pub fn set_handshake_server_name(&self, name: String) {
        if let Ok(mut slot) = self.discovered_server_name.lock() {
            if slot.is_none() {
                *slot = Some(name);
            }
        }
    }

    /// The server certificate's fingerprint as learned during the client-side
    /// handshake; None before the first successful verification.
    pub fn peer_fingerprint(&self) -> Option<String> {
        self.peer_fingerprint
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
    }

    pub fn new(
        splash_label: &str,
        approved_cert_fingerprints: Vec<String>,
        config_dir: &Path,
        allow_interactive_prompts: bool,
    ) -> Result<Arc<Self>> {
        let (our_cert, our_privkey) = certs::load_keypair(splash_label, config_dir)
            .with_context(|| format!("Failed to load {} keypair", splash_label))?;
        // Convert e.g. "18:AE:75:F2..." (openssl style) => "18ae75f2..." (our style)
        // Can get the openssl style from: openssl x509 -noout -sha256 -fingerprint -in /path/to/private.pem
        let approved_cert_fingerprints: Vec<String> = approved_cert_fingerprints
            .into_iter()
            .map(|fingerprint| fingerprint.to_lowercase().replace(':', ""))
            .collect();
        if !approved_cert_fingerprints.is_empty() {
            info!(
                "Configured {} preapproved fingerprints: {:?}",
                approved_cert_fingerprints.len(),
                approved_cert_fingerprints
            )
        }
        Ok(Arc::new(MonuxCertVerification {
            config_dir: config_dir.to_path_buf(),
            our_cert,
            our_privkey,
            approved_cert_fingerprints,
            approval_state: Arc::new(RwLock::new(ApprovalState {
                known_certs: certs::load_known_certs(config_dir)?,
                prompt_active: false,
                rejection_cooldowns: HashMap::new(),
            })),
            allow_interactive_prompts,
            discovered_server_name: Mutex::new(None),
            peer_fingerprint: Mutex::new(None),
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            rejection_cooldown: Duration::from_secs(REJECTION_COOLDOWN_SECS),
            stdin_is_tty: default_stdin_is_tty,
            prompt_spawner: spawn_prompt_thread,
        }))
    }

    /// Verifies a peer certificate. NEVER blocks: rustls runs this on quinn's
    /// single endpoint driver task, where blocking freezes I/O (keepalives,
    /// existing sessions) for every connection on the endpoint — and any
    /// unauthenticated LAN peer could retrigger that freeze at will. Unknown
    /// certs are rejected immediately; when prompting is possible, a dedicated
    /// thread runs the approval prompt while this handshake fails with
    /// "approval pending". The peer's reconnect loop retries, and once the
    /// prompt thread records an approval, a later retry passes the
    /// known-certs check below.
    fn verify_cert(
        &self,
        their_cert: &rustls_pki_types::CertificateDer<'_>,
        their_name: &str,
        we_are_server: bool,
    ) -> Result<String> {
        let their_cert_fingerprint = certs::fingerprint(their_cert);
        {
            // Poison-tolerant: a panicking prompt thread must not wedge
            // certificate verification for the lifetime of the process.
            let mut approval_state = self.approval_state.write().unwrap_or_else(|e| e.into_inner());
            if approval_state.known_certs.contains(their_cert) {
                info!(
                    "{} cert has been approved before: {}",
                    their_name, their_cert_fingerprint
                );
                return Ok(their_cert_fingerprint);
            } else if self
                .approved_cert_fingerprints
                .contains(&their_cert_fingerprint)
            {
                info!(
                    "{} cert approved via --fingerprints: {}",
                    their_name, their_cert_fingerprint
                );
                // Don't save the cert to disk for --fingerprints.
                // Saving to disk creates weird behavior if the user later changes the certs they approve.
                // Maybe they don't WANT old certs to still be approved if the arg changes? Play it safe.
                approval_state.known_certs.push(their_cert.clone().into_owned());
                return Ok(their_cert_fingerprint);
            } else if !self.allow_interactive_prompts {
                // Interactive prompts are disabled (--www): unknown peers must be
                // pre-approved via known_certs or --fingerprints.
                bail!(
                    "{} cert rejected: interactive approval disabled (--www); pre-approve it with '--fingerprints {}'",
                    their_name,
                    their_cert_fingerprint
                );
            } else if !(self.stdin_is_tty)() {
                warn!("Stdin is not a TTY, skipping user certificate approval prompt. Approve this cert by running the {} with '--fingerprints {}'", if we_are_server { "server" } else { "client" }, their_cert_fingerprint);
                bail!(
                    "{} cert rejected: unknown certificate and stdin is not a TTY",
                    their_name
                );
            }

            match prompt_decision(&approval_state, &their_cert_fingerprint, Instant::now()) {
                // Only one prompt at a time, reject other prompts. They will retry connecting anyway.
                PromptDecision::Pending => bail!(
                    "{} cert rejected for now: an approval prompt is already pending",
                    their_name
                ),
                PromptDecision::Cooldown => bail!(
                    "{} cert rejected for now: approval of {} was recently declined or timed out",
                    their_name,
                    their_cert_fingerprint
                ),
                PromptDecision::Prompt => {
                    // Claim the prompt slot under the lock, so a concurrent
                    // verification sees Pending instead of double-spawning.
                    approval_state.prompt_active = true;
                }
            }
        }

        // The prompt runs on its own thread (spawned below), never here.
        // This handshake is rejected; convergence happens on the peer's retry.
        (self.prompt_spawner)(PromptJob {
            cert: their_cert.clone().into_owned(),
            we_are_server,
            discovered_server_name: self
                .discovered_server_name
                .lock()
                .ok()
                .and_then(|slot| slot.clone()),
            config_dir: self.config_dir.clone(),
            rejection_cooldown: self.rejection_cooldown,
            approval_state: Arc::clone(&self.approval_state),
        });
        info!(
            "{} cert unknown ({}): approval prompt pending on this machine's console; the peer retries automatically",
            their_name, their_cert_fingerprint
        );
        bail!(
            "{} cert not approved yet: approval pending, the peer retries automatically",
            their_name
        )
    }
}

fn default_stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// What to do with an unknown certificate that could be prompted for.
/// Pure decision, separated from side effects so tests can drive it directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PromptDecision {
    /// No prompt active, no cooldown: spawn the approval prompt thread and
    /// reject this handshake with "approval pending".
    Prompt,
    /// A prompt (possibly for another fingerprint) is already active:
    /// reject this attempt; the peer retries anyway.
    Pending,
    /// This fingerprint was declined or timed out recently: reject without
    /// re-prompting until the cooldown lapses, so rapid automatic retries
    /// don't spam the console.
    Cooldown,
}

fn prompt_decision(state: &ApprovalState, fingerprint: &str, now: Instant) -> PromptDecision {
    if state.prompt_active {
        return PromptDecision::Pending;
    }
    match state.rejection_cooldowns.get(fingerprint) {
        Some(until) if now < *until => PromptDecision::Cooldown,
        _ => PromptDecision::Prompt,
    }
}

/// Records a prompt approval: the cert becomes known immediately, so the
/// peer's automatic retry passes the known-certs check.
fn record_approval(state: &mut ApprovalState, cert: rustls_pki_types::CertificateDer<'static>) {
    state.known_certs.push(cert);
}

/// Records a prompt rejection/timeout: reject this fingerprint without
/// re-prompting until the cooldown lapses. Also prunes lapsed entries.
fn record_rejection(state: &mut ApprovalState, fingerprint: String, now: Instant, cooldown: Duration) {
    state.rejection_cooldowns.retain(|_, until| *until > now);
    state.rejection_cooldowns.insert(fingerprint, now + cooldown);
}

/// Everything the approval prompt thread needs, bundled so the spawn step is
/// injectable in tests.
struct PromptJob {
    cert: rustls_pki_types::CertificateDer<'static>,
    we_are_server: bool,
    discovered_server_name: Option<String>,
    config_dir: PathBuf,
    rejection_cooldown: Duration,
    approval_state: Arc<RwLock<ApprovalState>>,
}

/// Default prompt spawner: runs the prompt on a dedicated OS thread, off
/// quinn's endpoint driver task. On spawn failure the prompt slot is
/// released again so the next retry can try spawning anew.
fn spawn_prompt_thread(job: PromptJob) {
    let approval_state = Arc::clone(&job.approval_state);
    if let Err(e) = thread::Builder::new()
        .name("cert-approval-prompt".to_string())
        .spawn(move || prompt_thread_main(job))
    {
        warn!("Failed to spawn certificate approval prompt thread: {}", e);
        approval_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .prompt_active = false;
    }
}

/// Owns the whole prompt lifecycle: render the prompt, read the answer,
/// persist on approval, record a cooldown on rejection/timeout/error. Runs
/// on a dedicated thread; the verify callback only ever spawns it.
fn prompt_thread_main(job: PromptJob) {
    // Clears prompt_active no matter how this thread exits — approval,
    // rejection, timeout, error, even a panic — so the prompt slot can
    // never stay wedged.
    let _guard = PromptActiveGuard {
        approval_state: Arc::clone(&job.approval_state),
    };
    let their_name = if job.we_are_server { "Client" } else { "Server" };
    let their_cert_fingerprint = certs::fingerprint(&job.cert);
    if prompt_unknown_cert(&job.cert, job.we_are_server, job.discovered_server_name.as_deref()) {
        info!("{} cert approved: {}", their_name, their_cert_fingerprint);
        if let Err(e) =
            certs::write_approved_cert(&job.cert, &their_cert_fingerprint, &job.config_dir)
        {
            warn!(
                "{} approved, but couldn't save cert to disk: {}",
                their_name, e
            );
        }
        // Store the approved cert locally too, so the peer's retry passes
        // the known-certs check right away without re-prompting (a restart
        // would see the disk write above).
        record_approval(
            &mut job.approval_state.write().unwrap_or_else(|e| e.into_inner()),
            job.cert,
        );
    } else {
        info!(
            "{} cert not approved: {}",
            their_name, their_cert_fingerprint
        );
        record_rejection(
            &mut job.approval_state.write().unwrap_or_else(|e| e.into_inner()),
            their_cert_fingerprint,
            Instant::now(),
            job.rejection_cooldown,
        );
    }
}

/// Clears `prompt_active` on drop: the prompt slot survives any exit path of
/// the prompt thread, including a panic.
struct PromptActiveGuard {
    approval_state: Arc<RwLock<ApprovalState>>,
}

impl Drop for PromptActiveGuard {
    fn drop(&mut self) {
        // Poison-tolerant: clearing must also work when the lock was poisoned
        // (e.g. by the panicking prompt thread itself).
        self.approval_state
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .prompt_active = false;
    }
}

/// Run by the client to verify servers
impl rustls::client::danger::ServerCertVerifier for MonuxCertVerification<'_> {
    fn verify_server_cert(
        &self,
        server_cert: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        match self.verify_cert(server_cert, "Server", false) {
            Err(e) => Err(rustls::Error::General(e.to_string())),
            Ok(their_cert_fingerprint) => {
                // Learn the server's fingerprint for the remembered-servers
                // store (known_servers.rs), read after a successful connect.
                if let Ok(mut slot) = self.peer_fingerprint.lock() {
                    *slot = Some(their_cert_fingerprint);
                }
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Default call used by WebPkiServerVerifier
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Default call used by WebPkiServerVerifier
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Run by the server to verify clients
impl<'a> rustls::server::danger::ClientCertVerifier for MonuxCertVerification<'a> {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        client_cert: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        match self.verify_cert(client_cert, "Client", true) {
            Err(e) => Err(rustls::Error::General(e.to_string())),
            Ok(_their_cert_fingerprint) => {
                // Nothing is stored here: server.rs pairs the connection with
                // its client's fingerprint by reading the verified chain back
                // from the established connection (connection_peer_fingerprint),
                // which can't mix fingerprints up between simultaneous
                // reconnects the way a shared slot could.
                Ok(rustls::server::danger::ClientCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Default call used by WebPkiServerVerifier
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls_pki_types::CertificateDer,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Default call used by WebPkiServerVerifier
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.crypto_provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.crypto_provider.signature_verification_algorithms.supported_schemes()
    }
}

fn prompt_unknown_cert(
    their_cert: &rustls_pki_types::CertificateDer,
    we_are_server: bool,
    discovered_server_name: Option<&str>,
) -> bool {
    let their_cert_fingerprint = certs::fingerprint(their_cert);
    if !io::stdin().is_terminal() {
        warn!("Stdin is not a TTY, skipping user certificate approval prompt. Approve this cert by running the {} with '--fingerprints {}'", if we_are_server { "server" } else { "client" }, their_cert_fingerprint);
        return false;
    }

    let message = if we_are_server {
        format!(
            "APPROVAL NEEDED: New unknown client connection

The server has received a connection from a new unknown client.
Only approve this if you are expecting a new client.
You will also likely need to confirm this connection on the client as well.

Confirm that the client startup image has this fingerprint:
    {}

Allow this new client and save its certificate for future connections? ({}s timeout) [y/N]
> ",
            their_cert_fingerprint, PROMPT_TIMEOUT_SECS
        )
    } else {
        let discovered_line = discovered_server_name
            .map(|name| format!("The server calls itself: {} (learned via mDNS or the handshake — unauthenticated)\n", name))
            .unwrap_or_default();
        format!(
            "APPROVAL NEEDED: New unknown server connection

The client has connected to a new unknown server.
{}Only approve this if you are expecting to be connecting to a new server.
You will also likely need to confirm this connection on the server as well.

Confirm that the server startup image has this fingerprint:
    {}

Allow this new server and save its certificate for future connections? ({}s timeout) [y/N]
> ",
            discovered_line, their_cert_fingerprint, PROMPT_TIMEOUT_SECS
        )
    };
    prompt_yn(&message, false)
}

fn prompt_yn(msg: &str, default: bool) -> bool {
    match prompt_internal(msg) {
        Ok(char_) => {
            match char_ {
                // Check for [yY]es or [tT]rue
                b'y' | b'Y' | b't' | b'T' => true,
                _ => false,
            }
        }
        Err(e) => {
            warn!(
                "Confirmation prompt failed, assuming '{}': {}",
                if default { "yes" } else { "no" },
                e
            );
            default
        }
    }
}

fn prompt_internal(msg: &str) -> Result<u8> {
    // Use nonblock to allow timeout on stdin.
    // Could try to use async, but Tokio docs don't recommend it in this context.
    let mut stdin = nonblock::NonBlockingReader::from_fd(io::stdin())
        .context("Failed to set up nonblocking reader for stdin")?;

    // Flush any preceding input before prompt
    {
        let mut discard = vec![];
        stdin
            .read_available(&mut discard)
            .context("Failed to flush initial input")?;
    }

    // Send the prompt
    let msg_formatted = msg.to_string();
    let mut stdout = io::stdout();
    stdout
        .write_all(msg_formatted.as_bytes())
        .context("Failed to write prompt to stdout")?;
    stdout.flush().context("Failed to flush stdout")?;

    // Wait for first char, or time out. Use blocking APIs.
    let end_at = Instant::now()
        .checked_add(Duration::from_secs(PROMPT_TIMEOUT_SECS))
        .expect("Failed to configure timeout");
    let mut content = vec![];
    loop {
        thread::sleep(Duration::from_millis(50));
        stdin
            .read_available(&mut content)
            .context("Failed to check for user input")?;

        // Check and return first character
        if let Some(c) = content.first() {
            return Ok(*c);
        }

        // Still nothing, check for timeout
        if Instant::now() >= end_at {
            println!();
            bail!("Prompt timed out after {}s", PROMPT_TIMEOUT_SECS)
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static PROMPT_SPAWNS: AtomicUsize = AtomicUsize::new(0);
    static COOLDOWN_SPAWNS: AtomicUsize = AtomicUsize::new(0);

    fn count_prompt_spawn(_job: PromptJob) {
        PROMPT_SPAWNS.fetch_add(1, Ordering::SeqCst);
    }

    fn count_cooldown_spawn(_job: PromptJob) {
        COOLDOWN_SPAWNS.fetch_add(1, Ordering::SeqCst);
    }

    fn noop_spawn(_job: PromptJob) {}

    fn tty_yes() -> bool {
        true
    }

    fn tty_no() -> bool {
        false
    }

    fn empty_state() -> ApprovalState {
        ApprovalState {
            known_certs: vec![],
            prompt_active: false,
            rejection_cooldowns: HashMap::new(),
        }
    }

    fn test_verifier(
        dir: &std::path::Path,
        allow_interactive_prompts: bool,
    ) -> Arc<MonuxCertVerification<'static>> {
        MonuxCertVerification::new(
            "test",
            vec![],
            dir,
            allow_interactive_prompts,
        )
        .expect("failed to construct verifier")
    }

    fn peer_cert(dir: &std::path::Path) -> rustls_pki_types::CertificateDer<'static> {
        certs::load_keypair("peer", dir)
            .expect("couldn't generate peer keypair")
            .0
    }

    #[test]
    fn unknown_cert_rejects_with_approval_pending_and_spawns_once() {
        PROMPT_SPAWNS.store(0, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier(dir.path(), true);
        Arc::get_mut(&mut verifier)
            .expect("fresh verifier should be uniquely owned")
            .stdin_is_tty = tty_yes;
        Arc::get_mut(&mut verifier)
            .expect("fresh verifier should be uniquely owned")
            .prompt_spawner = count_prompt_spawn;
        let their_cert = peer_cert(peer_dir.path());

        let err = verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("unknown cert must be rejected while the prompt is pending");
        assert!(
            err.to_string().contains("approval pending"),
            "unexpected error: {}",
            err
        );
        assert!(verifier.approval_state.read().unwrap().prompt_active);
        assert_eq!(PROMPT_SPAWNS.load(Ordering::SeqCst), 1);

        // A retry while the prompt is still pending must not spawn again.
        let err = verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("a pending prompt must reject the retry");
        assert!(
            err.to_string().contains("already pending"),
            "unexpected error: {}",
            err
        );
        assert_eq!(PROMPT_SPAWNS.load(Ordering::SeqCst), 1);
        assert!(verifier.approval_state.read().unwrap().prompt_active);
    }

    #[test]
    fn approval_by_thread_lets_retry_pass() {
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier(dir.path(), true);
        Arc::get_mut(&mut verifier)
            .expect("fresh verifier should be uniquely owned")
            .stdin_is_tty = tty_yes;
        Arc::get_mut(&mut verifier)
            .expect("fresh verifier should be uniquely owned")
            .prompt_spawner = noop_spawn;
        let their_cert = peer_cert(peer_dir.path());
        let their_fingerprint = certs::fingerprint(&their_cert);

        verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("first attempt is rejected while the prompt is pending");

        // Simulate the prompt thread recording an approval.
        {
            let mut state = verifier.approval_state.write().unwrap();
            record_approval(&mut state, their_cert.clone().into_owned());
            state.prompt_active = false;
        }

        // The retry passes the known-certs check without re-prompting.
        let approved = verifier
            .verify_cert(&their_cert, "Server", false)
            .expect("approved cert must verify on retry");
        assert_eq!(approved, their_fingerprint);
        assert!(!verifier.approval_state.read().unwrap().prompt_active);
    }

    #[test]
    fn rejection_cooldown_suppresses_reprompt_until_lapse() {
        COOLDOWN_SPAWNS.store(0, Ordering::SeqCst);
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier(dir.path(), true);
        {
            let v = Arc::get_mut(&mut verifier).expect("fresh verifier should be uniquely owned");
            v.stdin_is_tty = tty_yes;
            v.prompt_spawner = count_cooldown_spawn;
            v.rejection_cooldown = Duration::from_millis(50);
        }
        let their_cert = peer_cert(peer_dir.path());
        let their_fingerprint = certs::fingerprint(&their_cert);

        verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("first attempt is rejected while the prompt is pending");
        assert_eq!(COOLDOWN_SPAWNS.load(Ordering::SeqCst), 1);

        // Simulate the prompt thread recording a rejection (answer "no",
        // timeout, or prompt error all take this path).
        {
            let mut state = verifier.approval_state.write().unwrap();
            record_rejection(
                &mut state,
                their_fingerprint,
                Instant::now(),
                verifier.rejection_cooldown,
            );
            state.prompt_active = false;
        }

        // Retries during the cooldown are rejected without re-spawning.
        let err = verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("a fingerprint in cooldown must be rejected");
        assert!(
            err.to_string().contains("declined or timed out"),
            "unexpected error: {}",
            err
        );
        assert_eq!(COOLDOWN_SPAWNS.load(Ordering::SeqCst), 1);
        assert!(!verifier.approval_state.read().unwrap().prompt_active);

        // Once the cooldown lapses, a retry may prompt again.
        thread::sleep(Duration::from_millis(120));
        verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("after the cooldown a new prompt is pending again");
        assert_eq!(COOLDOWN_SPAWNS.load(Ordering::SeqCst), 2);
        assert!(verifier.approval_state.read().unwrap().prompt_active);
    }

    #[test]
    fn prompt_active_guard_clears_flag_on_drop() {
        let state = Arc::new(RwLock::new(ApprovalState {
            prompt_active: true,
            ..empty_state()
        }));
        {
            let _guard = PromptActiveGuard {
                approval_state: Arc::clone(&state),
            };
        }
        assert!(!state.read().unwrap().prompt_active);
    }

    #[test]
    fn prompt_active_guard_clears_flag_despite_panic_and_poison() {
        let state = Arc::new(RwLock::new(ApprovalState {
            prompt_active: true,
            ..empty_state()
        }));
        let state_in_thread = Arc::clone(&state);
        let handle = thread::spawn(move || {
            let _guard = PromptActiveGuard {
                approval_state: Arc::clone(&state_in_thread),
            };
            // Poison the lock on the way out, like a panic mid-approval.
            let _write = state_in_thread.write().unwrap();
            panic!("simulated prompt thread crash");
        });
        assert!(handle.join().is_err());
        // The guard ran during unwinding and tolerated the poisoned lock.
        assert!(!state.read().unwrap_or_else(|e| e.into_inner()).prompt_active);
    }

    #[test]
    fn prompt_decision_covers_prompt_cooldown_and_pending() {
        let mut state = empty_state();
        let now = Instant::now();
        assert_eq!(prompt_decision(&state, "fp", now), PromptDecision::Prompt);

        state
            .rejection_cooldowns
            .insert("fp".to_string(), now + Duration::from_secs(60));
        assert_eq!(prompt_decision(&state, "fp", now), PromptDecision::Cooldown);
        assert_eq!(
            prompt_decision(&state, "fp", now + Duration::from_secs(61)),
            PromptDecision::Prompt
        );
        // A different fingerprint is unaffected by the cooldown.
        assert_eq!(prompt_decision(&state, "other", now), PromptDecision::Prompt);

        // An active prompt wins over everything else.
        state.prompt_active = true;
        assert_eq!(
            prompt_decision(&state, "other", now),
            PromptDecision::Pending
        );
    }

    #[test]
    fn non_tty_stdin_rejects_without_spawning() {
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let mut verifier = test_verifier(dir.path(), true);
        Arc::get_mut(&mut verifier)
            .expect("fresh verifier should be uniquely owned")
            .stdin_is_tty = tty_no;
        let their_cert = peer_cert(peer_dir.path());

        let err = verifier
            .verify_cert(&their_cert, "Server", false)
            .expect_err("non-TTY stdin must reject without prompting");
        assert!(
            err.to_string().contains("not a TTY"),
            "unexpected error: {}",
            err
        );
        assert!(!verifier.approval_state.read().unwrap().prompt_active);
    }

    #[test]
    fn interactive_prompts_disabled_rejects_unknown_cert() {
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let verifier = test_verifier(dir.path(), false);
        let their_cert = peer_cert(peer_dir.path());

        let err = verifier
            .verify_cert(&their_cert, "Client", true)
            .expect_err("unknown cert must be rejected when prompts are disabled");
        assert!(
            err.to_string().contains("--fingerprints"),
            "unexpected error: {}",
            err
        );
        assert!(!verifier.approval_state.read().unwrap().prompt_active);
    }

    #[test]
    fn peer_fingerprint_from_identity_downcasts_the_rustls_chain() {
        let peer_dir = tempfile::tempdir().unwrap();
        let their_cert = peer_cert(peer_dir.path());
        let their_fingerprint = certs::fingerprint(&their_cert);
        // What quinn's rustls session hands over: the verified peer chain
        // boxed as Any (leaf first).
        let identity: Box<dyn std::any::Any> = Box::new(vec![their_cert]);
        assert_eq!(
            peer_fingerprint_from_identity(identity),
            Some(their_fingerprint)
        );
        // A foreign session type or an empty chain yields nothing.
        let foreign: Box<dyn std::any::Any> = Box::new("not-a-cert-chain".to_string());
        assert_eq!(peer_fingerprint_from_identity(foreign), None);
        let empty: Box<dyn std::any::Any> =
            Box::new(Vec::<rustls_pki_types::CertificateDer>::new());
        assert_eq!(peer_fingerprint_from_identity(empty), None);
    }

    #[test]
    fn preapproved_fingerprint_passes_without_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let their_cert = peer_cert(peer_dir.path());
        let their_fingerprint = certs::fingerprint(&their_cert);
        let verifier = MonuxCertVerification::new(
            "test",
            vec![their_fingerprint.clone()],
            dir.path(),
            false,
        )
        .expect("failed to construct verifier");

        let approved = verifier
            .verify_cert(&their_cert, "Client", true)
            .expect("pre-approved fingerprint must verify");
        assert_eq!(approved, their_fingerprint);
        assert!(!verifier.approval_state.read().unwrap().prompt_active);
    }
}
