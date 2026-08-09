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

/// Marker prefixed to every rejection that is part of the NORMAL pairing flow
/// rather than a fault: the cert is simply not approved yet, and the peer's
/// automatic retry converges once the console prompt is answered.
///
/// rustls flattens our verifier error into `Error::General(String)`, so the
/// connection layer can only recognize these by their text. It used to match
/// three separate phrases, which meant rewording any message here silently
/// turned the pairing flow back into an error storm. One sentinel, asserted by
/// a test on every rejection path, is the honest version of that.
pub const APPROVAL_PENDING_SENTINEL: &str = "monux-approval-pending";
const PROMPT_TIMEOUT_SECS: u64 = 60;
/// After a prompt is declined or times out, reject that fingerprint silently
/// for this long instead of re-prompting on every automatic retry.
const REJECTION_COOLDOWN_SECS: u64 = 60;

/// First global pause after an unanswered prompt, doubling per consecutive
/// unanswered prompt up to GLOBAL_PROMPT_BACKOFF_MAX (see
/// ApprovalState::prompt_backoff_until). Short enough that a user who walked
/// away mid-pairing just retries; steep enough that a peer minting fresh
/// certs stops being able to occupy the console.
const GLOBAL_PROMPT_BACKOFF_BASE: Duration = Duration::from_secs(15);
const GLOBAL_PROMPT_BACKOFF_MAX: Duration = Duration::from_secs(15 * 60);

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
    /// Earliest time ANY new fingerprint may raise a prompt (see
    /// GLOBAL_PROMPT_BACKOFF_BASE). The per-fingerprint cooldown above is the
    /// wrong granularity to stop repetition, because minting a fresh
    /// self-signed cert is free: an unauthenticated peer could raise a new
    /// prompt every PROMPT_TIMEOUT_SECS forever, holding the single prompt
    /// slot and burying the console — pre-authentication, from anyone who can
    /// reach the port.
    prompt_backoff_until: Option<Instant>,
    /// Consecutive prompts that went unanswered (declined or timed out),
    /// driving the backoff above. Reset the moment a prompt IS answered with
    /// an approval: a user who is actually pairing must not be made to wait
    /// out an attacker's accumulated penalty.
    unanswered_prompts: u32,
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
    /// Base of the global prompt backoff (see GLOBAL_PROMPT_BACKOFF_BASE).
    /// Injectable for the same reason as rejection_cooldown.
    global_backoff_base: Duration,
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
            .map(|fingerprint| normalize_fingerprint(&fingerprint))
            .collect();
        // Validate rather than silently carrying a value that can never
        // match: a typo or a truncated paste otherwise presents to the user
        // as "the peer keeps refusing me", with a startup line cheerfully
        // reporting N configured fingerprints.
        for fingerprint in &approved_cert_fingerprints {
            validate_fingerprint(fingerprint)?;
        }
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
                prompt_backoff_until: None,
                unanswered_prompts: 0,
            })),
            allow_interactive_prompts,
            discovered_server_name: Mutex::new(None),
            peer_fingerprint: Mutex::new(None),
            crypto_provider: Arc::new(rustls::crypto::ring::default_provider()),
            rejection_cooldown: Duration::from_secs(REJECTION_COOLDOWN_SECS),
            global_backoff_base: GLOBAL_PROMPT_BACKOFF_BASE,
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
                    "{}: {} cert rejected for now, an approval prompt is already pending",
                    APPROVAL_PENDING_SENTINEL,
                    their_name
                ),
                PromptDecision::Cooldown => bail!(
                    "{}: {} cert rejected for now, approval of {} was recently declined or timed out",
                    APPROVAL_PENDING_SENTINEL,
                    their_name,
                    their_cert_fingerprint
                ),
                PromptDecision::Backoff => bail!(
                    "{}: {} cert rejected for now, approval prompts are paused after recent unanswered ones",
                    APPROVAL_PENDING_SENTINEL,
                    their_name
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
            global_backoff_base: self.global_backoff_base,
            approval_state: Arc::clone(&self.approval_state),
        });
        info!(
            "{} cert unknown ({}): approval prompt pending on this machine's console; the peer retries automatically",
            their_name, their_cert_fingerprint
        );
        bail!(
            "{}: {} cert not approved yet, the peer retries automatically",
            APPROVAL_PENDING_SENTINEL,
            their_name
        )
    }
}

fn default_stdin_is_tty() -> bool {
    io::stdin().is_terminal()
}

/// Number of hex characters in a certificate fingerprint (a SHA-256 digest).
const FINGERPRINT_HEX_LEN: usize = 64;

/// Normalizes a user-supplied fingerprint to our storage form: lowercase hex
/// with the openssl-style colons removed ("18:AE:75:F2..." => "18ae75f2...").
pub fn normalize_fingerprint(fingerprint: &str) -> String {
    fingerprint.trim().to_lowercase().replace(':', "")
}

/// Rejects a normalized fingerprint that could never match a real certificate.
/// A SHA-256 digest is exactly 64 hex characters; anything else is a typo, a
/// truncated paste, or a value copied from the wrong tool, and accepting it
/// silently only surfaces later as an unexplained refusal.
pub fn validate_fingerprint(normalized: &str) -> Result<()> {
    if normalized.len() != FINGERPRINT_HEX_LEN
        || !normalized.chars().all(|c| c.is_ascii_hexdigit())
    {
        bail!(
            "'{}' is not a certificate fingerprint: expected {} hex characters (a SHA-256 digest), got {}. Read the peer's off its startup banner, or from 'monux status'.",
            normalized,
            FINGERPRINT_HEX_LEN,
            normalized.len()
        );
    }
    Ok(())
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
    /// Recent prompts went unanswered, so prompting is globally paused for a
    /// growing interval — including for fingerprints never seen before, which
    /// is the whole point (see ApprovalState::prompt_backoff_until).
    Backoff,
}

fn prompt_decision(state: &ApprovalState, fingerprint: &str, now: Instant) -> PromptDecision {
    if state.prompt_active {
        return PromptDecision::Pending;
    }
    // The global backoff is checked before the per-fingerprint cooldown: it
    // exists precisely for fingerprints that have never been seen before.
    if matches!(state.prompt_backoff_until, Some(until) if now < until) {
        return PromptDecision::Backoff;
    }
    match state.rejection_cooldowns.get(fingerprint) {
        Some(until) if now < *until => PromptDecision::Cooldown,
        _ => PromptDecision::Prompt,
    }
}

/// The global pause owed after `unanswered` consecutive unanswered prompts:
/// `base` doubling per repeat, capped (see GLOBAL_PROMPT_BACKOFF_BASE).
/// `base` is a parameter for the same reason rejection_cooldown is — so tests
/// can exercise the real path without waiting out a production interval.
fn global_backoff(unanswered: u32, base: Duration) -> Duration {
    if unanswered == 0 {
        return Duration::ZERO;
    }
    // Shift on u32 and saturate: an attacker can keep this counter climbing
    // indefinitely, and 1u32 << 32 is undefined-ish (a debug panic).
    let doublings = (unanswered - 1).min(20);
    base.saturating_mul(1u32 << doublings)
        .min(GLOBAL_PROMPT_BACKOFF_MAX)
}

/// Records a prompt approval: the cert becomes known immediately, so the
/// peer's automatic retry passes the known-certs check. A real answer also
/// clears the global backoff — the user is at the console pairing, which is
/// the situation the backoff must never obstruct.
fn record_approval(state: &mut ApprovalState, cert: rustls_pki_types::CertificateDer<'static>) {
    state.known_certs.push(cert);
    state.unanswered_prompts = 0;
    state.prompt_backoff_until = None;
}

/// Records a prompt rejection/timeout: reject this fingerprint without
/// re-prompting until the cooldown lapses, and pause prompting GLOBALLY for a
/// growing interval so a peer minting fresh certificates cannot re-raise the
/// prompt indefinitely. Also prunes lapsed entries.
fn record_rejection(
    state: &mut ApprovalState,
    fingerprint: String,
    now: Instant,
    cooldown: Duration,
    backoff_base: Duration,
) {
    state.rejection_cooldowns.retain(|_, until| *until > now);
    state.rejection_cooldowns.insert(fingerprint, now + cooldown);
    state.unanswered_prompts = state.unanswered_prompts.saturating_add(1);
    let backoff = global_backoff(state.unanswered_prompts, backoff_base);
    state.prompt_backoff_until = Some(now + backoff);
    if state.unanswered_prompts > 1 {
        warn!(
            "{} approval prompts in a row went unanswered; pausing new approval prompts for {}s. If you are not expecting to pair a machine, something on this network is repeatedly asking to.",
            state.unanswered_prompts,
            backoff.as_secs()
        );
    }
}

/// Everything the approval prompt thread needs, bundled so the spawn step is
/// injectable in tests.
struct PromptJob {
    cert: rustls_pki_types::CertificateDer<'static>,
    we_are_server: bool,
    discovered_server_name: Option<String>,
    config_dir: PathBuf,
    rejection_cooldown: Duration,
    global_backoff_base: Duration,
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
            job.global_backoff_base,
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
    // Read the answer from our OWN open file description on the controlling
    // terminal, never from fd 0.
    //
    // nonblock sets O_NONBLOCK on the descriptor it is handed and never
    // restores it (it has no Drop, and into_blocking is not on this path).
    // O_NONBLOCK lives on the open file DESCRIPTION, not the descriptor — and
    // when monux runs in a foreground terminal, fd 0 is the very same
    // description the invoking shell holds. Setting the flag there mutated the
    // user's shell, outlived the daemon, and left it failing reads with EAGAIN
    // ("bash: read error: 0: Resource temporarily unavailable"). The is_terminal
    // guard on this path made that certain rather than unlikely: it fires only
    // when the description IS a live shared terminal.
    //
    // Opening /dev/tty gives us a fresh description, so the flag is ours alone
    // and dies with the File at the end of this function. It also means the
    // prompt still works when stdin is redirected but a terminal is attached.
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("Failed to open /dev/tty for the approval prompt")?;
    let mut prompt_out = tty
        .try_clone()
        .context("Failed to duplicate /dev/tty for prompt output")?;
    let mut tty_in = nonblock::NonBlockingReader::from_fd(tty)
        .context("Failed to set up nonblocking reader for /dev/tty")?;

    // Flush any preceding input before prompt
    {
        let mut discard = vec![];
        tty_in
            .read_available(&mut discard)
            .context("Failed to flush initial input")?;
    }

    // Send the prompt to the terminal itself, so it is visible even when the
    // daemon's stdout is redirected to a log file.
    prompt_out
        .write_all(msg.as_bytes())
        .context("Failed to write prompt to the terminal")?;
    prompt_out.flush().context("Failed to flush the prompt")?;

    // Wait for first char, or time out. Use blocking APIs.
    let end_at = Instant::now()
        .checked_add(Duration::from_secs(PROMPT_TIMEOUT_SECS))
        .expect("Failed to configure timeout");
    let mut content = vec![];
    loop {
        thread::sleep(Duration::from_millis(50));
        tty_in
            .read_available(&mut content)
            .context("Failed to check for user input")?;

        // Check and return first character
        if let Some(c) = content.first() {
            return Ok(*c);
        }

        // Still nothing, check for timeout
        if Instant::now() >= end_at {
            let _ = prompt_out.write_all(b"\n");
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
            prompt_backoff_until: None,
            unanswered_prompts: 0,
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
            err.to_string().contains(APPROVAL_PENDING_SENTINEL),
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
        assert!(err.to_string().contains(APPROVAL_PENDING_SENTINEL));
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
            // No global backoff: it has its own tests, and leaving any here
            // would short-circuit the per-fingerprint cooldown under test
            // (the retry below is immediate).
            v.global_backoff_base = Duration::ZERO;
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
                verifier.global_backoff_base,
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

    /// The attack the global backoff exists for: minting a fresh self-signed
    /// certificate is free, so a per-FINGERPRINT cooldown alone let an
    /// unauthenticated peer raise a brand-new prompt every time one lapsed,
    /// holding the single prompt slot and burying the console indefinitely.
    /// A never-before-seen fingerprint must be refused while the backoff runs.
    #[test]
    fn a_fresh_fingerprint_cannot_reprompt_during_the_global_backoff() {
        let mut state = empty_state();
        let now = Instant::now();
        let cooldown = Duration::from_secs(60);
        let base = Duration::from_secs(15);

        // One prompt goes unanswered.
        record_rejection(&mut state, "fp-1".to_string(), now, cooldown, base);
        // The attacker's NEXT certificate is a fingerprint we have never seen,
        // so no per-fingerprint cooldown applies to it — only the global one.
        assert_eq!(
            prompt_decision(&state, "fp-2-brand-new", now + Duration::from_secs(1)),
            PromptDecision::Backoff
        );
        // Once it lapses, prompting resumes.
        assert_eq!(
            prompt_decision(&state, "fp-2-brand-new", now + base + Duration::from_secs(1)),
            PromptDecision::Prompt
        );
    }

    #[test]
    fn the_global_backoff_doubles_and_caps() {
        let base = Duration::from_secs(15);
        assert_eq!(global_backoff(0, base), Duration::ZERO);
        assert_eq!(global_backoff(1, base), base);
        assert_eq!(global_backoff(2, base), base * 2);
        assert_eq!(global_backoff(3, base), base * 4);
        // Capped, and a persistent attacker can't shift-overflow it.
        assert_eq!(global_backoff(50, base), GLOBAL_PROMPT_BACKOFF_MAX);
        assert_eq!(global_backoff(u32::MAX, base), GLOBAL_PROMPT_BACKOFF_MAX);
    }

    /// A user who is genuinely pairing must never be made to sit out a
    /// penalty someone else's traffic accumulated: an approval resets it.
    #[test]
    fn approving_clears_the_global_backoff() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = empty_state();
        let now = Instant::now();
        record_rejection(&mut state, "fp-1".to_string(), now, Duration::from_secs(60), Duration::from_secs(15));
        record_rejection(&mut state, "fp-2".to_string(), now, Duration::from_secs(60), Duration::from_secs(15));
        assert_eq!(state.unanswered_prompts, 2);
        assert!(state.prompt_backoff_until.is_some());

        record_approval(&mut state, peer_cert(dir.path()));
        assert_eq!(state.unanswered_prompts, 0);
        assert!(state.prompt_backoff_until.is_none());
        assert_eq!(
            prompt_decision(&state, "fp-3", now + Duration::from_secs(1)),
            PromptDecision::Prompt
        );
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

    /// Every rejection that is part of the normal pairing flow must carry the
    /// sentinel the connection layer keys on (server.rs is_approval_pending);
    /// every rejection that is NOT must not, or a genuine misconfiguration
    /// would be logged as a routine retry.
    #[test]
    fn pairing_rejections_carry_the_sentinel_and_faults_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let peer_dir = tempfile::tempdir().unwrap();
        let their_cert = peer_cert(peer_dir.path());

        // Prompt spawned, approval pending.
        let mut verifier = test_verifier(dir.path(), true);
        {
            let v = Arc::get_mut(&mut verifier).expect("fresh verifier is uniquely owned");
            v.stdin_is_tty = tty_yes;
            v.prompt_spawner = noop_spawn;
        }
        let pending = verifier.verify_cert(&their_cert, "Server", false).unwrap_err();
        assert!(pending.to_string().contains(APPROVAL_PENDING_SENTINEL), "{}", pending);

        // A second attempt while that prompt is active.
        let already = verifier.verify_cert(&their_cert, "Server", false).unwrap_err();
        assert!(already.to_string().contains(APPROVAL_PENDING_SENTINEL), "{}", already);

        // A fingerprint in its post-decline cooldown.
        {
            let mut state = verifier.approval_state.write().unwrap();
            record_rejection(
                &mut state,
                certs::fingerprint(&their_cert),
                Instant::now(),
                Duration::from_secs(60),
                // No global backoff, so this exercises the per-fingerprint
                // cooldown branch rather than being short-circuited by it.
                Duration::ZERO,
            );
            state.prompt_active = false;
        }
        let cooldown = verifier.verify_cert(&their_cert, "Server", false).unwrap_err();
        assert!(cooldown.to_string().contains(APPROVAL_PENDING_SENTINEL), "{}", cooldown);

        // Not pairing flow: --www with an unknown peer, and a non-TTY stdin.
        // These are setup faults and must keep erroring loudly.
        let www = test_verifier(dir.path(), false);
        let refused = www.verify_cert(&their_cert, "Client", true).unwrap_err();
        assert!(!refused.to_string().contains(APPROVAL_PENDING_SENTINEL), "{}", refused);

        let mut headless = test_verifier(dir.path(), true);
        Arc::get_mut(&mut headless)
            .expect("fresh verifier is uniquely owned")
            .stdin_is_tty = tty_no;
        let no_tty = headless.verify_cert(&their_cert, "Client", true).unwrap_err();
        assert!(!no_tty.to_string().contains(APPROVAL_PENDING_SENTINEL), "{}", no_tty);
    }

    #[test]
    fn fingerprint_validation_rejects_what_could_never_match() {
        let good = "a".repeat(64);
        assert!(validate_fingerprint(&good).is_ok());
        // Colons and case are normalized away before validation.
        let openssl = "18:AE:75:F2".to_string() + &"0".repeat(56);
        let normalized = normalize_fingerprint(&openssl);
        assert_eq!(normalized.len(), 64);
        assert!(validate_fingerprint(&normalized).is_ok());
        // Too short (a truncated paste), too long, and non-hex all refuse.
        for bad in ["", "aabbccdd", &"a".repeat(63), &"a".repeat(65), &"z".repeat(64)] {
            let err = validate_fingerprint(bad).unwrap_err().to_string();
            assert!(err.contains("hex characters"), "{}: {}", bad, err);
        }
    }

    /// A bad --fingerprints value must fail at construction, not silently
    /// never match while the startup log reports it as configured.
    #[test]
    fn constructing_with_a_malformed_fingerprint_fails() {
        let dir = tempfile::tempdir().unwrap();
        let err = MonuxCertVerification::new("test", vec!["nope".to_string()], dir.path(), false)
            .expect_err("a malformed fingerprint must be refused at startup");
        assert!(err.to_string().contains("hex characters"), "{}", err);
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
