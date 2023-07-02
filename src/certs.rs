use anyhow::{bail, Context, Result};
use async_std::io as aio;
use async_std::task;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

use std::fs;
use std::io::{self, prelude::*};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

pub fn load_known_certs() -> Result<Vec<rustls::Certificate>> {
    let mut certs = vec![];
    for path in fs::read_dir(init_known_certs_dir()?)? {
        let path = path?;
        let filetype = path.file_type()?;
        if !filetype.is_file() {
            continue;
        }
        certs.push(load_cert(&path.path())?);
    }
    Ok(certs)
}

pub fn load_keypair() -> Result<(rustls::Certificate, rustls::PrivateKey)> {
    let file_path = init_config_dir()?.join("private.pem");
    if file_path.is_file() {
        let mut reader = io::BufReader::new(fs::File::open(&file_path).with_context(|| format!("Failed to open keypair file: {}", file_path.display()))?);
        let mut cert: Option<rustls::Certificate> = None;
        let mut key: Option<rustls::PrivateKey> = None;
        for item in rustls_pemfile::read_all(&mut reader).with_context(|| format!("Failed to read keypair file: {}", file_path.display()))? {
            match item {
                rustls_pemfile::Item::X509Certificate(filecert) => {
                    cert = Some(rustls::Certificate(filecert));
                },
                rustls_pemfile::Item::PKCS8Key(filekey) => {
                    key = Some(rustls::PrivateKey(filekey));
                },
                _ => {
                    warn!("Unexpected item in {}", file_path.display());
                },
            }
        }
        if let (Some(cert), Some(key)) = (cert, key) {
            return Ok((cert, key));
        } else {
            bail!("Incomplete cert/key content in {}", file_path.display());
        }
    } else {
        let cert = rcgen::generate_simple_self_signed(vec![]).context("Failed to generate self-signed cert")?;
        let mut outfile = fs::File::create(&file_path).with_context(|| format!("Failed to open keypair file for writing: {}", file_path.display()))?;
        ensure_permissions(&file_path, 0o600).with_context(|| format!("Failed to set permissions on keypair file: {}", file_path.display()))?;
        outfile.write_all(cert.serialize_pem()?.as_bytes()).with_context(|| format!("Failed to write cert to keypair file: {}", file_path.display()))?;
        outfile.write_all(cert.serialize_private_key_pem().as_bytes()).with_context(|| format!("Failed to write key to keypair file: {}", file_path.display()))?;
        Ok((rustls::Certificate(cert.serialize_der()?), rustls::PrivateKey(cert.serialize_private_key_der())))
    }
}

pub struct ManualServerVerification {
    our_cert_sig: String,
    known_certs: Vec<rustls::Certificate>,
}

impl ManualServerVerification {
    pub fn new(our_cert: &rustls::Certificate, known_certs: Vec<rustls::Certificate>) -> Arc<Self> {
        Arc::new(ManualServerVerification {
            our_cert_sig: signature(our_cert),
            known_certs,
        })
    }
}

impl rustls::client::ServerCertVerifier for ManualServerVerification {
    fn verify_server_cert(
        &self,
        server_cert: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        if self.known_certs.contains(server_cert) {
            info!("[client] server cert found in known certificates: {}", signature(&server_cert));
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            prompt_unknown_cert(server_cert, &self.our_cert_sig, false, rustls::client::ServerCertVerified::assertion())
        }
    }
}

pub struct ManualClientVerification {
    our_cert_sig: String,
    known_certs: Vec<rustls::Certificate>,
}

impl ManualClientVerification {
    pub fn new(our_cert: &rustls::Certificate, known_certs: Vec<rustls::Certificate>) -> Arc<Self> {
        Arc::new(ManualClientVerification {
            our_cert_sig: signature(our_cert),
            known_certs,
        })
    }
}

impl rustls::server::ClientCertVerifier for ManualClientVerification {
    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        client_cert: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _now: SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        if self.known_certs.contains(client_cert) {
            info!("[server] client cert found in known certificates: {}", signature(&client_cert));
            Ok(rustls::server::ClientCertVerified::assertion())
        } else {
            prompt_unknown_cert(client_cert, &self.our_cert_sig, true, rustls::server::ClientCertVerified::assertion())
        }
    }
}

fn signature(cert: &rustls::Certificate) -> String {
    format!("{:x}", Sha256::digest(&cert))
}

fn prompt_unknown_cert<T>(their_cert: &rustls::Certificate, our_cert_sig: &String, we_are_server: bool, approved_obj: T) -> Result<T, rustls::Error> {
    let their_cert_sig = signature(&their_cert);
    // Let's assume the user will typically see this only once during initial setup of one client and one server.
    // Make it easier to compare by showing the same server/client info across both systems.
    let server_cert_sig: &String;
    let client_cert_sig: &String;
    if we_are_server {
        server_cert_sig = our_cert_sig;
        client_cert_sig = &their_cert_sig;
    } else {
        server_cert_sig = &their_cert_sig;
        client_cert_sig = our_cert_sig;
    }
    let message = format!("New connection, approval needed...

Check that the following hashes look the same on the server and on the client:
- Server hash: {}
- Client hash: {}

Confirm new connection? [y/N]", server_cert_sig, client_cert_sig);
    if prompt_yn(&message, false) {
        info!("Cert approved by user: {}", their_cert_sig);
        if let Err(e) = write_approved_cert(their_cert) {
            warn!("Couldn't store approved cert: {}", e);
        }
        Ok(approved_obj)
    } else {
        info!("Cert denied by user: {}", their_cert_sig);
        Err(rustls::Error::General(format!("Server cert was not approved: {}", signature(&their_cert))))
    }
}

fn prompt_yn(msg: &str, default: bool) -> bool {
    match prompt_internal(msg) {
        Ok(input) => {
            if input.is_empty() {
                return default;
            }
            match input.chars().nth(0).expect("Failed to get first char") {
                'y' | 'Y' | 't' | 'T' => true,
                _ => false,
            }
        },
        Err(e) => {
            warn!("Failed to prompt for confirmation, assuming {}: {}", if default { "Yes" } else { "No" }, e);
            return default;
        }
    }
}

fn prompt_internal(msg: &str) -> Result<String> {
    let msg_formatted = format!("{}: ", msg);
    let mut stdout = io::stdout();
    stdout
        .write_all(msg_formatted.as_bytes())
        .context("Failed to write prompt to stdout")?;
    stdout.flush().expect("Failed to flush stdout");
    let mut response = String::new();
    task::block_on(async {
        let timeout_secs = 60;
        match aio::timeout(Duration::from_secs(timeout_secs), aio::stdin().read_line(&mut response)).await {
            Ok(_) => {
                return Ok(());
            },
            Err(_e) => {
                // Skip output to next line so that logs don't print on top of the prompt
                println!("");
                bail!("Prompt timed out after {}s", timeout_secs)
            },
        }
    })?;
    Ok(response.trim().to_string())
}

fn write_approved_cert(cert: &rustls::Certificate) -> Result<()> {
    let file_path = init_known_certs_dir().context("Failed to init known_certs dir")?.join(signature(cert));
    let content = pem::encode_config(
        &pem::Pem::new("CERTIFICATE", cert.0.clone()),
        pem::EncodeConfig { line_ending: pem::LineEnding::LF }
    );
    let mut outfile = fs::File::create(&file_path).with_context(|| format!("Failed to open known cert file for writing: {}", file_path.display()))?;
    ensure_permissions(&file_path, 0o644).with_context(|| format!("Failed to set permissions on known cert file: {}", file_path.display()))?;
    outfile.write_all(content.as_bytes()).with_context(|| format!("Failed to write known cert to file: {}", file_path.display()))?;
    info!("Wrote approved cert to {}", file_path.display());
    Ok(())
}

fn load_cert(file_path: &PathBuf) -> Result<rustls::Certificate> {
    let mut reader = io::BufReader::new(fs::File::open(&file_path).with_context(|| format!("Failed to open cert file: {}", file_path.display()))?);
    if let Some(rustls_pemfile::Item::X509Certificate(filecert)) = rustls_pemfile::read_one(&mut reader).with_context(|| format!("Failed to read cert file: {}", file_path.display()))? {
        return Ok(rustls::Certificate(filecert));
    } else {
        bail!("Public certificate not found in {}", file_path.display());
    }
}

fn init_known_certs_dir() -> Result<PathBuf> {
    let dir_path = init_config_dir()?.join("known_certs");
    fs::create_dir_all(&dir_path).with_context(|| format!("Failed to ensure certs dir exists: {}", dir_path.display()))?;
    ensure_permissions(&dir_path, 0o755).with_context(|| format!("Failed to set permissions on certs dir: {}", dir_path.display()))?;
    Ok(dir_path)
}

fn ensure_permissions(path: &PathBuf, perms: u32) -> Result<()> {
    let mut permissions = fs::metadata(path).with_context(|| format!("Failed to read file metadata: {}", path.display()))?.permissions();
    if permissions.mode() != perms {
        permissions.set_mode(perms);
    }
    Ok(())
}

fn init_config_dir() -> Result<PathBuf> {
    let mut homedir = home::home_dir().context("No home dir found: Unable to store certs")?;
    homedir.push(".config");
    homedir.push("nikau");
    fs::create_dir_all(&homedir).with_context(|| format!("Failed to create config directory: {}", homedir.display()))?;
    Ok(homedir)
}
