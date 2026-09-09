use std::fs;
use std::io::{self, prelude::*};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

pub fn load_known_certs(config_dir: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let mut certs = vec![];
    let dir = init_known_certs_dir(config_dir)?;
    for entry in fs::read_dir(&dir)? {
        // A single bad entry must not abort the whole load, matching the
        // per-file warn-and-skip policy below.
        let path = match entry {
            Ok(entry) => entry,
            Err(e) => {
                warn!("Skipping unreadable entry in {}: {:?}", dir.display(), e);
                continue;
            }
        };
        let filetype = match path.file_type() {
            Ok(filetype) => filetype,
            Err(e) => {
                warn!("Skipping {}: {:?}", path.path().display(), e);
                continue;
            }
        };
        if !filetype.is_file() {
            continue;
        }
        match load_cert(path.path()) {
            Ok(cert) => certs.push(cert),
            Err(e) => warn!("Skipping unreadable cert file {}: {:?}", path.path().display(), e),
        }
    }
    Ok(certs)
}

fn splash(label: &str, fingerprint: &str) {
    println!(
        r"
 \\ //
  \V/
   U
   | monux {}
   | {}
",
        label, fingerprint
    );
}

pub fn load_keypair<'a>(
    splash_label: &str,
    config_dir: &Path,
) -> Result<(rustls_pki_types::CertificateDer<'a>, rustls_pki_types::PrivateKeyDer<'a>)> {
    let file_path = config_dir.join("private.pem");
    if file_path.is_file() {
        match read_existing_keypair(splash_label, &file_path) {
            Ok(keypair) => {
                // Repair permissions on existing keypairs that were left at the umask default.
                ensure_permissions(&file_path, 0o600).with_context(|| {
                    format!(
                        "Failed to set permissions on keypair file: {}",
                        file_path.display()
                    )
                })?;
                Ok(keypair)
            }
            // A corrupt keypair (truncated by a crash, clobbered by a copy)
            // must not be fatal: the daemon would never start again without
            // manual deletion. Move it aside and regenerate. Our fingerprint
            // changes, so peers will ask for approval once more.
            Err(e) => {
                let backup_path = file_path.with_extension("pem.corrupt");
                warn!(
                    "Existing keypair at {} is unreadable ({}); moving it aside to {} and generating a fresh one",
                    file_path.display(),
                    e,
                    backup_path.display()
                );
                fs::rename(&file_path, &backup_path).with_context(|| {
                    format!(
                        "Failed to move corrupt keypair {} aside to {}",
                        file_path.display(),
                        backup_path.display()
                    )
                })?;
                write_new_keypair(splash_label, &file_path)
            }
        }
    } else {
        write_new_keypair(splash_label, &file_path)
    }
}

fn read_existing_keypair<'a>(
    splash_label: &str,
    file_path: &PathBuf,
) -> Result<(rustls_pki_types::CertificateDer<'a>, rustls_pki_types::PrivateKeyDer<'a>)> {
    let mut reader =
        io::BufReader::new(fs::File::open(file_path).with_context(|| {
            format!("Failed to open keypair file: {}", file_path.display())
        })?);
    let mut cert: Option<rustls_pki_types::CertificateDer> = None;
    let mut key: Option<rustls_pki_types::PrivateKeyDer> = None;
    for item in rustls_pemfile::read_all(&mut reader) {
        match item.with_context(|| format!("Failed to read keypair file: {}", file_path.display()))? {
            rustls_pemfile::Item::X509Certificate(filecert) => {
                cert = Some(filecert);
            }
            rustls_pemfile::Item::Pkcs8Key(filekey) => {
                key = Some(rustls_pki_types::PrivateKeyDer::from(filekey));
            }
            _ => {
                // Avoid logging the content in case its a privkey
                warn!("Unexpected item in {}", file_path.display());
            }
        }
    }
    if let (Some(cert), Some(key)) = (cert, key) {
        splash(splash_label, &fingerprint(&cert));
        info!("Using keypair from {}", file_path.display());
        Ok((cert, key))
    } else {
        bail!("Incomplete cert/key content in {}", file_path.display());
    }
}

fn write_new_keypair<'a>(
    splash_label: &str,
    file_path: &PathBuf,
) -> Result<(rustls_pki_types::CertificateDer<'a>, rustls_pki_types::PrivateKeyDer<'a>)> {
    // The CN carries this machine's hostname so a peer can caption an
    // approval request with more than an IP address (see common_name). It is
    // a display hint, not an identity: peers authenticate by fingerprint.
    let mut params = rcgen::CertificateParams::new(vec![])
        .context("Failed to set up certificate parameters")?;
    if let Ok(host) = crate::discovery::get_hostname() {
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, host);
        params.distinguished_name = dn;
    }
    let signing_key = rcgen::KeyPair::generate().context("Failed to generate key")?;
    let cert = params
        .self_signed(&signing_key)
        .context("Failed to generate self-signed cert")?;

    info!("Writing a new keypair to {}", file_path.display());
    // Atomic install (same-dir tmp + rename, the idiom of config.rs and
    // known_servers.rs): a crash mid-write must never leave a truncated
    // private.pem behind, and two processes generating at once rename whole
    // pairs over each other instead of interleaving a mismatched cert/key.
    let tmp_path = file_path.with_extension("pem.tmp");
    let mut outfile = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| {
            format!(
                "Failed to open keypair file for writing: {}",
                tmp_path.display()
            )
        })?;
    // A leftover tmp from a crashed run may carry wider perms.
    ensure_permissions(&tmp_path, 0o600).with_context(|| {
        format!(
            "Failed to set permissions on keypair file: {}",
            tmp_path.display()
        )
    })?;
    outfile
        .write_all(cert.pem().as_bytes())
        .with_context(|| format!("Failed to write public key to file: {}", tmp_path.display()))?;
    outfile
        .write_all(signing_key.serialize_pem().as_bytes())
        .with_context(|| format!("Failed to write private key to file: {}", tmp_path.display()))?;
    fs::rename(&tmp_path, file_path).with_context(|| {
        format!(
            "Failed to install keypair file: {}",
            file_path.display()
        )
    })?;

    let rustls_cert = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    splash(splash_label, &fingerprint(&rustls_cert));
    Ok((
        rustls_cert,
        rustls_pki_types::PrivateKeyDer::from(rustls_pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
    ))
}

/// The CommonName of a certificate, when it carries a meaningful one.
///
/// New keypairs get this machine's hostname as CN (see write_new_keypair), so
/// approval listings can caption a knocking peer with more than an address.
/// Keypairs from before that carry rcgen's placeholder CN, which identifies
/// nothing — those report None rather than a name every old cert shares.
///
/// Hand-rolled DER scan (the CN's attribute value directly follows its
/// 2.5.4.3 OID; the x509-parser dependency isn't worth one field): bounded
/// reads throughout, anything malformed simply reports None. Display hint
/// only — identity is the fingerprint.
pub fn common_name(cert: &rustls_pki_types::CertificateDer) -> Option<String> {
    const CN_OID: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03];
    const PLACEHOLDER: &str = "rcgen self signed cert";
    let der = cert.as_ref();
    let mut i = 0;
    while i + CN_OID.len() < der.len() {
        if &der[i..i + CN_OID.len()] == CN_OID {
            let tag = der[i + CN_OID.len()];
            // UTF8String / PrintableString / IA5String values only.
            if matches!(tag, 0x0C | 0x13 | 0x16) {
                let len = *der.get(i + CN_OID.len() + 1)? as usize;
                let start = i + CN_OID.len() + 2;
                let end = start.checked_add(len)?;
                let name = std::str::from_utf8(der.get(start..end)?).ok()?;
                if !name.is_empty() && name != PLACEHOLDER {
                    return Some(name.to_string());
                }
            }
        }
        i += 1;
    }
    None
}

/// Returns the sha256 fingerprint of this certificate.
/// We use this for cert filenames and for comparing certs in confirmation prompts.
/// This should match the output of "openssl x509 -in <filename> -noout -sha256 -fingerprint"
pub fn fingerprint(cert: &rustls_pki_types::CertificateDer) -> String {
    hex::encode(Sha256::digest(cert))
}

pub fn write_approved_cert(
    cert: &rustls_pki_types::CertificateDer,
    fingerprint: &str,
    config_dir: &Path,
) -> Result<()> {
    let file_path = init_known_certs_dir(config_dir)
        .context("Failed to init known_certs dir")?
        .join(format!("{}.pem", fingerprint));
    let content = pem::encode_config(
        &pem::Pem::new("CERTIFICATE", cert.as_ref()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    );
    let mut outfile = fs::File::create(&file_path).with_context(|| {
        format!(
            "Failed to open known cert file for writing: {}",
            file_path.display()
        )
    })?;
    ensure_permissions(&file_path, 0o644).with_context(|| {
        format!(
            "Failed to set permissions on known cert file: {}",
            file_path.display()
        )
    })?;
    outfile.write_all(content.as_bytes()).with_context(|| {
        format!(
            "Failed to write known cert to file: {}",
            file_path.display()
        )
    })?;
    info!("Wrote approved cert to {}", file_path.display());
    Ok(())
}

fn load_cert<'a>(file_path: PathBuf) -> Result<rustls_pki_types::CertificateDer<'a>> {
    let mut reader = io::BufReader::new(
        fs::File::open(&file_path)
            .with_context(|| format!("Failed to open cert file: {}", file_path.display()))?,
    );
    if let Some(rustls_pemfile::Item::X509Certificate(filecert)) =
        rustls_pemfile::read_one(&mut reader)
            .with_context(|| format!("Failed to read cert file: {}", file_path.display()))?
    {
        Ok(filecert)
    } else {
        bail!("Public certificate not found in {}", file_path.display());
    }
}

fn init_known_certs_dir(config_dir: &Path) -> Result<PathBuf> {
    let dir_path = config_dir.join("known_certs");
    fs::create_dir_all(&dir_path)
        .with_context(|| format!("Failed to ensure certs dir exists: {}", dir_path.display()))?;
    ensure_permissions(&dir_path, 0o755).with_context(|| {
        format!(
            "Failed to set permissions on certs dir: {}",
            dir_path.display()
        )
    })?;
    Ok(dir_path)
}

fn ensure_permissions(path: &PathBuf, perms: u32) -> Result<()> {
    let permissions = fs::metadata(path)
        .with_context(|| format!("Failed to read file metadata: {}", path.display()))?
        .permissions();
    if permissions.mode() & 0o777 != perms {
        fs::set_permissions(path, fs::Permissions::from_mode(perms))
            .with_context(|| format!("Failed to set permissions on file: {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile;

    #[test]
    fn can_write_read_keys() {
        let dir = tempfile::tempdir().unwrap();
        // This should automatically write a new keypair
        let (cert1, privkey1) = load_keypair("foo", dir.path()).expect("couldn't load");
        // This should read the existing keypair
        let (cert2, privkey2) = load_keypair("foo", dir.path()).expect("couldn't load");
        // The results should match
        assert!(fingerprint(&cert1) == fingerprint(&cert2));
        assert!(cert1 == cert2);
        assert!(privkey1 == privkey2);
        // The atomic tmp+rename must not leave scratch files behind.
        assert!(!dir.path().join("private.pem.tmp").exists());
    }

    #[test]
    fn new_keypairs_carry_the_hostname_as_common_name() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = load_keypair("test", dir.path()).expect("couldn't generate");
        let host = crate::discovery::get_hostname().expect("hostname");
        assert_eq!(common_name(&cert).as_deref(), Some(host.as_str()));
    }

    #[test]
    fn placeholder_and_malformed_common_names_report_none() {
        // Old keypairs: rcgen's default placeholder identifies nothing.
        let old = rcgen::generate_simple_self_signed(vec![]).unwrap();
        let old_der = rustls_pki_types::CertificateDer::from(old.cert.der().to_vec());
        assert_eq!(common_name(&old_der), None);
        // Garbage DER: bounded reads degrade to None, never panic.
        assert_eq!(common_name(&rustls_pki_types::CertificateDer::from(vec![0x06, 0x03, 0x55, 0x04, 0x03, 0x0C])), None);
        assert_eq!(common_name(&rustls_pki_types::CertificateDer::from(vec![])), None);
    }

    #[test]
    fn corrupt_keypair_is_backed_up_and_regenerated() {
        let dir = tempfile::tempdir().unwrap();
        let (cert1, _) = load_keypair("foo", dir.path()).expect("couldn't load");
        // Simulate a crash mid-write: a truncated keypair must not be fatal.
        fs::write(dir.path().join("private.pem"), b"-----BEGIN CERTIFICATE-----\ntruncated")
            .unwrap();
        let (cert2, _) = load_keypair("foo", dir.path()).expect("corrupt keypair must regenerate");
        assert!(fingerprint(&cert1) != fingerprint(&cert2));
        assert!(dir.path().join("private.pem.corrupt").is_file());
        // The regenerated keypair loads cleanly from then on.
        let (cert3, _) = load_keypair("foo", dir.path()).expect("couldn't reload");
        assert!(cert2 == cert3);
    }
}
