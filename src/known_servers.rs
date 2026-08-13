//! Remembered servers: addresses a client connected to successfully, kept so
//! later runs can try them before mDNS discovery.
//!
//! Why this exists: mDNS (224.0.0.251:5353) is link-local multicast and
//! routers don't forward it, so a client on a different subnet (same modem,
//! different router) can never discover its server — while a direct
//! `monux client <ip>` works fine. Remembering that address makes later
//! connects work without retyping it.
//!
//! The store is `<config_dir>/known_servers`, one record per line:
//! `addr  fingerprint  hostname-or-dash  last-connected-unix-secs`, most
//! recent first, deduped on addr, capped at [`MAX_REMEMBERED`]. Writes are
//! atomic (tmp + rename) and owner-only (0600) like the rest of the monux
//! state.

use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use tracing::{debug, info};

/// At most this many servers are remembered; recording a new one beyond the
/// cap drops the least recently connected one.
pub const MAX_REMEMBERED: usize = 5;

const FILE_NAME: &str = "known_servers";

/// One remembered server: the address we connected to, its certificate
/// fingerprint, its hostname when known (mDNS instance name or the v15+
/// handshake name), and the last successful connection (unix seconds).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RememberedServer {
    pub addr: SocketAddr,
    pub fingerprint: String,
    pub hostname: Option<String>,
    pub last_connected: u64,
}

/// The store file inside the config directory.
fn store_path(config_dir: &Path) -> PathBuf {
    config_dir.join(FILE_NAME)
}

/// Parses one store line; corrupt lines (hand edits, a future format change)
/// are skipped, never fatal.
fn parse_line(line: &str) -> Option<RememberedServer> {
    let mut fields = line.split_whitespace();
    let addr: SocketAddr = fields.next()?.parse().ok()?;
    let fingerprint = fields.next()?.to_string();
    let hostname = match fields.next()? {
        "-" => None,
        name => Some(name.to_string()),
    };
    let last_connected: u64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    Some(RememberedServer {
        addr,
        fingerprint,
        hostname,
        last_connected,
    })
}

fn format_line(server: &RememberedServer) -> String {
    format!(
        "{}  {}  {}  {}",
        server.addr,
        server.fingerprint,
        server.hostname.as_deref().unwrap_or("-"),
        server.last_connected
    )
}

/// Loads the remembered servers, most recent first. A missing store is an
/// empty list; corrupt lines are skipped; duplicate addresses keep the first
/// (most recent) record.
pub fn load(config_dir: &Path) -> Vec<RememberedServer> {
    let path = store_path(config_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            debug!("Failed to read {}: {}", path.display(), e);
            return Vec::new();
        }
    };
    let mut servers: Vec<RememberedServer> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(server) => {
                if !servers.iter().any(|s| s.addr == server.addr) {
                    servers.push(server);
                }
            }
            None => debug!("Skipping corrupt line in {}: {:?}", path.display(), line),
        }
    }
    servers
}

/// Saves the remembered servers atomically (same-dir tmp + rename) with
/// owner-only permissions, like config.rs's atomic_write.
pub fn save(config_dir: &Path, servers: &[RememberedServer]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    fs::create_dir_all(config_dir)
        .with_context(|| format!("Failed to create {}", config_dir.display()))?;
    let path = store_path(config_dir);
    let tmp = PathBuf::from(format!("{}.tmp", path.display()));
    let mut text = String::new();
    for server in servers {
        text.push_str(&format_line(server));
        text.push('\n');
    }
    let write = || -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&tmp)?;
        // A leftover tmp from a crashed run may carry wider perms.
        file.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
        file.write_all(text.as_bytes())?;
        Ok(())
    };
    write().with_context(|| format!("Failed to write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("Failed to install {}", path.display()))
}

/// Records a successful connection: the server's address moves to the front
/// (dedup on addr), the least recently connected server beyond
/// [`MAX_REMEMBERED`] falls off. `hostname` is the mDNS instance name or the
/// v15+ handshake name when known.
pub fn record(
    config_dir: &Path,
    addr: SocketAddr,
    fingerprint: &str,
    hostname: Option<&str>,
    now_secs: u64,
) -> Result<()> {
    let mut servers = load(config_dir);
    servers.retain(|s| s.addr != addr);
    servers.insert(
        0,
        RememberedServer {
            addr,
            fingerprint: fingerprint.to_string(),
            hostname: sanitized_hostname(hostname),
            last_connected: now_secs,
        },
    );
    servers.truncate(MAX_REMEMBERED);
    save(config_dir, &servers)
}

/// The hostname arrives over the wire (mDNS or the v15 handshake) and goes
/// into the store verbatim, but the store is line-based and space-separated:
/// a hostname containing whitespace would split the record's fields and make
/// it unloadable, and a newline would inject forged records. Legit hostnames
/// never contain whitespace or control characters, so a hostile one is
/// recorded as absent (the address and fingerprint still count).
fn sanitized_hostname(hostname: Option<&str>) -> Option<String> {
    hostname
        .filter(|h| {
            !h.is_empty() && h.chars().all(|c| !c.is_whitespace() && !c.is_control())
        })
        .map(|h| h.to_string())
}

/// Finds a remembered server by its hostname (case-insensitive).
fn find_by_hostname<'a>(
    remembered: &'a [RememberedServer],
    name: &str,
) -> Option<&'a RememberedServer> {
    remembered
        .iter()
        .find(|s| s.hostname.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(name)))
}

/// Finds a remembered server by a certificate fingerprint prefix
/// (case-insensitive; fingerprints are stored lowercase). A prefix matching
/// more than one server is an error, never a silent first match: connecting
/// to the wrong (trusted) server without a word is worse than asking the user
/// for more characters.
fn find_by_fingerprint_prefix<'a>(
    remembered: &'a [RememberedServer],
    prefix: &str,
) -> Result<Option<&'a RememberedServer>> {
    if prefix.is_empty() {
        return Ok(None);
    }
    let prefix = prefix.to_lowercase();
    let matches: Vec<&RememberedServer> = remembered
        .iter()
        .filter(|s| s.fingerprint.starts_with(&prefix))
        .collect();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches[0])),
        n => bail!(
            "Fingerprint prefix '{}' is ambiguous, matches {} remembered servers",
            prefix,
            n
        ),
    }
}

/// Applies an explicitly requested port to a remembered server's address.
///
/// A remembered record stores the endpoint that worked last time, so its
/// port is the right answer for a name only the store knows: a server on a
/// non-standard port keeps answering to a plain `monux client <name>`. It
/// stops being the right answer the moment the user names a port — after the
/// server moves, `monux client desk --port 2000` has to dial 2000 instead of
/// redialing the dead port the store still holds.
///
/// INVARIANT: the port argument arrives pre-defaulted (main.rs collapses a
/// missing `--port` and a missing config entry into
/// [`crate::config::DEFAULT_PORT`]), so "no port given" and "port 1213
/// given" are indistinguishable here and only a non-default port counts as
/// deliberate. That asymmetry is the safe way round: moving a remembered
/// non-standard endpoint onto 1213 would break the very connect the store
/// exists to keep working.
fn with_requested_port(addr: SocketAddr, port: u16) -> SocketAddr {
    if port == crate::config::DEFAULT_PORT {
        return addr;
    }
    SocketAddr::new(addr.ip(), port)
}

/// Resolves a `--host` argument, in order: IP literal → remembered-store
/// hostname (case-insensitive) → system name resolution (`resolve`, today's
/// to_socket_addrs path) → remembered-store fingerprint prefix. Every field
/// printed by `monux servers` is then a valid connect target. The resolver
/// is injected so the order is testable without DNS. An explicitly requested
/// port wins over a remembered one on every path (see with_requested_port).
pub fn resolve_host(
    host: &str,
    port: u16,
    remembered: &[RememberedServer],
    resolve: impl FnOnce(&str) -> Result<Option<SocketAddr>>,
) -> Result<SocketAddr> {
    // 1) An IP literal connects directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    // 2) A remembered server's hostname (case-insensitive).
    if let Some(server) = find_by_hostname(remembered, host) {
        let addr = with_requested_port(server.addr, port);
        info!(
            "Resolved '{}' to {} via the remembered servers (hostname match)",
            host, addr
        );
        return Ok(addr);
    }
    // 3) System name resolution (DNS, /etc/hosts, <name>.local, ...).
    let resolved = resolve(host);
    if let Ok(Some(addr)) = &resolved {
        return Ok(*addr);
    }
    // 4) A remembered server's fingerprint prefix. An ambiguous prefix errors
    // out here rather than falling through to the generic "didn't resolve"
    // message below: the user named real servers, just not uniquely.
    if let Some(server) = find_by_fingerprint_prefix(remembered, host)? {
        let addr = with_requested_port(server.addr, port);
        info!(
            "Resolved '{}' to {} via the remembered servers (fingerprint-prefix match)",
            host, addr
        );
        return Ok(addr);
    }
    match resolved {
        Ok(_) => bail!(
            "Provided --host={} didn't resolve to an IP, a remembered server name, or a remembered fingerprint prefix",
            host
        ),
        Err(e) => Err(e).context(format!("Failed to resolve --host={}", host)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(addr: &str, fingerprint: &str, hostname: Option<&str>, last_connected: u64) -> RememberedServer {
        RememberedServer {
            addr: addr.parse().unwrap(),
            fingerprint: fingerprint.to_string(),
            hostname: hostname.map(|h| h.to_string()),
            last_connected,
        }
    }

    #[test]
    fn roundtrip_preserves_records_and_order() {
        let dir = tempfile::tempdir().unwrap();
        let servers = vec![
            server("192.168.1.10:1213", "aabbccdd", Some("myhost"), 1000),
            server("10.0.0.2:1213", "11223344", None, 900),
            server("[fd00::1]:1213", "ffee0011", Some("v6host"), 800),
        ];
        save(dir.path(), &servers).unwrap();
        assert_eq!(load(dir.path()), servers);
    }

    #[test]
    fn missing_store_loads_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(dir.path()).is_empty());
    }

    #[test]
    fn record_dedups_and_moves_to_front() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "10.0.0.1:1213".parse().unwrap(), "aa", Some("one"), 100).unwrap();
        record(dir.path(), "10.0.0.2:1213".parse().unwrap(), "bb", Some("two"), 200).unwrap();
        // Re-recording an existing address updates it and moves it to the front.
        record(dir.path(), "10.0.0.1:1213".parse().unwrap(), "aa2", Some("one-renamed"), 300).unwrap();
        let servers = load(dir.path());
        assert_eq!(servers.len(), 2);
        assert_eq!(
            servers[0],
            server("10.0.0.1:1213", "aa2", Some("one-renamed"), 300)
        );
        assert_eq!(servers[1], server("10.0.0.2:1213", "bb", Some("two"), 200));
        // The port is part of the address: same IP, other port is another server.
        record(dir.path(), "10.0.0.1:9999".parse().unwrap(), "cc", None, 400).unwrap();
        assert_eq!(load(dir.path()).len(), 3);
    }

    #[test]
    fn record_caps_at_max_remembered() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..MAX_REMEMBERED + 3 {
            record(
                dir.path(),
                format!("10.0.0.{}:1213", i + 1).parse().unwrap(),
                "aa",
                None,
                100 + i as u64,
            )
            .unwrap();
        }
        let servers = load(dir.path());
        assert_eq!(servers.len(), MAX_REMEMBERED);
        // Most recent first; the three oldest fell off.
        assert_eq!(servers[0].addr, "10.0.0.8:1213".parse().unwrap());
        assert_eq!(servers[4].addr, "10.0.0.4:1213".parse().unwrap());
    }

    #[test]
    fn hostile_hostnames_are_recorded_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        // A space would split the record's fields and make it unloadable.
        record(dir.path(), "10.0.0.1:1213".parse().unwrap(), "aa", Some("my host"), 100).unwrap();
        // A newline would inject a forged record into the store.
        record(
            dir.path(),
            "10.0.0.2:1213".parse().unwrap(),
            "bb",
            Some("evil\n10.9.9.9:1213  cc  forged  1"),
            200,
        )
        .unwrap();
        // Control characters too (a tab is whitespace; \x07 is control).
        record(dir.path(), "10.0.0.3:1213".parse().unwrap(), "dd", Some("bell\x07"), 300).unwrap();
        // The addr+fingerprint records survive; the hostnames read as "-".
        assert_eq!(
            load(dir.path()),
            vec![
                server("10.0.0.3:1213", "dd", None, 300),
                server("10.0.0.2:1213", "bb", None, 200),
                server("10.0.0.1:1213", "aa", None, 100),
            ]
        );
        // No forged line materialized either.
        let raw = fs::read_to_string(store_path(dir.path())).unwrap();
        assert_eq!(raw.lines().count(), 3);
        // Legit hostnames still round-trip.
        record(dir.path(), "10.0.0.4:1213".parse().unwrap(), "ee", Some("fine-host"), 400).unwrap();
        assert_eq!(
            load(dir.path())[0],
            server("10.0.0.4:1213", "ee", Some("fine-host"), 400)
        );
    }

    #[test]
    fn corrupt_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(dir.path());
        fs::write(
            &path,
            "\
192.168.1.10:1213  aabbccdd  myhost  1000
not-an-addr  aabbccdd  myhost  1000
192.168.1.11:1213  aabbccdd
192.168.1.12:1213  aabbccdd  otherhost  not-a-number
192.168.1.13:1213  aabbccdd  otherhost  1000  trailing-junk

10.0.0.2:1213  11223344  -  900
",
        )
        .unwrap();
        assert_eq!(
            load(dir.path()),
            vec![
                server("192.168.1.10:1213", "aabbccdd", Some("myhost"), 1000),
                server("10.0.0.2:1213", "11223344", None, 900),
            ]
        );
    }

    #[test]
    fn duplicate_addrs_in_the_file_keep_the_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = store_path(dir.path());
        fs::write(
            &path,
            "10.0.0.1:1213  aa  one  200\n10.0.0.1:1213  bb  two  100\n",
        )
        .unwrap();
        assert_eq!(
            load(dir.path()),
            vec![server("10.0.0.1:1213", "aa", Some("one"), 200)]
        );
    }

    #[test]
    fn store_is_owner_only_and_atomic() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        save(dir.path(), &[server("10.0.0.1:1213", "aa", None, 100)]).unwrap();
        let mode = fs::metadata(store_path(dir.path()))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "known_servers must be 0600");
        // The atomic tmp+rename must not leave scratch files behind.
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n != FILE_NAME)
            .collect();
        assert!(leftovers.is_empty(), "leftover files: {:?}", leftovers);
    }

    #[test]
    fn host_resolution_order() {
        let remembered = vec![
            server("10.1.1.1:1213", "aabbccdd1122", Some("myhost"), 100),
            server("10.2.2.2:1213", "ffeeddcc", Some("other"), 90),
            server("10.3.3.3:2000", "cc11", Some("moved"), 80),
        ];
        // 1) An IP literal wins over everything (the resolver must not run).
        assert_eq!(
            resolve_host("192.168.1.5", 1213, &remembered, |_| {
                panic!("resolver must not run for an IP literal")
            })
            .unwrap(),
            "192.168.1.5:1213".parse().unwrap()
        );
        // 2) A remembered hostname (case-insensitive) beats the system resolver.
        assert_eq!(
            resolve_host("MYHOST", 1213, &remembered, |_| {
                panic!("resolver must not run for a remembered hostname")
            })
            .unwrap(),
            "10.1.1.1:1213".parse().unwrap()
        );
        // 3) System resolution beats a remembered fingerprint prefix.
        let sys: SocketAddr = "10.9.9.9:1213".parse().unwrap();
        assert_eq!(
            resolve_host("aabb", 1213, &remembered, |_| Ok(Some(sys))).unwrap(),
            sys
        );
        // 4) A remembered fingerprint prefix when resolution finds nothing
        // (case-insensitive: fingerprints are stored lowercase).
        assert_eq!(
            resolve_host("aabb", 1213, &remembered, |_| Ok(None)).unwrap(),
            "10.1.1.1:1213".parse().unwrap()
        );
        assert_eq!(
            resolve_host("FFEEDD", 1213, &remembered, |_| Ok(None)).unwrap(),
            "10.2.2.2:1213".parse().unwrap()
        );
        // A remembered entry keeps its own port for a plain connect: that is
        // the endpoint that worked, and the caller's 1213 is indistinguishable
        // from no port at all.
        assert_eq!(
            resolve_host("moved", crate::config::DEFAULT_PORT, &remembered, |_| {
                panic!("resolver must not run for a remembered hostname")
            })
            .unwrap(),
            "10.3.3.3:2000".parse().unwrap()
        );
        // But a port the user asked for wins over the remembered one — the
        // server moved and the store still points at the dead port.
        assert_eq!(
            resolve_host("moved", 3000, &remembered, |_| {
                panic!("resolver must not run for a remembered hostname")
            })
            .unwrap(),
            "10.3.3.3:3000".parse().unwrap()
        );
        // Including on the fingerprint-prefix path.
        assert_eq!(
            resolve_host("cc11", 3000, &remembered, |_| Ok(None)).unwrap(),
            "10.3.3.3:3000".parse().unwrap()
        );
        // Nothing matches: an error, and the resolver's error propagates.
        assert!(resolve_host("nope", 1213, &remembered, |_| Ok(None)).is_err());
        let err = resolve_host("nope", 1213, &remembered, |_| {
            Err(anyhow::anyhow!("dns down"))
        })
        .unwrap_err();
        assert!(format!("{:?}", err).contains("dns down"));
    }

    /// A fingerprint prefix matching several remembered servers must not
    /// silently connect to the first one: it is an error naming the
    /// ambiguity, and more characters disambiguate.
    #[test]
    fn an_ambiguous_fingerprint_prefix_is_an_error() {
        let remembered = vec![
            server("10.1.1.1:1213", "aabbccdd1122", Some("one"), 100),
            server("10.2.2.2:1213", "aabbccdd3344", Some("two"), 90),
        ];
        let err = resolve_host("aabb", 1213, &remembered, |_| Ok(None)).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(msg.contains("ambiguous"), "{}", msg);
        assert!(msg.contains("2 remembered servers"), "{}", msg);
        // More characters pick one uniquely again.
        assert_eq!(
            resolve_host("aabbccdd33", 1213, &remembered, |_| Ok(None)).unwrap(),
            "10.2.2.2:1213".parse().unwrap()
        );
    }
}
