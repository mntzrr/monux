//! The `monux servers` listing: a display-only union of the servers visible
//! on the LAN via mDNS and the ones remembered from past connections
//! (known_servers.rs). It NEVER connects to anything — no probes, no
//! handshake — it reads the mDNS advertisements and the store file only.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use crate::discovery::DiscoveredServer;
use crate::known_servers::RememberedServer;

/// How long the listing browses for mDNS advertisements: long enough for a
/// running server to answer, short enough that the command doesn't appear to
/// hang (mirrors the update gate's browse timeout).
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Builds the listing printed by `monux servers`.
pub fn listing(config_dir: &Path) -> String {
    let remembered = crate::known_servers::load(config_dir);
    // A failed or empty browse is not an error for a display command: the
    // remembered entries still list (and the empty state says what to do).
    let discovered = crate::discovery::discover_servers_blocking(Some(DISCOVERY_TIMEOUT))
        .unwrap_or_default();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    render(&discovered, &remembered, now)
}

/// "2h ago"-style relative time for the remembered servers' last-connected
/// column. Saturates at zero for a future (clock-skewed) timestamp.
fn human_ago(now_secs: u64, then_secs: u64) -> String {
    let secs = now_secs.saturating_sub(then_secs);
    match secs {
        0..=59 => format!("{}s ago", secs),
        60..=3599 => format!("{}m ago", secs / 60),
        3600..=86399 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86400),
    }
}

/// One listing row: one per server ADDRESS (a server with several addresses
/// gets one row each).
struct Row {
    name: String,
    addr: SocketAddr,
    fingerprint: Option<String>,
    protocol_version: Option<u64>,
    source: String,
}

impl Row {
    fn render(&self, name_width: usize, addr_width: usize) -> String {
        let fingerprint = self
            .fingerprint
            .as_deref()
            .map(|fp| fp.chars().take(8).collect::<String>())
            .unwrap_or_else(|| "-".to_string());
        let protocol_version = self
            .protocol_version
            .map(|pv| format!("v{}", pv))
            .unwrap_or_else(|| "-".to_string());
        format!(
            "{:<name_width$}  {:<addr_width$}  fp {}  {:<4}  {}",
            self.name,
            self.addr.to_string(),
            fingerprint,
            protocol_version,
            self.source,
            name_width = name_width,
            addr_width = addr_width,
        )
    }
}

/// Renders the listing: the mDNS instances first (an address also present in
/// the remembered store shows once, as mdns), then the remembered-only
/// addresses, then the footer hints. Pure for testing.
fn render(
    discovered: &[DiscoveredServer],
    remembered: &[RememberedServer],
    now_secs: u64,
) -> String {
    let mut rows: Vec<Row> = Vec::new();
    for instance in discovered {
        for ip in &instance.addrs {
            rows.push(Row {
                name: instance.name.clone(),
                addr: SocketAddr::new(*ip, instance.port),
                fingerprint: instance.fingerprint.clone(),
                protocol_version: instance.protocol_version,
                source: "mdns".to_string(),
            });
        }
    }
    for server in remembered {
        if rows.iter().any(|row| row.addr == server.addr) {
            // Visible via mDNS AND remembered: shows once, as mdns.
            continue;
        }
        rows.push(Row {
            name: server.hostname.clone().unwrap_or_else(|| "-".to_string()),
            addr: server.addr,
            fingerprint: Some(server.fingerprint.clone()),
            protocol_version: None,
            source: format!(
                "remembered, last connected {}",
                human_ago(now_secs, server.last_connected)
            ),
        });
    }

    let mut out = String::new();
    if rows.is_empty() {
        out.push_str(
            "No Monux servers found: nothing answered mDNS on this network and nothing is remembered yet.\nRun a server with 'monux server', or connect once with 'monux client <ip>' (remembered thereafter).\n",
        );
    } else {
        let name_width = rows.iter().map(|row| row.name.len()).max().unwrap_or(0);
        let addr_width = rows
            .iter()
            .map(|row| row.addr.to_string().len())
            .max()
            .unwrap_or(0);
        for row in &rows {
            out.push_str(&row.render(name_width, addr_width));
            out.push('\n');
        }
    }
    out.push_str("connect with: monux client <ip|name|fingerprint-prefix>\n");
    out.push_str("pre-approve with: --fingerprints <fingerprint>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn discovered(name: &str, ips: &[&str], port: u16, pv: Option<u64>, fp: Option<&str>) -> DiscoveredServer {
        DiscoveredServer {
            name: name.to_string(),
            addrs: ips.iter().map(|ip| ip.parse::<IpAddr>().unwrap()).collect(),
            port,
            protocol_version: pv,
            fingerprint: fp.map(|fp| fp.to_string()),
        }
    }

    fn remembered(addr: &str, fp: &str, hostname: Option<&str>, last_connected: u64) -> RememberedServer {
        RememberedServer {
            addr: addr.parse().unwrap(),
            fingerprint: fp.to_string(),
            hostname: hostname.map(|h| h.to_string()),
            last_connected,
        }
    }

    #[test]
    fn human_ago_picks_the_largest_unit() {
        assert_eq!(human_ago(1000, 1000), "0s ago");
        assert_eq!(human_ago(1000, 955), "45s ago");
        assert_eq!(human_ago(1000, 910), "1m ago");
        assert_eq!(human_ago(10_000, 10_000 - 7_200), "2h ago");
        assert_eq!(human_ago(300_000, 300_000 - 3 * 86_400), "3d ago");
        // Clock skew (the timestamp is in the future) saturates at zero.
        assert_eq!(human_ago(100, 200), "0s ago");
    }

    #[test]
    fn renders_one_line_per_address_and_the_footer() {
        let discovered = vec![discovered(
            "myhost",
            &["192.168.1.187", "192.168.56.1"],
            1213,
            Some(15),
            Some("aabbccdd11223344"),
        )];
        let remembered = vec![remembered(
            "192.0.2.1:1213",
            "ffeeddcc00112233",
            Some("oldhost"),
            1000,
        )];
        let out = render(&discovered, &remembered, 1000 + 7_200);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines,
            vec![
                "myhost   192.168.1.187:1213  fp aabbccdd  v15   mdns",
                "myhost   192.168.56.1:1213   fp aabbccdd  v15   mdns",
                "oldhost  192.0.2.1:1213      fp ffeeddcc  -     remembered, last connected 2h ago",
                "connect with: monux client <ip|name|fingerprint-prefix>",
                "pre-approve with: --fingerprints <fingerprint>",
            ]
        );
    }

    #[test]
    fn an_address_visible_via_both_shows_once_as_mdns() {
        let discovered = vec![discovered(
            "myhost",
            &["192.168.1.187"],
            1213,
            Some(15),
            Some("aabbccdd11223344"),
        )];
        let remembered = vec![remembered(
            "192.168.1.187:1213",
            "aabbccdd11223344",
            Some("myhost"),
            1000,
        )];
        let out = render(&discovered, &remembered, 1000);
        assert_eq!(out.lines().filter(|line| line.contains("192.168.1.187")).count(), 1);
        assert!(out.contains("mdns"));
        assert!(!out.contains("remembered"));
    }

    #[test]
    fn empty_state_points_at_the_ways_forward() {
        let out = render(&[], &[], 1000);
        assert!(out.contains("No Monux servers found"));
        assert!(out.contains("monux client <ip>"));
        assert!(out.contains("connect with: monux client <ip|name|fingerprint-prefix>"));
        assert!(out.contains("pre-approve with: --fingerprints <fingerprint>"));
    }

    #[test]
    fn missing_txt_properties_and_hostname_render_as_dashes() {
        let discovered = vec![discovered("noname", &["10.0.0.1"], 1213, None, None)];
        let remembered = vec![remembered("10.0.0.2:1213", "aabb", None, 1000)];
        let out = render(&discovered, &remembered, 1060);
        // Compare fields, not padding (the exact column widths are pinned by
        // renders_one_line_per_address_and_the_footer).
        let fields: Vec<Vec<&str>> = out
            .lines()
            .take(2)
            .map(|line| line.split_whitespace().collect())
            .collect();
        assert_eq!(
            fields,
            vec![
                vec!["noname", "10.0.0.1:1213", "fp", "-", "-", "mdns"],
                vec![
                    "-",
                    "10.0.0.2:1213",
                    "fp",
                    "aabb",
                    "-",
                    "remembered,",
                    "last",
                    "connected",
                    "1m",
                    "ago"
                ],
            ]
        );
    }
}
