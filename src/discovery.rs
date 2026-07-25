use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo, TxtProperties};
use tracing::{debug, info, warn};

/// mDNS service type used to advertise and discover Monux servers on the local network.
const SERVICE_TYPE: &str = "_monux._udp.local.";

/// TXT property under which a server advertises its wire protocol version, so
/// clients can refresh their update gate (see update.rs) from the LAN instead
/// of waiting for a handshake.
const PROTOCOL_VERSION_PROPERTY: &str = "pv";

/// TXT property under which a server advertises its certificate fingerprint,
/// so `monux servers` can display it (and pre-approve with --fingerprints).
const FINGERPRINT_PROPERTY: &str = "fp";

/// How long `monux update` browses for advertised server protocol versions
/// before falling back to the recorded gate value: long enough for a running
/// server to answer, short enough that the command doesn't appear to hang.
const SERVER_VERSION_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(2);

/// Default time to wait for a server to be discovered on the LAN.
const DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// After the first server resolves, keep listening this long for additional servers
/// so that "first wins" doesn't silently hide them.
const EXTRA_RESOLVE_GRACE: Duration = Duration::from_millis(500);

/// Error message when no server is discovered within the timeout.
const DISCOVERY_TIMEOUT_HINT: &str = "Discovery timeout: no Monux server found on the local network. Check that: the server is running, both machines are on the same subnet, and no firewall is blocking UDP port 5353 (mDNS). Note that mDNS is link-local multicast and cannot cross routers/subnets: on a different subnet, connect once with 'monux client <ip>' — the address is remembered thereafter";

/// Registers a Monux server on the local network via mDNS.
pub struct DiscoveryRegistration {
    daemon: ServiceDaemon,
    fullname: String,
}

impl DiscoveryRegistration {
    /// Advertises a Monux server listening on the given address, with its
    /// certificate fingerprint in the TXT record.
    pub fn register(listen_addr: SocketAddr, fingerprint: &str) -> Result<Self> {
        let hostname = get_hostname().context("Failed to get hostname")?;
        let instance_name = if hostname.is_empty() {
            "monux".to_string()
        } else {
            hostname
        };
        let host_name = format!("{}.local.", instance_name);
        let port = listen_addr.port();
        let ips = advertise_ips(listen_addr.ip())?;

        // Advertise the wire protocol version so clients can refresh their
        // update gate from the LAN (see update.rs), and the certificate
        // fingerprint so 'monux servers' can display it. Both are
        // informational only: like all mDNS data the TXT record is
        // unauthenticated — acceptable because the gate is only a
        // convenience and real trust is the cert approval flow. Old clients
        // ignore unknown TXT properties; there is no protocol dependency.
        let properties = HashMap::from([
            (
                PROTOCOL_VERSION_PROPERTY.to_string(),
                crate::msgs::shared::PROTOCOL_VERSION.to_string(),
            ),
            (FINGERPRINT_PROPERTY.to_string(), fingerprint.to_string()),
        ]);

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_name,
            &ips[..],
            port,
            properties,
        )
        .context("Failed to create mDNS service info")?;

        let fullname = service_info.get_fullname().to_string();
        let daemon = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
        daemon
            .register(service_info)
            .context("Failed to register mDNS service")?;

        info!(
            "Registered mDNS service: {} at {:?}:{}",
            fullname, ips, port
        );

        Ok(Self {
            daemon,
            fullname,
        })
    }
}

impl Drop for DiscoveryRegistration {
    fn drop(&mut self) {
        // Wait for each response (with a timeout) instead of dropping the
        // receivers: the daemon thread error-logs "failed to send response"
        // when it can't deliver the status to a dropped receiver.
        match self.daemon.unregister(&self.fullname) {
            Ok(resp) => {
                let _ = resp.recv_timeout(std::time::Duration::from_secs(2));
            }
            Err(e) => warn!("Failed to unregister mDNS service: {}", e),
        }
        match self.daemon.shutdown() {
            Ok(resp) => {
                let _ = resp.recv_timeout(std::time::Duration::from_secs(2));
            }
            Err(e) => warn!("Failed to shutdown mDNS daemon: {}", e),
        }
    }
}

/// One Monux server instance discovered via mDNS.
#[derive(Clone, Debug)]
pub struct DiscoveredServer {
    /// Instance name (normally the server's hostname), stripped of the
    /// service-type suffix.
    pub name: String,
    /// All advertised addresses, merged across resolve events (mDNS delivers
    /// a service's addresses incrementally) and deduped.
    pub addrs: Vec<IpAddr>,
    /// The advertised port.
    pub port: u16,
    /// The advertised wire protocol version (TXT `pv`); None when the server
    /// predates the advertisement.
    pub protocol_version: Option<u64>,
    /// The advertised certificate fingerprint (TXT `fp`); None when the
    /// server predates the advertisement.
    pub fingerprint: Option<String>,
}

/// Discovers ALL Monux servers advertised on the local network via mDNS, in
/// resolve order. The mDNS browse is synchronous (mdns_sd is a channel API);
/// it runs off the async workers so a long timeout can't park one.
pub async fn discover_servers(timeout: Option<Duration>) -> Result<Vec<DiscoveredServer>> {
    tokio::task::spawn_blocking(move || discover_servers_blocking(timeout))
        .await
        .context("mDNS discovery task failed")?
}

/// Synchronous core of `discover_servers` (also used by `monux servers`,
/// which runs before the tokio runtime exists). Browses until the timeout,
/// but ends a grace period (EXTRA_RESOLVE_GRACE) after the first resolve:
/// mDNS answers are near-instant on a LAN, and waiting out the full timeout
/// would make a listing feel hung. Errors only when NOTHING resolved within
/// the timeout (DISCOVERY_TIMEOUT_HINT) or the browse itself failed.
pub fn discover_servers_blocking(timeout: Option<Duration>) -> Result<Vec<DiscoveredServer>> {
    let timeout = timeout.unwrap_or(DEFAULT_DISCOVERY_TIMEOUT);
    let daemon = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .context("Failed to browse for Monux servers")?;

    let deadline = Instant::now() + timeout;
    // Once the first instance has resolved, only wait out the grace period
    // for the rest of its addresses (and other servers) to arrive.
    let mut grace_deadline: Option<Instant> = None;
    let mut instances: Vec<DiscoveredServer> = Vec::new();
    // Parallel to `instances`: the service fullname, for merging the
    // incremental resolve events of one instance.
    let mut fullnames: Vec<String> = Vec::new();

    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            // The grace period can outlast the overall timeout: a first
            // resolve arriving in its last moments must not fail discovery
            // AFTER finding a server — return what we have.
            None if keep_found_past_deadline(&instances) => break,
            None => bail!("{}", DISCOVERY_TIMEOUT_HINT),
        };
        let wait = match grace_deadline {
            Some(grace) => match grace.checked_duration_since(Instant::now()) {
                Some(grace_remaining) => grace_remaining,
                None => break,
            },
            None => remaining,
        };

        let event = match receiver.recv_timeout(wait) {
            Ok(event) => event,
            // Timeout (normal: no more answers within the window) or the
            // daemon's channel closing: either way the browse is over.
            Err(_) => {
                if grace_deadline.is_some() {
                    // Grace period expired with no more events
                    break;
                }
                let _ = daemon.shutdown();
                bail!("{}", DISCOVERY_TIMEOUT_HINT);
            }
        };

        match event {
            ServiceEvent::ServiceResolved(resolved) => {
                let fullname = resolved.get_fullname().to_string();
                match fullnames.iter().position(|known| *known == fullname) {
                    Some(idx) => {
                        // More addresses for the same server arrived.
                        for scoped_ip in resolved.get_addresses() {
                            let ip = scoped_ip.to_ip_addr();
                            if !instances[idx].addrs.contains(&ip) {
                                instances[idx].addrs.push(ip);
                            }
                        }
                    }
                    None => {
                        info!("Discovered Monux server: {}", fullname);
                        let mut addrs: Vec<IpAddr> = Vec::new();
                        for scoped_ip in resolved.get_addresses() {
                            // ScopedIp carries the discovering interface(s);
                            // reduce to a plain address, deduped.
                            let ip = scoped_ip.to_ip_addr();
                            if !addrs.contains(&ip) {
                                addrs.push(ip);
                            }
                        }
                        fullnames.push(fullname.clone());
                        instances.push(DiscoveredServer {
                            name: instance_name_of(&fullname).to_string(),
                            addrs,
                            port: resolved.get_port(),
                            protocol_version: protocol_version_of(resolved.get_properties()),
                            fingerprint: fingerprint_of(resolved.get_properties()),
                        });
                        if grace_deadline.is_none() {
                            grace_deadline = Some(Instant::now() + EXTRA_RESOLVE_GRACE);
                        }
                    }
                }
            }
            other => {
                debug!("mDNS event: {:?}", other);
            }
        }
    }

    let _ = daemon.shutdown();
    Ok(instances)
}

/// Whether an expired overall discovery deadline ends the browse with what
/// was found (true) instead of failing with DISCOVERY_TIMEOUT_HINT (false):
/// the grace period extends past the deadline, so a first resolve can arrive
/// when the deadline has already passed — finding a server must never fail
/// discovery.
fn keep_found_past_deadline(instances: &[DiscoveredServer]) -> bool {
    !instances.is_empty()
}

/// Discovers a Monux server on the local network via mDNS.
/// Returns the first server found — unless a later instance's address is in
/// the remembered store (a server we connected to before beats a stranger) —
/// along with its advertised instance name (normally the server's hostname)
/// for display in e.g. approval prompts.
pub async fn discover_server(
    timeout: Option<Duration>,
    remembered: &[crate::known_servers::RememberedServer],
) -> Result<(SocketAddr, String)> {
    let instances = discover_servers(timeout).await?;
    let remembered_hit = instances.iter().position(|instance| {
        instance.addrs.iter().any(|ip| {
            remembered
                .iter()
                .any(|server| server.addr == SocketAddr::new(*ip, instance.port))
        })
    });
    let chosen_idx = remembered_hit.unwrap_or(0);
    let chosen = &instances[chosen_idx];
    if instances.len() > 1 {
        let others: Vec<&str> = instances
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != chosen_idx)
            .map(|(_, instance)| instance.name.as_str())
            .collect();
        info!(
            "Multiple Monux servers discovered: {}; connecting to: {}{}",
            others.join(", "),
            chosen.name,
            if remembered_hit.is_some() {
                " (remembered from a previous connection)"
            } else {
                ""
            }
        );
        info!("Run 'monux servers' to list them, 'monux client <ip|name|fp-prefix>' to choose another");
    }
    let addr = pick_addr(&chosen.addrs, chosen.port)
        .ok_or_else(|| anyhow!("Discovered server has no addresses"))?;
    info!(
        "Discovered {} address(es) for server, connecting to: {}",
        chosen.addrs.len(),
        addr
    );
    Ok((addr, chosen.name.clone()))
}

/// Extracts a server's advertised protocol version from its mDNS TXT
/// properties: `None` when the property is absent (servers predate the
/// advertisement) or isn't a number — both mean "no information".
fn protocol_version_of(properties: &TxtProperties) -> Option<u64> {
    properties
        .get_property_val_str(PROTOCOL_VERSION_PROPERTY)?
        .parse()
        .ok()
}

/// Extracts a server's advertised certificate fingerprint from its mDNS TXT
/// properties: `None` when the property is absent (servers predate the
/// advertisement) — "no information", never an error.
fn fingerprint_of(properties: &TxtProperties) -> Option<String> {
    properties
        .get_property_val_str(FINGERPRINT_PROPERTY)
        .map(|fp| fp.to_string())
}

/// Picks the update-gate constraint from the protocol versions discovered on
/// the LAN: the minimum, so a client never upgrades beyond any server it
/// might pair with. `None` when nothing was discovered.
pub fn protocol_version_constraint(discovered: &[u64]) -> Option<u64> {
    discovered.iter().min().copied()
}

/// Synchronously collects the distinct protocol versions (sorted) advertised
/// by Monux servers on the LAN, for the update gate in `monux update` — which
/// runs before the tokio runtime exists, hence the blocking API. Best-effort
/// within a short timeout; servers without the property are skipped.
pub fn discover_server_protocol_versions() -> Result<Vec<u64>> {
    let daemon = ServiceDaemon::new().context("Failed to create mDNS daemon")?;
    let versions = collect_server_protocol_versions(&daemon);
    if let Err(e) = daemon.shutdown() {
        debug!("Failed to shutdown mDNS daemon: {}", e);
    }
    versions
}

fn collect_server_protocol_versions(daemon: &ServiceDaemon) -> Result<Vec<u64>> {
    let receiver = daemon
        .browse(SERVICE_TYPE)
        .context("Failed to browse for Monux servers")?;
    let deadline = Instant::now() + SERVER_VERSION_DISCOVERY_TIMEOUT;
    let own_instance = get_hostname().unwrap_or_default();
    let own_ips: std::collections::HashSet<IpAddr> = local_ipv4_addrs()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let mut versions = BTreeSet::new();
    loop {
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            None => break,
        };
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(resolved)) => {
                match protocol_version_of(resolved.get_properties()) {
                    Some(version) => {
                        let instance = instance_name_of(resolved.get_fullname());
                        // Our own advertisement must not gate our own update.
                        // Match on hostname OR advertised IPs: cloned images
                        // share a hostname, so the IP check is essential.
                        let is_own = instance == own_instance
                            || resolved
                                .get_addresses()
                                .iter()
                                .any(|scoped| own_ips.contains(&scoped.to_ip_addr()));
                        if is_own {
                            // Our own advertisement must not gate our own
                            // update: a server leads protocol upgrades — the
                            // gate exists for client machines.
                            debug!(
                                "Ignoring our own mDNS advertisement of protocol v{} for the update gate",
                                version
                            );
                        } else {
                            debug!(
                                "Discovered Monux server {} advertising protocol v{}",
                                resolved.get_fullname(),
                                version
                            );
                            versions.insert(version);
                        }
                    }
                    None => debug!(
                        "Discovered Monux server {} without a protocol version; skipping it",
                        resolved.get_fullname()
                    ),
                }
            }
            Ok(other) => debug!("mDNS event: {:?}", other),
            // Timeout (normal: no more servers answered) or the browse stream
            // ending: return what we have.
            Err(_) => break,
        }
    }
    Ok(versions.into_iter().collect())
}

/// The instance-name part of a service fullname (everything before the
/// service-type suffix), e.g. "myhost" from "myhost._monux._udp.local.".
fn instance_name_of(fullname: &str) -> &str {
    fullname
        .strip_suffix(&format!(".{}", SERVICE_TYPE))
        .unwrap_or(fullname)
}

/// Picks an address to connect to. A link-local pair (169.254.0.0/16 on both
/// sides — almost certainly a direct, routerless link like a plugged-in
/// cable) is preferred over any routed path. Otherwise a server may advertise
/// several addresses (LAN, docker bridges, VPN, ...), so prefer the one
/// sharing the longest bit prefix with one of our own interface addresses
/// (i.e. most likely on our subnet), falling back to any IPv4 address, then
/// any address.
fn pick_addr(addrs: &[IpAddr], port: u16) -> Option<SocketAddr> {
    pick_addr_with_locals(addrs, &local_ipv4_addrs().unwrap_or_default(), port)
}

/// pick_addr with the local interface addresses passed in, so the preference
/// logic is testable without real interfaces.
fn pick_addr_with_locals(addrs: &[IpAddr], local_ips: &[IpAddr], port: u16) -> Option<SocketAddr> {
    let link_local = |ip: &IpAddr| matches!(ip, IpAddr::V4(v4) if v4.is_link_local());
    // Without our own link-local address a link-local peer is unreachable, so
    // the preference only fires when the direct segment exists on both sides.
    if local_ips.iter().any(&link_local) {
        if let Some(ip) = addrs.iter().find(|ip| link_local(ip)) {
            return Some(SocketAddr::new(*ip, port));
        }
    }
    addrs
        .iter()
        .filter(|ip| ip.is_ipv4())
        .max_by_key(|ip| {
            local_ips
                .iter()
                .map(|local| common_prefix_len(ip, local))
                .max()
                .unwrap_or(0)
        })
        .or_else(|| addrs.iter().next())
        .map(|ip| SocketAddr::new(*ip, port))
}

/// Length of the common leading bit prefix of two IP addresses (0 across families).
fn common_prefix_len(a: &IpAddr, b: &IpAddr) -> u32 {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (a.to_bits() ^ b.to_bits()).leading_zeros(),
        (IpAddr::V6(a), IpAddr::V6(b)) => (a.to_bits() ^ b.to_bits()).leading_zeros(),
        _ => 0,
    }
}

/// Picks the addresses to advertise for a server listening on `listen_ip`.
pub fn advertise_ips(listen_ip: IpAddr) -> Result<Vec<IpAddr>> {
    if !listen_ip.is_unspecified() {
        // A concrete --listen address was provided: advertise exactly that.
        return Ok(vec![listen_ip]);
    }
    // Listening on the wildcard address: advertise every usable local IPv4 address.
    let ips = local_ipv4_addrs().unwrap_or_else(|e| {
        warn!(
            "Failed to enumerate local IPv4 addresses ({}), falling back to route probe",
            e
        );
        Vec::new()
    });
    if !ips.is_empty() {
        return Ok(ips);
    }
    // Last resort: probe the outbound route for a primary address.
    match get_local_ip() {
        Ok(ip) => Ok(vec![ip]),
        Err(e) => bail!(
            "Failed to determine any local IP address to advertise: {}. Check that the network is up and that no firewall is blocking the route probe, or specify the address to advertise explicitly with '-l <ip>'",
            e
        ),
    }
}

/// Interface name prefixes for virtual overlay links (docker/VM bridges, VPN
/// tunnels). LAN peers can't reach these addresses — and docker bridges have
/// the SAME default IPs on every host, which poisons subnet prefix matching.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "docker", "br-", "veth", "virbr", "vnet", "tun", "tap", "wg", "tailscale", "zt", "mullvad",
];

fn is_virtual_iface(name: &str) -> bool {
    VIRTUAL_IFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Enumerates this host's non-loopback IPv4 addresses, preferring
/// physical/primary interfaces over virtual overlay ones. Link-local
/// (169.254.0.0/16) addresses are included: a direct, routerless link between
/// the machines (e.g. a plugged-in cable) lives there, and both the
/// advertisement and the path preference (pick_addr) need to see them.
fn local_ipv4_addrs() -> Result<Vec<IpAddr>> {
    let mut ips: Vec<(String, IpAddr)> = Vec::new();
    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            bail!("getifaddrs failed: {}", std::io::Error::last_os_error());
        }
        let mut current = ifaddrs;
        while !current.is_null() {
            let ifa = &*current;
            if !ifa.ifa_addr.is_null()
                && (*ifa.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t
            {
                let name = if ifa.ifa_name.is_null() {
                    String::new()
                } else {
                    std::ffi::CStr::from_ptr(ifa.ifa_name)
                        .to_string_lossy()
                        .to_string()
                };
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                // s_addr is stored in network byte order; to_ne_bytes() preserves
                // the in-memory octet order on any host endianness.
                let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                let ip = IpAddr::V4(ip);
                if !ip.is_loopback() && !ip.is_unspecified() && !ips.iter().any(|(_, existing)| *existing == ip)
                {
                    ips.push((name, ip));
                }
            }
            current = ifa.ifa_next;
        }
        libc::freeifaddrs(ifaddrs);
    }
    // Drop virtual overlay interfaces; if that would leave nothing (e.g. the
    // machine's only link really is a bridge/VPN), keep the unfiltered list.
    let physical: Vec<IpAddr> = ips
        .iter()
        .filter(|(name, _)| !is_virtual_iface(name))
        .map(|(_, ip)| *ip)
        .collect();
    if !physical.is_empty() {
        return Ok(physical);
    }
    Ok(ips.into_iter().map(|(_, ip)| ip).collect())
}

/// Returns the machine hostname.
pub fn get_hostname() -> Result<String> {
    let mut buf = [0i8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) };
    if ret != 0 {
        bail!("gethostname failed: {}", std::io::Error::last_os_error());
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Ok(c_str.to_string_lossy().to_string())
}

/// Determines the primary local IP address by connecting a UDP socket to a public IP.
fn get_local_ip() -> Result<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    Ok(socket.local_addr()?.ip())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_advertised_protocol_version() {
        use mdns_sd::IntoTxtProperties;
        let props = HashMap::from([("pv".to_string(), "8".to_string())]).into_txt_properties();
        assert_eq!(protocol_version_of(&props), Some(8));
        // No property (a pre-advertisement server) or a malformed one: no
        // information, never an error.
        let empty = HashMap::<String, String>::new().into_txt_properties();
        assert_eq!(protocol_version_of(&empty), None);
        let junk = HashMap::from([("pv".to_string(), "eight".to_string())]).into_txt_properties();
        assert_eq!(protocol_version_of(&junk), None);
    }

    #[test]
    fn extracts_advertised_fingerprint() {
        use mdns_sd::IntoTxtProperties;
        let props =
            HashMap::from([("fp".to_string(), "aabbccdd".to_string())]).into_txt_properties();
        assert_eq!(fingerprint_of(&props), Some("aabbccdd".to_string()));
        // No property (a pre-advertisement server): no information.
        let empty = HashMap::<String, String>::new().into_txt_properties();
        assert_eq!(fingerprint_of(&empty), None);
    }

    #[test]
    fn instance_name_strips_the_service_type() {
        assert_eq!(instance_name_of("myhost._monux._udp.local."), "myhost");
        // No suffix present: the name is returned unchanged.
        assert_eq!(instance_name_of("myhost"), "myhost");
    }

    #[test]
    fn constraint_is_the_minimum_discovered_version() {
        assert_eq!(protocol_version_constraint(&[]), None);
        assert_eq!(protocol_version_constraint(&[8]), Some(8));
        assert_eq!(protocol_version_constraint(&[8, 7, 9]), Some(7));
    }

    #[test]
    fn expired_deadline_keeps_already_found_servers() {
        // Nothing found: the deadline expiry still fails the discovery.
        assert!(!keep_found_past_deadline(&[]));
        // A resolve landing in the last grace window (past the deadline) is
        // returned, not discarded by the timeout error.
        let found = vec![DiscoveredServer {
            name: "host".to_string(),
            addrs: vec!["192.168.1.2".parse().unwrap()],
            port: 1213,
            protocol_version: None,
            fingerprint: None,
        }];
        assert!(keep_found_past_deadline(&found));
    }

    #[test]
    fn prefix_len_prefers_same_subnet() {
        let server: IpAddr = "192.168.1.187".parse().unwrap();
        let same_lan: IpAddr = "192.168.1.23".parse().unwrap();
        let docker: IpAddr = "172.17.0.1".parse().unwrap();
        assert_eq!(common_prefix_len(&server, &same_lan), 24);
        assert!(common_prefix_len(&server, &docker) < 24);
        // Cross-family is always 0
        let v6: IpAddr = "fe80::1".parse().unwrap();
        assert_eq!(common_prefix_len(&server, &v6), 0);
    }

    #[test]
    fn link_local_pair_is_preferred_over_routed_path() {
        let lan: IpAddr = "192.168.1.187".parse().unwrap();
        let direct: IpAddr = "169.254.10.1".parse().unwrap();
        let our_lan: IpAddr = "192.168.1.102".parse().unwrap();
        let our_direct: IpAddr = "169.254.10.2".parse().unwrap();
        let addrs = [lan, direct];
        // Both sides have a link-local address (a cable plugged straight in):
        // the direct path wins over the better-prefix LAN path.
        assert_eq!(
            pick_addr_with_locals(&addrs, &[our_lan, our_direct], 1213),
            Some(SocketAddr::new(direct, 1213))
        );
        // Without our own link-local address the link-local peer is
        // unreachable: the routed LAN path wins instead.
        assert_eq!(
            pick_addr_with_locals(&addrs, &[our_lan], 1213),
            Some(SocketAddr::new(lan, 1213))
        );
        // No link-local advertised either: the prefix match picks the LAN path.
        assert_eq!(
            pick_addr_with_locals(&[lan], &[our_lan, our_direct], 1213),
            Some(SocketAddr::new(lan, 1213))
        );
    }

    #[test]
    fn virtual_ifaces_are_detected() {
        for name in ["docker0", "br-9f1c2e", "veth1234", "virbr0", "tun0", "wg0", "tailscale0", "mullvad"] {
            assert!(is_virtual_iface(name), "{} should be treated as virtual", name);
        }
        for name in ["eth0", "enp3s0", "wlan0", "wlp2s0", "eno1"] {
            assert!(!is_virtual_iface(name), "{} should be treated as physical", name);
        }
    }

    #[test]
    fn enumerated_addrs_are_usable_and_not_byte_swapped() {
        let ips = local_ipv4_addrs().expect("failed to enumerate interfaces");
        println!("local ipv4 addrs: {:?}", ips);
        assert!(!ips.is_empty(), "expected at least one usable IPv4 address");
        for ip in &ips {
            assert!(ip.is_ipv4());
            assert!(!ip.is_loopback(), "loopback leaked into advertisement list");
            assert!(!ip.is_unspecified());
            if let IpAddr::V4(v4) = ip {
                assert!(!v4.is_link_local(), "link-local leaked into advertisement list");
                // Byte-reversal guard: 1.0.0.127 is 127.0.0.1 with swapped octets
                assert_ne!(v4.octets()[0], 1, "suspicious byte-swapped address: {}", v4);
                // Docker's default bridges have the same address on every host;
                // advertising them makes discovery picks useless.
                assert!(
                    !v4.octets().starts_with(&[172, 17]) && !v4.octets().starts_with(&[172, 18]),
                    "docker bridge leaked into advertisement list: {}", v4
                );
            }
        }
    }
}
