use serde::{Deserialize, Serialize};

/// The protocol version exchanged between client and server on each stream.
/// This is compared on initial connection between client and server.
/// If the event/bulk definitions change, then this should change.
pub const PROTOCOL_VERSION: u64 = 18;

/// The first protocol version whose peers can negotiate: two v16+ peers
/// connect at min(their, our) and each side only uses features the negotiated
/// version supports (see [`negotiate`]). Pre-negotiation peers still require
/// an exact match.
pub const PROTOCOL_VERSION_NEGOTIATION: u64 = 16;

/// The oldest protocol version this binary can fully speak: the direct
/// ancestor of [`PROTOCOL_VERSION_NEGOTIATION`]. A newer client clamps down
/// to a speakable older server (see client.rs); anything older is refused.
pub const MIN_SPEAKABLE_VERSION: u64 = 15;

/// The protocol version a pair runs at, or None when the connection must be
/// refused. Equal versions always pair (the fast path: nothing degraded);
/// two negotiation-era peers (v16+) run at the lower version, each side
/// using only features that version supports (see [`features_above`]).
/// Anything else is a pre-negotiation mismatch and is refused, as before
/// negotiation existed.
pub fn negotiate(theirs: u64, ours: u64) -> Option<u64> {
    if theirs == ours {
        Some(ours)
    } else if theirs >= PROTOCOL_VERSION_NEGOTIATION && ours >= PROTOCOL_VERSION_NEGOTIATION {
        Some(theirs.min(ours))
    } else {
        None
    }
}

/// Version-gated wire features, oldest first: the version that introduced
/// the feature and its name, for degraded-set logging when a pair negotiates
/// down (see [`features_above`]). v16 itself is the negotiation machinery —
/// no new wire feature rides it.
const FEATURES: &[(u64, &str)] = &[
    (15, "server hostname in handshake"),
    (17, "input device class"),
    (18, "peer diagnostics in bug reports"),
];

/// The features a version misses out on: every feature newer than `v`,
/// oldest first. Logged as the degraded set when a pair negotiates below our
/// own version.
pub fn features_above(v: u64) -> Vec<(u64, &'static str)> {
    FEATURES
        .iter()
        .copied()
        .filter(|(since, _)| *since > v)
        .collect()
}

/// The degraded set for a negotiated version as a log-ready list: the
/// comma-separated names of every feature newer than `v`, or "nothing".
pub fn disabled_features(v: u64) -> String {
    let names: Vec<&str> = features_above(v).iter().map(|(_, name)| *name).collect();
    if names.is_empty() {
        "nothing".to_string()
    } else {
        names.join(", ")
    }
}

/// The protocol version that introduced the device class on input frames:
/// the server tags each forwarded frame with the class of the device it came
/// from, so the client routes it to the matching virtual device instead of
/// inferring the destination from which device's capability set happens to
/// contain the event's code (see uinput::route_event).
pub const PROTOCOL_VERSION_DEVICE_CLASS: u64 = 17;

/// Whether the server tags input frames with their device class: only when
/// the pair's NEGOTIATED version is v17+. An older client has no variant for
/// it and would fail to deserialize the frame, so those pairs keep the
/// untagged frame and the client's capability-based inference.
pub fn sends_device_class(negotiated: u64) -> bool {
    negotiated >= PROTOCOL_VERSION_DEVICE_CLASS
}

/// The protocol version that introduced peer diagnostics: the server can ask
/// each connected client for its own bug-report bundle, so one paste covers
/// both machines (see diagnostics.rs). A KVM failure — a freeze, a dead key,
/// a clipboard that won't cross — is a two-machine event, and correlating it
/// used to mean asking the reporter to run a second command on the other box
/// and hoping the clocks lined up.
pub const PROTOCOL_VERSION_PEER_DIAGNOSTICS: u64 = 18;

/// Whether a client can answer a diagnostics request: only when the pair's
/// NEGOTIATED version is v18+. An older client has no variant for the
/// request and would fail to deserialize the bulk frame — which would drop a
/// working connection over a bug report, so the server skips those clients
/// and says so in the bundle instead.
pub fn supports_peer_diagnostics(negotiated: u64) -> bool {
    negotiated >= PROTOCOL_VERSION_PEER_DIAGNOSTICS
}

/// The protocol version that introduced the server-hostname frame: right
/// after the events-stream version exchange, the server sends its hostname
/// to v15+ clients (for the approval prompt and the remembered-servers
/// store; see client.rs/server.rs).
pub const PROTOCOL_VERSION_HOSTNAME: u64 = 15;

/// Whether the server sends its hostname after the events-stream version
/// exchange: only when the pair's NEGOTIATED version is v15+ — an older
/// client would misparse the bytes as the start of an event frame.
pub fn sends_hostname(negotiated: u64) -> bool {
    negotiated >= PROTOCOL_VERSION_HOSTNAME
}

/// Whether the client expects a hostname after the events-stream version
/// exchange: only when the pair's NEGOTIATED version is v15+ — an older
/// server sends nothing, so there is nothing to wait for.
pub fn expects_hostname(negotiated: u64) -> bool {
    negotiated >= PROTOCOL_VERSION_HOSTNAME
}

/// Cap on the hostname as sent on the wire: gethostname(2) allows at most 64
/// bytes (HOST_NAME_MAX); a longer one is cut on a char boundary.
pub const MAX_HOSTNAME_BYTES: usize = 64;

/// Encodes the server hostname for the events stream: a u16 big-endian
/// length prefix followed by the UTF-8 bytes, truncated to
/// [`MAX_HOSTNAME_BYTES`]. Plain bytes, not postcard — the frame rides the
/// version gate, so it needs no self-describing format.
pub fn encode_hostname(hostname: &str) -> Vec<u8> {
    let mut bytes = hostname.as_bytes();
    if bytes.len() > MAX_HOSTNAME_BYTES {
        // Cut on a char boundary so the wire form stays valid UTF-8.
        let mut end = MAX_HOSTNAME_BYTES;
        while !hostname.is_char_boundary(end) {
            end -= 1;
        }
        bytes = &bytes[..end];
    }
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Decodes a hostname frame (see [`encode_hostname`]), returning the hostname
/// and the consumed byte count. None when `buf` doesn't hold a complete
/// frame yet (the caller keeps reading); Some(Err) on invalid UTF-8.
pub fn decode_hostname(buf: &[u8]) -> Option<std::result::Result<(String, usize), std::str::Utf8Error>> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    Some(
        std::str::from_utf8(&buf[2..2 + len]).map(|hostname| (hostname.to_string(), 2 + len)),
    )
}

/// An initial handshake message exchanged between client and server on each stream.
/// If the peer doesn't support the provided version value, it can cut off the connection early.
/// The intent is for the structure of this message to never change.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct VersionBootstrapMessage {
    pub version: u64,
}

/// Returns true if `buf` contains at least one complete COBS frame.
/// COBS-encoded frames never contain a 0x00 byte and are terminated by one 0x00,
/// so the first 0x00 marks the end of the current frame.
pub fn has_complete_cobs_frame(buf: &[u8]) -> bool {
    buf.contains(&0)
}

/// Maximum bytes retained in a COBS frame buffer without a terminator. A peer
/// that streams bytes without ever emitting a 0x00 grows the buffer without
/// bound; cap it and reject the connection. Events are small (key/mouse
/// batches, type lists); bulk headers are slightly larger. The clipboard
/// payload itself is length-prefixed (not COBS-framed) so it's not affected.
pub const MAX_FRAME_BUFFER_BYTES: usize = 1024 * 1024;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_pins_the_three_branches() {
        // Fast path: equal versions pair at themselves, nothing degraded —
        // including pre-negotiation versions (two v15 peers still pair).
        assert_eq!(negotiate(16, 16), Some(16));
        assert_eq!(negotiate(15, 15), Some(15));
        assert_eq!(negotiate(0, 0), Some(0));
        // Negotiation era: two v16+ peers run at the lower version.
        assert_eq!(negotiate(17, 16), Some(16));
        assert_eq!(negotiate(16, 17), Some(16));
        assert_eq!(negotiate(18, 17), Some(17));
        // Pre-negotiation peer in a mismatch: refused (a v15 peer can't
        // negotiate, so a v15/v16 pair only connects via the client clamp).
        assert_eq!(negotiate(15, 16), None);
        assert_eq!(negotiate(16, 15), None);
        assert_eq!(negotiate(14, 16), None);
        assert_eq!(negotiate(14, 15), None);
    }

    #[test]
    fn features_above_content() {
        // Nothing is newer than our own version.
        assert_eq!(features_above(18), vec![]);
        assert_eq!(features_above(u64::MAX), vec![]);
        // A v17 pair misses only the v18 peer diagnostics.
        assert_eq!(
            features_above(17),
            vec![(18, "peer diagnostics in bug reports")]
        );
        // v16 rode no wire feature of its own, so a pair that lands on v15 or
        // v16 misses the v17 device class as well.
        assert_eq!(
            features_above(15),
            vec![
                (17, "input device class"),
                (18, "peer diagnostics in bug reports")
            ]
        );
        assert_eq!(
            features_above(16),
            vec![
                (17, "input device class"),
                (18, "peer diagnostics in bug reports")
            ]
        );
        // Below v15 the hostname frame is missing too, oldest first.
        assert_eq!(
            features_above(14),
            vec![
                (15, "server hostname in handshake"),
                (17, "input device class"),
                (18, "peer diagnostics in bug reports")
            ]
        );
        assert_eq!(
            features_above(0),
            vec![
                (15, "server hostname in handshake"),
                (17, "input device class"),
                (18, "peer diagnostics in bug reports")
            ]
        );
    }

    /// The class tag rides v17: a pair that negotiated lower must keep
    /// sending the untagged frame, which every peer understands.
    #[test]
    fn device_class_gate_follows_the_negotiated_version() {
        assert!(sends_device_class(PROTOCOL_VERSION));
        assert!(sends_device_class(17));
        assert!(sends_device_class(u64::MAX));
        assert!(!sends_device_class(16));
        assert!(!sends_device_class(15));
        assert!(!sends_device_class(0));
    }

    #[test]
    fn disabled_features_list_for_logs() {
        assert_eq!(disabled_features(18), "nothing");
        assert_eq!(disabled_features(17), "peer diagnostics in bug reports");
        assert_eq!(
            disabled_features(15),
            "input device class, peer diagnostics in bug reports"
        );
        assert_eq!(
            disabled_features(14),
            "server hostname in handshake, input device class, peer diagnostics in bug reports"
        );
    }

    #[test]
    fn peer_diagnostics_are_gated_on_v18() {
        assert!(supports_peer_diagnostics(PROTOCOL_VERSION));
        assert!(supports_peer_diagnostics(18));
        // A v17 pair predates the bulk variant: asking would fail its
        // deserialization and drop a working connection.
        assert!(!supports_peer_diagnostics(17));
        assert!(!supports_peer_diagnostics(15));
    }

    #[test]
    fn cobs_frame_detection() {
        assert!(!has_complete_cobs_frame(&[]));
        assert!(!has_complete_cobs_frame(&[1, 2, 3]));
        assert!(has_complete_cobs_frame(&[1, 2, 0]));
        assert!(has_complete_cobs_frame(&[1, 0, 5, 6, 0]));
    }

    #[test]
    fn version_bootstrap_roundtrip() {
        // The bootstrap message is exchanged as postcard + COBS on every
        // stream (see network/transport.rs) and must never change shape.
        for version in [0u64, PROTOCOL_VERSION, u64::MAX] {
            let msg = VersionBootstrapMessage { version };
            let mut bytes = postcard::to_stdvec_cobs(&msg).unwrap();
            let (decoded, _) =
                postcard::take_from_bytes_cobs::<VersionBootstrapMessage>(&mut bytes).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    #[test]
    fn hostname_send_expect_predicates_gate_on_v15() {
        for version in [0, 14] {
            assert!(!sends_hostname(version));
            assert!(!expects_hostname(version));
        }
        for version in [15, 16, u64::MAX] {
            assert!(sends_hostname(version));
            assert!(expects_hostname(version));
        }
    }

    #[test]
    fn hostname_roundtrip() {
        for hostname in ["", "myhost", "my-host.example", "h\u{00e6}st"] {
            let encoded = encode_hostname(hostname);
            let (decoded, consumed) = decode_hostname(&encoded).unwrap().unwrap();
            assert_eq!(decoded, hostname);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn hostname_decode_waits_for_a_complete_frame() {
        let encoded = encode_hostname("myhost");
        // Neither the bare prefix byte nor a partial payload completes a frame.
        assert!(decode_hostname(&[]).is_none());
        assert!(decode_hostname(&encoded[..1]).is_none());
        assert!(decode_hostname(&encoded[..encoded.len() - 1]).is_none());
        // Trailing bytes (the next frame) are left alone.
        let mut buf = encoded.clone();
        buf.extend_from_slice(&[0xAA, 0xBB]);
        let (decoded, consumed) = decode_hostname(&buf).unwrap().unwrap();
        assert_eq!(decoded, "myhost");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hostname_encode_caps_at_max_bytes_on_a_char_boundary() {
        // 100 ASCII bytes: cut to exactly MAX_HOSTNAME_BYTES.
        let long = "a".repeat(100);
        let encoded = encode_hostname(&long);
        assert_eq!(encoded.len(), 2 + MAX_HOSTNAME_BYTES);
        let (decoded, _) = decode_hostname(&encoded).unwrap().unwrap();
        assert_eq!(decoded.len(), MAX_HOSTNAME_BYTES);
        // Multi-byte: the cut must not split a character (each '€' is 3
        // bytes, so 21 fit in 63 bytes; the 22nd would straddle the cap).
        let unicode = "\u{20ac}".repeat(30);
        let encoded = encode_hostname(&unicode);
        assert_eq!(encoded.len(), 2 + 63);
        let (decoded, _) = decode_hostname(&encoded).unwrap().unwrap();
        assert_eq!(decoded, "\u{20ac}".repeat(21));
    }

    #[test]
    fn hostname_decode_rejects_invalid_utf8() {
        let bad = [0u8, 2, 0xFF, 0xFF];
        assert!(decode_hostname(&bad).unwrap().is_err());
    }
}
