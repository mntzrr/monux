use serde::{Deserialize, Serialize};

/// The protocol version exchanged between client and server on each stream.
/// This is compared on initial connection between client and server.
/// If the event/bulk definitions change, then this should change.
pub const PROTOCOL_VERSION: u64 = 15;

/// The protocol version that introduced the server-hostname frame: right
/// after the events-stream version exchange, the server sends its hostname
/// to v15+ clients (for the approval prompt and the remembered-servers
/// store; see client.rs/server.rs).
pub const PROTOCOL_VERSION_HOSTNAME: u64 = 15;

/// Whether the server sends its hostname after the events-stream version
/// exchange: only to a client that spoke v15+ — an older client would
/// misparse the bytes as the start of an event frame.
pub fn sends_hostname(client_version: u64) -> bool {
    client_version >= PROTOCOL_VERSION_HOSTNAME
}

/// Whether the client expects a hostname after the events-stream version
/// exchange: only from a server that spoke v15+ — an older server sends
/// nothing, so there is nothing to wait for.
pub fn expects_hostname(server_version: u64) -> bool {
    server_version >= PROTOCOL_VERSION_HOSTNAME
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
