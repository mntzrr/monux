//! One client's connection, behind a trait.
//!
//! `ClientLink` is what makes the rotation testable: with the quinn handles
//! behind it, a `ClientInfo` can be built in a unit test, and the switch,
//! silence and clipboard interactions can be exercised through the rotation's
//! real entry points instead of through logic lifted out to dodge them.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use quinn::{SendDatagramError, SendStream};
use tokio::sync::mpsc;

/// The QUIC path facts the rotation actually reads. An owned snapshot rather
/// than quinn's own stats type, so a test can state "this link has 200ms RTT"
/// without constructing a connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    pub rtt: Duration,
    pub sent_packets: u64,
    pub lost_packets: u64,
    pub congestion_events: u64,
    pub black_holes_detected: u64,
    pub cwnd: u64,
}

/// Why a bulk frame could not be queued. The distinction matters: a FULL
/// queue is ordinary during a large clipboard transfer (the writer sleeps
/// between paced frames), while a CLOSED one means the writer task is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BulkQueueError {
    Full,
    Closed,
}

impl std::fmt::Display for BulkQueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(match self {
            BulkQueueError::Full => "bulk queue full",
            BulkQueueError::Closed => "bulk queue closed (writer task gone)",
        })
    }
}

/// Everything the rotation needs from one client's connection.
///
/// This exists so `ClientInfo` can be fabricated in a unit test. Before it,
/// the three quinn handles made that impossible, and the workaround was to
/// lift each piece of logic out into a free function over plain SocketAddrs —
/// six of them, each carrying the same apologetic comment. The result was that
/// the switch/silence/clipboard interactions, which are where this file's real
/// complexity lives, could only be tested one function at a time, never
/// together.
///
/// Dyn rather than a generic parameter: it matches how the clipboard traits in
/// this crate are already used, and it keeps the type parameter off five
/// signatures. The cost is one vtable dispatch per forwarded frame, which is
/// nothing beside the QUIC write it precedes.
#[async_trait::async_trait]
pub trait ClientLink: Send {
    /// Writes one serialized message to the ordered, reliable events stream.
    async fn send_events(&mut self, bytes: &[u8]) -> Result<()>;

    /// Queues one whole bulk frame (a header glued to its payload) for the
    /// connection's writer task. Never blocks.
    fn queue_bulk(&self, frame: Vec<u8>) -> std::result::Result<(), BulkQueueError>;

    /// Free slots in the bulk queue, for the state dump.
    fn bulk_queue_free(&self) -> usize;

    /// Sends an unreliable, unordered datagram (pointer motion).
    fn send_datagram(&self, bytes: Bytes) -> std::result::Result<(), SendDatagramError>;

    /// Current path statistics for this connection.
    fn stats(&self) -> LinkStats;
}

/// The real link: a QUIC connection's events stream, bulk queue and handle.
pub struct QuicClientLink {
    pub(crate) events_send: SendStream,
    /// Queue for the client's bulk writer task, which owns the actual bulk
    /// stream. Keeping large clipboard writes out of the rotation loop means
    /// they never stall input forwarding. Bounded (bulk::BULK_QUEUE_CAPACITY):
    /// a client that can't drain is dropped like a write failure rather than
    /// queueing clipboard payloads without limit.
    pub(crate) bulk_tx: mpsc::Sender<Vec<u8>>,
    pub(crate) conn: quinn::Connection,
}

#[async_trait::async_trait]
impl ClientLink for QuicClientLink {
    async fn send_events(&mut self, bytes: &[u8]) -> Result<()> {
        self.events_send
            .write_all(bytes)
            .await
            .context("Failed to send serialized message")
    }

    fn queue_bulk(&self, frame: Vec<u8>) -> std::result::Result<(), BulkQueueError> {
        self.bulk_tx.try_send(frame).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => BulkQueueError::Full,
            mpsc::error::TrySendError::Closed(_) => BulkQueueError::Closed,
        })
    }

    fn bulk_queue_free(&self) -> usize {
        self.bulk_tx.capacity()
    }

    fn send_datagram(&self, bytes: Bytes) -> std::result::Result<(), SendDatagramError> {
        self.conn.send_datagram(bytes)
    }

    fn stats(&self) -> LinkStats {
        let path = self.conn.stats().path;
        LinkStats {
            rtt: path.rtt,
            sent_packets: path.sent_packets,
            lost_packets: path.lost_packets,
            congestion_events: path.congestion_events,
            black_holes_detected: path.black_holes_detected,
            cwnd: path.cwnd,
        }
    }
}

/// Channels for communicating with a connected client.
pub struct ClientInfo {
    /// The primary identifier for a client. We can have multiple clients with the same fingerprint:
    /// - When the user is sharing certificates between clients (they are free to do so)
    /// - When a client has reconnected without the old connection timing out yet
    pub(crate) endpoint: SocketAddr,
    /// Cert fingerprint used to select clients via --shortcut-goto keyboard shortcuts
    pub(crate) fingerprint: String,
    /// How to reach this client (see ClientLink).
    pub(crate) link: Box<dyn ClientLink>,
    /// Whether the peer accepts QUIC datagrams. Defense-only: both peers run
    /// the identical binary with identical quinn config, so datagram support
    /// is symmetric and this is never false in normal operation. The fallback
    /// to the ordered stream exists for forward-compatibility / safety.
    pub(crate) datagrams_ok: bool,
    /// Unique-per-process token of the accepted connection that owns this
    /// entry (see server.rs). A reconnect can reuse the same addr:port and
    /// replace this entry in place; the old connection's late RemoveClient
    /// then carries a stale token and is ignored instead of killing the
    /// healthy new entry.
    pub(crate) conn_token: u64,
    /// When this client was added; published as connected_since_secs in the
    /// control socket's status (control.rs).
    pub(crate) connected_at: Instant,
    /// The protocol version this pair negotiated, so the send path only uses
    /// frames this client understands (see shared::sends_device_class).
    pub(crate) negotiated_version: u64,
}

/// Hand-written so the state dump stays readable — and pasteable.
///
/// A derived Debug expands the three quinn handles (`events_send`, `conn`,
/// `bulk_tx`) into several KILOBYTES of connection internals per client:
/// mutex guards, notify lists, waker slots. That noise dwarfs the fields a
/// human actually reads, and since the dump goes into every bug report
/// (diagnostics.rs) it was making reports too large to paste. The handles
/// are reduced to the one fact worth reporting about them — whether the
/// bulk queue has backed up, which is a real failure mode.
impl std::fmt::Debug for ClientInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientInfo")
            .field("endpoint", &self.endpoint)
            // The prefix is what the UI, the logs and --shortcut-goto use.
            .field("fingerprint", &fingerprint_prefix(&self.fingerprint))
            .field("negotiated_version", &self.negotiated_version)
            .field("datagrams_ok", &self.datagrams_ok)
            .field("conn_token", &self.conn_token)
            .field("connected_for_secs", &self.connected_at.elapsed().as_secs())
            .field("bulk_queue_free", &self.link.bulk_queue_free())
            .finish()
    }
}

/// The leading chunk of a certificate fingerprint, as every other
/// user-facing surface prints it.
pub fn fingerprint_prefix(fingerprint: &str) -> &str {
    &fingerprint[..fingerprint.len().min(8)]
}


/// Fabricating a client for a test: the thing `ClientLink` exists to allow.
#[cfg(test)]
pub mod test_support {
    use super::*;

    /// A link that swallows everything and reports a healthy path. For tests
    /// about roster shape rather than about what a client receives — those
    /// use the recording FakeLink in the rotation's own tests.
    pub struct NullLink;

    #[async_trait::async_trait]
    impl ClientLink for NullLink {
        async fn send_events(&mut self, _bytes: &[u8]) -> Result<()> {
            Ok(())
        }
        fn queue_bulk(&self, _frame: Vec<u8>) -> std::result::Result<(), BulkQueueError> {
            Ok(())
        }
        fn bulk_queue_free(&self) -> usize {
            crate::msgs::bulk::BULK_QUEUE_CAPACITY
        }
        fn send_datagram(&self, _bytes: Bytes) -> std::result::Result<(), SendDatagramError> {
            Ok(())
        }
        fn stats(&self) -> LinkStats {
            LinkStats::default()
        }
    }

    /// A ClientInfo with no network behind it.
    pub fn fake_client(endpoint: SocketAddr, fingerprint: &str) -> ClientInfo {
        client_with_link(endpoint, fingerprint, Box::new(NullLink))
    }

    /// A ClientInfo wrapping a caller-supplied link, for tests that assert on
    /// what the client was sent.
    pub fn client_with_link(
        endpoint: SocketAddr,
        fingerprint: &str,
        link: Box<dyn ClientLink>,
    ) -> ClientInfo {
        ClientInfo {
            endpoint,
            fingerprint: fingerprint.to_string(),
            link,
            datagrams_ok: true,
            // The port doubles as a distinct token per test client.
            conn_token: endpoint.port() as u64,
            connected_at: Instant::now(),
            negotiated_version: crate::msgs::shared::PROTOCOL_VERSION,
        }
    }
}
