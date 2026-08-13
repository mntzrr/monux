use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Mutex;
use tracing::debug;

use crate::clipboard::{ClipboardReader, convert};

/// How long a failed or empty serve is remembered. Clipboard managers retry
/// failed fetches in tight bursts; without this, every retry pays the full
/// slow read (and its stall) again, re-wedging the serve mutex each time.
/// Kept short so a transient failure (the source app was momentarily busy)
/// is retried soon after.
const NEGATIVE_SERVE_CACHE_TTL: Duration = Duration::from_secs(10);

/// A clipboard reader shared with spawned clipboard-serving tasks.
///
/// Serving a request can be slow and CPU-heavy: when the clipboard holds a
/// copied file, the payload is zipped from disk, and compressing a large
/// clipboard takes noticeable time. Clipboard managers often request every
/// advertised mime type at once and retry on timeout, so without protection
/// the same slow read+convert would run many times concurrently, saturating
/// the CPU and starving the input-forwarding loops (seen in the wild as
/// keyboards freezing on both machines).
///
/// This type serializes serves and caches the last served payload, so a
/// burst of requests for the same clipboard costs only one slow read+convert.
/// Failed or empty serves are negatively cached for a short TTL, so a retry
/// burst after a stall doesn't re-pay the slow read on every request.
/// Cache invalidation, on the other hand, is deliberately lock-free: it only
/// bumps an epoch, so the rotation and client event loops can drop the cache
/// even while a slow serve holds the serialization lock.
#[derive(Clone)]
pub struct SharedClipboardReader {
    inner: Arc<Mutex<Inner>>,
    /// Bumped by invalidate(). A payload cached under an older epoch is
    /// treated as a cache miss by read(). Kept outside the mutex so
    /// invalidation never queues behind a slow serve.
    cache_epoch: Arc<AtomicU64>,
    /// Negative-cache TTL; a field (not the const directly) so tests can use
    /// a short TTL instead of sleeping out the real one.
    negative_ttl: Duration,
}

/// A cached successful serve: the cache epoch it was read under, the
/// requested mime type, the payload, and the data type it was converted to.
/// The payload is Arc'd: retry bursts from clipboard managers are the hits
/// this cache exists for, and a Vec clone would memcpy the whole (potentially
/// tens of MB) payload per request.
type ServedEntry = (u64, String, Arc<[u8]>, Option<String>);

struct Inner {
    reader: Box<dyn ClipboardReader>,
    /// The last successful serve. Single slot: requests within a burst are
    /// for the same clipboard.
    last_served: Option<ServedEntry>,
    /// (cache epoch, requested_type, size cap, when) of the last failed or
    /// empty serve. A matching request within NEGATIVE_SERVE_CACHE_TTL gets
    /// an empty answer without re-reading; an epoch bump (clipboard changed)
    /// or a TTL expiry lets the next request read again. The cap is part of
    /// the replay condition because a failure can BE the cap (payload too
    /// big): replaying it to a larger-cap requester would poison that
    /// requester for the whole TTL, so only a request whose cap is no larger
    /// than the failed one gets the empty replay.
    last_failed: Option<(u64, String, u64, Instant)>,
}

impl SharedClipboardReader {
    pub fn new(reader: Box<dyn ClipboardReader>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                reader,
                last_served: None,
                last_failed: None,
            })),
            cache_epoch: Arc::new(AtomicU64::new(0)),
            negative_ttl: NEGATIVE_SERVE_CACHE_TTL,
        }
    }

    #[cfg(test)]
    fn new_with_negative_ttl(reader: Box<dyn ClipboardReader>, negative_ttl: Duration) -> Self {
        let mut reader = Self::new(reader);
        reader.negative_ttl = negative_ttl;
        reader
    }

    /// Drops the cached payload and any negative entry. Must be called when
    /// the local clipboard contents change, so stale data is never served.
    /// Lock-free: it only bumps the cache epoch, so it never waits on a serve
    /// in progress (those can take seconds). A serve that started before the
    /// bump caches under the old epoch and is missed by the next read.
    pub fn invalidate(&self) {
        self.cache_epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Reads and converts the clipboard for the specified type, serving from
    /// the cache when a request for the same type was just fulfilled and the
    /// cache hasn't been invalidated since.
    pub async fn read(
        &self,
        requested_type: &str,
        max_size_bytes: u64,
        request_source: &str,
    ) -> Result<(Arc<[u8]>, Option<String>)> {
        let mut inner = self.inner.lock().await;
        let epoch = self.cache_epoch.load(Ordering::SeqCst);
        if let Some((cached_epoch, cached_type, content, data_type)) = &inner.last_served {
            // The size cap is part of the hit condition even though it isn't
            // part of the cache key: it is per REQUESTER (every machine has
            // its own --max-clipboard-size), while the payload was read under
            // whichever cap happened to come first. Handing a payload read
            // under a larger cap to a smaller requester frames a header the
            // receive side treats as fatal — it resets the connection and
            // retries, and the retry hits the same cache while the epoch is
            // unchanged. Falling through instead re-reads under this
            // requester's cap, which at worst fails into an empty answer.
            if *cached_epoch == epoch
                && cached_type == requested_type
                && content.len() as u64 <= max_size_bytes
            {
                debug!(
                    "Serving clipboard type {} from cache for {}: {} bytes",
                    requested_type,
                    request_source,
                    content.len()
                );
                return Ok((Arc::clone(content), data_type.clone()));
            }
        }
        // Negative cache: a failed or empty serve for this type is replayed
        // as an empty answer within the TTL, so a retry burst (e.g. a
        // clipboard manager fetching every advertised type after a timeout)
        // doesn't pay the slow read — and its stall — again.
        if let Some((failed_epoch, failed_type, failed_cap, when)) = &inner.last_failed {
            if *failed_epoch == epoch
                && failed_type == requested_type
                && max_size_bytes <= *failed_cap
                && when.elapsed() < self.negative_ttl
            {
                debug!(
                    "Serving clipboard type {} for {} as empty: cached failed/empty serve from {:.1}s ago",
                    requested_type,
                    request_source,
                    when.elapsed().as_secs_f32()
                );
                return Ok((Default::default(), None));
            }
        }
        let result = match inner
            .reader
            .read(requested_type, max_size_bytes, request_source)
            .await
        {
            Ok(original_data) => {
                convert::read(original_data, max_size_bytes, requested_type).await
            }
            Err(e) => Err(e),
        };
        match result {
            Err(e) => {
                inner.last_failed =
                    Some((epoch, requested_type.to_string(), max_size_bytes, Instant::now()));
                Err(e)
            }
            Ok((content, data_type)) => {
                if content.is_empty() {
                    // An empty serve (the source app didn't answer) is only
                    // negatively cached, never in the positive slot: after the
                    // TTL the next request reads again — the app may answer
                    // then.
                    inner.last_failed =
                        Some((epoch, requested_type.to_string(), max_size_bytes, Instant::now()));
                    Ok((Default::default(), data_type))
                } else {
                    // Arc the payload once; the cache slot and this answer
                    // share it (no memcpy on later hits).
                    let content: Arc<[u8]> = content.into();
                    inner.last_served = Some((
                        epoch,
                        requested_type.to_string(),
                        Arc::clone(&content),
                        data_type.clone(),
                    ));
                    // A fresh non-empty serve supersedes any negative entry.
                    inner.last_failed = None;
                    Ok((content, data_type))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use tokio::sync::Notify;

    struct CountingReader {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ClipboardReader for CountingReader {
        async fn read(
            &mut self,
            requested_type: &str,
            _max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(format!("data-for-{}", requested_type).into_bytes())
        }
    }

    #[tokio::test]
    async fn repeated_requests_hit_the_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new(Box::new(CountingReader {
            calls: calls.clone(),
        }));
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert_eq!(&*content, b"data-for-text/plain");
        // Second request for the same type must not hit the system clipboard again.
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert_eq!(&*content, b"data-for-text/plain");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A different type misses the single-slot cache and reads again.
        let _ = reader.read("text/html", u64::MAX, "test").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidation_forces_a_fresh_read() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new(Box::new(CountingReader {
            calls: calls.clone(),
        }));
        let _ = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        reader.invalidate();
        let _ = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A reader that answers with a fixed-size payload, erroring when it
    /// doesn't fit the caller's cap — as the real readers do, since
    /// max_size_bytes becomes their LimitedCursor limit.
    struct SizedReader {
        calls: Arc<AtomicUsize>,
        len: usize,
    }

    #[async_trait]
    impl ClipboardReader for SizedReader {
        async fn read(
            &mut self,
            _requested_type: &str,
            max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.len as u64 > max_size_bytes {
                return Err(anyhow::anyhow!("payload exceeds max size"));
            }
            Ok(vec![b'x'; self.len])
        }
    }

    #[tokio::test]
    async fn cached_payload_is_not_served_past_a_smaller_requesters_cap() {
        let calls = Arc::new(AtomicUsize::new(0));
        // Under the 100-byte compression floor, so the cached payload is the
        // 50 bytes the reader produced rather than a zstd frame.
        let reader = SharedClipboardReader::new(Box::new(SizedReader {
            calls: calls.clone(),
            len: 50,
        }));
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert_eq!(content.len(), 50);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A requester whose cap the cached payload exactly fits still hits.
        let (content, _) = reader.read("text/plain", 50, "test").await.unwrap();
        assert_eq!(content.len(), 50);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A requester with a smaller cap must not be handed the oversized
        // payload: its receive side treats an over-cap header as fatal and
        // resets the connection, then retries into the same cache. Falling
        // through re-reads under this cap, which fails cleanly instead.
        assert!(reader.read("text/plain", 49, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A reader whose reads always fail.
    struct FailingReader {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ClipboardReader for FailingReader {
        async fn read(
            &mut self,
            _requested_type: &str,
            _max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(anyhow::anyhow!("clipboard read failed"))
        }
    }

    #[tokio::test]
    async fn failed_serves_are_negatively_cached_within_the_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new_with_negative_ttl(
            Box::new(FailingReader {
                calls: calls.clone(),
            }),
            Duration::from_secs(10),
        );
        // The first read fails against the underlying reader.
        assert!(reader.read("text/plain", u64::MAX, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // A retry within the TTL gets an empty answer without re-reading.
        let (content, data_type) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert!(content.is_empty());
        assert!(data_type.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn negative_cache_expires_after_the_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new_with_negative_ttl(
            Box::new(FailingReader {
                calls: calls.clone(),
            }),
            Duration::from_millis(50),
        );
        assert!(reader.read("text/plain", u64::MAX, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // After the TTL the next request reads the underlying reader again.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(reader.read("text/plain", u64::MAX, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn invalidation_clears_the_negative_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new_with_negative_ttl(
            Box::new(FailingReader {
                calls: calls.clone(),
            }),
            Duration::from_secs(10),
        );
        assert!(reader.read("text/plain", u64::MAX, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // The clipboard changed (epoch bump): the negative entry must not be
        // replayed, the next request reads again even within the TTL.
        reader.invalidate();
        assert!(reader.read("text/plain", u64::MAX, "test").await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn negative_cache_does_not_poison_a_larger_cap_requester() {
        let calls = Arc::new(AtomicUsize::new(0));
        // 50 bytes: under the 100-byte compression floor, so a successful
        // serve is exactly the reader's payload.
        let reader = SharedClipboardReader::new_with_negative_ttl(
            Box::new(SizedReader {
                calls: calls.clone(),
                len: 50,
            }),
            Duration::from_secs(10),
        );
        // A requester whose cap the payload exceeds fails, and a retry at the
        // same cap gets the cached empty answer without re-reading.
        assert!(reader.read("text/plain", 49, "test").await.is_err());
        let (content, _) = reader.read("text/plain", 49, "test").await.unwrap();
        assert!(content.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // But the failure was keyed to that cap: a larger-cap requester the
        // payload fits must get a real read, not the replayed empty answer.
        let (content, _) = reader.read("text/plain", 50, "test").await.unwrap();
        assert_eq!(content.len(), 50);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A reader whose reads always succeed with empty content (the source
    /// app didn't answer).
    struct EmptyReader {
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl ClipboardReader for EmptyReader {
        async fn read(
            &mut self,
            _requested_type: &str,
            _max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn empty_serves_are_negatively_cached_within_the_ttl() {
        let calls = Arc::new(AtomicUsize::new(0));
        let reader = SharedClipboardReader::new_with_negative_ttl(
            Box::new(EmptyReader {
                calls: calls.clone(),
            }),
            Duration::from_secs(10),
        );
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert!(content.is_empty());
        // An empty result is negatively cached: the retry doesn't re-read.
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert!(content.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A reader whose reads park (holding the serve serialization lock) until
    /// the gate opens, so a test can invalidate mid-serve.
    struct GatedReader {
        calls: Arc<AtomicUsize>,
        /// Reads park while false.
        open: Arc<AtomicBool>,
        /// Signalled once a read has parked.
        parked: Arc<Notify>,
        /// Opens the gate for one parked read.
        release: Arc<Notify>,
    }

    #[async_trait]
    impl ClipboardReader for GatedReader {
        async fn read(
            &mut self,
            requested_type: &str,
            _max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if !self.open.load(Ordering::SeqCst) {
                self.parked.notify_one();
                self.release.notified().await;
            }
            Ok(format!("data-for-{}", requested_type).into_bytes())
        }
    }

    #[tokio::test]
    async fn invalidation_mid_serve_is_lock_free_and_misses_the_cache() {
        let calls = Arc::new(AtomicUsize::new(0));
        let open = Arc::new(AtomicBool::new(true));
        let parked = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let reader = SharedClipboardReader::new(Box::new(GatedReader {
            calls: calls.clone(),
            open: open.clone(),
            parked: parked.clone(),
            release: release.clone(),
        }));

        // Fill the cache.
        let (content, _) = reader.read("text/plain", u64::MAX, "test").await.unwrap();
        assert_eq!(&*content, b"data-for-text/plain");
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Park a serve for a different type inside the slow underlying read:
        // it misses the cache and then holds the serialization lock.
        open.store(false, Ordering::SeqCst);
        let parked_serve = {
            let reader = reader.clone();
            tokio::spawn(async move { reader.read("text/html", u64::MAX, "test").await })
        };
        parked.notified().await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Invalidate while the serve above holds the lock. A lock-based
        // invalidate would queue behind the parked serve and the stale cache
        // would survive; the epoch bump takes effect immediately.
        reader.invalidate();

        // Let the parked serve finish; it caches its payload under the
        // now-stale epoch it started with. Reopen the gate first so the
        // final read below doesn't park.
        open.store(true, Ordering::SeqCst);
        release.notify_one();
        let (content, _) = parked_serve.await.unwrap().unwrap();
        assert_eq!(&*content, b"data-for-text/html");

        // The payload cached across the invalidation must not be served: the
        // next request misses and reads the system clipboard again.
        let (content, _) = reader.read("text/html", u64::MAX, "test").await.unwrap();
        assert_eq!(&*content, b"data-for-text/html");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}
