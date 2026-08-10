use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Result};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::clipboard::{data, filter_shareable_mime_types, serve, wayland};

/// Wrapper around client-local clipboard storage, if available.
pub struct LocalClipboard {
    /// Shared with spawned clipboard-serving tasks so that slow reads (e.g.
    /// zipping large copied files) never block the client event loop.
    /// Serializes serves and caches the last payload, so request bursts
    /// (e.g. clipboard managers fetching every type) can't pile up CPU work.
    /// Cache invalidation is lock-free (see SharedClipboardReader).
    reader: serve::SharedClipboardReader,
    /// Queue to the writer dispatcher thread: keeps blocking clipboard
    /// advertisements off the client event loop (see spawn_writer_dispatcher).
    types_tx: std::sync::mpsc::Sender<Vec<String>>,
    // TODO can we nest a tokio select here instead of exposing these upstream?:
    pub clipboard_fetch_rx: mpsc::Receiver<data::ClipboardFetch>,
    pub local_types_rx: watch::Receiver<Vec<String>>,
    /// A second receiver on the same watch, read only by
    /// clear_remote_clipboard to tell whether a local app has taken the
    /// selection since we advertised the server's clipboard. It cannot share
    /// local_types_rx: the client event loop awaits changed() on that one and
    /// thereby marks every change seen, and it only acts on those changes
    /// while this client is active — so an inactive client would otherwise
    /// have no record at all that a local owner appeared.
    local_takeover_rx: watch::Receiver<Vec<String>>,
    local_types: Option<Vec<String>>,
    serving_remote_clipboard: bool,
}

impl LocalClipboard {
    pub async fn new(config_dir: PathBuf, max_uncompressed_size_bytes: u64) -> Option<Self> {
        match Self::new_wayland(config_dir, max_uncompressed_size_bytes).await {
            Ok(Some(c)) => {
                info!("Using wayland clipboard");
                return Some(c);
            }
            Ok(None) => {
                info!("Unable to reach wayland clipboard");
            }
            Err(e) => {
                warn!("Failed to reach wayland clipboard: {}", e);
            }
        };
        warn!("CLIPBOARD SHARING DISABLED: no wayland clipboard is reachable. If monux is running under sudo, start it with 'sudo -E ...' to preserve the session environment (WAYLAND_DISPLAY, XDG_RUNTIME_DIR)");
        None
    }

    async fn new_wayland(config_dir: PathBuf, max_uncompressed_size_bytes: u64) -> Result<Option<Self>> {
        // The watcher call is set up to be permissive of missing wayland, so let's try that first
        let (local_regular_types_tx, local_regular_types_rx) = watch::channel(vec![]);
        if wayland::type_watcher::start(Some(local_regular_types_tx))?.is_none() {
            return Ok(None);
        }
        // Wayland should work from here, treat any init issues as an error
        let reader = wayland::reader::ClipboardReader::new()?;
        let (clipboard_fetch_tx, clipboard_fetch_rx) = mpsc::channel::<data::ClipboardFetch>(32);
        let writer = wayland::writer::ClipboardWriter::new(
            config_dir,
            max_uncompressed_size_bytes,
            clipboard_fetch_tx,
        );
        Ok(Some(Self{
            reader: serve::SharedClipboardReader::new(Box::new(reader)),
            types_tx: crate::clipboard::spawn_writer_dispatcher(Box::new(writer)),
            clipboard_fetch_rx,
            local_takeover_rx: local_regular_types_rx.clone(),
            local_types_rx: local_regular_types_rx,
            local_types: None,
            serving_remote_clipboard: false,
        }))
    }

    /// Handle for sharing the clipboard reader with spawned serving tasks,
    /// so that slow reads never block the client event loop.
    pub fn reader_handle(&self) -> serve::SharedClipboardReader {
        self.reader.clone()
    }

    /// Reads the clipboard data for the specified type.
    /// The result may be converted/compressed to a different type for network transfer.
    pub async fn read(
        reader: &serve::SharedClipboardReader,
        requested_type: &str,
        max_size_bytes: u64,
        request_client: Option<SocketAddr>,
    ) -> Result<(std::sync::Arc<[u8]>, Option<String>)> {
        let request_source = if let Some(c) = request_client {
            format!("server for {}", c)
        } else {
            "server".to_string()
        };
        debug!(
            "Reading clipboard data for requested type {} to {}",
            requested_type,
            request_source,
        );
        reader
            .read(requested_type, max_size_bytes, &request_source)
            .await
    }

    /// Switches to serving the local clipboard, rather than from the monux server
    pub fn set_local_clipboard(&mut self) {
        // Machine-internal types (chromium/x-internal-* etc.) are never
        // announced to the server; the local clipboard itself is untouched.
        self.local_types
            .replace(filter_shareable_mime_types(self.local_types_rx.borrow().clone()));
        // The local clipboard changed: never serve stale cached contents.
        // Lock-free: never waits on a serve in progress.
        self.reader.invalidate();
        // Now that we have a local clipboard, don't fetch clipboards from the server.
        self.serving_remote_clipboard = false;
    }

    /// Returns the locally available clipboard types
    pub fn get_local_clipboard_types(&mut self) -> Option<Vec<String>> {
        self.local_types.clone()
    }

    /// Clears the clipboard, discarding any types provided by the monux server
    pub fn clear_remote_clipboard(&mut self) -> Result<()> {
        if self.serving_remote_clipboard {
            self.local_types = None;
            self.serving_remote_clipboard = false;
            // Clearing is a global set_selection(NULL) on every seat — it
            // unsets whatever the compositor currently holds, not only our own
            // offer (this is how `wl-copy --clear` works). So it is only safe
            // while the selection is still ours: if a local app took it since
            // we advertised — a clipboard manager re-owning it, a wl-copy
            // script — clearing would destroy content monux never put there.
            // A watch error means the type watcher is gone, which is no
            // evidence of a local owner, so clear as usual rather than leave a
            // stale advertisement no fetch can ever answer.
            if self.local_takeover_rx.has_changed().unwrap_or(false) {
                debug!("Leaving the local clipboard alone: an app took the selection while the server's clipboard was advertised");
                return Ok(());
            }
            // Non-blocking: the actual advertisement happens on the writer
            // dispatcher thread; a failed send only means we're shutting down.
            let _ = self.types_tx.send(vec![]);
        }
        Ok(())
    }

    /// Sets the clipboard to types provided by the monux server
    pub fn set_remote_clipboard(&mut self, types: Vec<String>) -> Result<()> {
        self.local_types = None;
        self.serving_remote_clipboard = true;
        // The selection is ours again as of this advertisement: any watch
        // change from here on is a local app taking it back (our own offers
        // never reach the watcher — they carry IGNORED_MIME_TYPE), which is
        // exactly what clear_remote_clipboard must not stomp on.
        self.local_takeover_rx.mark_unchanged();
        // Defense in depth: a peer on an older build may still advertise
        // machine-internal types; never offer those to local apps.
        // Non-blocking: the actual advertisement happens on the writer
        // dispatcher thread; a failed send only means we're shutting down.
        let _ = self.types_tx.send(filter_shareable_mime_types(types));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;

    /// Stands in for the wayland reader: nothing in these tests serves a
    /// fetch, only the advertisement side is exercised.
    struct NullReader;

    #[async_trait]
    impl crate::clipboard::ClipboardReader for NullReader {
        async fn read(
            &mut self,
            _requested_type: &str,
            _max_size_bytes: u64,
            _request_source: &str,
        ) -> Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    /// A LocalClipboard with the wayland pieces replaced, plus the ends the
    /// test drives: the watch sender the type watcher would own, and the
    /// receiver the writer dispatcher would own (so advertisements — the empty
    /// list among them — can be observed).
    fn test_clipboard() -> (
        LocalClipboard,
        watch::Sender<Vec<String>>,
        std::sync::mpsc::Receiver<Vec<String>>,
    ) {
        let (local_types_tx, local_types_rx) = watch::channel(vec![]);
        let (types_tx, advertised_rx) = std::sync::mpsc::channel();
        // Nothing serves a fetch here, so the sending half can go.
        let (_, clipboard_fetch_rx) = mpsc::channel(1);
        let clipboard = LocalClipboard {
            reader: serve::SharedClipboardReader::new(Box::new(NullReader)),
            types_tx,
            clipboard_fetch_rx,
            local_takeover_rx: local_types_rx.clone(),
            local_types_rx,
            local_types: None,
            serving_remote_clipboard: false,
        };
        (clipboard, local_types_tx, advertised_rx)
    }

    #[test]
    fn clearing_releases_the_selection_while_it_is_still_ours() {
        let (mut clipboard, _local_types_tx, advertised) = test_clipboard();
        clipboard
            .set_remote_clipboard(vec!["text/plain".to_string()])
            .unwrap();
        assert_eq!(advertised.try_recv().unwrap(), vec!["text/plain"]);
        // Nothing else took the selection, so the connection loss must take
        // our own advertisement back down.
        clipboard.clear_remote_clipboard().unwrap();
        assert_eq!(advertised.try_recv().unwrap(), Vec::<String>::new());
    }

    #[test]
    fn clearing_leaves_a_local_owner_alone() {
        let (mut clipboard, local_types_tx, advertised) = test_clipboard();
        clipboard
            .set_remote_clipboard(vec!["text/plain".to_string()])
            .unwrap();
        assert_eq!(advertised.try_recv().unwrap(), vec!["text/plain"]);
        // A local app takes the selection while this client is INACTIVE: the
        // client event loop only calls set_local_clipboard while active, so
        // this change is the sole record that the clipboard is no longer ours.
        local_types_tx.send(vec!["text/html".to_string()]).unwrap();
        // set_selection(None) is global, so clearing here would destroy that
        // app's clipboard — nothing may be advertised.
        clipboard.clear_remote_clipboard().unwrap();
        assert!(advertised.try_recv().is_err());
    }

    #[test]
    fn a_fresh_server_clipboard_makes_the_selection_ours_again() {
        let (mut clipboard, local_types_tx, advertised) = test_clipboard();
        clipboard
            .set_remote_clipboard(vec!["text/plain".to_string()])
            .unwrap();
        local_types_tx.send(vec!["text/html".to_string()]).unwrap();
        // The server pushes a new clipboard: we take the selection back, so
        // the earlier local owner no longer protects it from a later clear.
        clipboard
            .set_remote_clipboard(vec!["image/png".to_string()])
            .unwrap();
        assert_eq!(advertised.try_recv().unwrap(), vec!["text/plain"]);
        assert_eq!(advertised.try_recv().unwrap(), vec!["image/png"]);
        clipboard.clear_remote_clipboard().unwrap();
        assert_eq!(advertised.try_recv().unwrap(), Vec::<String>::new());
    }
}
