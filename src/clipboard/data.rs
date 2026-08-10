use std::path::Path;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time;
use tracing::{debug, error};

use crate::clipboard::{CLIPBOARD_TIMEOUT_SECS, convert};

pub struct ClipboardData {
    /// The type that this data is associated with, the format it should be returned as.
    pub requested_type: String,

    /// The type that is actually present in data, if it's different from requested_type.
    /// For example, if the data is compressed text/plain then this is the type of compression.
    pub data_type: Option<String>,

    /// The retrieved data
    pub bytes: Vec<u8>,

    /// Zero once the data is retrieved
    pub remaining_bytes: usize,
}

/// A clipboard fetch request
pub struct ClipboardFetch {
    /// The type that we want. The resulting ClipboardData may have a different type.
    pub requested_type: String,

    /// The channel for sending back the result.
    pub fetch_result_tx: oneshot::Sender<ClipboardData>,
}

pub async fn fetch_clipboard_data(
    fetch_data_tx: &mpsc::Sender<ClipboardFetch>,
    requested_type: &str,
    max_uncompressed_size_bytes: u64,
    config_dir: &Path,
) -> Option<ClipboardData> {
    debug!("Fetching clipboard with type {}", requested_type);
    let (fetch_result_tx, fetch_result_rx) = oneshot::channel();
    let fetch_request = ClipboardFetch {
        requested_type: requested_type.to_string(),
        fetch_result_tx,
    };
    if let Err(e) = fetch_data_tx.send(fetch_request).await {
        error!("Failed to submit clipboard fetch request, writing empty clipboard: {}", e);
        // Assume that this problem isn't recoverable - return empty clipboard to avoid retrying
        return Some(empty_clipboard_data(requested_type));
    }

    // Wait for response with clipboard data, or give up
    match time::timeout(
        Duration::from_secs(CLIPBOARD_TIMEOUT_SECS),
        fetch_result_rx,
    )
    .await
    {
        Ok(Ok(mut clipboard_data)) => {
            if clipboard_data.requested_type != requested_type {
                error!("Returned clipboard type {} doesn't match requested type {}", clipboard_data.requested_type, requested_type);
                // Assume that this problem isn't recoverable - return empty clipboard to avoid retrying
                return Some(empty_clipboard_data(requested_type))
            }
            if clipboard_data.data_type.is_none() && convert::is_file_list_type(requested_type) {
                // A file list with no datatype never comes from monux: the read
                // side always stamps the zip datatype on these types. Without
                // conversion the peer's bytes would go to the paste fd verbatim
                // — a list of paths on THIS machine, which the file manager
                // would then copy or (for a "cut" payload) move. Serve nothing.
                error!("Refusing unconverted clipboard file list for requested type {}", requested_type);
                return Some(empty_clipboard_data(requested_type));
            }
            if let Some(data_type) = &clipboard_data.data_type {
                clipboard_data.bytes = match convert::write(
                    clipboard_data.bytes,
                    max_uncompressed_size_bytes,
                    requested_type,
                    data_type,
                    config_dir,
                ).await {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        error!("Failed to convert returned data type {} to requested clipboard type {}: {}", data_type, requested_type, e);
                        // Assume that this problem isn't recoverable - return empty clipboard to avoid retrying
                        return Some(empty_clipboard_data(requested_type));
                    }
                }
            }
            debug!(
                "Writing clipboard data with type {}: {} bytes",
                clipboard_data.requested_type,
                clipboard_data.bytes.len()
            );
            Some(clipboard_data)
        }
        Ok(Err(e)) => {
            error!(
                "Waiting for clipboard data failed, returning empty result to try again later: {}",
                e
            );
            // Let upstream try fetching again next time
            None
        }
        Err(_e) => {
            error!(
                "Waiting for clipboard data timed out after {}s, returning empty result to try again later",
                CLIPBOARD_TIMEOUT_SECS
            );
            // Let upstream try fetching again next time
            None
        }
    }
}

fn empty_clipboard_data(requested_type: &str) -> ClipboardData {
    ClipboardData {
        requested_type: requested_type.to_string(),
        data_type: None,
        bytes: vec![],
        remaining_bytes: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a fetch against a fake source that answers with exactly the
    /// datatype and bytes given — standing in for a peer's reply, which is
    /// where both fields come from on the wire.
    async fn fetch_answered_with(
        requested_type: &str,
        data_type: Option<&str>,
        bytes: Vec<u8>,
    ) -> Option<ClipboardData> {
        let (fetch_data_tx, mut fetch_data_rx) = mpsc::channel::<ClipboardFetch>(1);
        let data_type = data_type.map(|t| t.to_string());
        tokio::spawn(async move {
            let fetch = fetch_data_rx.recv().await.expect("no fetch request");
            let _ = fetch.fetch_result_tx.send(ClipboardData {
                requested_type: fetch.requested_type,
                data_type,
                bytes,
                remaining_bytes: 0,
            });
        });
        fetch_clipboard_data(
            &fetch_data_tx,
            requested_type,
            100_000_000,
            Path::new("/nonexistent"),
        )
        .await
    }

    #[tokio::test]
    async fn unconverted_file_list_is_never_served() {
        // A peer answering a file-list fetch without the zip datatype is
        // contradicting the protocol: its bytes are a list of paths on THIS
        // machine, which the file manager would copy — or, for a "cut"
        // payload, MOVE — instead of the files unpacked under config_dir.
        for requested_type in ["x-special/gnome-copied-files", "text/uri-list"] {
            let data = fetch_answered_with(
                requested_type,
                None,
                b"cut\nfile:///home/victim/Documents".to_vec(),
            )
            .await
            .expect("fetch should answer");
            assert_eq!(data.requested_type, requested_type);
            assert!(
                data.bytes.is_empty(),
                "{} was served unconverted: {:?}",
                requested_type,
                data.bytes
            );
        }
    }

    #[tokio::test]
    async fn unconverted_ordinary_type_passes_through() {
        // Small payloads legitimately arrive with no datatype (convert::read
        // doesn't compress them), so the refusal above must not touch them.
        let data = fetch_answered_with("text/plain", None, b"hello".to_vec())
            .await
            .expect("fetch should answer");
        assert_eq!(data.bytes, b"hello");
    }
}
