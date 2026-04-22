use std::path::PathBuf;
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
    config_dir: &PathBuf,
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
