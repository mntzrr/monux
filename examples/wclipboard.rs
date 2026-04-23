use std::path::PathBuf;

use anyhow::Result;
use tokio::sync::{mpsc, watch};
use tokio::task;
use tracing::{error, info};

use nikau::clipboard::{
    ClipboardReader as ClipboardReaderTrait,
    ClipboardWriter as ClipboardWriterTrait,
    data,
};
use nikau::clipboard::wayland::{reader, type_watcher, writer};
use nikau::logging;

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let (regular_types_tx, mut regular_types_rx) = watch::channel(vec![]);
    let (primary_types_tx, mut primary_types_rx) = watch::channel(vec![]);
    task::spawn(async move {
        loop {
            tokio::select! {
                changed = regular_types_rx.changed() => {
                    if let Err(e) = changed {
                        info!("error for regular mime types update: {}", e);
                        break;
                    }
                    info!("[UPDATE] regular mime types: {:?}", regular_types_rx.borrow().clone());
                },
                changed = primary_types_rx.changed() => {
                    if let Err(e) = changed {
                        info!("failed to read primary mime types update: {}", e);
                        break;
                    }
                    info!("[UPDATE] primary mime types: {:?}", primary_types_rx.borrow().clone());
                },
            }
        }
    });

    type_watcher::start(Some(regular_types_tx), Some(primary_types_tx))?;
    let mut reader = reader::ClipboardReader::new()?;

    let text_mime_type = "text/plain";

    info!("read 1");
    read(&mut reader, text_mime_type.to_string()).await?;

    info!("write b");
    write("\n\nHello world!\n")?;
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    info!("read b 1");
    read(&mut reader, text_mime_type.to_string()).await?;
    info!("read b 2");
    read(&mut reader, text_mime_type.to_string()).await?;

    info!("write c");
    write("\n\nhey hi\n")?;
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    info!("read c 1");
    read(&mut reader, text_mime_type.to_string()).await?;
    info!("read c 2");
    read(&mut reader, text_mime_type.to_string()).await?;

    Ok(())
}

fn write(content: &str) -> Result<()> {
    let text_types = vec!["text/plain".to_string(), "UTF8_STRING".to_string(), "STRING".to_string(), "TEXT".to_string(), "COMPOUND_TEXT".to_string()];
    let max_uncompressed_bytes = 1024 * 1024;
    let (fetch_tx, mut fetch_rx) = mpsc::channel(32);
    writer::ClipboardWriter::new(
        writer::ClipboardType::Regular,
        PathBuf::from("/tmp/nikau"),
        max_uncompressed_bytes,
        fetch_tx,
    ).store_types(text_types)?;

    let mut bytes = Vec::new();
    bytes.extend_from_slice(content.as_bytes());

    task::spawn(async move {
        loop {
            if let Some(fetch) = fetch_rx.recv().await {
                info!("got clipboard lookup from writer, try pasting");
                // pretend that we're a server fetching a result here...
                let d = data::ClipboardData {
                    requested_type: fetch.requested_type,
                    data_type: None,
                    bytes: bytes.clone(),
                    remaining_bytes: 0,
                };
                if let Err(_d_again) = fetch.fetch_result_tx.send(d) {
                    error!("storing clipboard data failed");
                }
            }
        }
    });
    Ok(())
}

async fn read(reader: &mut reader::ClipboardReader, mime_type: String) -> Result<()> {
    let contents = reader.read(&mime_type, 1024 * 1024, "wclipboard test").await?;
    info!("clipboard data for type={}: {}", mime_type, String::from_utf8_lossy(&contents));
    Ok(())
}
