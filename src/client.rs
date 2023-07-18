use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures::{select, FutureExt, StreamExt};
use quinn::SendStream;
use tracing::{info, trace};

use crate::{approval, deviceoutput, messages, transport, x11clipboard};

pub async fn run_client(
    bind_addr: &SocketAddr,
    server_addr: &SocketAddr,
    virtual_devices: &mut deviceoutput::VirtualDevices,
    cert_verifier: Arc<approval::NikauCertVerification>,
) -> Result<()> {
    let client_endpoint = transport::build_client(bind_addr, cert_verifier)?;
    // Connect to server, our custom cert verifiers result in server_name being ignored
    let conn = client_endpoint
        .connect(server_addr.clone(), "__ignored__")?
        .await?;
    info!("Connected to server: {}", conn.remote_address());
    let (mut events_send, mut events_recv) = conn
        .open_bi()
        .await
        .context("Failed to initialize events stream")?;

    // Send version to server, who will close the connection if they can't support it.
    let mut event_bytes = Vec::with_capacity(1024);
    transport::send_version(&mut events_send, &mut event_bytes).await?;

    let (mut bulk_send, mut bulk_recv) = conn
        .open_bi()
        .await
        .context("Failed to initialize bulk stream")?;

    let (fetch_tx, mut fetch_rx) = async_channel::bounded(32);
    let clipboard_writer = x11clipboard::writer::ClipboardWriter::new(fetch_tx).await?;

    let mut bulk_recv_bytes = Vec::with_capacity(1024); // TODO 65536 here and below once chunking is known-good
    let mut clipboard: Option<x11clipboard::ClipboardData> = None;
    info!("Waiting to be activated by server...");
    loop {
        // TODO is there a race condition where both of these read a chunk but we only get one of them?
        let mut event_fut = pin!(events_recv.read_chunk(1024, true).fuse());
        let mut bulk_fut = pin!(bulk_recv.read_chunk(1024, true).fuse());
        select! {
            fetch_request = fetch_rx.next() => {
                if let Some(fetch_request) = fetch_request {
                    let msg = messages::BulkMessage::ClipboardContentRequest(messages::ClipboardContentRequest{
                        type_: &fetch_request.desired_type,
                        max_size_bytes: 1048576, // TODO configurable
                    });
                    let serializedmsg = postcard::to_slice_cobs(&msg, &mut event_bytes)
                        .map_err(|e| anyhow!("Failed to serialize clipboard request message: {:?}", e))?;
                    trace!(
                        "Sending {} byte event: {:X?}",
                        serializedmsg.len(),
                        &serializedmsg
                    );
                    bulk_send.write_all(&serializedmsg)
                        .await
                        .context("Failed to send clipboard request message")?;
                }
            },
            event_result = event_fut => {
                // Incoming data may contain one or more messages, but I've never seen fragments of messages.
                let resp = event_result
                    .context("Lost events connection, does server need to approve our fingerprint?")?
                    .context("Server closed events connection")?;
                trace!("Received {} bytes from events stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Copy the immutable response data into a mutable buffer
                event_bytes.extend_from_slice(&*resp.bytes);
                handle_event_messages(&mut events_send, &mut event_bytes, virtual_devices)?;
                event_bytes.clear();
            },
            bulk_result = bulk_fut => {
                let resp = bulk_result
                    .context("Lost server bulk connection, does server need to approve our fingerprint?")?
                    .context("Server closed bulk connection")?;
                trace!("Received {} bytes from bulk stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                if let Some(c) = &mut clipboard {
                    if c.remaining_bytes >= resp.bytes.len() {
                        // Chunk is all clipboard data.
                        c.data.extend_from_slice(&*resp.bytes);
                        c.remaining_bytes -= resp.bytes.len();
                    } else {
                        // Chunk contains additional data past the clipboard entry.
                        c.data.extend_from_slice(&(*resp.bytes)[..c.remaining_bytes]);
                        bulk_recv_bytes.extend_from_slice(&(*resp.bytes)[c.remaining_bytes..]);
                        c.remaining_bytes = 0;
                    }

                    if c.remaining_bytes == 0 {
                        // Clipboard data is all accumulated, flush and clear
                        clipboard_writer.store_data(clipboard.take().expect("missing clipboard")).await?;
                    }

                    if bulk_recv_bytes.len() > 0 {
                        // Handle any data following the clipboard entry.
                        // Hopefully it's not fragmented too since we don't really support that
                        clipboard = handle_bulk_messages(&mut bulk_send, &mut bulk_recv_bytes, &clipboard_writer).await?;
                        bulk_recv_bytes.clear();
                    }
                } else {
                    // Copy the immutable response data into a mutable buffer
                    bulk_recv_bytes.extend_from_slice(&*resp.bytes);
                    clipboard = handle_bulk_messages(&mut bulk_send, &mut bulk_recv_bytes, &clipboard_writer).await?;
                    bulk_recv_bytes.clear();
                }
            },
        }
    }
}

fn handle_event_messages(
    _todo_event_send: &mut SendStream,
    bytes: &mut Vec<u8>,
    virtual_devices: &mut deviceoutput::VirtualDevices,
) -> Result<()> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes.len() {
        let (msg, resp_remainder) =
            postcard::take_from_bytes_cobs::<messages::ServerMessage>(&mut bytes[offset..])
                .map_err(|e| anyhow!("Failed to deserialize server message: {:?}", e))?;
        let consumed = bytes_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            msg,
            consumed
        );
        match msg {
            messages::ServerMessage::Switch(e) => {
                virtual_devices.switch(e.enabled)?;
                if !e.enabled {
                    // TODO send any clipboard status event_send
                }
            }
            messages::ServerMessage::Input(input) => {
                virtual_devices.add_event(input)?;
            }
            messages::ServerMessage::ClipboardTypes(_types) => {
                // TODO provide to X11
            }
        }
        offset += consumed;
    }
    Ok(())
}

async fn handle_bulk_messages(
    _todo_bulk_send: &mut SendStream,
    bytes: &mut Vec<u8>,
    clipboard_writer: &x11clipboard::writer::ClipboardWriter,
) -> Result<Option<x11clipboard::ClipboardData>> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes_len {
        let (msg, resp_remainder) =
            postcard::take_from_bytes_cobs::<messages::BulkMessage>(&mut bytes[offset..])
                .map_err(|e| anyhow!("Failed to deserialize bulk message: {:?}", e))?;
        let consumed = bytes_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            msg,
            consumed
        );
        offset += consumed;

        match msg {
            messages::BulkMessage::ClipboardContentRequest(c) => {
                // TODO get from X11, send back via bulk_send
            }
            messages::BulkMessage::ClipboardContentHeader(c) => {
                if c.content_bytes as usize <= resp_remainder.len() {
                    // The clipboard content fits fully within resp_remainder
                    // Mark content as consumed and continue looping in case another message follows?
                    let mut data = Vec::with_capacity(c.content_bytes as usize);
                    data.extend_from_slice(&resp_remainder[..c.content_bytes as usize]);
                    let d = x11clipboard::ClipboardData {
                        type_: c.type_.to_string(),
                        data,
                        remaining_bytes: 0,
                    };
                    clipboard_writer.store_data(d).await?;
                    offset += c.content_bytes as usize;
                } else {
                    // Need to collect more data.
                    // TODO enforce a limit on content_bytes
                    let mut data = Vec::with_capacity(c.content_bytes as usize);
                    data.extend_from_slice(resp_remainder);
                    return Ok(Some(x11clipboard::ClipboardData {
                        type_: c.type_.to_string(),
                        data,
                        remaining_bytes: c.content_bytes as usize - resp_remainder.len(),
                    }));
                }
            }
        }
    }
    Ok(None)
}
