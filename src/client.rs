use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use futures::{select, FutureExt};
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
    let (mut events_send, mut events_recv) = conn.open_bi().await.context("Failed to initialize events stream")?;
    let mut bulk_bytes = Vec::with_capacity(1024); // TODO 64k here and in read_chunk below
    let mut event_bytes = Vec::with_capacity(1024);

    // Send version to server, who will close the connection if they can't support it.
    transport::send_version(&mut events_send, &mut event_bytes).await?;

    let (mut bulk_send, mut bulk_recv) = conn.open_bi().await.context("Failed to initialize bulk stream")?;

    let clipboard_writer = x11clipboard::writer::ClipboardWriter::new().await;

    info!("Waiting to be activated by server...");
    loop {
        let mut bulk_fut = pin!(bulk_recv.read_chunk(1024, true).fuse());
        let mut event_fut = pin!(events_recv.read_chunk(1024, true).fuse());
        select! {
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
                // Copy the immutable response data into a mutable buffer
                // TODO data will likely be coming in fragmented, need to accumulate before passing to handle (and then maybe reuse the logic elsewhere)
                bulk_bytes.extend_from_slice(&*resp.bytes);
                handle_bulk_messages(&mut bulk_send, &mut bulk_bytes)?;
                event_bytes.clear();
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
                .map_err(|e| anyhow!("Failed to deserialize message: {:?}", e))?;
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

fn handle_bulk_messages(
    _todo_bulk_send: &mut SendStream,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes.len() {
        let (msg, resp_remainder) =
            postcard::take_from_bytes_cobs::<messages::BulkMessage>(&mut bytes[offset..])
                .map_err(|e| anyhow!("Failed to deserialize message: {:?}", e))?;
        let consumed = bytes_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            msg,
            consumed
        );
        match msg {
            messages::BulkMessage::ClipboardContentRequest(c) => {
                // TODO get from X11, send back via bulk_send
            }
            messages::BulkMessage::ClipboardContentHeader(c) => {
                // TODO provide to X11
            }
        }
        offset += consumed;
    }
    Ok(())
}
