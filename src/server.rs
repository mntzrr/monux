use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use async_lock::Mutex;
use async_std::task;
use futures::{select, FutureExt, StreamExt};
use tracing::{error, trace};

use crate::{approval, deviceinput, devicewatch, messages, rotation, transport};

pub async fn run_server(
    listen_addr: &SocketAddr,
    cert_verifier: Arc<approval::NikauCertVerification>,
    mut input_rx: async_channel::Receiver<deviceinput::Event>,
    grab_tx: async_channel::Sender<devicewatch::GrabEvent>,
) -> Result<()> {
    let rotation: Arc<Mutex<rotation::Rotation>> =
        Arc::new(Mutex::new(rotation::Rotation::new(grab_tx)));
    let rotation2 = rotation.clone();

    task::spawn(async move {
        while let Some(event) = input_rx.next().await {
            match event {
                deviceinput::Event::Input(evt) => {
                    // rotation handles and logs failed sends internally
                    let _result = rotation2
                        .lock()
                        .await
                        .send_event(messages::ServerMessage::Input(evt))
                        .await;
                }
                deviceinput::Event::SwitchNext => {
                    rotation2.lock().await.next_client().await;
                }
                deviceinput::Event::SwitchPrev => {
                    rotation2.lock().await.prev_client().await;
                }
            }
        }
    });

    let server_endpoint = transport::build_server(listen_addr, cert_verifier)?;
    while let Some(conn) = server_endpoint.accept().await {
        let rotation3 = rotation.clone();
        task::spawn(async move {
            match conn.await {
                Ok(conn) => {
                    let remote_addr = conn.remote_address();
                    if let Err(e) = handle_connection(conn, rotation3.clone()).await {
                        // Always try to remove the client from rotation, even if it wasn't added yet.
                        rotation3
                            .lock()
                            .await
                            .remove_client(remote_addr)
                            .await;
                        error!("Client connection error: {:?}", e);
                    }
                },
                Err(e) => {
                    error!("Client failed to connect: {}", e);
                }
            }
        });
    }
    error!("Exiting server");
    Ok(())
}

async fn handle_connection(
    conn: quinn::Connection,
    rotation: Arc<Mutex<rotation::Rotation>>,
) -> Result<()> {
    let (events_send, mut events_recv) = conn.accept_bi().await.context("Failed to initialize events stream")?;

    // Receive version from client and close the connection if it's not supported.
    // Future versions could follow the version message with more data. We ignore/discard it here.
    {
        let mut version_buf = vec![];
        transport::recv_version(&mut events_recv, &mut version_buf).await?;
    }

    // Start second stream for bulk messages
    let (bulk_send, mut bulk_recv) = conn.accept_bi().await.context("Failed to initialize bulk stream")?;

    // Add client to the rotation after a successful init
    rotation
        .lock()
        .await
        .add_client(conn.remote_address(), events_send, bulk_send)
        .await;

    let mut bulk_bytes = Vec::with_capacity(1024); // TODO 64k here and in read_chunk below once chunking logic is solid
    let mut event_bytes = Vec::with_capacity(1024);
    loop {
        let mut bulk_fut = pin!(bulk_recv.read_chunk(1024, true).fuse());
        let mut event_fut = pin!(events_recv.read_chunk(1024, true).fuse());
        select! {
            event_result = event_fut => {
                let resp = event_result
                    .context("Lost client events connection")?
                    .context("Client closed events connection")?;
                trace!("Received {} bytes from events stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Copy the immutable response data into a mutable buffer
                event_bytes.extend_from_slice(&*resp.bytes);
                handle_event_messages(conn.remote_address(), &rotation, &mut event_bytes).await?;
                event_bytes.clear();
            },
            bulk_result = bulk_fut => {
                let resp = bulk_result
                    .context("Lost client bulk connection")?
                    .context("Client closed bulk connection")?;
                trace!("Received {} bytes from bulk stream: {:X?}", resp.bytes.len(), &*resp.bytes);
                // Copy the immutable response data into a mutable buffer
                // TODO data will likely be coming in fragmented, need to accumulate before passing to handle (and then maybe reuse the logic elsewhere)
                bulk_bytes.extend_from_slice(&*resp.bytes);
                handle_bulk_messages(conn.remote_address(), &rotation, &mut bulk_bytes).await?;
                bulk_bytes.clear();
            },
        }
    }
}

async fn handle_event_messages(
    source: SocketAddr,
    rotation: &Arc<Mutex<rotation::Rotation>>,
    bytes: &mut Vec<u8>,
) -> Result<()> {
    let mut offset = 0;
    let bytes_len = bytes.len();
    while offset < bytes.len() {
        let (msg, resp_remainder) =
            postcard::take_from_bytes_cobs::<messages::ClientMessage>(&mut bytes[offset..])
                .map_err(|e| anyhow!("Failed to deserialize message: {:?}", e))?;
        let consumed = bytes_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            msg,
            consumed
        );
        match msg {
            messages::ClientMessage::ClipboardTypes(types) => {
                let types: Vec<String> = types.types.split(",").map(|t| t.to_string()).collect();
                rotation
                    .lock()
                    .await
                    .clipboard_update_source(Some(source), types)
                    .await;
            }
        }
        offset += consumed;
    }

    bytes.clear();
    Ok(())
}

async fn handle_bulk_messages(
    source: SocketAddr,
    rotation: &Arc<Mutex<rotation::Rotation>>,
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
                rotation
                    .lock()
                    .await
                    .clipboard_request_content(Some(source), c.type_, c.max_size_bytes)
                    .await;
            }
            messages::BulkMessage::ClipboardContentHeader(c) => {
                // TODO accumulate up to c.content_bytes bytes. resp_remainder just has the start.
                rotation
                    .lock()
                    .await
                    .clipboard_send_content(c.type_, &resp_remainder)
                    .await;
            }
        }
        offset += consumed;
    }
    Ok(())
}
