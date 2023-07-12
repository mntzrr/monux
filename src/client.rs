use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use tracing::{info, trace};

use crate::{approval, deviceoutput, messages, transport};

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
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    let mut bytes = Vec::with_capacity(1024);

    // Send version to server, who will close the connection if they can't support it.
    transport::send_version(&mut send, &mut bytes).await?;

    info!("Waiting to be activated by server...");
    loop {
        // Incoming data may contain one or more messages, but I've never seen fragments of messages.
        let resp = recv
            .read_chunk(1024, true)
            .await
            .context(
                "Failed reading events from server, does server need to approve this connection?",
            )?
            .context("Server closed connection")?;
        trace!("Received {} bytes: {:X?}", resp.bytes.len(), &*resp.bytes);
        // Copy the immutable response data into a mutable buffer
        bytes.extend_from_slice(&*resp.bytes);
        handle_messages(0, &mut bytes, resp.bytes.len(), virtual_devices)?;
    }
}

fn handle_messages(
    mut offset: usize,
    bytes: &mut Vec<u8>,
    resp_len: usize,
    virtual_devices: &mut deviceoutput::VirtualDevices,
) -> Result<()> {
    while offset < bytes.len() {
        let (networkmsg, resp_remainder) =
            postcard::take_from_bytes_cobs::<messages::ServerMessage>(&mut bytes[offset..])
                .map_err(|e| anyhow!("Failed to deserialize message: {:?}", e))?;
        let consumed = resp_len - resp_remainder.len() - offset;
        trace!(
            "Consumed event at offset={}: {} ({} bytes)",
            offset,
            networkmsg,
            consumed
        );
        match networkmsg {
            messages::ServerMessage::Switch(e) => {
                virtual_devices.switch(e.enabled)?;
            }
            messages::ServerMessage::Input(input) => {
                virtual_devices.add_event(input)?;
            }
        }
        offset += consumed;
    }

    bytes.clear();
    Ok(())
}
