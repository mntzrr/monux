use anyhow::{bail, Context, Result};
use async_std::task;
use tracing::{error, info};

use std::net::SocketAddr;

use crate::transport;

pub async fn run_server(listen_addr: SocketAddr, known_client_certs: Vec<rustls::Certificate>) -> Result<()> {
    let server_endpoint = transport::build_server(listen_addr, known_client_certs)?;
    while let Some(conn) = server_endpoint.accept().await {
        info!("[server] got client: {}", conn.remote_address());
        task::spawn(async move {
            if let Err(e) = handle_connection(conn).await {
                error!("[server] connection error: {}", e);
            }
        });
    }
    info!("[server] exiting");
    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let connection = conn.await?;
    loop {
        let stream = connection.accept_bi().await;
        let (send, recv) = match stream {
            Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                info!("[server] connection closed");
                break;
            }
            Err(e) => {
                bail!("Connection error: {}", e);
            }
            Ok(stream) => stream,
        };
        handle_request(send, recv).await?;
    }
    info!("[server] connection complete");
    Ok(())
}

async fn handle_request(mut send: quinn::SendStream, mut recv: quinn::RecvStream) -> Result<()> {
    let req = recv.read_to_end(64 * 1024).await.context("failed reading request")?;
    let resp = format!("oh hello there {}", std::str::from_utf8(&req)?);
    // [... handle request ...]

    send.write_all(resp.as_bytes()).await.context("Failed to send response")?;
    send.finish().await.context("Failed to close stream")?;
    info!("[server] request complete");
    Ok(())
}
