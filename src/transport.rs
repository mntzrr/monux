use anyhow::{bail, Context, Result};
use async_std::task;
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use tracing::{error, info};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::certs;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const TIMEOUT_MILLIS: u32 = 86400000; // 1d

pub async fn start_server(listen_addr: SocketAddr, known_client_certs: Vec<rustls::Certificate>) -> Result<()> {
    let server_endpoint: Endpoint;
    {
        let (server_cert, server_privkey) = certs::load_keypair().context("Failed to load server keypair")?;
        let mut rustls_config = rustls::ServerConfig::builder()
            .with_safe_defaults() // includes TLS1.3 required by QUIC
            .with_client_cert_verifier(certs::ManualClientVerification::new(known_client_certs))
            .with_single_cert(vec![server_cert], server_privkey)?;
        rustls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        rustls_config.max_early_data_size = u32::MAX; // required by QUIC
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_uni_streams(0_u8.into()) // all the examples have this?
            .keep_alive_interval(Some(Duration::from_secs(25))) // go with value recommended by wireguard
            .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(TIMEOUT_MILLIS))));
        let mut server_config = ServerConfig::with_crypto(Arc::new(rustls_config));
        server_config
            .use_retry(true)
            .transport_config(Arc::new(transport_config));
        server_endpoint = Endpoint::server(server_config, listen_addr)?;
    }
    while let Some(conn) = server_endpoint.accept().await {
        info!("[server] connection: addr={}", conn.remote_address());
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

pub async fn start_client(server_addr: SocketAddr, known_server_certs: Vec<rustls::Certificate>) -> Result<()> {
    let mut client_endpoint: Endpoint;
    {
        client_endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
        let (client_cert, client_privkey) = certs::load_keypair().context("Failed to load client keypair")?;
        let mut rustls_config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(certs::ManualServerVerification::new(known_server_certs))
            .with_single_cert(vec![client_cert], client_privkey)?;
        rustls_config.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        let mut transport_config = TransportConfig::default();
        transport_config
            .max_concurrent_uni_streams(0_u8.into()) // all the examples have this?
            .keep_alive_interval(Some(Duration::from_secs(25))) // go with value recommended by wireguard
            .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(TIMEOUT_MILLIS))));
        let mut client_config = ClientConfig::new(Arc::new(rustls_config));
        client_config
            .transport_config(Arc::new(transport_config));
        client_endpoint.set_default_client_config(client_config);
    }

    // connect to server (TODO loop retry?)
    let conn = client_endpoint
        .connect(server_addr, "localhost")?
        .await?;
    info!("[client] connected: addr={}", conn.remote_address());
    let (mut send, mut recv) = conn.open_bi().await.context("failed to open stream")?;
    send.write_all(b"bob burger").await.context("failed to send request")?;
    send.finish().await.context("failed to shutdown send stream")?;
    let resp = recv.read_to_end(usize::max_value()).await.context("failed to read response")?;
    info!("[client] got data: {}", std::str::from_utf8(&resp)?);
    // Dropping handles allows the corresponding objects to automatically shut down
    drop(conn);
    // Make sure the server has a chance to clean up
    client_endpoint.wait_idle().await;
    info!("[client] exiting");
    Ok(())
}
