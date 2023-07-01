use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, IdleTimeout, ServerConfig, TransportConfig, VarInt};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::certs;

const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
const TIMEOUT_MILLIS: u32 = 86400000; // 1d

pub fn build_client(bind_addr: SocketAddr, known_server_certs: Vec<rustls::Certificate>) -> Result<quinn::Endpoint> {
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

    let mut client_endpoint = Endpoint::client(bind_addr)?;
    client_endpoint.set_default_client_config(client_config);
    Ok(client_endpoint)
}

pub fn build_server(listen_addr: SocketAddr, known_client_certs: Vec<rustls::Certificate>) -> Result<quinn::Endpoint> {
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
    Ok(Endpoint::server(server_config, listen_addr)?)
}
