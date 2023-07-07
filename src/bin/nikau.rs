use std::sync::Arc;

use anyhow::{bail, Result};
use async_std::task;
use tracing::{error, info};

use nikau::{approval, client, deviceinput, devicewatch, logging, server};

fn main() -> Result<()> {
    // TODO server args: left/right shortcuts, ip/port to listen on, cert hash(es) to auto-accept, whether to automatically stop grabbing after N seconds for testing
    // TODO client args: server to connect to, cert hash(es) to auto-accept

    logging::init_logging();

    let approved_cert_fingerprints = vec![];
    let verifier = approval::NikauCertVerification::new(approved_cert_fingerprints)?;

    // TODO first arg: <server/client/approve>
    if true {
        server(verifier)
    } else {
        let connect_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;
        client(connect_addr, verifier)
    }
}

fn server(verifier: Arc<approval::NikauCertVerification>) -> Result<()> {
    let listen_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;

    let (event_tx, event_rx): (
        async_channel::Sender<deviceinput::Event>,
        async_channel::Receiver<deviceinput::Event>,
    ) = async_channel::bounded(32);

    task::spawn(async move {
        info!("Listening for clients: {}", listen_addr);
        if let Err(e) = server::run_server(&listen_addr, verifier, event_rx).await {
            error!("server fail: {}", e);
        }
    });

    // TODO args for user-specified key combos. require at least one key
    let input_handler = deviceinput::InputHandler::new("rightctrl,leftshift,f", None, event_tx)?;

    task::block_on(async move {
        if let Err(e) = devicewatch::watch_loop(input_handler).await {
            error!("Input device watch failure: {}", e);
        }
    });

    bail!("Exiting due to server failure")
}

fn client(
    connect_addr: std::net::SocketAddr,
    verifier: Arc<approval::NikauCertVerification>,
) -> Result<()> {
    logging::init_logging();

    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()?;

    task::block_on(async move {
        // TODO connection loop: handle server not up yet, or server restarting
        loop {
            let verifier2 = verifier.clone();
            info!("Connecting to server: {}", connect_addr);
            if let Err(e) = client::run_client(&bind_addr, &connect_addr, verifier2).await {
                error!("Client failure: {}", e);
            }
        }
    });

    bail!("Exiting due to client failure")
}
