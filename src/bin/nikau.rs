use nikau::{certs, client, deviceinput, devicewatch, logging, server};

use anyhow::{bail, Result};
use async_std::task;
use tracing::{error, info};

fn main() -> Result<()> {
    // TODO server args: left/right shortcuts, ip/port to listen on, cert hash(es) to auto-accept, whether to automatically stop grabbing after N seconds for testing

    logging::init_logging();

    // TODO first arg: <server/client>
    server()
}

fn server() -> Result<()> {
    let listen_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;

    // Fetch known certs once up-front.
    // Approvals in this run will be added to this list, as well as written to disk for future runs.
    let known_certs = match certs::load_known_certs() {
        Ok(known_certs) => known_certs,
        Err(e) => {
            error!("failed to load known certs, continuing with no known certs: {}", e);
            vec![]
        }
    };

    let (event_tx, event_rx): (
        async_channel::Sender<server::Event>,
        async_channel::Receiver<server::Event>,
    ) = async_channel::bounded(32);

    task::spawn(async move {
        info!("Listening for clients: {}", listen_addr);
        if let Err(e) = server::run_server(&listen_addr, known_certs, event_rx).await {
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

fn client() -> Result<()> {
    // TODO client args: server to connect to, cert hash(es) to auto-accept
    // TODO connection loop: handle server not up yet, or server restarting

    logging::init_logging();

    let connect_addr: std::net::SocketAddr = "127.0.0.1:5000".parse()?;
    let bind_addr: std::net::SocketAddr = "0.0.0.0:0".parse()?;

    // Fetch known certs once up-front.
    // Approvals in this run will be added to this list, as well as written to disk for future runs.
    let known_certs = match certs::load_known_certs() {
        Ok(known_certs) => known_certs,
        Err(e) => {
            error!("failed to load known certs, continuing with no known certs: {}", e);
            vec![]
        }
    };
    let known_certs2 = known_certs.clone();

    task::block_on(async move {
        info!("Connecting to server: {}", connect_addr);
        if let Err(e) = client::run_client(&bind_addr, &connect_addr, known_certs2).await {
            error!("Client failure: {}", e);
        }
    });

    bail!("Exiting due to client failure")
}
