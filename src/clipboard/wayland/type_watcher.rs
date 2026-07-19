use std::collections::HashMap;

use anyhow::{Context, Result};
use tokio::sync::watch;
use tracing::{error, warn};
use wayland_client::globals::registry_queue_init;
use wayland_client::Connection;

use crate::clipboard::wayland::{common, state};

/// Task that listens for updates to the clipboard types (local cut or copy).
/// Sends out an event when an update occurs, indicating a new clipboard is available.
/// If wayland is unavailable, this returns Ok(None).
pub fn start(
    regular_types_tx: Option<watch::Sender<Vec<String>>>,
    primary_types_tx: Option<watch::Sender<Vec<String>>>,
) -> Result<Option<()>> {
    let conn = match Connection::connect_to_env() {
        Ok(conn) => conn,
        Err(e) => {
            warn!("Disabling wayland clipboard support: Failed to connect to wayland: {}", e);
            return Ok(None)
        }
    };
    let (globals, mut queue) = match registry_queue_init::<state::State>(&conn) {
        Ok(vals) => vals,
        Err(e) => {
            warn!("Disabling wayland clipboard support: Failed to init Wayland registry queue: {}", e);
            return Ok(None)
        }
    };
    let qh = queue.handle();

    let clipboard_manager = if let Some(clipboard_manager) = common::clipboard_manager(&globals, &qh) {
        clipboard_manager
    } else {
        warn!("Disabling wayland clipboard support: Display manager lacks both ext-data-control and wlr-data-control protocols");
        return Ok(None)
    };

    let mut seats = HashMap::new();
    for seat in common::seats(&globals, &qh) {
        let data = state::SeatData::new(clipboard_manager.get_data_device(&seat, &qh, seat.clone()));
        seats.insert(seat, data);
    }
    if seats.is_empty() {
        warn!("Disabling wayland clipboard support: No seats found");
        return Ok(None);
    }
    // State handles advertising the regular and/or primary clipboard types to upstream listeners
    let mut state = state::State::new(seats, regular_types_tx, primary_types_tx);

    queue.roundtrip(&mut state).context("Failed to initialize Wayland state")?;

    let (thread_ready_tx, thread_ready_rx) = std::sync::mpsc::sync_channel(1);
    let _ = std::thread::spawn(move || {
        if let Err(e) = thread_ready_tx.send(()) {
            error!("Failed to send ready_tx: {}", e);
            return;
        }
        loop {
            // Have to explicitly pump the queue, otherwise we don't get anything
            if let Err(e) = queue.blocking_dispatch(&mut state) {
                error!("Error in wayland clipboard type watcher queue dispatch: {}", e);
                return;
            }
        }
    });
    // Wait for thread to have started before returning
    thread_ready_rx.recv()?;
    Ok(Some(()))
}
