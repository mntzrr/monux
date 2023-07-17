use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_lock::{Barrier, Mutex};
use async_std::task;
use futures::{select, FutureExt, StreamExt};
use tracing::{debug, info, warn};
use x11rb_async::connection::{Connection, RequestConnection};
use x11rb_async::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt, EventMask, PropMode, Property,
    SelectionNotifyEvent, Time, Window, SELECTION_NOTIFY_EVENT,
};
use x11rb_async::protocol::Event;
use x11rb_async::rust_connection::RustConnection;

use crate::x11clipboard::shared;

/// A fetch request, and a path for sending the response.
pub struct ClipboardFetch {
    pub desired_type: String,
    /// Barrier to wait for the result to appear. The requestor should wait on this before accessing result.
    pub result_barrier: Arc<Barrier>,
    /// Where the result should go.
    pub result: Arc<Mutex<Option<Result<Option<ResolvedClipboardData>>>>>,
}

pub struct ResolvedClipboardData {
    /// The type that this data is associated with
    pub type_: String,

    /// The retrieved data
    pub data: Vec<u8>,
}

pub struct ClipboardWriter {
    /// Push: available clipboard types, advertised by server
    types_tx: async_channel::Sender<Vec<String>>,
}

impl ClipboardWriter {
    pub async fn new() -> Result<(Self, async_channel::Receiver<ClipboardFetch>)> {
        let context = shared::XContext::new().await?;
        let (types_tx, types_rx) = async_channel::bounded(32);
        let (fetch_tx, fetch_rx) = async_channel::bounded(32);
        task::spawn(async move {
            let mut clipboard_server = ClipboardServer{ context, types_rx, fetch_tx };
            if let Err(e) = clipboard_server.serve().await {
                warn!("clipboard server died: {}", e);
            }
        });
        Ok((ClipboardWriter { types_tx }, fetch_rx))
    }

    /// Advertises with X11 that we have a new clipboard entry available
    pub async fn store_types<K: Into<Vec<String>>>(&self, types: K) -> Result<()> {
        self.types_tx
            .send(types.into())
            .await?;
        Ok(())
    }
}

struct ClipboardServer {
    context: shared::XContext,
    /// Push: available clipboard types, advertised by server
    types_rx: async_channel::Receiver<Vec<String>>,
    /// Pull: get clipboard content for one of the previously advertised types
    fetch_tx: async_channel::Sender<ClipboardFetch>,
}

impl ClipboardServer {
    async fn serve(&mut self) -> Result<()> {
        let mut state = ClipboardServerState::new(&self.context.conn).await?;
        loop {
            let mut event_wait_fused = self.context.conn.wait_for_event().fuse();
            select! {
                clipboard_types = self.types_rx.next() => {
                    info!("Got new clipboard types: {:?}", clipboard_types);
                    // New (or cleared) clipboard: Update types, and clear any prior clipboard data
                    if let Some(clipboard_types) = clipboard_types {
                        if clipboard_types.is_empty() {
                            // Treat empty types as a clipboard clear
                            state.clipboard_types = None;
                        } else {
                            let mut type_atoms = Vec::with_capacity(clipboard_types.len());
                            for type_ in clipboard_types {
                                type_atoms.push((state.atoms.to_atom(&self.context.conn, &type_).await?, type_));
                            }
                            state.clipboard_types = Some(type_atoms);
                        }
                    } else {
                        state.clipboard_types = None;
                    }
                    state.clipboard_data = None;

                    if state.clipboard_types.is_some() {
                        // Advertise the new clipboard to X11
                        self.context.conn.set_selection_owner(
                            self.context.window,
                            state.atoms.clipboard,
                            Time::CURRENT_TIME
                        ).await?.check().await?;
                    }
                },
                event = event_wait_fused => {
                    if let Ok(event) = event {
                        if let Err(e) = state.handle_event(event, &self.context, &self.fetch_tx).await {
                            warn!("X11 event handling failed: {:?}", e);
                            // keep going...
                        }
                    }
                }
            }
        }
    }
}

struct IncrState {
    requestor: Window,
    property: Atom,
    target: Atom,
    pos: usize,
}

struct ClipboardServerState {
    selection_to_property: HashMap<Atom, Atom>,
    property_to_state: HashMap<Atom, IncrState>,
    atoms: shared::Atoms,
    max_length: usize,
    /// Received via server advertisement
    clipboard_types: Option<Vec<(Atom, String)>>,
    /// Received via pull/lookup from server
    clipboard_data: Option<ResolvedClipboardData>,
}

impl ClipboardServerState {
    async fn new(conn: &RustConnection) -> Result<Self> {
        let ret = ClipboardServerState {
            selection_to_property: HashMap::<Atom, Atom>::new(),
            property_to_state: HashMap::<Atom, IncrState>::new(),
            atoms: shared::Atoms::new(conn).await?,
            max_length: conn.maximum_request_bytes().await,
            clipboard_types: None,
            clipboard_data: None,
        };
        Ok(ret)
    }

    async fn handle_event(&mut self, event: Event, context: &shared::XContext, fetch_tx: &async_channel::Sender<ClipboardFetch>) -> Result<()> {
        debug!("X11 writer/server event: {:?}", event);
        match event {
            Event::SelectionRequest(event) => {
                let clipboard_types = match &self.clipboard_types {
                    Some(t) => t,
                    None => {
                        warn!("Got selection request when we don't have a clipboard to serve");
                        return Ok(());
                    },
                };

                if event.target == self.atoms.targets {
                    // request to get the available clipboard targets
                    debug!("Returning available clipboard types: {:?}", clipboard_types);
                    let target_count = 1 + clipboard_types.len(); // the data types, plus TARGETS
                    let mut data_u8 = Vec::with_capacity(4 * target_count);
                    data_u8.extend(self.atoms.targets.to_ne_bytes());
                    for type_ in clipboard_types {
                        data_u8.extend(type_.0.to_ne_bytes());
                    }
                    context
                        .conn
                        .change_property(
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            Atom::from(AtomEnum::ATOM),
                            32,
                            target_count as u32,
                            &data_u8,
                        )
                        .await?;
                } else {
                    // This is a clipboard retrieval.
                    // If we don't have the correct type data already, fetch it.
                    let target = match clipboard_types.iter().find(|t| t.0 == event.target) {
                        Some(t) => t,
                        None => bail!("Client requested clipboard type {} when we support {:?}", event.target, clipboard_types),
                    };
                    let needs_fetch = self.clipboard_data.as_ref().map(|d| d.type_ != target.1).unwrap_or(true);
                    if needs_fetch {
                        info!("Fetching clipboard for type {}={}", target.0, target.1);
                        // Fetch clipboard data from upstream: Send request and wait for response via barrier
                        let result_barrier = Arc::new(Barrier::new(2));
                        let result = Arc::new(Mutex::new(None));
                        fetch_tx
                            .send(ClipboardFetch {
                                desired_type: target.1.clone(),
                                result_barrier: result_barrier.clone(),
                                result: result.clone(),
                            })
                            .await
                            .context("Failed to send cache fetch query")?;

                        // Wait on the barrier to complete
                        result_barrier.wait().await;
                        // Barrier has completed, get the stored result.
                        // Do a swap to get the result out without yet another copy.
                        match result
                            .lock()
                            .await
                            .replace(Ok(None))
                            .expect("Missing fetch result following barrier")
                        {
                            Ok(Some(clipboard_data)) => {
                                info!("Fetched clipboard data with type {}: {} bytes", target.1, clipboard_data.data.len());
                                self.clipboard_data = Some(clipboard_data);
                            },
                            Ok(None) => {
                                bail!("Clipboard data not available for type {}", target.1);
                            },
                            Err(e) => {
                                bail!("Clipboard retrieval failed for type {}: {:?}", target.1, e);
                            }
                        };
                    } else {
                        info!("Reusing existing clipboard content ({} bytes) for type {}", self.clipboard_data.as_ref().map(|d| d.data.len()).unwrap_or(0), target.1);
                    }

                    let clipboard_data = match &self.clipboard_data {
                        Some(data) => data,
                        None => return Ok(()),
                    };
                    if clipboard_data.data.len() < self.max_length - 24 {
                        // request to get clipboard content, and data fits within max_length
                        context
                            .conn
                            .change_property(
                                PropMode::REPLACE,
                                event.requestor,
                                event.property,
                                event.target,
                                8,
                                clipboard_data.data.len() as u32,
                                &clipboard_data.data,
                            )
                            .await?;
                    } else {
                        // request to get clipboard content, but data doesn't fit within max_length
                        context
                            .conn
                            .change_window_attributes(
                                event.requestor,
                                &ChangeWindowAttributesAux::new()
                                    .event_mask(EventMask::PROPERTY_CHANGE),
                            )
                            .await?;
                        context
                            .conn
                            .change_property(
                                PropMode::REPLACE,
                                event.requestor,
                                event.property,
                                self.atoms.incr,
                                32,
                                0,
                                &[],
                            )
                            .await?;
                        self.selection_to_property
                            .insert(event.selection, event.property);
                        self.property_to_state.insert(
                            event.property,
                            IncrState {
                                requestor: event.requestor,
                                property: event.property,
                                target: event.target,
                                pos: 0,
                            },
                        );
                    }
                }
                context
                    .conn
                    .send_event(
                        false,
                        event.requestor,
                        EventMask::default(),
                        SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: event.time,
                            requestor: event.requestor,
                            selection: event.selection,
                            target: event.target,
                            property: event.property,
                        },
                    )
                    .await?;
                context.conn.flush().await?;
            }
            Event::PropertyNotify(event) => {
                if event.state != Property::DELETE {
                    return Ok(());
                };

                // requestor has deleted the last chunk of clipboard content, write the next chunk
                let state = match self.property_to_state.get_mut(&event.atom) {
                    Some(val) => val,
                    None => return Ok(()),
                };
                let clipboard_data = match &self.clipboard_data {
                    Some(data) => data,
                    None => return Ok(()),
                };

                let mut len = clipboard_data.data.len() - state.pos;
                // Max out at 1MB per chunk
                if len > 1048576 {
                    len = 1048576;
                }
                let data = &clipboard_data.data[state.pos..][..len];
                context
                    .conn
                    .change_property(
                        PropMode::REPLACE,
                        state.requestor,
                        state.property,
                        state.target,
                        8,
                        data.len() as u32,
                        data,
                    )
                    .await?;
                state.pos += len;
                if len == 0 {
                    self.property_to_state.remove(&event.atom);
                }
                context.conn.flush().await?;
            }
            Event::SelectionClear(event) => {
                if let Some(property) = self.selection_to_property.remove(&event.selection) {
                    self.property_to_state.remove(&property);
                }
            }
            _ => (),
        }
        Ok(())
    }
}
