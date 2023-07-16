use std::collections::HashMap;

use anyhow::Result;
use async_std::task;
use futures::{select, FutureExt, StreamExt};
use tracing::warn;
use x11rb_async::connection::{Connection, RequestConnection};
use x11rb_async::protocol::xproto::{
    Atom, AtomEnum, ChangeWindowAttributesAux, ConnectionExt, EventMask, PropMode, Property,
    SelectionNotifyEvent, Time, Window, SELECTION_NOTIFY_EVENT,
};
use x11rb_async::protocol::Event;
use x11rb_async::rust_connection::RustConnection;

use crate::x11clipboard::shared;

struct ClipboardEntry {
    kinds: Vec<String>,
    data: Vec<u8>,
}

pub struct ClipboardWriter {
    sender: async_channel::Sender<ClipboardEntry>,
}

impl ClipboardWriter {
    pub async fn new() -> Result<Self> {
        let context = shared::XContext::new().await?;
        let (sender, receiver) = async_channel::bounded(32);
        task::spawn(async move {
            let mut clipboard_server = ClipboardServer::new(context, receiver).await;
            if let Err(e) = clipboard_server.serve().await {
                warn!("clipboard server died: {}", e);
            }
        });
        Ok(ClipboardWriter { sender })
    }

    pub async fn store<K: Into<Vec<String>>, T: Into<Vec<u8>>>(
        &self,
        kinds: K,
        data: T,
    ) -> Result<()> {
        self.sender
            .send(ClipboardEntry {
                kinds: kinds.into(),
                data: data.into(),
            })
            .await?;
        Ok(())
    }
}

struct ClipboardServer {
    context: shared::XContext,
    entry_rx: async_channel::Receiver<ClipboardEntry>,
}

impl ClipboardServer {
    async fn new(
        context: shared::XContext,
        entry_rx: async_channel::Receiver<ClipboardEntry>,
    ) -> Self {
        ClipboardServer { context, entry_rx }
    }

    async fn serve(&mut self) -> Result<()> {
        let mut state = ClipboardServerState::new(&self.context.conn).await?;
        loop {
            let mut event_wait_fused = self.context.conn.wait_for_event().fuse();
            select! {
                entry = self.entry_rx.next() => {
                    state.clipboard_entry = entry;

                    // Advertise that we've got a new clipboard entry available
                    self.context.conn.set_selection_owner(
                        self.context.window,
                        state.atoms.clipboard,
                        Time::CURRENT_TIME
                    ).await?.check().await?;
                },
                event = event_wait_fused => {
                    if let Ok(event) = event {
                        state.handle_event(event, &self.context).await?;
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
    clipboard_entry: Option<ClipboardEntry>,
    atoms: shared::Atoms,
    max_length: usize,
}

impl ClipboardServerState {
    async fn new(conn: &RustConnection) -> Result<Self> {
        let ret = ClipboardServerState {
            selection_to_property: HashMap::<Atom, Atom>::new(),
            property_to_state: HashMap::<Atom, IncrState>::new(),
            clipboard_entry: None,
            atoms: shared::Atoms::new(conn).await?,
            max_length: conn.maximum_request_bytes().await,
        };
        Ok(ret)
    }

    async fn handle_event(&mut self, event: Event, context: &shared::XContext) -> Result<()> {
        warn!("X11 writer/server event: {:?}", event);
        match event {
            Event::SelectionRequest(event) => {
                let entry = match &self.clipboard_entry {
                    Some(entry) => entry,
                    None => return Ok(()),
                };

                if event.target == self.atoms.targets {
                    // request to get the available clipboard targets
                    let mut data_u8 = Vec::with_capacity(4 * (1 + entry.kinds.len()));
                    data_u8.extend(self.atoms.targets.to_ne_bytes());
                    for kind in &entry.kinds {
                        data_u8
                            .extend(self.atoms.to_atom(&context.conn, kind).await?.to_ne_bytes());
                    }
                    context
                        .conn
                        .change_property(
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            Atom::from(AtomEnum::ATOM),
                            32,
                            2, // 2 entries in vec, each 32-bit
                            &data_u8,
                        )
                        .await?;
                } else if entry.data.len() < self.max_length - 24 {
                    // request to get clipboard content, and data fits within max_length
                    context
                        .conn
                        .change_property(
                            PropMode::REPLACE,
                            event.requestor,
                            event.property,
                            event.target,
                            8,
                            entry.data.len() as u32,
                            &entry.data,
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
                let entry = match &self.clipboard_entry {
                    Some(entry) => entry,
                    None => return Ok(()),
                };

                let mut len = entry.data.len() - state.pos;
                // Max out at 1MB per chunk
                if len > 1048576 {
                    len = 1048576;
                }
                let data = &entry.data[state.pos..][..len];
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
                self.clipboard_entry = None;
            }
            _ => (),
        }
        Ok(())
    }
}
