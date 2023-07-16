use anyhow::{anyhow, bail, Result};
use tracing::warn;
use x11rb_async::connection::Connection;
use x11rb_async::protocol::xproto::{Atom, AtomEnum, ConnectionExt, Property, Time};
use x11rb_async::protocol::{xfixes, Event};
use x11rb_async::x11_utils::TryParse;

use crate::x11clipboard::shared;

pub struct ClipboardReader {
    context: shared::XContext,
    atoms: shared::Atoms,
}

impl ClipboardReader {
    pub async fn new() -> Result<Self> {
        let context = shared::XContext::new().await?;
        let atoms = shared::Atoms::new(&context.conn).await?;
        Ok(ClipboardReader { context, atoms })
    }

    async fn process_event(&self, buf: &mut Vec<u8>, target: Atom, property: Atom) -> Result<()> {
        let mut is_incr = false;
        loop {
            let event = self.context.conn.wait_for_event().await?;
            warn!("X11 reader event: {:?}", event);

            match event {
                Event::XfixesSelectionNotify(event) => {
                    self.context
                        .conn
                        .convert_selection(
                            self.context.window,
                            self.atoms.clipboard,
                            target,
                            property,
                            event.timestamp,
                        )
                        .await?
                        .check()
                        .await?;
                }
                Event::SelectionNotify(event) => {
                    if event.selection != self.atoms.clipboard {
                        continue;
                    }
                    if event.property == Atom::from(AtomEnum::NONE) {
                        break;
                    }

                    let reply = self
                        .context
                        .conn
                        .get_property(
                            false,
                            self.context.window,
                            event.property,
                            AtomEnum::NONE,
                            buf.len() as u32,
                            u32::MAX,
                        )
                        .await?
                        .reply()
                        .await?;

                    if reply.type_ == self.atoms.incr {
                        if let Some(mut value) = reply.value32() {
                            if let Some(size) = value.next() {
                                buf.reserve(size as usize);
                            }
                        }
                        // Signal to other side that they should send more data:
                        self.context
                            .conn
                            .delete_property(self.context.window, property)
                            .await?
                            .check()
                            .await?;
                        is_incr = true;
                        continue;
                    }

                    buf.extend_from_slice(&reply.value);
                    break;
                }
                Event::PropertyNotify(event) if is_incr => {
                    if event.state != Property::NEW_VALUE {
                        continue;
                    };

                    let length = self
                        .context
                        .conn
                        .get_property(false, self.context.window, property, AtomEnum::NONE, 0, 0)
                        .await?
                        .reply()
                        .await?
                        .bytes_after;

                    let reply = self
                        .context
                        .conn
                        .get_property(
                            true,
                            self.context.window,
                            property,
                            AtomEnum::NONE,
                            0,
                            length,
                        )
                        .await?
                        .reply()
                        .await?;
                    if reply.type_ != target {
                        continue;
                    };

                    let value = reply.value;

                    if !value.is_empty() {
                        buf.extend_from_slice(&value);
                    } else {
                        break;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }

    pub async fn types_wait(&mut self) -> Result<Vec<String>> {
        let buf = self.read_wait(self.atoms.targets, false).await?;
        let mut atom_names = Vec::new();
        for atom in to_atoms(&buf)? {
            atom_names.push(self.atoms.to_name(&self.context.conn, atom).await?);
        }
        Ok(atom_names)
    }

    pub async fn read(&mut self, kind: &str, delete: bool) -> Result<Vec<u8>> {
        let kind_atom = self.atoms.to_atom(&self.context.conn, kind).await?;

        self.context
            .conn
            .convert_selection(
                self.context.window,
                self.atoms.clipboard,
                kind_atom,
                self.atoms.recv_clipboard,
                Time::CURRENT_TIME,
            )
            .await?
            .check()
            .await?;

        let mut buf = Vec::new();
        self.process_event(&mut buf, kind_atom, self.atoms.recv_clipboard)
            .await?;
        if delete {
            self.context
                .conn
                .delete_property(self.context.window, self.atoms.recv_clipboard)
                .await?
                .check()
                .await?;
        }
        Ok(buf)
    }

    async fn read_wait(&self, target: Atom, delete: bool) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        let screen = &self
            .context
            .conn
            .setup()
            .roots
            .get(self.context.screen)
            .ok_or(anyhow!("xcb connection error: invalid screen"))?;

        xfixes::query_version(&self.context.conn, 5, 0).await?;
        xfixes::select_selection_input(
            &self.context.conn,
            screen.root,
            self.atoms.clipboard,
            xfixes::SelectionEventMask::default(),
        )
        .await?;
        xfixes::select_selection_input(
            &self.context.conn,
            screen.root,
            self.atoms.clipboard,
            xfixes::SelectionEventMask::SET_SELECTION_OWNER
                | xfixes::SelectionEventMask::SELECTION_CLIENT_CLOSE
                | xfixes::SelectionEventMask::SELECTION_WINDOW_DESTROY,
        )
        .await?
        .check()
        .await?;

        self.process_event(&mut buf, target, self.atoms.recv_clipboard)
            .await?;

        if delete {
            self.context
                .conn
                .delete_property(self.context.window, self.atoms.recv_clipboard)
                .await?
                .check()
                .await?;
        }

        Ok(buf)
    }
}

fn to_atoms(buf: &Vec<u8>) -> Result<Vec<Atom>> {
    if buf.len() % 4 != 0 {
        bail!("Expected u32s, but buf.len={}", buf.len());
    }
    let mut atoms: Vec<Atom> = Vec::new();
    let mut next = buf.as_slice();
    loop {
        if next.len() <= 0 {
            break;
        }
        if let Ok((atom, remaining)) = Atom::try_parse(&next) {
            atoms.push(atom);
            next = remaining;
        } else {
            break;
        }
    }
    Ok(atoms)
}
