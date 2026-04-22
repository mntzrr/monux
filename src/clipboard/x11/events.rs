use anyhow::Result;
use tracing::{trace, warn};
use x11rb_async::connection::Connection;
use x11rb_async::protocol::xproto::{Atom, AtomEnum, ConnectionExt, Property};
use x11rb_async::protocol::Event;

use crate::clipboard::x11::shared;

pub async fn process_event(
    context: &shared::XContext,
    atoms: &shared::Atoms,
    buf: &mut Vec<u8>,
    max_size_bytes: u64,
    target: Atom,
    property: Atom,
) -> Result<()> {
    let mut is_incr = false;
    loop {
        let event = context.conn.wait_for_event().await?;
        trace!("X11 reader event: {:?}", event);

        match event {
            Event::XfixesSelectionNotify(event) => {
                context
                    .conn
                    .convert_selection(
                        context.window,
                        atoms.clipboard,
                        target,
                        property,
                        event.timestamp,
                    )
                    .await?
                    .check()
                    .await?;
            }
            Event::SelectionNotify(event) => {
                if event.selection != atoms.clipboard {
                    continue;
                }
                if event.property == Atom::from(AtomEnum::NONE) {
                    break;
                }

                let reply = context
                    .conn
                    .get_property(
                        false,
                        context.window,
                        event.property,
                        AtomEnum::NONE,
                        // Fetch data as of this offset
                        buf.len() as u32,
                        u32::MAX,
                    )
                    .await?
                    .reply()
                    .await?;

                if reply.type_ == atoms.incr {
                    if let Some(mut value) = reply.value32() {
                        if let Some(size) = value.next() {
                            buf.reserve(size as usize);
                        }
                    }
                    context
                        .conn
                        .delete_property(context.window, property)
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

                let length = context
                    .conn
                    .get_property(false, context.window, property, AtomEnum::NONE, 0, 0)
                    .await?
                    .reply()
                    .await?
                    .bytes_after;

                let reply = context
                    .conn
                    .get_property(true, context.window, property, AtomEnum::NONE, 0, length)
                    .await?
                    .reply()
                    .await?;
                if reply.type_ != target {
                    continue;
                };

                if reply.value.is_empty() {
                    // End of data
                    break;
                }

                if max_size_bytes > 0 && (buf.len() + reply.value.len()) > max_size_bytes as usize {
                    // When this happens, we still need to send _something_ back,
                    // so that the receiving client (and its WM) can stop waiting.
                    // So let's just send back a zero-byte clipboard, which isn't great but probably won't hurt.
                    warn!(
                        "Sending empty clipboard data: size read so far ({}) exceeds max={}",
                        buf.len() + reply.value.len(),
                        max_size_bytes
                    );
                    buf.clear();
                    break;
                }

                buf.extend_from_slice(&reply.value);
            }
            _ => (),
        }
    }
    Ok(())
}
