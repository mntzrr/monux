use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use evdev::{EventStream, EventType, Key};
use tokio::sync::{broadcast, mpsc};
use tokio::task;
use tracing::{debug, info, trace, warn};

use crate::device::util;
use crate::device::watch::{DeviceHandle, DeviceHandler, GrabEvent};
use crate::msgs::event;

#[derive(Clone, Debug)]
pub enum Event {
    /// A group of input events to send to the active client, if any
    Input(Vec<event::InputEvent>),
    /// Activate the next client (or the server) in the rotation
    SwitchNext,
    /// Activate the previous client (or the server) in the rotation
    SwitchPrev,
    /// Activate the client with matching cert fingerprint, or the server if the string is empty
    SwitchTo(String),
}

pub struct InputHandler {
    config: HandlerConfig,
}

#[derive(Clone)]
struct HandlerConfig {
    combo_states: Vec<ComboState>,
    event_tx: mpsc::Sender<Event>,
}

impl InputHandler {
    pub fn new(
        keys_next: &str,
        keys_prev: Option<&str>,
        keys_goto: Vec<String>,
        event_tx: mpsc::Sender<Event>,
    ) -> Result<InputHandler> {
        let mut keymap = HashMap::new();
        add_key_combo(&mut keymap, keys_next, Event::SwitchNext)?;
        if let Some(keys_prev) = keys_prev {
            add_key_combo(&mut keymap, keys_prev, Event::SwitchPrev)?;
        }
        for entry in keys_goto {
            let entry_split: Vec<&str> = entry.split('=').collect();
            if entry_split.len() != 2 {
                bail!("Invalid --shortcut-goto: Expected 'key1,key2,key3=[fingerprint-prefix]', but was '{}'", entry);
            }
            let keystr = entry_split.get(0).expect("entry_split has len=2");
            let fingerprint = entry_split.get(1).expect("entry_split has len=2");
            add_key_combo(
                &mut keymap,
                keystr,
                Event::SwitchTo(fingerprint.to_string()),
            )?;
        }
        if keymap.is_empty() {
            bail!(
                "At least one keyboard shortcut must be configured for switching between devices"
            );
        }
        Ok(InputHandler {
            config: HandlerConfig {
                combo_states: keymap
                    .into_iter()
                    .filter_map(|(keys, action)| {
                        if keys.is_empty() {
                            None
                        } else {
                            Some(ComboState::new(keys, action))
                        }
                    })
                    .collect(),
                event_tx,
            },
        })
    }
}

fn add_key_combo(
    keymap: &mut HashMap<Vec<Key>, Event>,
    keys_raw: &str,
    action: Event,
) -> Result<()> {
    // Allow key string to be either 'x,y,z' or 'x+y+z' but not a mix of both
    let keys_iter = if keys_raw.contains(",") {
        keys_raw.split(',')
    } else {
        keys_raw.split('+')
    };
    let mut keys = vec![];
    for key in keys_iter {
        keys.push(
            Key::from_str(format!("KEY_{}", key.trim().to_uppercase()).as_str())
                .map_err(|e| anyhow!("Unsupported key '{}': {:?}", key, e))?,
        );
    }
    // Sort the keys to detect duplicates across e.g. "shift+alt+n" and "alt+shift+n".
    // The key combo handling waits for all keys to be held simultaneously in any order and
    // so doesn't check for keypress ordering. So sorting the keys here shouldn't affect that.
    keys.sort();
    // Add combo to keymap, complain if an identical combo already exists
    if !keys.is_empty() {
        if let Some(existing_action) = keymap.insert(keys.clone(), action.clone()) {
            bail!(
                "Key combination '{:?}' for {:?} collides with existing combination for {:?}",
                keys,
                action,
                existing_action
            )
        }
    }
    Ok(())
}

impl DeviceHandler for InputHandler {
    /// Spawns a task for listening to a device's events and for controlling its grab state.
    fn handle_device_stream(
        &mut self,
        mut events: EventStream,
        grab_rx: broadcast::Receiver<GrabEvent>,
        device_info: util::DeviceInfo,
    ) -> Result<DeviceHandle> {
        let config = self.config.clone();
        let handle = task::spawn(async move {
            read_device_events(&mut events, config, grab_rx, device_info).await
        });
        Ok(DeviceHandle { handle })
    }
}

/// Result of checking an input event for matching key combination shortcuts
enum ComboAction {
    /// The caller should not send the input event.
    ConsumeEvent,
    /// The caller should emit the input event as-is.
    PassEvent,
    /// The caller should emit the provided switch event, without sending the original input event.
    ConsumeEventAndEmitAction(Event),
    /// The caller should emit the provided switch event after sending the original input event as-is.
    PassEventAndEmitAction(Event),
}

/// Checks input events for a specified key combination.
///
/// For now we allow the keys to be pressed in any order, as long as there's a point where they're all being held down at the same time.
///
/// The key combination is only considered "complete" after the combo keys have all been released.
/// This avoids issues around the server machine thinking device keys are still held down when we grab the device.
#[derive(Clone)]
struct ComboState {
    /// The action to take
    action: Event,
    /// The combo keys that we're looking for. Indexes are mapped to pressed_keys.
    combo_key_codes: Vec<u16>,
    pressed_keys: bit_vec::BitVec,
    last_keypress: Option<evdev::InputEvent>,
}

impl ComboState {
    fn new(combo_keys: Vec<Key>, action: Event) -> ComboState {
        let len = combo_keys.len();
        ComboState {
            action,
            combo_key_codes: combo_keys.into_iter().map(|k| k.code()).collect(),
            pressed_keys: bit_vec::BitVec::from_elem(len, false),
            last_keypress: None,
        }
    }

    /// Checks if the provided event completes a combo according to internal state.
    /// If so, then the action to be taken is returned.
    fn check_combo(&mut self, event: &evdev::InputEvent) -> ComboAction {
        if event.event_type() != EventType::KEY {
            // Not a keypress, pass through
            return ComboAction::PassEvent;
        }
        // Check if this key is one of our assigned combo keys.
        // This search should be cheap as it's limited to the size of the key combo (2-4 keys?)
        if let Some(idx) = self.key_idx(event.code()) {
            // The key event is related to our combo. Update our state to reflect the keypress or release.
            self.pressed_keys.set(idx, event.value() >= 1);
            if let Some(last_keypress) = &self.last_keypress {
                // We're in the stage of waiting for keys to be released so that we can activate the switch.
                // We specifically wait for keys to be released so that a target machine doesn't see a "hanging" keypress.
                // We want the target machine to see the full press+release cycle before we switch targets.
                // However, we do consume/block the last keypress event in the combo, when the combo is "activated".
                // We need to check for the matching release event so that we can block that too.
                // We only block the last event because before that point we don't know if the user is intending to activate a combo,
                // and if we consume keys then the user will notice that e.g. their N key isn't working in the ALT+N combo case.
                let matching = last_keypress.event_type() == event.event_type()
                    && last_keypress.code() == event.code();
                if self.pressed_keys.none() {
                    // Waiting for keys to be released, and all the keys are released.
                    // The combo is complete.
                    self.last_keypress = None;
                    if matching {
                        // This key being released is the one that we consumed the press on earlier.
                        // For example, user pressed ALT, N: We consumed the N press.
                        // Now the user has released ALT and is now releasing N, and we should consume the N release.
                        ComboAction::ConsumeEventAndEmitAction(self.action.clone())
                    } else {
                        // This key being released isn't the one that we consumed earlier.
                        // In the above example, the user released N first and is now releasing ALT, and ALT's keypress wasn't consumed.
                        ComboAction::PassEventAndEmitAction(self.action.clone())
                    }
                } else {
                    // Not all keys have been released yet.
                    // Pass or consume the release event depending on what matching keypress had been consumed.
                    if matching {
                        // This key being released is the one that we consumed the press on earlier.
                        // For example, user pressed ALT, N: We consumed the N press.
                        // Now the user is releasing N first before releasing ALT, and we should consume the N release.
                        ComboAction::ConsumeEvent
                    } else {
                        // This key being released isn't the one that we consumed earlier.
                        // In the above example, the user is releasing ALT before releasing N, and ALT's keypress wasn't consumed.
                        ComboAction::PassEvent
                    }
                }
            } else {
                // Waiting for keys to be pressed before considering the combo to be complete.
                // We consume the last keypress, for example with ALT,N in that order, the destination machine only sees the ALT press/release, we consume the N press/release.
                // If the user pressed N before ALT then we consume the ALT press/release instead. It's just whatever key was pressed last.
                // We only consume the last keypress because we can't speculatively consume keypresses.
                // For example the user might be pressing N,P: If we consume the N keypress before ALT is pressed, it'll look like the N button isn't working.
                if self.pressed_keys.all() {
                    // All the keys are now pressed. Now we start waiting for them to be released.
                    // We also consume this last keypress event. For example if someone presses Alt+N, we drop the N keypress.
                    self.last_keypress = Some(event.clone());
                    ComboAction::ConsumeEvent
                } else {
                    // Not all of the keys are pressed. Keep waiting and let this event through since it might not intended as a combo activation.
                    ComboAction::PassEvent
                }
            }
        } else {
            // The key isn't relevant to the combo at all. Pass it through.
            ComboAction::PassEvent
        }
    }

    fn key_idx(&self, key_code: u16) -> Option<usize> {
        for (idx, combo_key_code) in self.combo_key_codes.iter().enumerate() {
            if key_code == *combo_key_code {
                return Some(idx);
            }
        }
        return None;
    }
}

async fn read_device_events(
    stream: &mut EventStream,
    mut c: HandlerConfig,
    mut grab_rx: broadcast::Receiver<GrabEvent>,
    device_info: util::DeviceInfo,
) {
    let mut input_events_batch = Vec::new();
    let mut combo_events_batch = Vec::new();
    loop {
        tokio::select! {
            event = stream.next_event() => {
                match event {
                    Ok(event) => {
                        // 100 limit: Just in case, avoid the risk of collecting queued events forever.
                        //            In practice we should only be collecting 2-3 events between syncs.
                        if event.event_type() == EventType::SYNCHRONIZATION
                            || (input_events_batch.len() + combo_events_batch.len()) >= 100 {
                            // Flush events to be handled by the client as a group
                            if !input_events_batch.is_empty() {
                                if let Err(e) = c.event_tx.send(Event::Input(input_events_batch)).await {
                                    warn!("Error sending input events for routing: {:?}", e);
                                }
                                input_events_batch = Vec::new();
                            }
                            // Follow original events with event(s) from combo completion(s)
                            if !combo_events_batch.is_empty() {
                                for combo_event in combo_events_batch {
                                    if let Err(e) = c.event_tx.send(combo_event).await {
                                        warn!("Error sending combo events for routing: {:?}", e);
                                    }
                                }
                                combo_events_batch = Vec::new();
                            }
                        } else {
                            // Check whether this event completes a key combo, which creates an additional event.
                            // No short-circuit: Ensure that all combo_states have a chance to be updated
                            let mut any_consume = false;
                            for cs in c.combo_states.iter_mut() {
                                match cs.check_combo(&event) {
                                    ComboAction::ConsumeEvent => {
                                        any_consume = true;
                                    }
                                    ComboAction::PassEvent => {
                                    }
                                    ComboAction::ConsumeEventAndEmitAction(action) => {
                                        any_consume = true;
                                        combo_events_batch.push(action);
                                    }
                                    ComboAction::PassEventAndEmitAction(action) => {
                                        combo_events_batch.push(action);
                                    }
                                }
                            }
                            if any_consume {
                                debug!("Dropping key event as it's the last key completing one or more combos: {:?}", event);
                            } else {
                                input_events_batch.push(convert_device_event(event, stream.device(), &device_info))
                            }
                        }
                    }
                    Err(e) => {
                        // Common when the device has been unplugged.
                        // We'll frequently get this error just as inotify is telling us the file is deleted.
                        // Exit to avoid an infinite loop on trying to read the missing file.
                        info!(
                            "Got an error event for {:?}, removing device (might be unplugged?): {}",
                            stream.device().name().unwrap_or("(Unnamed device)"),
                            e
                        );
                        return;
                    }
                }
            },
            grab = grab_rx.recv() => {
                match grab {
                    Ok(GrabEvent::Grab) => {
                        debug!("Grabbing device: {:?}", stream.device().name().unwrap_or("(Unnamed device)"));
                        if let Err(e) = stream.device_mut().grab() {
                            panic!("Failed to grab device {:?}: {:?}", stream.device().name(), e);
                        }
                    }
                    Ok(GrabEvent::Ungrab) => {
                        debug!("Ungrabbing device: {:?}", stream.device().name().unwrap_or("(Unnamed device)"));
                        if let Err(e) = stream.device_mut().ungrab() {
                            panic!("Failed to ungrab device {:?}: {:?}", stream.device().name(), e);
                        }
                    }
                    Err(e) => {
                        // Shouldn't happen, but don't want to loop forever if it does
                        warn!(
                            "Error on grab broadcast for {:?}, removing device: {}",
                            stream.device().name(),
                            e
                        );
                        return
                    }
                }
            }
        }
    }
}

fn convert_device_event(
    event: evdev::InputEvent,
    device: &evdev::Device,
    device_info: &util::DeviceInfo,
) -> event::InputEvent {
    // Convert the original event before any combo-generated events.
    let net_event = if let evdev::InputEventKind::AbsAxis(axis) = event.kind() {
        // Special handling for evdev absolute axis (e.g. touchpad) events
        if let Some((axis_min, axis_max)) = device_info.dims.get(&axis.0) {
            // Apply scaling from hardware width to [0.0, 1.0]
            event::InputEvent {
                inputi32: None,
                inputf64: Some(event::InputF64::from_evdev(event, *axis_min, *axis_max)),
            }
        } else {
            event::InputEvent {
                inputi32: Some(event::InputI32::from_evdev(event)),
                inputf64: None,
            }
        }
    } else {
        event::InputEvent {
            inputi32: Some(event::InputI32::from_evdev(event)),
            inputf64: None,
        }
    };
    trace!(
        "Input event @ {}: {} -> {:?}",
        device.name().unwrap_or("(Unnamed device)"),
        util::log_event(&event),
        net_event
    );
    net_event
}
