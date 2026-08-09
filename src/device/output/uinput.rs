use anyhow::{Context, Result};
use async_trait::async_trait;
use evdev::{
    uinput, AbsInfo, AbsoluteAxisCode, AttributeSet, EvdevEnum, EventSummary, KeyCode, MiscCode,
    RelativeAxisCode,
};
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

use crate::device::output::{OutputHandler, VIRTUAL_DEVICE_NAME_PREFIX};
use crate::device::util;
use crate::msgs::event;

pub const SCALED_DIM_MIN: i32 = 0;
pub const SCALED_DIM_MAX: i32 = 65535;
pub const SCALED_DIM_RES_X: i32 = 640; // 65536 / 640 = 102.4mm
pub const SCALED_DIM_RES_Y: i32 = 960; // for a 3/2 ratio vs X: 65536 / 960 = 68.3mm

/// Creates virtual uinput devices on the client machine and emits input events locally.
pub struct VirtualUInputDevices {
    keyboard_keys: AttributeSet<KeyCode>,
    mouse_keys: AttributeSet<KeyCode>,
    touchpad_keys: AttributeSet<KeyCode>,

    mouse_axes: AttributeSet<RelativeAxisCode>,
    touchpad_axes: AttributeSet<AbsoluteAxisCode>,

    keyboard_misc: AttributeSet<MiscCode>,
    mouse_misc: AttributeSet<MiscCode>,
    touchpad_misc: AttributeSet<MiscCode>,

    keyboard_device: uinput::VirtualDevice,
    mouse_device: uinput::VirtualDevice,
    touchpad_device: uinput::VirtualDevice,

    /// Currently held keys/buttons with when each press was emitted, so they
    /// can be released on deactivation/disconnect and so delivery anomalies
    /// (duplicated presses, catch-up bursts) can be logged.
    pressed_keys: HashMap<u16, Instant>,
    /// When the last key event was emitted; used to detect catch-up bursts
    /// (a large batch of key events arriving right after a gap = stall flush,
    /// which presents to the user as repeated characters).
    last_key_event_at: Option<Instant>,
    /// Per-key coalescing of auto-repeat delivery (see REPEAT_MIN_INTERVAL).
    repeat_coalescer: RepeatCoalescer,
}

/// Minimum spacing between delivered auto-repeat events for the same key.
/// Real-time repeats arrive at the keyboard's repeat rate (tens of ms apart);
/// a faster run is a backlog flushing after a stall — collapsing it keeps a
/// network blip from presenting as a burst of repeated characters. 20ms
/// (50/s) leaves generous headroom over typical 25-30/s repeat rates.
const REPEAT_MIN_INTERVAL: Duration = Duration::from_millis(20);

/// Per-key auto-repeat rate limiter. Real-time repeats pass through; a run
/// arriving faster than the physical repeat rate (a stall backlog) is
/// collapsed. The key is still physically held, so live repeats keep arriving
/// at the natural rate afterwards — the user just doesn't see the stale burst.
struct RepeatCoalescer {
    last_delivered: HashMap<u16, Instant>,
}

impl RepeatCoalescer {
    fn new() -> Self {
        Self {
            last_delivered: HashMap::new(),
        }
    }

    /// Whether this repeat should be delivered now; updates the timestamp
    /// when it should.
    fn should_deliver(&mut self, code: u16) -> bool {
        self.should_deliver_at(code, Instant::now())
    }

    fn should_deliver_at(&mut self, code: u16, now: Instant) -> bool {
        if let Some(last) = self.last_delivered.get(&code) {
            if now.duration_since(*last) < REPEAT_MIN_INTERVAL {
                return false;
            }
        }
        self.last_delivered.insert(code, now);
        true
    }
}

impl VirtualUInputDevices {
    pub fn new() -> Result<VirtualUInputDevices> {
        let pid = std::process::id();
        let (keyboard_device, keyboard_keys, keyboard_misc) =
            keyboard(pid).context("Failed to create virtual keyboard for simulated output")?;
        let (mouse_device, mouse_keys, mouse_misc, mouse_axes) =
            mouse(pid).context("Failed to create virtual mouse for simulated output")?;
        let (touchpad_device, touchpad_keys, touchpad_misc, touchpad_axes) =
            touchpad(pid).context("Failed to create virtual touchpad for simulated output")?;
        debug!(
            "Event->device routing:

  keyboard_keys: {:?}

  mouse_keys: {:?}

  touchpad_keys: {:?}

  mouse_axes: {:?}

  touchpad_axes: {:?}

  keyboard_misc: {:?}

  mouse_misc: {:?}

  touchpad_misc: {:?}",
            keyboard_keys,
            mouse_keys,
            touchpad_keys,
            mouse_axes,
            touchpad_axes,
            keyboard_misc,
            mouse_misc,
            touchpad_misc
        );
        let ret = VirtualUInputDevices {
            keyboard_keys,
            mouse_keys,
            touchpad_keys,

            mouse_axes,
            touchpad_axes,

            keyboard_misc,
            mouse_misc,
            touchpad_misc,

            keyboard_device,
            mouse_device,
            touchpad_device,
            pressed_keys: HashMap::new(),
            last_key_event_at: None,
            repeat_coalescer: RepeatCoalescer::new(),
        };
        info!("Created virtual uinput devices: keyboard, mouse, touchpad");
        Ok(ret)
    }

    /// Paths of the /dev/input event nodes backing our virtual devices.
    /// Logged at startup and given to the device watcher, which raises an
    /// error if one of them ever disappears mid-session (a broken virtual
    /// keyboard is one way input goes dead while devices are grabbed).
    pub fn device_nodes(&mut self) -> Vec<PathBuf> {
        [
            &mut self.keyboard_device,
            &mut self.mouse_device,
            &mut self.touchpad_device,
        ]
        .into_iter()
        .flat_map(|dev| {
            dev.enumerate_dev_nodes_blocking()
                .map(|nodes| {
                    nodes
                        .filter_map(|res| res.ok())
                        .filter(|p| {
                            p.file_name()
                                .is_some_and(|n| n.to_string_lossy().starts_with("event"))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
        .collect()
    }

    /// Where an event should be emitted. `class` is the source device's
    /// class when the sender tagged the frame (protocol v17+): it settles
    /// destinations that the capability sets leave ambiguous, since a mouse
    /// and a touchpad necessarily share codes like BTN_LEFT. Without it the
    /// ambiguity falls back to a count heuristic over the frame.
    fn route_event(
        &self,
        event: evdev::InputEvent,
        class: Option<event::DeviceClass>,
    ) -> Option<EventDest> {
        match event.destructure() {
            EventSummary::Key(_evt, code, _val) => {
                if self.keyboard_keys.contains(code) {
                    Some(EventDest::Keyboard)
                } else if self.mouse_keys.contains(code) {
                    // mouse_keys and touchpad_keys have a lot of BTN_* key overlap
                    if self.touchpad_keys.contains(code) {
                        match class {
                            // The sender told us which device this came from,
                            // so the overlap isn't ambiguous at all.
                            Some(event::DeviceClass::Touchpad) => Some(EventDest::Touchpad),
                            Some(event::DeviceClass::Mouse) => Some(EventDest::Mouse),
                            _ => Some(EventDest::MouseOrTouchpad),
                        }
                    } else {
                        Some(EventDest::Mouse)
                    }
                } else if self.touchpad_keys.contains(code) {
                    Some(EventDest::Touchpad)
                } else {
                    // The real code is masked (like util::log_event): key
                    // codes must never reach the logs (passwords).
                    debug!("Dropping key event with unsupported code: {:?}", KeyCode::KEY_X);
                    None
                }
            }
            EventSummary::RelativeAxis(_evt, code, _val) => {
                if self.mouse_axes.contains(code) {
                    Some(EventDest::Mouse)
                } else {
                    debug!("Dropping relaxis event with unsupported code: {:?}", code);
                    None
                }
            }
            EventSummary::AbsoluteAxis(_evt, code, _val) => {
                if self.touchpad_axes.contains(code) {
                    Some(EventDest::Touchpad)
                } else {
                    debug!("Dropping absaxis event with unsupported code: {:?}", code);
                    None
                }
            }
            EventSummary::Misc(_evt, code, _val) => {
                if self.keyboard_misc.contains(code) {
                    // keyboard_misc and mouse_misc have MSC_SCAN overlap
                    if self.mouse_misc.contains(code) {
                        Some(EventDest::KeyboardOrMouse)
                    } else {
                        Some(EventDest::Keyboard)
                    }
                } else if self.mouse_misc.contains(code) {
                    Some(EventDest::Mouse)
                } else if self.touchpad_misc.contains(code) {
                    Some(EventDest::Touchpad)
                } else {
                    debug!("Dropping misc event with unsupported code: {:?}", code);
                    None
                }
            }
            _ => {
                debug!("Dropping event with unsupported type: {:?}", event);
                None
            }
        }
    }
}

/// The byte-cast in emit_events reinterprets `&[evdev::InputEvent]` as the
/// kernel's `struct input_event` array. That holds because evdev's InputEvent
/// is a repr(transparent) newtype over `libc::input_event` — but that is an
/// implementation detail of a third-party crate, not part of its public
/// contract. Without this assertion an evdev release that adds a field or
/// changes the representation still COMPILES here, and starts writing garbage
/// into /dev/uinput at 8 kHz. Fail the build instead.
const _: () = {
    assert!(
        std::mem::size_of::<evdev::InputEvent>() == std::mem::size_of::<libc::input_event>(),
        "evdev::InputEvent is no longer layout-compatible with struct input_event; emit_events must stop byte-casting"
    );
    assert!(
        std::mem::align_of::<evdev::InputEvent>() == std::mem::align_of::<libc::input_event>(),
        "evdev::InputEvent alignment diverged from struct input_event; emit_events must stop byte-casting"
    );
};

/// Emits a batch of events plus the terminating SYN_REPORT with a single
/// writev() syscall. evdev's VirtualDevice::emit issues two separate write()
/// calls (events, then SYN_REPORT); at high event rates (e.g. an 8000 Hz
/// gaming mouse) halving the syscall count keeps up more comfortably.
///
/// A short write is resumed rather than reported: uinput accepts whole events,
/// but a frame that stops halfway leaves the kernel holding a partial report,
/// which presents downstream as a stuck modifier or a touch that never lifts.
/// Finishing the frame is strictly better than surfacing the error.
fn emit_events(device: &mut uinput::VirtualDevice, events: &[evdev::InputEvent]) -> std::io::Result<()> {
    if events.is_empty() {
        return Ok(());
    }
    let syn = evdev::InputEvent::new(evdev::EventType::SYNCHRONIZATION.0, 0, 0);
    // SAFETY: evdev::InputEvent is a repr(transparent) newtype over the
    // kernel's struct input_event (asserted layout-compatible above), and the
    // evdev crate itself byte-casts event slices to write them
    // (evdev::write_events), so viewing the slices as byte iovecs is sound.
    let event_bytes = unsafe {
        std::slice::from_raw_parts(events.as_ptr() as *const u8, std::mem::size_of_val(events))
    };
    let syn_bytes = unsafe {
        std::slice::from_raw_parts(&syn as *const _ as *const u8, std::mem::size_of_val(&syn))
    };
    write_all_vectored(device.as_raw_fd(), event_bytes, syn_bytes)
}

/// writev()s the two buffers, resuming from wherever a short write stopped
/// until both are fully delivered (see emit_events). Split out so the resume
/// arithmetic is unit-testable against a pipe.
fn write_all_vectored(fd: libc::c_int, first: &[u8], second: &[u8]) -> std::io::Result<()> {
    let total = first.len() + second.len();
    let mut done = 0usize;
    while done < total {
        // Rebuild the iovecs from the resume offset: whichever buffer the
        // previous write stopped inside is submitted from that byte on, and a
        // buffer already fully written contributes nothing.
        let (first_at, second_at) = if done < first.len() {
            (&first[done..], second)
        } else {
            (&first[first.len()..], &second[done - first.len()..])
        };
        let mut iov: Vec<libc::iovec> = Vec::with_capacity(2);
        for buf in [first_at, second_at] {
            if !buf.is_empty() {
                iov.push(libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                });
            }
        }
        // SAFETY: the fd is valid (owned by the caller) and every iovec points
        // into a live buffer for its stated length.
        let written =
            unsafe { libc::writev(fd, iov.as_ptr(), iov.len() as libc::c_int) };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if written == 0 {
            // No progress and no error: the fd will not take the rest.
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "uinput device accepted no bytes",
            ));
        }
        done += written as usize;
    }
    Ok(())
}

#[derive(PartialEq)]
enum EventDest {
    Keyboard,
    Mouse,
    Touchpad,
    KeyboardOrMouse,
    MouseOrTouchpad,
}

#[async_trait]
impl OutputHandler for VirtualUInputDevices {
    async fn release_all(&mut self) -> Result<()> {
        if self.pressed_keys.is_empty() {
            return Ok(());
        }
        debug!(
            "Releasing {} held keys/buttons on virtual devices",
            self.pressed_keys.len()
        );
        // Pre-size to pressed-keys plus the trailing SYN event: an exact-fit
        // collect would just reallocate on the push below.
        let mut releases: Vec<event::InputEvent> = Vec::with_capacity(self.pressed_keys.len() + 1);
        releases.extend(self.pressed_keys.keys().map(|code| event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: evdev::EventType::KEY.0,
                code: *code,
                value: 0,
            }),
            inputf64: None,
        }));
        releases.push(event::InputEvent {
            inputi32: Some(event::InputI32 {
                type_: evdev::EventType::SYNCHRONIZATION.0,
                code: 0,
                value: 0,
            }),
            inputf64: None,
        });
        // write() routes the releases to the right devices and clears them from
        // the tracking set (on failure it keeps them tracked, so a later
        // release_all can retry).
        self.write(releases).await
    }

    async fn write(&mut self, events: Vec<event::InputEvent>) -> Result<()> {
        // Every write emits exactly one SYN_REPORT per device, so a write is
        // one evdev frame. A caller that has several frames to deliver can
        // therefore pass them in one call by separating them with an
        // explicit SYN_REPORT, and each arrives as its own frame — the
        // multitouch protocol is frame-based, and merging frames collapses a
        // whole touch into one the compositor reads as no touch at all.
        // Without this split the boundary would depend on callers making one
        // call per frame, which is invisible to break and silently kills
        // touchpad forwarding.
        for frame in events.split(is_frame_separator) {
            if frame.is_empty() {
                continue;
            }
            self.write_frame(frame, None).await?;
        }
        Ok(())
    }

    async fn write_classed(
        &mut self,
        class: event::DeviceClass,
        events: Vec<event::InputEvent>,
    ) -> Result<()> {
        for frame in events.split(is_frame_separator) {
            if frame.is_empty() {
                continue;
            }
            self.write_frame(frame, Some(class)).await?;
        }
        Ok(())
    }
}

/// Whether this event is a SYN_REPORT, the evdev frame terminator (see
/// VirtualUInputDevices::write).
fn is_frame_separator(event: &event::InputEvent) -> bool {
    event.inputi32.as_ref().is_some_and(|e| {
        e.type_ == evdev::EventType::SYNCHRONIZATION.0
            && e.code == evdev::SynchronizationCode::SYN_REPORT.0
    })
}

impl VirtualUInputDevices {
    /// Writes one frame: routes its events to the virtual devices and emits
    /// them, each device's share terminated by a single SYN_REPORT.
    async fn write_frame(
        &mut self,
        events: &[event::InputEvent],
        class: Option<event::DeviceClass>,
    ) -> Result<()> {
        // Pre-size to the incoming batch: batches arrive at up to 8kHz, so a
        // collect-grown Vec (doublings from empty) is per-call churn.
        let mut routed: Vec<(evdev::InputEvent, EventDest)> = Vec::with_capacity(events.len());
        routed.extend(events.iter().filter_map(|event| {
            if let Some(e) = &event.inputf64 {
                let evdev_event = e.to_evdev(SCALED_DIM_MIN, SCALED_DIM_MAX);
                self.route_event(evdev_event, class).map(|dest| (evdev_event, dest))
            } else if let Some(e) = &event.inputi32 {
                let evdev_event = e.to_evdev();
                check_discrete_axis_range(&evdev_event);
                self.route_event(evdev_event, class).map(|dest| (evdev_event, dest))
            } else {
                warn!("Event missing either an i32 or an f64 value: {}", event);
                None
            }
        }));
        let events = routed;
        if events.is_empty() {
            return Ok(());
        }

        // Track held keys/buttons so release_all() can unstick them later, and
        // log delivery anomalies that present as spurious repeated characters:
        // duplicated presses (event delivered twice) and catch-up bursts (a
        // backlog flushed after a stall).
        let mut key_events_in_batch = 0u32;
        // Releases untracked by this batch, with their original press time. If
        // the emit below fails, these are re-tracked so the kernel's still-held
        // keys stay visible to a later release_all retry.
        let mut removed_releases: Vec<(u16, Instant)> = Vec::new();
        let mut filtered_events: Vec<(evdev::InputEvent, EventDest)> =
            Vec::with_capacity(events.len());
        for (e, dest) in events {
            if e.event_type() == evdev::EventType::KEY {
                key_events_in_batch += 1;
                match e.value() {
                    0 => {
                        if let Some(since) = self.pressed_keys.remove(&e.code()) {
                            removed_releases.push((e.code(), since));
                            let held = since.elapsed();
                            if held > Duration::from_millis(600) {
                                // No code: these lines reach the log ring and
                                // from there every bug report (MASKED_KEY_CODE).
                                // The timing is the evidence; which key is not.
                                debug!(
                                    "A key was held {:.1}s before its release arrived (delivery delay?)",
                                    held.as_secs_f32()
                                );
                            }
                        }
                    }
                    1 => {
                        if self.pressed_keys.insert(e.code(), Instant::now()).is_some() {
                            warn!(
                                "Duplicate key press with no release in between (event duplicated?)"
                            );
                        }
                    }
                    // value == 2: auto-repeat, keep the original press timestamp
                    _ => {
                        if !self.pressed_keys.contains_key(&e.code()) {
                            // Repeat for a key we never saw pressed (e.g. held
                            // across a switch): this target never got the press,
                            // so drop the repeat instead of injecting it.
                            if crate::device::key_traced(e.code()) {
                                info!(
                                    "KEYTRACE uinput: dropping auto-repeat for key {} with no matching press",
                                    e.code()
                                );
                            } else {
                                trace!("Dropping an auto-repeat with no matching press");
                            }
                            continue;
                        }
                        // Collapse auto-repeats arriving faster than the
                        // physical repeat rate: a run like that is a stall
                        // backlog flushing, and delivering it presents as a
                        // burst of repeated characters. Real-time repeats at
                        // the natural rate pass through untouched.
                        if !self.repeat_coalescer.should_deliver(e.code()) {
                            trace!("Coalescing a backlog auto-repeat");
                            continue;
                        }
                    }
                }
            }
            if e.event_type() == evdev::EventType::KEY && crate::device::key_traced(e.code()) {
                info!("KEYTRACE uinput: emit key {} value {}", e.code(), e.value());
            }
            filtered_events.push((e, dest));
        }
        let events = filtered_events;
        if key_events_in_batch >= 12 {
            if let Some(last) = self.last_key_event_at {
                let gap = last.elapsed();
                if gap > Duration::from_millis(1500) {
                    info!(
                        "Input burst: {} key events delivered after a {:.1}s gap (catch-up after a stall? presents as repeated characters)",
                        key_events_in_batch,
                        gap.as_secs_f32()
                    );
                }
            }
        }
        if key_events_in_batch > 0 {
            self.last_key_event_at = Some(Instant::now());
        }

        // Hand the batch to the kernel. If that fails, the releases untracked
        // above may never have taken effect on the device: re-track them (with
        // their original press times) so the keys don't stay pressed in the
        // kernel while invisible to a later release_all retry.
        if let Err(e) = self.emit_routed_events(&events) {
            for (code, since) in removed_releases {
                self.pressed_keys.insert(code, since);
            }
            return Err(e.into());
        }

        Ok(())
    }
}

impl VirtualUInputDevices {
    /// Routes a prepared batch to the right virtual device(s) and emits it.
    /// Split from write() so the caller can roll back its pressed-key tracking
    /// when the kernel never saw the events.
    fn emit_routed_events(&mut self, events: &[(evdev::InputEvent, EventDest)]) -> std::io::Result<()> {
        // Collect stats on how many events apply to each device
        // We specifically avoid grouping the events themselves so that ordering is preserved
        let mut keyboard_count = 0;
        let mut mouse_count = 0;
        let mut touchpad_count = 0;
        for e in events {
            match e.1 {
                EventDest::Keyboard => {
                    keyboard_count += 1;
                }
                EventDest::Mouse => {
                    mouse_count += 1;
                }
                EventDest::Touchpad => {
                    touchpad_count += 1;
                }
                EventDest::KeyboardOrMouse => {
                    keyboard_count += 1;
                    mouse_count += 1;
                }
                EventDest::MouseOrTouchpad => {
                    mouse_count += 1;
                    touchpad_count += 1;
                }
            }
        }
        // Route the events according to the count stats.
        // The events should be single-device in most cases, but we support mixed events too, just in case.
        if keyboard_count == events.len() {
            // All of the events can be classified as keyboard
            let events = events
                .iter()
                .map(|e| e.0)
                .collect::<Vec<evdev::InputEvent>>();
            trace!(
                "Emitting {} keyboard events: {:?}",
                events.len(),
                events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>()
            );
            emit_events(&mut self.keyboard_device, &events)?;
        } else if mouse_count == events.len() {
            // All of the events can be classified as mouse
            let events = events
                .iter()
                .map(|e| e.0)
                .collect::<Vec<evdev::InputEvent>>();
            trace!(
                "Emitting {} mouse events: {:?}",
                events.len(),
                events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>()
            );
            emit_events(&mut self.mouse_device, &events)?;
        } else if touchpad_count == events.len() {
            // All of the events can be classified as touchpad
            let events = events
                .iter()
                .map(|e| e.0)
                .collect::<Vec<evdev::InputEvent>>();
            trace!(
                "Emitting {} touchpad events: {:?}",
                events.len(),
                events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>()
            );
            emit_events(&mut self.touchpad_device, &events)?;
        } else {
            // Events don't all 'fit' in one device, group by device
            let mut keyboard_events = Vec::with_capacity(keyboard_count);
            let mut mouse_events = Vec::with_capacity(mouse_count);
            let mut touchpad_events = Vec::with_capacity(touchpad_count);
            for event in events {
                match event.1 {
                    EventDest::Keyboard => {
                        keyboard_events.push(event.0);
                    }
                    EventDest::Mouse => {
                        mouse_events.push(event.0);
                    }
                    EventDest::Touchpad => {
                        touchpad_events.push(event.0);
                    }
                    EventDest::KeyboardOrMouse => {
                        // Arbitrarily pick whichever device has the most events
                        // For example, if the batch is a mix of keyboard and touchpad events,
                        // then this lets us keep the keyboard-or-mouse events with the keyboard.
                        if keyboard_count >= mouse_count {
                            keyboard_events.push(event.0);
                        } else {
                            mouse_events.push(event.0);
                        }
                    }
                    EventDest::MouseOrTouchpad => {
                        // Arbitrarily pick whichever device has the most events
                        // For example, if the batch is a mix of keyboard and touchpad events,
                        // then this lets us keep the mouse-or-touchpad events with the touchpad.
                        if mouse_count >= touchpad_count {
                            mouse_events.push(event.0);
                        } else {
                            touchpad_events.push(event.0);
                        }
                    }
                }
            }
            trace!(
                "Emitting events: keyboard({})={:?} mouse({})={:?} touchpad({})={:?}",
                keyboard_events.len(),
                keyboard_events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>(),
                mouse_events.len(),
                mouse_events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>(),
                touchpad_events.len(),
                touchpad_events
                    .iter()
                    .map(util::log_event)
                    .collect::<Vec<String>>(),
            );
            if !keyboard_events.is_empty() {
                emit_events(&mut self.keyboard_device, &keyboard_events)?;
            }
            if !mouse_events.is_empty() {
                emit_events(&mut self.mouse_device, &mouse_events)?;
            }
            if !touchpad_events.is_empty() {
                emit_events(&mut self.touchpad_device, &touchpad_events)?;
            }
        }

        Ok(())
    }
}

pub fn keyboard(
    pid: u32,
) -> Result<(
    uinput::VirtualDevice,
    AttributeSet<KeyCode>,
    AttributeSet<MiscCode>,
)> {
    let mut keys = AttributeSet::<KeyCode>::new();
    // Report as many keys as possible to emit by the virtual device.
    for code in 1..libc::KEY_MAX {
        let key = KeyCode::new(code);
        // HACK: Include only known KEY_* keys, or else the keyboard will be ignored.
        let key_name = format!("{:?}", key);
        if key_name.starts_with("KEY_") {
            keys.insert(key);
        }
    }
    let device = uinput::VirtualDevice::builder()?
        .name(format!("{} keyboard for pid {}", VIRTUAL_DEVICE_NAME_PREFIX, pid).as_str())
        .with_keys(&keys)?
        .build()?;

    // We don't seem to need to advertise this, but mark it as a possible event so that we aren't dropping it and logging infos about it.
    let mut misc = AttributeSet::<MiscCode>::new();
    misc.insert(MiscCode::MSC_SCAN);

    Ok((device, keys, misc))
}

/// A freshly built virtual device plus the capability sets it advertises,
/// which route_event matches incoming events against. `A` is the axis kind
/// the device claims (relative for the mouse, absolute for the touchpad).
type BuiltDevice<A> = (
    uinput::VirtualDevice,
    AttributeSet<KeyCode>,
    AttributeSet<MiscCode>,
    AttributeSet<A>,
);

pub fn mouse(pid: u32) -> Result<BuiltDevice<RelativeAxisCode>> {
    // Only the button blocks a mouse actually has: misc (BTN_0..BTN_9),
    // the mouse buttons themselves, and the wheel buttons.
    //
    // Claiming every BTN_* (the previous behavior) made udev classify this
    // device as neither a mouse nor a joystick — measured here as a bare
    // `ID_INPUT=1 ID_INPUT_KEY=1`, with no ID_INPUT_MOUSE — because the
    // gamepad and joystick blocks it claimed outvote the mouse evidence.
    // libinput then can't apply pointer-acceleration or scroll settings to
    // it, and per-device compositor config never matches it. Claiming the
    // gamepad or joystick block alone is worse still: udev tags the device
    // ID_INPUT_JOYSTICK, which libinput ignores outright.
    //
    // A side benefit: BTN_TOUCH is no longer claimed here, so a touch
    // release can't be routed to the mouse (route_event only had a batch's
    // event counts to break that tie, and a tie went to the mouse).
    let mut keys = AttributeSet::<KeyCode>::new();
    for code in MOUSE_BUTTON_RANGES.iter().flat_map(|range| range.clone()) {
        keys.insert(KeyCode::new(code));
    }

    // Claim ALL axes. The mouse will be ignored if it claims keys that aren't relevant to claimed axes.
    let mut axes = AttributeSet::<RelativeAxisCode>::new();
    for code in 0..(libc::REL_CNT as u16) {
        axes.insert(RelativeAxisCode(code));
    }

    let device = uinput::VirtualDevice::builder()?
        .name(format!("{} mouse for pid {}", VIRTUAL_DEVICE_NAME_PREFIX, pid).as_str())
        .with_keys(&keys)?
        .with_relative_axes(&axes)?
        .build()?;

    // We don't seem to need to advertise this, but mark it as a possible event so that we aren't dropping it and logging infos about it.
    let mut misc = AttributeSet::<MiscCode>::new();
    misc.insert(MiscCode::MSC_SCAN);

    Ok((device, keys, misc, axes))
}

/// The contiguous `BTN_*` blocks of linux/input-event-codes.h: misc buttons,
/// mouse buttons, joystick, gamepad, digitizer/tool, wheel, the gamepad
/// d-pad, and the "trigger happy" block. Used to decide which key codes the
/// virtual devices advertise.
///
/// These were previously derived by formatting every code with `{:?}` and
/// testing the string for a `BTN_` prefix, which made the capabilities of
/// both virtual devices depend on the evdev crate's Debug output: a renamed
/// variant upstream would silently change what the devices claim, and the
/// symptom — a device the compositor quietly ignores — gives no hint where
/// to look. The code ranges are the kernel's ABI and don't move. An
/// equivalence test pins the two definitions together.
/// The blocks are not contiguous: the kernel leaves unassigned gaps (0x12c
/// through 0x12e in the joystick block, everything past BTN_TRIGGER_HAPPY40),
/// and those codes have no BTN_ name, so they were never claimed before
/// either. The equivalence test below holds the list to exactly that.
const BTN_CODE_RANGES: &[std::ops::RangeInclusive<u16>] = &[
    0x100..=0x109, // BTN_MISC     .. BTN_9
    0x110..=0x117, // BTN_MOUSE    .. BTN_TASK
    0x120..=0x12b, // BTN_JOYSTICK .. BTN_BASE6
    0x12f..=0x12f, // BTN_DEAD (past the 0x12c-0x12e gap)
    0x130..=0x13e, // BTN_GAMEPAD  .. BTN_THUMBR
    0x140..=0x148, // BTN_DIGI     .. BTN_TOOL_QUINTTAP
    0x14a..=0x14f, // BTN_TOUCH    .. BTN_TOOL_QUADTAP (0x149 BTN_STYLUS3 is
    // unnamed by our evdev version, so it was never claimed)
    0x150..=0x151, // BTN_WHEEL    .. BTN_GEAR_UP
    0x220..=0x223, // BTN_DPAD_UP  .. BTN_DPAD_RIGHT
    0x2c0..=0x2e7, // BTN_TRIGGER_HAPPY1 .. BTN_TRIGGER_HAPPY40
];

/// The button blocks the virtual mouse claims: misc, mouse, wheel. Kept
/// narrow so udev tags the device ID_INPUT_MOUSE (see mouse()).
const MOUSE_BUTTON_RANGES: &[std::ops::RangeInclusive<u16>] = &[
    0x100..=0x109, // BTN_MISC  .. BTN_9
    0x110..=0x117, // BTN_MOUSE .. BTN_TASK
    0x150..=0x151, // BTN_WHEEL .. BTN_GEAR_UP
];

/// The discrete absolute axes (those util::axis_scale_type returns
/// AxisScale::Discrete for) advertised by the virtual touchpad, with their
/// (min, max) ranges. Discrete events are forwarded raw from the capture
/// side, so these ranges must cover whatever values real devices emit.
const DISCRETE_AXES: &[(AbsoluteAxisCode, i32, i32)] = &[
    // max: arbitrarily big in case some real device uses big values?
    (AbsoluteAxisCode::ABS_MISC, -1, 1048576),
    // max: if this is too big then something panics
    (AbsoluteAxisCode::ABS_MT_SLOT, 0, 32),
    (AbsoluteAxisCode::ABS_MT_TOOL_TYPE, 0, 4095),
    // max: arbitrarily big in case some real device uses big IDs
    (AbsoluteAxisCode::ABS_MT_BLOB_ID, -1, 1048576),
    // max: arbitrarily big in case some real device uses big IDs
    (AbsoluteAxisCode::ABS_MT_TRACKING_ID, -1, 1048576),
];

/// The advertised (min, max) range for a discrete axis on the virtual
/// touchpad, if the axis is one of the DISCRETE_AXES.
fn discrete_axis_range(code: AbsoluteAxisCode) -> Option<(i32, i32)> {
    DISCRETE_AXES
        .iter()
        .find(|(axis, _, _)| *axis == code)
        .map(|(_, min, max)| (*min, *max))
}

/// Loudly logs when a raw discrete-axis event falls outside the range the
/// virtual touchpad advertises for it. Shouldn't happen — the capture side
/// forwards these raw and real devices stay within the advertised ranges —
/// but if a future device exceeds them, libinput would silently drop the
/// event (dead multitouch), so make the mismatch visible.
fn check_discrete_axis_range(event: &evdev::InputEvent) {
    if let EventSummary::AbsoluteAxis(_, code, value) = event.destructure() {
        if let Some((min, max)) = discrete_axis_range(code) {
            if value < min || value > max {
                debug!(
                    "Discrete axis {:?} value {} is outside the virtual touchpad's advertised range {}..={} and will likely be dropped by libinput",
                    code, value, min, max
                );
            }
        }
    }
}

pub fn touchpad(pid: u32) -> Result<BuiltDevice<AbsoluteAxisCode>> {
    let mut props = AttributeSet::<evdev::PropType>::new();
    // Doesn't seem to be required, but real touchpads have it:
    props.insert(evdev::PropType::BUTTONPAD);
    // Required for movement events to be recognized:
    props.insert(evdev::PropType::POINTER);

    // Most BTN_* keys, or the device won't work. The exceptions are the pen
    // and stylus codes: with any of them present, libinput classifies this
    // as an ID_INPUT_TABLET rather than an ID_INPUT_TOUCHPAD. (Check with
    // "sudo libinput record /dev/input/eventNN".)
    const BTN_TOOL_PEN: u16 = 0x140;
    const BTN_STYLUS: u16 = 0x14b;
    const BTN_STYLUS2: u16 = 0x14c;
    let mut keys = AttributeSet::<KeyCode>::new();
    for code in BTN_CODE_RANGES.iter().flat_map(|range| range.clone()) {
        if matches!(code, BTN_TOOL_PEN | BTN_STYLUS | BTN_STYLUS2) {
            continue;
        }
        keys.insert(KeyCode::new(code));
    }

    let mut misc = AttributeSet::<MiscCode>::new();
    misc.insert(MiscCode::MSC_TIMESTAMP);

    let name = format!(
        "{} multi touchpad for pid {}",
        VIRTUAL_DEVICE_NAME_PREFIX, pid
    );
    // These are the axes that util::axis_scale_type returns Discrete for,
    // declared from the shared DISCRETE_AXES table so that raw forwarded
    // values always land within an advertised range.
    let mut axis_codes = AttributeSet::<AbsoluteAxisCode>::new();
    let mut axes: Vec<evdev::UinputAbsSetup> = DISCRETE_AXES
        .iter()
        .map(|(axis, min, max)| abs_axis(*axis, *min, *max, 0, &mut axis_codes))
        .collect();
    for i in 0..libc::ABS_MAX + 1 {
        let axis = AbsoluteAxisCode::from_index(i as usize);
        match util::axis_scale_type(axis) {
            util::AxisScale::X => {
                // X axis values: use MAX_X
                axes.push(abs_axis(
                    axis,
                    SCALED_DIM_MIN,
                    SCALED_DIM_MAX,
                    SCALED_DIM_RES_X,
                    &mut axis_codes,
                ));
                axis_codes.insert(axis);
            }
            util::AxisScale::Y => {
                // Y axis values: use MAX_Y
                axes.push(abs_axis(
                    axis,
                    SCALED_DIM_MIN,
                    SCALED_DIM_MAX,
                    SCALED_DIM_RES_Y,
                    &mut axis_codes,
                ));
                axis_codes.insert(axis);
            }
            util::AxisScale::Other => {
                axes.push(abs_axis(
                    axis,
                    SCALED_DIM_MIN,
                    SCALED_DIM_MAX,
                    1,
                    &mut axis_codes,
                ));
                axis_codes.insert(axis);
            }
            _ => {}
        }
    }

    let mut device_builder = uinput::VirtualDevice::builder()?
        .name(name.as_str())
        .with_properties(&props)?
        .with_keys(&keys)?
        .with_msc(&misc)?;
    for axis in &axes {
        device_builder = device_builder.with_absolute_axis(axis)?;
    }
    let device = device_builder.build()?;
    Ok((device, keys, misc, axis_codes))
}

fn abs_axis(
    axis: AbsoluteAxisCode,
    min: i32,
    max: i32,
    res: i32,
    codes: &mut AttributeSet<AbsoluteAxisCode>,
) -> evdev::UinputAbsSetup {
    codes.insert(axis);
    evdev::UinputAbsSetup::new(
        axis,
        AbsInfo::new(
            0,   // value
            min, // min
            max, // max
            0,   // fuzz
            0,   // flat
            res, // res
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn in_ranges(ranges: &[std::ops::RangeInclusive<u16>], code: u16) -> bool {
        ranges.iter().any(|range| range.contains(&code))
    }

    /// Pins BTN_CODE_RANGES to the evdev crate's own naming, which is what
    /// the previous `format!("{:?}", key).starts_with("BTN_")` test used.
    /// The ranges are the kernel ABI and don't move, but if a future evdev
    /// version names a code we don't cover (or stops naming one we do), this
    /// fails loudly here instead of silently changing what the virtual
    /// devices advertise — a change whose only symptom is a device the
    /// compositor quietly ignores.
    #[test]
    fn btn_code_ranges_agree_with_the_evdev_names() {
        for code in 1..libc::KEY_MAX {
            let named_btn = format!("{:?}", KeyCode::new(code)).starts_with("BTN_");
            assert_eq!(
                in_ranges(BTN_CODE_RANGES, code),
                named_btn,
                "code {:#x} ({:?}): ranges and evdev naming disagree",
                code,
                KeyCode::new(code)
            );
        }
    }

    /// The virtual mouse claims pointer buttons only. Claiming the gamepad
    /// or joystick blocks costs it its ID_INPUT_MOUSE tag (measured: udev
    /// then reports a bare ID_INPUT_KEY, or ID_INPUT_JOYSTICK, which
    /// libinput ignores outright).
    #[test]
    fn the_virtual_mouse_claims_pointer_buttons_only() {
        for claimed in [
            KeyCode::BTN_LEFT,
            KeyCode::BTN_RIGHT,
            KeyCode::BTN_MIDDLE,
            KeyCode::BTN_SIDE,
            KeyCode::BTN_EXTRA,
            KeyCode::BTN_FORWARD,
            KeyCode::BTN_BACK,
            KeyCode::BTN_TASK,
        ] {
            assert!(
                in_ranges(MOUSE_BUTTON_RANGES, claimed.0),
                "the mouse must claim {:?}",
                claimed
            );
        }
        for rejected in [
            KeyCode::BTN_TOUCH,        // a touch release must reach the touchpad
            KeyCode::BTN_TOOL_FINGER,  // tool reports belong to the touchpad
            KeyCode::BTN_SOUTH,        // gamepad block: costs ID_INPUT_MOUSE
            KeyCode::BTN_TRIGGER,      // joystick block: udev tags it a joystick
        ] {
            assert!(
                !in_ranges(MOUSE_BUTTON_RANGES, rejected.0),
                "the mouse must not claim {:?}",
                rejected
            );
        }
        // Every mouse button is a BTN_* code.
        for range in MOUSE_BUTTON_RANGES {
            for code in range.clone() {
                assert!(in_ranges(BTN_CODE_RANGES, code), "{:#x} is not a BTN_ code", code);
            }
        }
    }

    fn ev(type_: u16, code: u16, value: i32) -> event::InputEvent {
        event::InputEvent {
            inputi32: Some(event::InputI32 { type_, code, value }),
            inputf64: None,
        }
    }

    /// A batch carrying several frames separated by SYN_REPORT is split back
    /// into those frames, so each is emitted with its own terminator. The
    /// separators themselves are consumed: write emits one per frame.
    #[test]
    fn a_batch_splits_back_into_its_frames() {
        let abs = evdev::EventType::ABSOLUTE.0;
        let syn = evdev::EventType::SYNCHRONIZATION.0;
        let syn_report = evdev::SynchronizationCode::SYN_REPORT.0;
        let mt_x = evdev::AbsoluteAxisCode::ABS_MT_POSITION_X.0;

        let batch = [ev(abs, mt_x, 100),
            ev(syn, syn_report, 0),
            ev(abs, mt_x, 200),
            ev(syn, syn_report, 0),
            ev(abs, mt_x, 300)];
        let frames: Vec<&[event::InputEvent]> = batch
            .split(is_frame_separator)
            .filter(|f| !f.is_empty())
            .collect();

        assert_eq!(frames.len(), 3, "each SYN_REPORT ends a frame");
        for (frame, expected) in frames.iter().zip([100, 200, 300]) {
            assert_eq!(frame.len(), 1);
            assert_eq!(frame[0].inputi32.as_ref().unwrap().value, expected);
        }
    }

    /// A batch with no separators is one frame — the coalesced relative
    /// motion path, where merging is lossless and saves syscalls at 8kHz.
    #[test]
    fn an_unseparated_batch_stays_one_frame() {
        let rel = evdev::EventType::RELATIVE.0;
        let rel_x = evdev::RelativeAxisCode::REL_X.0;
        let batch = [ev(rel, rel_x, 3), ev(rel, rel_x, 4)];

        let frames: Vec<&[event::InputEvent]> = batch
            .split(is_frame_separator)
            .filter(|f| !f.is_empty())
            .collect();

        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].len(), 2);
        // Only SYN_REPORT separates; other synchronization codes do not.
        assert!(!is_frame_separator(&ev(
            evdev::EventType::SYNCHRONIZATION.0,
            evdev::SynchronizationCode::SYN_DROPPED.0,
            0
        )));
    }

    /// A short write must be resumed, not reported: a frame that stops halfway
    /// leaves the kernel with a partial report. A pipe with a small buffer
    /// forces the short write that /dev/uinput only produces under load.
    #[test]
    fn a_short_write_is_resumed_until_the_frame_is_whole() {
        use std::io::Read;
        use std::os::fd::AsRawFd;

        let (mut reader, writer) = os_pipe::pipe().unwrap();
        // Comfortably more than a pipe's 64 KiB buffer, so writev cannot
        // deliver it in one call and must be resumed.
        let first = vec![b'a'; 96 * 1024];
        let second = vec![b'b'; 32 * 1024];
        let total = first.len() + second.len();

        // Drain concurrently: a pipe blocks the writer once full.
        let drain = std::thread::spawn(move || {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).unwrap();
            got
        });
        write_all_vectored(writer.as_raw_fd(), &first, &second).unwrap();
        drop(writer);

        let got = drain.join().unwrap();
        assert_eq!(got.len(), total, "every byte of the frame must land");
        // ...and in order, with the boundary between the two buffers intact.
        assert!(got[..first.len()].iter().all(|b| *b == b'a'));
        assert!(got[first.len()..].iter().all(|b| *b == b'b'));
    }

    #[test]
    fn repeat_coalescer_collapses_backlog_bursts() {
        let mut c = RepeatCoalescer::new();
        let t0 = Instant::now();
        // A backlog flush: many repeats of one key arriving at once — only
        // the first is delivered.
        assert!(c.should_deliver_at(28, t0));
        for i in 1..10 {
            assert!(
                !c.should_deliver_at(28, t0 + Duration::from_millis(i)),
                "repeat {}ms into the burst should be coalesced",
                i
            );
        }
        // A different key is independent.
        assert!(c.should_deliver_at(42, t0 + Duration::from_millis(1)));
        // Once the natural repeat interval has passed, delivery resumes.
        assert!(c.should_deliver_at(28, t0 + REPEAT_MIN_INTERVAL));
        assert!(!c.should_deliver_at(28, t0 + REPEAT_MIN_INTERVAL + Duration::from_millis(5)));
    }

    /// Every axis classified Discrete must be advertised (with a raw range)
    /// on the virtual touchpad, and nothing else may be in the table: the
    /// capture side forwards exactly the classified-discrete axes raw.
    #[test]
    fn discrete_axes_match_classification() {
        for i in 0..libc::ABS_MAX + 1 {
            let axis = AbsoluteAxisCode::from_index(i as usize);
            assert_eq!(
                util::axis_scale_type(axis) == util::AxisScale::Discrete,
                discrete_axis_range(axis).is_some(),
                "classification/advertisement mismatch for {:?}",
                axis
            );
        }
    }

    /// Raw values a capture device legitimately emits must fit the advertised
    /// ranges — the -1 tracking-id liftoff marker and small slot indexes in
    /// particular.
    #[test]
    fn advertised_ranges_cover_raw_values() {
        let (min, max) = discrete_axis_range(AbsoluteAxisCode::ABS_MT_TRACKING_ID).unwrap();
        assert!(min <= -1 && -1 <= max);
        let (min, max) = discrete_axis_range(AbsoluteAxisCode::ABS_MT_SLOT).unwrap();
        assert!(min <= 3 && 3 <= max);
    }

    /// The injection path emits inputi32 events untouched: no clamping or
    /// remapping of raw discrete values on their way to the virtual device.
    #[test]
    fn raw_discrete_values_are_emitted_untouched() {
        for (code, value) in [
            (AbsoluteAxisCode::ABS_MT_TRACKING_ID.0, -1),
            (AbsoluteAxisCode::ABS_MT_SLOT.0, 3),
        ] {
            let raw = event::InputI32 {
                type_: evdev::EventType::ABSOLUTE.0,
                code,
                value,
            };
            let ev = raw.to_evdev();
            assert_eq!(ev.code(), code);
            assert_eq!(ev.value(), value);
        }
    }

    /// The out-of-range guard accepts in-range values for every discrete
    /// axis without logging (it only fires outside the advertised range).
    #[test]
    fn range_check_accepts_in_range_values() {
        for (axis, min, max) in DISCRETE_AXES {
            for value in [*min, *max] {
                // Must not panic; the interesting property (no log) can't be
                // captured without a tracing subscriber, so this pins the
                // boundary values as accepted by construction.
                check_discrete_axis_range(&evdev::InputEvent::new(
                    evdev::EventType::ABSOLUTE.0,
                    axis.0,
                    value,
                ));
            }
        }
    }
}
