//! macOS input injection via CGEvent posting (the OutputHandler for macOS).
//!
//! The Linux backend creates uinput virtual devices and lets the kernel
//! replay raw evdev frames; macOS has no equivalent, so this backend
//! translates the same wire events into CGEvents posted at the HID tap:
//!
//! - Keyboard: evdev key codes map onto macOS virtual key codes (ANSI
//!   layout) and are posted as key-down/key-up, with a synthesized modifier
//!   flags word so shortcuts (Cmd+C etc.) resolve. Auto-repeat frames from
//!   the server are re-posted as key-downs carrying the autorepeat field.
//! - Mouse: relative deltas are turned into absolute moves at
//!   cursor + delta (CGEvents carry absolute positions); button presses
//!   become left/right/other mouse-down/up pairs at the current location;
//!   wheel detents become line-unit scroll events.
//! - Touchpad frames (protocol class Touchpad, scaled 0.0..=1.0 absolute
//!   axes) drive pointer MOTION, not absolute warps: each frame's delta
//!   from the previous contact position is scaled by the main display size
//!   and applied like mouse motion, which is how libinput interprets the
//!   same frames on Linux. Buttons in touchpad frames click as mouse
//!   buttons; BTN_TOUCH/BTN_TOOL_* are mac-no-ops.
//!
//! MVP limitations, to revisit with on-device tuning:
//! - ANSI key layout assumed; non-ANSI/JIS-specific keys are unmapped
//!   (logged at DEBUG and dropped; KEYTRACE-promotable via MONUX_TRACE_
//!   KEYS). Consumer keys map only where a macOS target exists AND the OS
//!   actually honors it synthetically: macOS 26 ignores NX media events
//!   and F-key media roles for brightness/media/eject, but the keycode-160
//!   launcher slot works (see the SCALE and APPSELECT entries).
//! - Only REL_WHEEL/REL_HWHEEL detents are injected; hi-res wheel axes
//!   (REL_*_HI_RES) are dropped.
//! - No repeat coalescing (the server's repeat rate is a keyboard-native
//!   25-30/s, cheap to post).
//! - Synthetic deltas bypass the pointer-acceleration curve (that lives in
//!   the driver for real devices); --mouse-scale is the tuning knob.
//!
//! Injection requires the Accessibility TCC grant; `new()` checks it (with
//! the system prompt) and bails with instructions when missing.

use std::collections::HashSet;

use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use core_foundation::base::TCFType;
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use core_graphics::display::CGDisplay;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventType, CGMouseButton, CGEventTapLocation, EventField,
    ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;

use crate::device::output::OutputHandler;
use crate::msgs::consts;
use crate::msgs::event::{self, DeviceClass};

/// evdev key code → macOS virtual key code (ANSI layout). Sorted by evdev
/// code for binary search; values are the HIToolbox kVK_* constants.
/// Mouse buttons (BTN_*) are handled separately — they never map here.
static KEY_TABLE: &[(u16, u16)] = &[
    (1, 0x35),    // ESC
    (2, 0x12),    // 1
    (3, 0x13),    // 2
    (4, 0x14),    // 3
    (5, 0x15),    // 4
    (6, 0x17),    // 5
    (7, 0x16),    // 6
    (8, 0x1A),    // 7
    (9, 0x1C),    // 8
    (10, 0x19),   // 9
    (11, 0x1D),   // 0
    (12, 0x1B),   // MINUS
    (13, 0x18),   // EQUAL
    (14, 0x33),   // BACKSPACE
    (15, 0x30),   // TAB
    (16, 0x0C),   // Q
    (17, 0x0D),   // W
    (18, 0x0E),   // E
    (19, 0x0F),   // R
    (20, 0x11),   // T
    (21, 0x10),   // Y
    (22, 0x20),   // U
    (23, 0x22),   // I
    (24, 0x1F),   // O
    (25, 0x23),   // P
    (26, 0x21),   // LEFTBRACE [
    (27, 0x1E),   // RIGHTBRACE ]
    (28, 0x24),   // ENTER
    (29, 0x3B),   // LEFTCTRL
    (30, 0x00),   // A
    (31, 0x01),   // S
    (32, 0x02),   // D
    (33, 0x03),   // F
    (34, 0x05),   // G
    (35, 0x04),   // H
    (36, 0x26),   // J
    (37, 0x28),   // K
    (38, 0x25),   // L
    (39, 0x29),   // SEMICOLON
    (40, 0x27),   // APOSTROPHE
    (41, 0x32),   // GRAVE
    (42, 0x38),   // LEFTSHIFT
    (43, 0x2A),   // BACKSLASH
    (44, 0x06),   // Z
    (45, 0x07),   // X
    (46, 0x08),   // C
    (47, 0x09),   // V
    (48, 0x0B),   // B
    (49, 0x2D),   // N
    (50, 0x2E),   // M
    (51, 0x2B),   // COMMA
    (52, 0x2F),   // DOT
    (53, 0x2C),   // SLASH
    (54, 0x3C),   // RIGHTSHIFT
    (55, 0x43),   // KPASTERISK
    (56, 0x3A),   // LEFTALT
    (57, 0x31),   // SPACE
    (58, 0x39),   // CAPSLOCK
    (59, 0x7A),   // F1
    (60, 0x78),   // F2
    (61, 0x63),   // F3
    (62, 0x76),   // F4
    (63, 0x60),   // F5
    (64, 0x61),   // F6
    (65, 0x62),   // F7
    (66, 0x64),   // F8
    (67, 0x65),   // F9
    (68, 0x6D),   // F10
    (69, 0x47),   // NUMLOCK (acts as keypad Clear)
    (70, 0x71),   // SCROLLLOCK (acts as F15)
    (71, 0x59),   // KP7
    (72, 0x5B),   // KP8
    (73, 0x5C),   // KP9
    (74, 0x4E),   // KPMINUS
    (75, 0x56),   // KP4
    (76, 0x57),   // KP5
    (77, 0x58),   // KP6
    (78, 0x45),   // KPPLUS
    (79, 0x53),   // KP1
    (80, 0x54),   // KP2
    (81, 0x55),   // KP3
    (82, 0x52),   // KP0
    (83, 0x41),   // KPDOT
    (86, 0x0A),   // 102ND (ISO extra key next to left shift)
    (87, 0x67),   // F11
    (88, 0x6F),   // F12
    (96, 0x4C),   // KPENTER
    (97, 0x3E),   // RIGHTCTRL
    (98, 0x4B),   // KPSLASH
    (100, 0x3D),  // RIGHTALT
    (102, 0x73),  // HOME
    (103, 0x7E),  // UP
    (104, 0x74),  // PAGEUP
    (105, 0x7B),  // LEFT
    (106, 0x7C),  // RIGHT
    (107, 0x77),  // END
    (108, 0x7D),  // DOWN
    (109, 0x79),  // PAGEDOWN
    (110, 0x72),  // INSERT (acts as Help)
    (111, 0x75),  // DELETE (forward delete)
    (113, 0x4A),  // MUTE
    (114, 0x49),  // VOLUMEDOWN
    (115, 0x48),  // VOLUMEUP
    (117, 0x51),  // KPEQUAL
    // Apple keyboards' Mission Control key and several Mac-layout boards'
    // launchpad key emit consumer usage 0x0083, which Linux surfaces as
    // KEY_SCALE (120) — NOT 0x0082/KEY_APPSELECT (580). On macOS 26 the
    // 0x0083 hardware event opens the Apps pane, so keycode 160 is the
    // faithful target; Mission Control has no working synthetic path at
    // all (NX_SYSDEFINED media events and plain F3 media roles are both
    // ignored by 26), so the launcher is strictly better than dropping.
    (120, 0xA0),  // SCALE (Apple mission-control / Mac-board launchpad)
    // kVK_JIS_KeypadComma, the PC numpad comma (JIS/ABNT layouts) — NOT
    // 0x5E, which is kVK_JIS_Underscore.
    (121, 0x5F),  // KPCOMMA
    (125, 0x37),  // LEFTMETA (Command)
    (126, 0x36),  // RIGHTMETA
    (183, 0x69),  // F13
    (184, 0x6B),  // F14
    (185, 0x71),  // F15
    (186, 0x6A),  // F16
    (187, 0x40),  // F17
    (188, 0x4F),  // F18
    (189, 0x50),  // F19
    (190, 0x5A),  // F20
    (464, 0x3F),  // FN
    // Not a kVK_* constant: 160 is the NX media-keycode slot (NX_KEYTYPE_
    // LAUNCHPAD, IOKit hidsystem/ev_keymap.h; same slot AppleScript's
    // `key code 160` targets). The WindowServer resolves it to the launcher
    // toggle — Launchpad, or the Apps pane on macOS 26+ — exactly as for the
    // hardware key, which Linux exposes as KEY_APPSELECT (HID consumer usage
    // 0x0082). Posting it beats synthesizing F4, which only opens the
    // launcher while the system-wide "media role" of F4 is in effect — and
    // it ONLY works from the combined session source on macOS 26 (see
    // needs_session_source).
    (580, 0xA0),  // APPSELECT (Apple Launchpad/apps-revealer key)
];

fn map_key(code: u16) -> Option<u16> {
    KEY_TABLE
        .binary_search_by(|(evdev, _)| (*evdev).cmp(&code))
        .ok()
        .map(|idx| KEY_TABLE[idx].1)
}

/// Virtual keycodes the WindowServer only honors when the event carries the
/// combined session source: macOS 26 drops synthetic media-slot keycodes
/// (160 = Launchpad/Apps) posted from the HID-system-state source, but
/// accepts them from the session source (verified on 26.6 — see the
/// session_source field docs).
static SESSION_SOURCE_KEYS: &[u16] = &[0xA0];

fn needs_session_source(vk: u16) -> bool {
    SESSION_SOURCE_KEYS.binary_search(&vk).is_ok()
}

/// The CGEventFlags bit an evdev modifier code contributes, if any.
fn modifier_of(code: u16) -> Option<CGEventFlags> {
    match code {
        29 | 97 => Some(CGEventFlags::CGEventFlagControl),   // LEFT/RIGHTCTRL
        42 | 54 => Some(CGEventFlags::CGEventFlagShift),     // LEFT/RIGHTSHIFT
        56 | 100 => Some(CGEventFlags::CGEventFlagAlternate), // LEFT/RIGHTALT
        125 | 126 => Some(CGEventFlags::CGEventFlagCommand), // LEFT/RIGHTMETA
        464 => Some(CGEventFlags::CGEventFlagSecondaryFn),   // FN
        _ => None,
    }
}

/// Whether the evdev key code is a touchpad contact/tool marker with no
/// macOS CGEvent equivalent (they ride along in touchpad frames):
/// BTN_TOOL_PEN..BTN_TOOL_QUINTTAP (0x140..=0x148) and BTN_TOUCH (0x14A).
fn is_touchpad_marker(code: u16) -> bool {
    (0x140..=0x14f).contains(&code)
}

// NX media keys (NX_SYSDEFINED subtype-8 events) were implemented and
// reverted: macOS 26 ignores synthetic NX media events for brightness,
// media transport, eject, and keyboard illumination, no matter the poster
// (verified from an Accessibility-trusted process — volume did not move).
// Real Apple keyboards map those keys onto kVK_*-representable codes or
// the 160 media slot instead; consumer-only codes stay dropped (KEYTRACE-
// visible). Reintroduce only with an on-machine verification story.

// AXIsProcessTrustedWithOptions: prompt=true asks macOS to put up the
// Accessibility grant dialog naming this process.
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrustedWithOptions(options: *const std::os::raw::c_void) -> u8;
}

fn ax_trusted_with_prompt() -> bool {
    let key = CFString::new("AXTrustedCheckOptionPrompt");
    let options: CFDictionary<CFString, CFBoolean> =
        CFDictionary::from_CFType_pairs(&[(key, CFBoolean::true_value())]);
    // SAFETY: options is a live CFDictionary for the duration of the call;
    // the C ABI takes an untyped CFDictionaryRef.
    unsafe { AXIsProcessTrustedWithOptions(options.as_CFTypeRef() as *const std::os::raw::c_void) != 0 }
}

/// CGEventSource marked Send: foreign-types only asserts !Send by default
/// (a raw pointer hides in there), but CoreGraphics event APIs are
/// documented thread-safe — events may be created and posted from any
/// thread — and the OutputHandler trait requires this handler to move
/// between the executor's threads.
struct SendEventSource(CGEventSource);
// SAFETY: CGEventSource is an immutable CF object whose lifetime is
// refcounted; creating events from it and posting them is thread-safe.
unsafe impl Send for SendEventSource {}

/// The macOS output backend: translates wire events into posted CGEvents.
pub struct MacOutputHandler {
    /// Events are created against the HID system state, the layer physical
    /// devices feed — posted events land where real input would.
    source: SendEventSource,
    /// Source in the combined session state, used ONLY for the launcher-slot
    /// keycodes (see needs_session_source): macOS 26 filters synthetic
    /// special keycodes claimed from the HID system state — an anti-spoof
    /// stance toward fake hardware input — but honors them from the session
    /// state. Normal keys keep the HID source; only special slots need the
    /// session source (verified live on 26.6: keycode 160 opened the Apps
    /// pane from the session source and did nothing from the HID source).
    session_source: SendEventSource,
    /// Evdev codes of keys currently held (for release_all).
    held_keys: HashSet<u16>,
    /// Accumulated modifier mask implied by held modifier keys; stamped on
    /// every posted keyboard event so shortcuts resolve.
    held_flags: CGEventFlags,
    /// Mouse button state, for drag-event typing and release_all.
    left_down: bool,
    right_down: bool,
    /// Non-primary button number held, if any (2=center, 3=side, 4=extra).
    other_down: Option<u16>,
    /// Last touchpad contact position (normalized), while a contact is
    /// active; deltas against it become pointer motion.
    touchpad_last: Option<(f64, f64)>,
}

impl MacOutputHandler {
    pub fn new() -> Result<Self> {
        if !ax_trusted_with_prompt() {
            bail!(
                "macOS has not granted monux the Accessibility permission, so it cannot inject keyboard or mouse input.\n\
                 Grant it, then restart this client: System Settings -> Privacy & Security -> Accessibility -> enable monux\n\
                 (the system dialog should already be open; the toggle can take a few seconds to appear)."
            );
        }
        let source = SendEventSource(
            CGEventSource::new(CGEventSourceStateID::HIDSystemState)
                .map_err(|_| anyhow!("Failed to create the CGEvent source"))?,
        );
        let session_source = SendEventSource(
            CGEventSource::new(CGEventSourceStateID::CombinedSessionState)
                .map_err(|_| anyhow!("Failed to create the session CGEvent source"))?,
        );
        Ok(Self {
            source,
            session_source,
            held_keys: HashSet::new(),
            held_flags: CGEventFlags::empty(),
            left_down: false,
            right_down: false,
            other_down: None,
            touchpad_last: None,
        })
    }

    /// The current pointer location (a fresh null CGEvent carries it).
    fn cursor(&self) -> CGPoint {
        CGEvent::new(self.source.0.clone())
            .ok()
            .map(|e| e.location())
            .unwrap_or(CGPoint { x: 0.0, y: 0.0 })
    }

    /// Posts a keyboard event for an evdev key code, maintaining held-key
    /// and modifier-flag state. `value` is the raw evdev value: 1 press,
    /// 0 release, 2 auto-repeat.
    fn key_event(&mut self, code: u16, value: i32) -> Result<()> {
        if is_touchpad_marker(code) {
            // BTN_TOUCH/BTN_TOOL_* bracket a contact: any transition means
            // the previous contact is over, so its position must not seed
            // the next contact's first delta (that would warp the cursor).
            self.touchpad_last = None;
            return Ok(());
        }
        let Some(vk) = map_key(code) else {
            if crate::device::key_traced(code) {
                tracing::info!(
                    "KEYTRACE macOS output: no mapping for key code {}, dropped",
                    code
                );
            } else {
                tracing::debug!("macOS output: no mapping for key code {}, dropped", code);
            }
            return Ok(());
        };
        let (down, repeat) = match value {
            1 => (true, false),
            2 => (true, true),
            _ => (false, false),
        };
        // Update state first so a modifier's own press carries its flag and
        // its release doesn't.
        if let Some(bit) = modifier_of(code) {
            if down {
                self.held_flags |= bit;
                self.held_keys.insert(code);
            } else {
                self.held_flags &= !bit;
                self.held_keys.remove(&code);
            }
        } else if down {
            self.held_keys.insert(code);
        } else {
            self.held_keys.remove(&code);
        }
        // Launcher-slot keycodes must come from the session source (see the
        // session_source field docs); everything else posts from the HID
        // source as before.
        let session = needs_session_source(vk);
        let source = if session {
            &self.session_source.0
        } else {
            &self.source.0
        };
        if crate::device::key_traced(code) {
            tracing::info!(
                "KEYTRACE macOS output: posting code {} as keycode {:#x} from {} source",
                code,
                vk,
                if session { "session" } else { "hid" }
            );
        }
        let event = CGEvent::new_keyboard_event(source.clone(), vk, down)
            .map_err(|_| anyhow!("CGEventCreateKeyboardEvent failed"))?;
        // Launcher-slot keys must keep the event's default flag bits:
        // stamping a zero mask (the no-modifier case) strips device-state
        // bits the WindowServer's special-keycode handler requires, which
        // leaves keycode 160 inert (verified on 26.6). They carry no
        // modifier semantics, so nothing is lost by leaving them alone.
        if !session {
            event.set_flags(self.held_flags);
        }
        if repeat {
            event.set_integer_value_field(EventField::KEYBOARD_EVENT_AUTOREPEAT, 1);
        }
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    /// Posts a mouse button event. `number`: 0=left, 1=right, 2=center,
    /// 3=side, 4=extra (the CGEvent button-number convention). Idempotent:
    /// a duplicate down (e.g. a stray button repeat on the wire) must not
    /// post twice — the window server counts downs into its click state,
    /// so a duplicate would synthesize double-clicks.
    fn button_event(&mut self, number: u16, down: bool) -> Result<()> {
        let already = match number {
            0 => self.left_down == down,
            1 => self.right_down == down,
            _ => self.other_down == if down { Some(number) } else { None },
        };
        if already {
            return Ok(());
        }
        let loc = self.cursor();
        let (ty, button) = match number {
            0 => (
                if down { CGEventType::LeftMouseDown } else { CGEventType::LeftMouseUp },
                CGMouseButton::Left,
            ),
            1 => (
                if down { CGEventType::RightMouseDown } else { CGEventType::RightMouseUp },
                CGMouseButton::Right,
            ),
            _ => (
                if down { CGEventType::OtherMouseDown } else { CGEventType::OtherMouseUp },
                CGMouseButton::Center,
            ),
        };
        let event = CGEvent::new_mouse_event(self.source.0.clone(), ty, loc, button)
            .map_err(|_| anyhow!("CGEventCreateMouseEvent failed"))?;
        if number >= 2 {
            event.set_integer_value_field(EventField::MOUSE_EVENT_BUTTON_NUMBER, number as i64);
        }
        event.post(CGEventTapLocation::HID);
        // Record state after posting so an early error leaves it untouched.
        match number {
            0 => self.left_down = down,
            1 => self.right_down = down,
            other => {
                self.other_down = if down { Some(other) } else { None };
            }
        }
        Ok(())
    }

    /// The event type a pointer move at the current button state should
    /// carry (dragged variants while a button is held).
    fn move_type(&self) -> (CGEventType, CGMouseButton) {
        if self.left_down {
            (CGEventType::LeftMouseDragged, CGMouseButton::Left)
        } else if self.right_down {
            (CGEventType::RightMouseDragged, CGMouseButton::Right)
        } else if self.other_down.is_some() {
            (CGEventType::OtherMouseDragged, CGMouseButton::Center)
        } else {
            (CGEventType::MouseMoved, CGMouseButton::Left)
        }
    }

    /// Moves the pointer by a delta in CG points.
    fn move_by(&self, dx: f64, dy: f64) -> Result<()> {
        if dx == 0.0 && dy == 0.0 {
            return Ok(());
        }
        let mut loc = self.cursor();
        loc.x += dx;
        loc.y += dy;
        let (ty, button) = self.move_type();
        let event = CGEvent::new_mouse_event(self.source.0.clone(), ty, loc, button)
            .map_err(|_| anyhow!("CGEventCreateMouseEvent failed"))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    /// Posts a wheel scroll in line units. Positive vertical = up, positive
    /// horizontal = right (matching the evdev REL_WHEEL/REL_HWHEEL signs).
    fn scroll(&self, vertical: i32, horizontal: i32) -> Result<()> {
        if vertical == 0 && horizontal == 0 {
            return Ok(());
        }
        let (count, w1, w2) = if horizontal == 0 {
            (1, vertical, 0)
        } else {
            (2, vertical, horizontal)
        };
        let event = CGEvent::new_scroll_event(
            self.source.0.clone(),
            ScrollEventUnit::LINE,
            count,
            w1,
            w2,
            0,
        )
        .map_err(|_| anyhow!("CGEventCreateScrollWheelEvent failed"))?;
        event.post(CGEventTapLocation::HID);
        Ok(())
    }

    /// Applies one batch of wire events. Motion deltas accumulate and post
    /// once per batch (a batch is one device frame); keys, buttons, and
    /// scrolls post as they come.
    fn apply_batch(&mut self, events: Vec<event::InputEvent>, class: Option<DeviceClass>) -> Result<()> {
        let _ = class; // routing is event-type driven; the class is advisory here
        let mut dx = 0f64;
        let mut dy = 0f64;
        // Touchpad contact position seen in this batch, and whether the
        // contact ended in it (tracking id -1 rides at the frame's end).
        let mut tp_x: Option<f64> = None;
        let mut tp_y: Option<f64> = None;
        let mut contact_ended = false;
        for e in events {
            if let Some(i) = e.inputi32 {
                if i.type_ == consts::EV_KEY {
                    match i.code {
                        consts::BTN_LEFT => self.button_event(0, i.value >= 1)?,
                        consts::BTN_RIGHT => self.button_event(1, i.value >= 1)?,
                        consts::BTN_MIDDLE => self.button_event(2, i.value >= 1)?,
                        0x113 => self.button_event(3, i.value >= 1)?, // BTN_SIDE
                        0x114 => self.button_event(4, i.value >= 1)?, // BTN_EXTRA
                        _ => self.key_event(i.code, i.value)?,
                    }
                } else if i.type_ == consts::EV_REL {
                    match i.code {
                        consts::REL_X => dx += i.value as f64,
                        consts::REL_Y => dy += i.value as f64,
                        consts::REL_WHEEL => self.scroll(i.value, 0)?,
                        consts::REL_HWHEEL => self.scroll(0, i.value)?,
                        consts::REL_WHEEL_HI_RES | consts::REL_HWHEEL_HI_RES => {
                            tracing::debug!(
                                "macOS output: hi-res wheel axis {} dropped (detents only)",
                                i.code
                            );
                        }
                        _ => {}
                    }
                } else if i.type_ == consts::EV_ABS
                    && i.code == consts::ABS_MT_TRACKING_ID
                    && i.value == -1
                {
                    contact_ended = true;
                }
                // EV_SYN and EV_MSC (MSC_SCAN et al.) carry no CGEvent
                // meaning.
            } else if let Some(f) = e.inputf64 {
                if f.type_ == consts::EV_ABS {
                    match f.code {
                        consts::ABS_X | consts::ABS_MT_POSITION_X => tp_x = Some(f.value),
                        consts::ABS_Y | consts::ABS_MT_POSITION_Y => tp_y = Some(f.value),
                        _ => {}
                    }
                }
            }
        }
        // Touchpad frames drive pointer MOTION, not absolute warps
        // (libinput semantics): the first frame of a contact only records,
        // later frames move by their scaled delta.
        if let (Some(x), Some(y)) = (tp_x, tp_y) {
            if let Some((lx, ly)) = self.touchpad_last {
                dx += (x - lx) * self.display_width();
                dy += (y - ly) * self.display_height();
            }
            self.touchpad_last = Some((x, y));
        }
        if contact_ended {
            self.touchpad_last = None;
        }
        self.move_by(dx, dy)
    }

    fn display_width(&self) -> f64 {
        CGDisplay::main().bounds().size.width.max(1.0)
    }

    fn display_height(&self) -> f64 {
        CGDisplay::main().bounds().size.height.max(1.0)
    }
}

#[async_trait]
impl OutputHandler for MacOutputHandler {
    async fn write(&mut self, event: Vec<event::InputEvent>) -> Result<()> {
        self.apply_batch(event, None)
    }

    async fn write_classed(
        &mut self,
        class: event::DeviceClass,
        events: Vec<event::InputEvent>,
    ) -> Result<()> {
        self.apply_batch(events, Some(class))
    }

    async fn release_all(&mut self) -> Result<()> {
        // Release keys first (with modifier flags collapsing as they go),
        // then buttons — the same order a client switch wants: nothing may
        // arrive on the new target held down.
        let held: Vec<u16> = self.held_keys.drain().collect();
        for code in held {
            self.key_event(code, 0)?;
        }
        self.held_flags = CGEventFlags::empty();
        if self.left_down {
            self.button_event(0, false)?;
        }
        if self.right_down {
            self.button_event(1, false)?;
        }
        if let Some(number) = self.other_down {
            self.button_event(number, false)?;
        }
        self.touchpad_last = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_table_is_sorted_and_unique() {
        // binary_search_by relies on both invariants.
        for pair in KEY_TABLE.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{} not before {}", pair[0].0, pair[1].0);
        }
    }

    #[test]
    fn spot_checks_of_the_mapping() {
        assert_eq!(map_key(30), Some(0x00)); // A
        assert_eq!(map_key(1), Some(0x35)); // ESC
        assert_eq!(map_key(125), Some(0x37)); // LEFTMETA -> Command
        assert_eq!(map_key(464), Some(0x3F)); // FN
        assert_eq!(map_key(580), Some(0xA0)); // APPSELECT -> NX Launchpad slot
        assert_eq!(map_key(120), Some(0xA0)); // SCALE -> same launcher slot
        assert_eq!(map_key(121), Some(0x5F)); // KPCOMMA -> kVK_JIS_KeypadComma (not 0x5E)
        assert_eq!(map_key(0x110), None); // BTN_LEFT is not a keyboard key
        assert_eq!(map_key(9999), None);
    }

    #[test]
    fn launcher_slot_posts_from_the_session_source() {
        assert!(needs_session_source(0xA0));
        assert!(!needs_session_source(0x00)); // plain A posts from the HID source
        assert!(!needs_session_source(0x76)); // F4 likewise
    }

    #[test]
    fn modifiers_map_to_their_flag_bits() {
        assert!(modifier_of(29).unwrap().contains(CGEventFlags::CGEventFlagControl));
        assert!(modifier_of(97).unwrap().contains(CGEventFlags::CGEventFlagControl));
        assert!(modifier_of(42).unwrap().contains(CGEventFlags::CGEventFlagShift));
        assert!(modifier_of(100).unwrap().contains(CGEventFlags::CGEventFlagAlternate));
        assert!(modifier_of(125).unwrap().contains(CGEventFlags::CGEventFlagCommand));
        assert!(modifier_of(464).unwrap().contains(CGEventFlags::CGEventFlagSecondaryFn));
        assert!(modifier_of(30).is_none()); // plain A
    }
}
