use serde::{Deserialize, Serialize};

/// The protocol version sent from the client to the server.
/// This is compared on initial connection between client and server.
/// If the message definitions below change, then this should change.
pub const PROTOCOL_VERSION: u64 = 1;

/// An initial handshake message sent from the client to the server, and from the server to the client.
/// If either side doesn't support the provided version value, it can cut off the connection early.
/// The structure of this message shouldn't ever change as it breaks the bootstrap handshake.
#[derive(Debug, Deserialize, Serialize)]
pub struct VersionBootstrapMessage {
    pub version: u64,
}

/// A serialized message sent from the server to a client.
/// Changes to this signature likely require changing PROTOCOL_VERSION.
#[derive(Debug, Deserialize, Serialize)]
pub enum ServerMessage {
    /// Notification to client that the input stream has started or ended.
    /// This allows the client to init or clear any local state, or to indicate being selected to the user.
    Switch(SwitchEvent),

    /// An input event to be written to a virtual device on the client as indicated by the target.
    Input(InputEvent),
}

impl std::fmt::Display for ServerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ServerMessage::Switch(e) => e.fmt(f),
            ServerMessage::Input(e) => e.fmt(f),
        }
    }
}

// SwitchEvent

/// Notifies the client that it should enable or disable its virtual devices for input.
#[derive(Debug, Deserialize, Serialize)]
pub struct SwitchEvent {
    pub enabled: bool,
}

impl std::fmt::Display for SwitchEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(format!("SwitchEvent(enabled={})", self.enabled).as_str())
    }
}

// InputEvent

/// An input event to be written to a virtual device indicated by the target.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputEvent {
    pub target: EventTarget,
    /// For discrete unscaled values.
    pub inputi32: Option<InputI32>,
    /// For continuous values. This is scaled from 0.0 to 1.0.
    pub inputf64: Option<InputF64>,
}

impl std::fmt::Display for InputEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let inputi32 = if let Some(evt) = &self.inputi32 {
            format!(", inputi32={}", evt)
        } else {
            "".to_string()
        };
        let inputf64 = if let Some(evt) = &self.inputf64 {
            format!(", inputf64={}", evt)
        } else {
            "".to_string()
        };
        f.write_str(
            format!(
                "InputEvent(target={}{}{})",
                self.target, inputi32, inputf64
            )
            .as_str(),
        )
    }
}

/// The device type where the event should be sent on the client.
/// This maps to the virtual devices created by the client.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EventTarget {
    /// A keyboard device: events from uinput key devices (that aren't rel or abs) go here
    Keyboard,
    /// A mouse device: events from uinput rel devices go here
    Mouse,
    /// A touchpad device: events from uinput abs devices go here
    Touchpad,
    // Other devices (tablet, joystick?) may be added here someday, but I don't have any to test.
    // From uinput's perspective, they will be other rel/abs devices, but libinput detects them
    // based on the controls they advertise support for, and treats them differently.
    // For example, a 'tablet' is an abs device where touching the device immediately moves the
    // cursor to that coordinate location on screen.
}

impl std::fmt::Display for EventTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            EventTarget::Keyboard => f.write_str("Keyboard"),
            EventTarget::Mouse => f.write_str("Mouse"),
            EventTarget::Touchpad => f.write_str("Touchpad"),
        }
    }
}

// InputI32

/// Equivalent to a uinput event for the client to emit locally.
/// Omits the timestamp since it isn't required.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputI32 {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

impl std::fmt::Display for InputI32 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(
            format!(
                "InputI32(type={}, code={}, value={})",
                self.type_, self.code, self.value
            )
            .as_str(),
        )
    }
}

impl InputI32 {
    pub fn from_evdev(e: evdev::InputEvent) -> InputI32 {
        InputI32 {
            type_: e.event_type().0,
            code: e.code(),
            value: e.value(),
        }
    }

    pub fn to_evdev(&self) -> evdev::InputEvent {
        evdev::InputEvent::new(evdev::EventType { 0: self.type_ }, self.code, self.value)
    }
}

// InputF64

/// Equivalent to a uinput event for the client to emit locally.
/// Omits the timestamp since it isn't required.
/// Used for absolute coordinates, with a scale of [0.0, 1.0] to be resized by the client.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputF64 {
    pub type_: u16,
    pub code: u16,
    pub value: f64,
}

impl std::fmt::Display for InputF64 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(
            format!(
                "InputF64(type={}, code={}, value={})",
                self.type_, self.code, self.value
            )
            .as_str(),
        )
    }
}

impl InputF64 {
    pub fn from_evdev(e: evdev::InputEvent, min: i32, max: i32) -> InputF64 {
        InputF64 {
            type_: e.event_type().0,
            code: e.code(),
            // For example: min=-10, max=10, vali=5 -> valf=0.75
            value: ((e.value() - min) as f64) / ((max - min) as f64),
        }
    }

    pub fn to_evdev(&self, min: i32, max: i32) -> evdev::InputEvent {
        evdev::InputEvent::new(
            evdev::EventType { 0: self.type_ },
            self.code,
            // Inverse of from_evdev math:
            (self.value * ((max - min) as f64)) as i32 + min,
        )
    }
}
