use serde::{Deserialize, Serialize};

/// The protocol version sent from the client to the server.
/// If the message definitions below change, then this must change.
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
pub enum NetworkMessageV1 {
    /// Notification to client that stream has started or ended.
    /// This allows the client to init or clear any local state, or to indicate selection to the user.
    Switch(SwitchEventV1),

    /// An input event to be sent to a virtual device as indicated by the target.
    Input(InputEventV1),
}

impl std::fmt::Display for NetworkMessageV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            NetworkMessageV1::Switch(e) => e.fmt(f),
            NetworkMessageV1::Input(e) => e.fmt(f),
        }
    }
}

// SwitchEventV1

/// Notifies the client that it should enable or disable its virtual devices for input.
#[derive(Debug, Deserialize, Serialize)]
pub struct SwitchEventV1 {
    pub enabled: bool,
}

impl std::fmt::Display for SwitchEventV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(format!("SwitchEventV1(enabled={})", self.enabled).as_str())
    }
}

// InputEventV1

/// An input event to be written to a virtual device indicated by the target.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputEventV1 {
    pub target: EventTargetV1,
    pub i32event: Option<I32EventV1>,
    pub f64event: Option<F64EventV1>,
}

impl std::fmt::Display for InputEventV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let i32event = if let Some(evt) = &self.i32event {
            format!(", i32event={}", evt)
        } else {
            "".to_string()
        };
        let f64event = if let Some(evt) = &self.f64event {
            format!(", f64event={}", evt)
        } else {
            "".to_string()
        };
        f.write_str(
            format!(
                "InputEventV1(target={}{}{})",
                self.target, i32event, f64event
            )
            .as_str(),
        )
    }
}

/// The device type where the event should be sent on the client.
/// This maps to the virtual devices created by the client.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum EventTargetV1 {
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

impl std::fmt::Display for EventTargetV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            EventTargetV1::Keyboard => f.write_str("Keyboard"),
            EventTargetV1::Mouse => f.write_str("Mouse"),
            EventTargetV1::Touchpad => f.write_str("Touchpad"),
        }
    }
}

// I32EventV1

/// Equivalent to a uinput event for the client to emit locally.
/// Omits the timestamp since it isn't required.
#[derive(Debug, Deserialize, Serialize)]
pub struct I32EventV1 {
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

impl std::fmt::Display for I32EventV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(
            format!(
                "I32EventV1(type={}, code={}, value={})",
                self.type_, self.code, self.value
            )
            .as_str(),
        )
    }
}

impl I32EventV1 {
    pub fn from_evdev(e: evdev::InputEvent) -> I32EventV1 {
        I32EventV1 {
            type_: e.event_type().0,
            code: e.code(),
            value: e.value(),
        }
    }

    pub fn to_evdev(&self) -> evdev::InputEvent {
        evdev::InputEvent::new(evdev::EventType { 0: self.type_ }, self.code, self.value)
    }
}

// F64EventV1

/// Equivalent to a uinput event for the client to emit locally.
/// Omits the timestamp since it isn't required.
/// Used for absolute coordinates, with a scale of [0.0, 1.0] to be resized by the client.
#[derive(Debug, Deserialize, Serialize)]
pub struct F64EventV1 {
    pub type_: u16,
    pub code: u16,
    pub value: f64,
}

impl std::fmt::Display for F64EventV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(
            format!(
                "F64EventV1(type={}, code={}, value={})",
                self.type_, self.code, self.value
            )
            .as_str(),
        )
    }
}

impl F64EventV1 {
    pub fn from_evdev(e: evdev::InputEvent, min: i32, max: i32) -> F64EventV1 {
        F64EventV1 {
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
