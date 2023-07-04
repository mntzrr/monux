use serde::{Serialize, Deserialize};

/// The protocol version sent from the client to the server.
/// If the message definitions below change, then this must change.
pub const PROTOCOL_VERSION: &[u8] = b"v1";

/// A serialized message sent from the server to a client.
/// Changes to this signature likely require changing PROTOCOL_VERSION.
#[derive(Debug, Deserialize, Serialize)]
pub enum NetworkMessageV1 {
    Switch(SwitchEventV1),
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

/// Equivalent to a uinput event for the client to emit locally.
/// Omits the timestamp because client should just handle events ASAP.
#[derive(Debug, Deserialize, Serialize)]
pub struct InputEventV1 {
    type_: u16,
    code: u16,
    value: i32,
}

impl std::fmt::Display for InputEventV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(format!("InputEventV1(type={}, code={}, value={})", self.type_, self.code, self.value).as_str())
    }
}

impl InputEventV1 {
    pub fn from_evdev(e: evdev::InputEvent) -> InputEventV1 {
        InputEventV1 {
            type_: e.event_type().0,
            code: e.code(),
            value: e.value(),
        }
    }

    pub fn to_evdev(&self) -> evdev::InputEvent {
        evdev::InputEvent::new(
            evdev::EventType{0:self.type_},
            self.code,
            self.value,
        )
    }
}
