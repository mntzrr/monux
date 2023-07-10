use std::collections::BTreeMap;

use evdev::{AbsoluteAxisType, Device, EvdevEnum, EventType, InputEvent, InputEventKind, Key};
use tracing::{debug, trace};

use crate::messages;

#[derive(Debug, PartialEq)]
pub enum AxisScale {
    /// Values against the X axis
    X,
    /// Values against the Y axis
    Y,
    /// Continous values against other axes/scales
    OTHER,
    /// Values that aren't continuous
    DISCRETE,
    /// Not known axis values
    INVALID,
}

pub fn axis_scale_type(axis: AbsoluteAxisType) -> AxisScale {
    match axis {
        AbsoluteAxisType::ABS_X => AxisScale::X,
        AbsoluteAxisType::ABS_Y => AxisScale::Y,
        AbsoluteAxisType::ABS_Z => AxisScale::OTHER,
        AbsoluteAxisType::ABS_RX => AxisScale::X,
        AbsoluteAxisType::ABS_RY => AxisScale::Y,
        AbsoluteAxisType::ABS_RZ => AxisScale::OTHER,
        AbsoluteAxisType::ABS_THROTTLE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_RUDDER => AxisScale::OTHER,
        AbsoluteAxisType::ABS_WHEEL => AxisScale::OTHER,
        AbsoluteAxisType::ABS_GAS => AxisScale::OTHER,
        AbsoluteAxisType::ABS_BRAKE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT0X => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT0Y => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT1X => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT1Y => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT2X => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT2Y => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT3X => AxisScale::OTHER,
        AbsoluteAxisType::ABS_HAT3Y => AxisScale::OTHER,
        AbsoluteAxisType::ABS_PRESSURE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_DISTANCE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_TILT_X => AxisScale::OTHER,
        AbsoluteAxisType::ABS_TILT_Y => AxisScale::OTHER,
        AbsoluteAxisType::ABS_TOOL_WIDTH => AxisScale::OTHER,
        AbsoluteAxisType::ABS_VOLUME => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MISC => AxisScale::DISCRETE,
        AbsoluteAxisType::ABS_MT_SLOT => AxisScale::DISCRETE,
        AbsoluteAxisType::ABS_MT_TOUCH_MAJOR => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_TOUCH_MINOR => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_WIDTH_MAJOR => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_WIDTH_MINOR => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_ORIENTATION => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_POSITION_X => AxisScale::X,
        AbsoluteAxisType::ABS_MT_POSITION_Y => AxisScale::Y,
        AbsoluteAxisType::ABS_MT_TOOL_TYPE => AxisScale::DISCRETE,
        AbsoluteAxisType::ABS_MT_BLOB_ID => AxisScale::DISCRETE,
        AbsoluteAxisType::ABS_MT_TRACKING_ID => AxisScale::DISCRETE,
        AbsoluteAxisType::ABS_MT_PRESSURE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_DISTANCE => AxisScale::OTHER,
        AbsoluteAxisType::ABS_MT_TOOL_X => AxisScale::X,
        AbsoluteAxisType::ABS_MT_TOOL_Y => AxisScale::Y,
        _ => AxisScale::INVALID,
    }
}

pub struct DeviceInfo {
    pub target: messages::EventTargetV1,
    pub dims: BTreeMap<u16, (i32, i32)>,
}

pub fn device_info(device: &Device) -> DeviceInfo {
    let supported_events = device.supported_events();
    let mut dims = BTreeMap::new();
    let target = if supported_events.contains(EventType::ABSOLUTE) {
        // For each abs axis supported by the device, record its max and min
        // Result will be something like ABS_X(0,100), ABS_Y(0,70), ABS_MT_POSITION_X(0,100) ...
        if let Some(abs_axes) = device.supported_absolute_axes() {
            if let Ok(state) = device.get_abs_state() {
                let mut i: u16 = 0;
                for s in state {
                    let type_ = AbsoluteAxisType::from_index(i as usize);
                    if abs_axes.contains(type_) && axis_scale_type(type_) != AxisScale::INVALID {
                        dims.insert(i, (s.minimum, s.maximum));
                    }
                    i += 1;
                }
            }
        }
        messages::EventTargetV1::Touchpad
    } else if supported_events.contains(EventType::RELATIVE) {
        messages::EventTargetV1::Mouse
    } else {
        messages::EventTargetV1::Keyboard
    };
    log_device(device, &target, &dims);
    DeviceInfo { target, dims }
}

pub fn log_event(event: &InputEvent) -> String {
    let kind = match event.kind() {
        InputEventKind::Key(_key) => {
            // Replace the key with an X to avoid logging passwords etc
            InputEventKind::Key(Key::KEY_X)
        }
        k => k,
    };
    format!("{:?}={}", kind, event.value())
}

fn log_device(device: &Device, target: &messages::EventTargetV1, dims: &BTreeMap<u16, (i32, i32)>) {
    let device_name = device.name().unwrap_or("(Unnamed device)").to_string();
    let mut abs_entries = vec![];
    if let Some(abs_axes) = device.supported_absolute_axes() {
        if let Ok(state) = device.get_abs_state() {
            let mut i = 0;
            for s in state {
                let type_ = AbsoluteAxisType::from_index(i);
                if abs_axes.contains(type_) {
                    abs_entries.push(format!("{:?}:{:?}", type_, s));
                }
                i += 1;
            }
        }
    }
    debug!(
        "Input {} device {} details:
  props: {:?}
  misc: {:?}
  events: {:?}
  keys: {:?}
  leds: {:?}
  rel: {:?}
  abs: {:?}
  dims: {:?}",
        target,
        device_name,
        device.properties(),
        device.misc_properties(),
        device.supported_events(),
        device.supported_keys(),
        device.supported_leds(),
        device.supported_relative_axes(),
        abs_entries,
        dims,
    );
    // under trace, show evdev version of things too, but note that the abs values are missing:
    trace!("{}", device);
}
