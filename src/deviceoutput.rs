use anyhow::Result;
use input_linux::{
    AbsoluteAxis,
    AbsoluteEvent,
    AbsoluteInfo,
    AbsoluteInfoSetup,
    EventKind,
    EventTime,
    InputEvent,
    InputId,
    InputProperty,
    Key,
    KeyEvent,
    KeyState,
    RelativeAxis,
    RelativeEvent,
    SynchronizeEvent,
    SynchronizeKind,
    UInputHandle,
};
use libc::O_NONBLOCK;

use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::thread;
use std::time::Duration;

const ZERO: EventTime = EventTime::new(0, 0);
pub const VIRTUAL_DEVICE_NAME_PREFIX: &str = "nikau virtual";

// TODO actually the evdev library has support for virtual devices, switch these demos to that:
// - https://docs.rs/evdev/latest/evdev/uinput/index.html
// - https://docs.rs/crate/evdev/latest/source/examples/virtual_keyboard.rs

fn create_device() -> Result<UInputHandle<fs::File>> {
    Ok(UInputHandle::new(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/uinput")?
    ))
}

fn setup_device(uhandle: &UInputHandle<fs::File>, name: &str, abs: &[AbsoluteInfoSetup]) -> Result<()> {
    let input_id = InputId {
        bustype: input_linux::sys::BUS_USB,
        vendor: 0x1234,
        product: 0x5678,
        version: 0,
    };
    let device_name = format!("{} {}", VIRTUAL_DEVICE_NAME_PREFIX, name);
    if let Ok(version) = uhandle.version() {
        if version >= input_linux::sys::UINPUT_VERSION as u32 {
            // "new" API circa 08/13/2015
            uhandle.create(&input_id, device_name.as_bytes(), 0, abs)?;

            // This call to sleep was not necessary on my machine,
            // but this translation is meant to match exactly
            thread::sleep(Duration::from_secs(1));

            return Ok(());
        }
    }
    // Version lookup failed, or version is old
    uhandle.create_legacy(&input_id, device_name.as_bytes(), 0, abs)?;

    // This call to sleep was not necessary on my machine,
    // but this translation is meant to match exactly
    thread::sleep(Duration::from_secs(1));

    Ok(())
}

pub fn mouse() -> Result<()> {
    let uhandle = create_device()?;

    // Input device: DLL0945:00 06CB:CDE6 Mouse @ /dev/input/event8, props={}, events={SYNCHRONIZATION, KEY, RELATIVE, MISC}, keys=Some({BTN_LEFT, BTN_RIGHT}), rel=Some({REL_X, REL_Y}), abs=None

    uhandle.set_evbit(EventKind::Key)?;
    uhandle.set_keybit(Key::ButtonLeft)?;

    uhandle.set_evbit(EventKind::Relative)?;
    uhandle.set_relbit(RelativeAxis::X)?;
    uhandle.set_relbit(RelativeAxis::Y)?;

    setup_device(&uhandle, "mouse", &[])?;

    for _ in 0..50 {
        let events = [
            *InputEvent::from(RelativeEvent::new(ZERO, RelativeAxis::X, 5)).as_raw(),
            *InputEvent::from(RelativeEvent::new(ZERO, RelativeAxis::Y, 5)).as_raw(),
            *InputEvent::from(SynchronizeEvent::new(ZERO, SynchronizeKind::Report, 0)).as_raw(),
        ];
        uhandle.write(&events)?;
        thread::sleep(Duration::from_micros(15_000));
    }

    // This call to sleep was not necessary on my machine,
    // but this translation is meant to match exactly
    thread::sleep(Duration::from_secs(1));
    uhandle.dev_destroy()?;

    Ok(())
}

pub fn keyboard() -> Result<()> {
    let uhandle = create_device()?;

    // Input device: AT Translated Set 2 keyboard @ /dev/input/event2, props={}, events={SYNCHRONIZATION, KEY, MISC, LED, REPEAT}, keys=Some({KEY_ESC, KEY_1, ...many entries..., KEY_BATTERY, KEY_UNKNOWN}), rel=None, abs=None

    uhandle.set_evbit(EventKind::Key)?;
    uhandle.set_keybit(Key::Space)?;

    setup_device(&uhandle, "keyboard", &[])?;

    for _ in 0..5 {
        let events = [
            *InputEvent::from(KeyEvent::new(ZERO, Key::Space, KeyState::PRESSED)).as_raw(),
            *InputEvent::from(SynchronizeEvent::new(ZERO, SynchronizeKind::Report, 0)).as_raw(),
            *InputEvent::from(KeyEvent::new(ZERO, Key::Space, KeyState::RELEASED)).as_raw(),
            *InputEvent::from(SynchronizeEvent::new(ZERO, SynchronizeKind::Report, 0)).as_raw(),
        ];
        uhandle.write(&events)?;
        thread::sleep(Duration::from_micros(15_000));
    }

    // This call to sleep was not necessary on my machine,
    // but this translation is meant to match exactly
    thread::sleep(Duration::from_secs(1));

    // NOTE: if the device is left with a key held down, the key repeat automatically stops when the device is destroyed
    uhandle.dev_destroy()?;

    Ok(())
}

pub fn touchpad() -> Result<()> {
    let uhandle = create_device()?;

    // Input device: DLL0945:00 06CB:CDE6 Touchpad @ /dev/input/event9, props={POINTER, BUTTONPAD}, events={SYNCHRONIZATION, KEY, ABSOLUTE, MISC}, keys=Some({BTN_LEFT, BTN_TOOL_FINGER, BTN_TOOL_QUINTTAP, BTN_TOUCH, BTN_TOOL_DOUBLETAP, BTN_TOOL_TRIPLETAP, BTN_TOOL_QUADTAP}), rel=None, abs=Some({ABS_X, ABS_Y, ABS_MT_SLOT, ABS_MT_POSITION_X, ABS_MT_POSITION_Y, ABS_MT_TOOL_TYPE, ABS_MT_TRACKING_ID})

    uhandle.set_propbit(InputProperty::ButtonPad)?;
    // Required for mouse movements to be recognized:
    uhandle.set_propbit(InputProperty::Pointer)?;

    uhandle.set_evbit(EventKind::Key)?;
    uhandle.set_keybit(Key::ButtonLeft)?;

    uhandle.set_evbit(EventKind::Absolute)?;
    uhandle.set_absbit(AbsoluteAxis::X)?;
    uhandle.set_absbit(AbsoluteAxis::Y)?;

    let abs = [
        AbsoluteInfoSetup {
            axis: AbsoluteAxis::X,
            info: AbsoluteInfo {
                value: 0,
                minimum: 0,
                maximum: 255,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            },
        },
        AbsoluteInfoSetup {
            axis: AbsoluteAxis::Y,
            info: AbsoluteInfo {
                value: 0,
                minimum: 0,
                maximum: 255,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            },
        },
    ];

    setup_device(&uhandle, "touchpad", &abs)?;

    for i in 100..200 {
        let events = [
            *InputEvent::from(AbsoluteEvent::new(ZERO, AbsoluteAxis::X, i)).as_raw(),
            *InputEvent::from(AbsoluteEvent::new(ZERO, AbsoluteAxis::Y, i)).as_raw(),
            *InputEvent::from(SynchronizeEvent::new(ZERO, SynchronizeKind::Report, 0)).as_raw(),
        ];
        uhandle.write(&events)?;
        thread::sleep(Duration::from_micros(15_000));
    }

    // This call to sleep was not necessary on my machine,
    // but this translation is meant to match exactly
    thread::sleep(Duration::from_secs(1));
    uhandle.dev_destroy()?;

    Ok(())
}
