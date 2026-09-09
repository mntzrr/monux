//! Platform-neutral evdev constants.
//!
//! The wire protocol carries raw evdev `(type, code, value)` triples
//! (see event.rs), so every platform — including macOS, where the `evdev`
//! crate does not build — needs the numeric codes to classify and map
//! events. These are the canonical values from linux/input-event-codes.h,
//! copied from the evdev 0.13 crate's generated tables.
//!
//! Only the constants referenced outside the Linux `device/` modules are
//! listed here; device capture/injection on Linux keeps using the `evdev`
//! crate directly. A Linux-only test pins these values against the crate so
//! the copy cannot silently drift.

/// Event types (`evdev::EventType`).
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;
pub const EV_MSC: u16 = 0x04;

/// Relative axes (`evdev::RelativeAxisCode`).
pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_Z: u16 = 0x02;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;
pub const REL_WHEEL_HI_RES: u16 = 0x0b;
pub const REL_HWHEEL_HI_RES: u16 = 0x0c;

/// Absolute axes (`evdev::AbsoluteAxisCode`).
pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;
pub const ABS_MT_POSITION_X: u16 = 0x35;
pub const ABS_MT_POSITION_Y: u16 = 0x36;
pub const ABS_MT_TRACKING_ID: u16 = 0x39;

/// Miscellaneous event codes (`evdev::MiscCode`).
pub const MSC_SCAN: u16 = 0x04;

/// Mouse buttons (`evdev::KeyCode`).
pub const BTN_LEFT: u16 = 0x110;
pub const BTN_RIGHT: u16 = 0x111;
pub const BTN_MIDDLE: u16 = 0x112;

#[cfg(all(test, target_os = "linux"))]
mod parity_tests {
    // Pins the vendored values above against the evdev crate. Linux-only
    // because the crate itself doesn't build elsewhere — which is exactly
    // the situation these constants exist for.
    use super::*;
    use evdev::{AbsoluteAxisCode, EventType, KeyCode, MiscCode, RelativeAxisCode};

    #[test]
    fn event_types_match_evdev_crate() {
        assert_eq!(EV_SYN, EventType::SYNCHRONIZATION.0);
        assert_eq!(EV_KEY, EventType::KEY.0);
        assert_eq!(EV_REL, EventType::RELATIVE.0);
        assert_eq!(EV_ABS, EventType::ABSOLUTE.0);
        assert_eq!(EV_MSC, EventType::MISC.0);
    }

    #[test]
    fn relative_axes_match_evdev_crate() {
        assert_eq!(REL_X, RelativeAxisCode::REL_X.0);
        assert_eq!(REL_Y, RelativeAxisCode::REL_Y.0);
        assert_eq!(REL_Z, RelativeAxisCode::REL_Z.0);
        assert_eq!(REL_HWHEEL, RelativeAxisCode::REL_HWHEEL.0);
        assert_eq!(REL_WHEEL, RelativeAxisCode::REL_WHEEL.0);
        assert_eq!(REL_WHEEL_HI_RES, RelativeAxisCode::REL_WHEEL_HI_RES.0);
        assert_eq!(REL_HWHEEL_HI_RES, RelativeAxisCode::REL_HWHEEL_HI_RES.0);
    }

    #[test]
    fn absolute_axes_match_evdev_crate() {
        assert_eq!(ABS_X, AbsoluteAxisCode::ABS_X.0);
        assert_eq!(ABS_Y, AbsoluteAxisCode::ABS_Y.0);
        assert_eq!(ABS_MT_POSITION_X, AbsoluteAxisCode::ABS_MT_POSITION_X.0);
        assert_eq!(ABS_MT_POSITION_Y, AbsoluteAxisCode::ABS_MT_POSITION_Y.0);
        assert_eq!(ABS_MT_TRACKING_ID, AbsoluteAxisCode::ABS_MT_TRACKING_ID.0);
    }

    #[test]
    fn misc_and_buttons_match_evdev_crate() {
        assert_eq!(MSC_SCAN, MiscCode::MSC_SCAN.0);
        assert_eq!(BTN_LEFT, KeyCode::BTN_LEFT.0);
        assert_eq!(BTN_RIGHT, KeyCode::BTN_RIGHT.0);
        assert_eq!(BTN_MIDDLE, KeyCode::BTN_MIDDLE.0);
    }
}
