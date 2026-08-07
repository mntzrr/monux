//! Diagnostic: replays a synthetic touch stroke into a virtual touchpad
//! built exactly as the client builds it, and reports whether the
//! compositor's cursor moved. Isolates the client's emit path from the
//! network and from the capture side.

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use evdev::{AbsoluteAxisCode, EventType, InputEvent, KeyCode};
use monux::device::output::uinput::{touchpad, SCALED_DIM_MAX};

fn cursor_pos() -> String {
    Command::new("hyprctl")
        .arg("cursorpos")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("(hyprctl failed: {e})"))
}

fn abs(axis: AbsoluteAxisCode, value: i32) -> InputEvent {
    InputEvent::new(EventType::ABSOLUTE.0, axis.0, value)
}

fn key(code: KeyCode, value: i32) -> InputEvent {
    InputEvent::new(EventType::KEY.0, code.0, value)
}

fn main() -> anyhow::Result<()> {
    // "merged" replays the whole stroke as ONE frame (a single trailing
    // SYN_REPORT), reproducing what the client's pending_input coalescing
    // does to frames that arrive in the same network chunk.
    let merged = std::env::args().any(|a| a == "merged");
    let (mut device, _keys, _misc, _axes) = touchpad(std::process::id())?;
    println!(
        "virtual touchpad created ({}); waiting for the compositor to pick it up",
        if merged { "MERGED frames" } else { "per-frame SYN" }
    );
    sleep(Duration::from_millis(1500));

    let before = cursor_pos();
    if merged {
        let mid = SCALED_DIM_MAX / 2;
        let mut all = vec![
            abs(AbsoluteAxisCode::ABS_MT_TRACKING_ID, 1000),
            abs(AbsoluteAxisCode::ABS_MT_POSITION_X, mid),
            abs(AbsoluteAxisCode::ABS_MT_POSITION_Y, mid),
            key(KeyCode::BTN_TOUCH, 1),
            key(KeyCode::BTN_TOOL_FINGER, 1),
            abs(AbsoluteAxisCode::ABS_X, mid),
            abs(AbsoluteAxisCode::ABS_Y, mid),
        ];
        for step in 1..=40 {
            let x = mid + step * 400;
            let y = mid + step * 200;
            all.push(abs(AbsoluteAxisCode::ABS_MT_POSITION_X, x));
            all.push(abs(AbsoluteAxisCode::ABS_MT_POSITION_Y, y));
            all.push(abs(AbsoluteAxisCode::ABS_X, x));
            all.push(abs(AbsoluteAxisCode::ABS_Y, y));
        }
        all.push(abs(AbsoluteAxisCode::ABS_MT_TRACKING_ID, -1));
        all.push(key(KeyCode::BTN_TOUCH, 0));
        all.push(key(KeyCode::BTN_TOOL_FINGER, 0));
        // One emit() = one trailing SYN_REPORT, exactly like one write().
        device.emit(&all)?;
        sleep(Duration::from_millis(500));
        let after = cursor_pos();
        println!("cursor before: {before}");
        println!("cursor after:  {after}");
        println!(
            "{}",
            if before == after {
                "RESULT: merged frames produce NO cursor movement"
            } else {
                "RESULT: merged frames still moved the cursor"
            }
        );
        return Ok(());
    }

    // Touch down in the middle of the pad, then drag right and down. Values
    // are in the client's re-expanded range (see SCALED_DIM_MAX), which is
    // exactly what write() emits after rescaling a forwarded event.
    let mid = SCALED_DIM_MAX / 2;
    device.emit(&[
        abs(AbsoluteAxisCode::ABS_MT_TRACKING_ID, 1000),
        abs(AbsoluteAxisCode::ABS_MT_POSITION_X, mid),
        abs(AbsoluteAxisCode::ABS_MT_POSITION_Y, mid),
        key(KeyCode::BTN_TOUCH, 1),
        key(KeyCode::BTN_TOOL_FINGER, 1),
        abs(AbsoluteAxisCode::ABS_X, mid),
        abs(AbsoluteAxisCode::ABS_Y, mid),
    ])?;

    for step in 1..=40 {
        let x = mid + step * 400;
        let y = mid + step * 200;
        device.emit(&[
            abs(AbsoluteAxisCode::ABS_MT_POSITION_X, x),
            abs(AbsoluteAxisCode::ABS_MT_POSITION_Y, y),
            abs(AbsoluteAxisCode::ABS_X, x),
            abs(AbsoluteAxisCode::ABS_Y, y),
        ])?;
        sleep(Duration::from_millis(8));
    }

    device.emit(&[
        abs(AbsoluteAxisCode::ABS_MT_TRACKING_ID, -1),
        key(KeyCode::BTN_TOUCH, 0),
        key(KeyCode::BTN_TOOL_FINGER, 0),
    ])?;
    sleep(Duration::from_millis(500));

    let after = cursor_pos();
    println!("cursor before: {before}");
    println!("cursor after:  {after}");
    println!(
        "{}",
        if before == after {
            "RESULT: the cursor did NOT move — the emit path is broken locally"
        } else {
            "RESULT: the cursor moved — the emit path works on this machine"
        }
    );
    Ok(())
}
