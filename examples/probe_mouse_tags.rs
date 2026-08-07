//! Diagnostic: creates candidate virtual mice with different key sets and
//! reports how udev classifies each (`ID_INPUT_*`). Answers "which buttons
//! may the virtual mouse claim and still be tagged ID_INPUT_MOUSE?", which
//! decides what libinput will do with it.

use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use evdev::{AttributeSet, KeyCode, RelativeAxisCode};
use evdev::uinput::VirtualDevice;

fn tags_for(dev: &mut VirtualDevice) -> String {
    let nodes: Vec<_> = dev
        .enumerate_dev_nodes_blocking()
        .map(|nodes| {
            nodes
                .filter_map(|r| r.ok())
                .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("event")))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let Some(node) = nodes.first() else {
        return "(no event node)".to_string();
    };
    let out = Command::new("udevadm")
        .args(["info", "--query=property", &node.to_string_lossy()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let tags: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("ID_INPUT"))
        .collect();
    if tags.is_empty() {
        "(no ID_INPUT tags)".to_string()
    } else {
        tags.join(" ")
    }
}

fn build(name: &str, keys: AttributeSet<KeyCode>) -> anyhow::Result<VirtualDevice> {
    let mut axes = AttributeSet::<RelativeAxisCode>::new();
    for code in 0..(libc::REL_CNT as u16) {
        axes.insert(RelativeAxisCode(code));
    }
    Ok(VirtualDevice::builder()?
        .name(name)
        .with_keys(&keys)?
        .with_relative_axes(&axes)?
        .build()?)
}

fn keys_from(ranges: &[std::ops::RangeInclusive<u16>]) -> AttributeSet<KeyCode> {
    let mut keys = AttributeSet::<KeyCode>::new();
    for range in ranges {
        for code in range.clone() {
            keys.insert(KeyCode::new(code));
        }
    }
    keys
}

fn main() -> anyhow::Result<()> {
    // (a) today's set: every BTN_* except BTN_TOOL_*.
    let mut current = AttributeSet::<KeyCode>::new();
    for code in 1..libc::KEY_MAX as u16 {
        let key = KeyCode::new(code);
        let name = format!("{:?}", key);
        if name.starts_with("BTN_") && !name.starts_with("BTN_TOOL_") {
            current.insert(key);
        }
    }

    let candidates: Vec<(&str, AttributeSet<KeyCode>)> = vec![
        ("a: all BTN_* except BTN_TOOL_* (current)", current),
        ("b: mouse buttons only (0x110..=0x117)", keys_from(&[0x110..=0x117])),
        (
            "c: misc + mouse buttons",
            keys_from(&[0x100..=0x109, 0x110..=0x117]),
        ),
        (
            "d: misc + mouse + wheel buttons",
            keys_from(&[0x100..=0x109, 0x110..=0x117, 0x150..=0x151]),
        ),
        (
            "e: mouse buttons + gamepad block",
            keys_from(&[0x110..=0x117, 0x130..=0x13e]),
        ),
        (
            "f: mouse buttons + joystick block",
            keys_from(&[0x110..=0x117, 0x120..=0x12f]),
        ),
    ];

    let mut built = Vec::new();
    for (label, keys) in candidates {
        built.push((label, build(&format!("monux probe {label}"), keys)?));
    }
    // The real thing, as the client builds it.
    let (real_mouse, _, _, _) = monux::device::output::uinput::mouse(std::process::id())?;
    built.push(("REAL monux::mouse()", real_mouse));
    // One settle for all of them: udev needs a moment to process the adds.
    sleep(Duration::from_millis(1200));
    for (label, dev) in &mut built {
        println!("{label}\n    {}", tags_for(dev));
    }
    Ok(())
}
