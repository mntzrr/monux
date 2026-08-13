use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use evdev::{Device, EventType, KeyCode};
use notify::Watcher;
use regex::Regex;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::device::{handles, output, util};

#[derive(Debug)]
enum DeviceEventKind {
    Created,
    Deleted,
}

#[derive(Debug)]
struct DeviceEvent {
    pub kind: DeviceEventKind,
    pub path: PathBuf,
}

pub async fn watch_loop<H: handles::DeviceHandler>(
    mut device_handles: handles::DeviceHandles<H>,
    device_filters: Vec<Regex>,
    virtual_nodes: Vec<PathBuf>,
) -> Result<()> {
    // Start watch for new and removed devices BEFORE scanning current devices.
    // Unbounded deliberately: these events are rare (a hotplug, a monux
    // restart's virtual-device churn) and tiny, while DROPPING one is not
    // recoverable — a missed Created leaves a keyboard unwatched until the
    // next replug, and a missed Deleted leaks its reader task. A bounded
    // channel could only offer backpressure the notify callback cannot apply
    // (it is a sync callback on the inotify thread, so it must try_send).
    let (device_event_tx, mut device_event_rx): (
        mpsc::UnboundedSender<DeviceEvent>,
        mpsc::UnboundedReceiver<DeviceEvent>,
    ) = mpsc::unbounded_channel();
    let mut watcher = notify::RecommendedWatcher::new(
        move |res: Result<notify::Event, notify::Error>| match res {
            Ok(event) => send_device_events(event, &device_event_tx),
            Err(e) => warn!("filesystem watch error: {:?}", e),
        },
        notify::Config::default(),
    )
    .context("failed to init watcher")?;
    watcher.watch(
        std::path::Path::new("/dev/input"),
        notify::RecursiveMode::NonRecursive,
    )?;

    // Scan current devices
    for (path, device) in evdev::enumerate() {
        // enumerate() already filters for 'event*' filenames
        let device_info = util::DeviceInfo::new(&device, false);
        if !compatible_device(&device, &path, &device_info) {
            continue;
        }
        if !matches_filters(&device_filters, &device, &path, &device_info) {
            continue;
        }
        device_handles.add(&path, device)?;
    }
    if device_handles.is_empty() {
        bail!("Didn't find any compatible input devices to listen to.");
    }

    // Start handler to consume new/removed device events
    loop {
        if let Some(event) = device_event_rx.recv().await {
            handle_device_event(&mut device_handles, &device_filters, &virtual_nodes, event).await;
        } else {
            // Channel lost, exit
            return Ok(());
        }
    }
}

async fn handle_device_event<H: handles::DeviceHandler>(
    device_handles: &mut handles::DeviceHandles<H>,
    device_filters: &[Regex],
    virtual_nodes: &[PathBuf],
    event: DeviceEvent,
) {
    trace!("Device file event: {:?}", event);
    match event.kind {
        DeviceEventKind::Created => {
            if !compatible_path(&event.path) {
                return;
            }
            match open_device_with_retry(&event.path).await {
                Ok(device) => {
                    let device_info = util::DeviceInfo::new(&device, false);
                    if !compatible_device(&device, &event.path, &device_info) {
                        return;
                    }
                    if !matches_filters(device_filters, &device, &event.path, &device_info) {
                        return;
                    }
                    // Avoid exiting loop and aborting program if a newly added device fails
                    if let Err(e) = device_handles.add(&event.path, device) {
                        warn!(
                            "Failed to set up new device {}: {}",
                            event.path.to_string_lossy(),
                            e
                        );
                    }
                }
                Err(e) => {
                    // Avoid exiting loop and aborting program if a new device fails
                    warn!(
                        "Failed to init device {}: {}",
                        event.path.to_string_lossy(),
                        e
                    );
                }
            };
        }
        DeviceEventKind::Deleted => {
            if virtual_nodes.contains(&event.path) {
                // One of OUR virtual devices disappeared mid-session: any input
                // we emit now goes nowhere, which presents as dead keyboard/
                // mouse while devices are grabbed. There is no recovery path
                // short of recreating the devices, so make this loud.
                error!(
                    "Our own virtual device node {} vanished! Emitted input has nowhere to go until monux restarts",
                    event.path.to_string_lossy()
                );
            }
            if let Some(device_handle) = device_handles.remove(&event.path) {
                info!("Removing device: {}", event.path.to_string_lossy());
                device_handle.handle.abort();
            }
        }
    }
}

/// Opens a newly-appeared device node, tolerating the window between the
/// kernel creating the node (root:root 0600) and udev applying group/mode
/// permissions (root:input 0660). Without this, devices appearing while we
/// run — hot-plugged keyboards, but also the virtual devices of any monux
/// instance (including our own) — are skipped with a spurious Permission
/// denied and, in the hot-plug case, never picked up at all.
async fn open_device_with_retry(path: &Path) -> std::io::Result<Device> {
    const MAX_ATTEMPTS: u32 = 20;
    const RETRY_DELAY: Duration = Duration::from_millis(50);
    let mut attempt = 0;
    loop {
        match Device::open(path) {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && attempt < MAX_ATTEMPTS => {
                attempt += 1;
                tokio::time::sleep(RETRY_DELAY).await;
            }
            result => return result,
        }
    }
}

fn compatible_path(path: &Path) -> bool {
    // Filename should be 'event<N>', like 'event3' or 'event14'
    let is_match = path
        .file_name()
        .filter(|f| f.to_string_lossy().starts_with("event"))
        .is_some();
    if !is_match {
        debug!("Ignoring new device path: {}", path.display());
    }
    is_match
}

fn compatible_device(d: &Device, path: &Path, device_info: &util::DeviceInfo) -> bool {
    // Avoid a situation where we're consuming our own virtual output device, risking an infinite loop.
    // This could happen if client and server are running on the same machine (e.g. for testing)
    if let Some(name) = d.name() {
        if name.contains(output::VIRTUAL_DEVICE_NAME_PREFIX) {
            trace!(
                "Ignoring monux virtual device to avoid loopback problem: {} @ {}",
                name,
                path.display()
            );
            return false;
        }
    }
    // We care about these kinds of devices: keyboard, mouse, and touchpad
    let evts = d.supported_events();
    if evts.contains(EventType::ABSOLUTE)
        && d
            .supported_absolute_axes()
            .is_some_and(|axes| abs_axes_show_a_pointer(axes, d.supported_keys()))
    {
        // absolute with pointer evidence: a touchpad or touchscreen. Without
        // the evidence check an accelerometer (EV_ABS with ABS_X/Y/Z and no
        // keys) qualifies too, gets classified as a touchpad, and is grabbed
        // while a client is active — pointer jitter with no user input.
        true
    } else if evts.contains(EventType::RELATIVE) {
        // relative: probably a mouse
        true
    } else if evts.contains(EventType::KEY) {
        // probably a keyboard or utility keys
        if let Some(keys) = d.supported_keys() {
            // Some machines have special devices for the power/suspend button, we can ignore those.
            // If the device only supports one or more of these keys, then ignore the device.
            // If this button is pressed on the server, we shouldn't send the power event to clients.
            !keys
                .iter()
                .all(|key| key == KeyCode::KEY_POWER || key == KeyCode::KEY_SLEEP || key == KeyCode::KEY_WAKEUP)
        } else {
            // Key device without any keys? Skip it
            util::log_device_info(
                d,
                path,
                device_info,
                "Ignoring KEY device lacking supported keys",
                false,
            );
            false
        }
    } else if evts.contains(EventType::ABSOLUTE) {
        util::log_device_info(
            d,
            path,
            device_info,
            "Ignoring ABS device without pointer evidence (accelerometer?)",
            false,
        );
        false
    } else {
        // For example this might be an audio device
        util::log_device_info(
            d,
            path,
            device_info,
            "Ignoring device that isn't ABSOLUTE or RELATIVE or KEY",
            false,
        );
        false
    }
}

/// Whether a device's absolute axes look like a pointing device: a
/// multitouch position axis (touchpad/touchscreen), or single-touch ABS_X
/// together with any button/touch key. An accelerometer advertises
/// ABS_X/Y/Z and no keys at all, and must not qualify (see
/// compatible_device).
fn abs_axes_show_a_pointer(
    axes: &evdev::AttributeSetRef<evdev::AbsoluteAxisCode>,
    keys: Option<&evdev::AttributeSetRef<KeyCode>>,
) -> bool {
    axes.contains(evdev::AbsoluteAxisCode::ABS_MT_POSITION_X)
        || (axes.contains(evdev::AbsoluteAxisCode::ABS_X)
            && keys.is_some_and(|keys| {
                // BTN_0 (0x100) is the first of the kernel's BTN_* block:
                // any button or touch code counts as pointer evidence.
                keys.iter().any(|key| key.0 >= KeyCode::BTN_0.0)
            }))
}

fn matches_filters(
    name_filters: &[Regex],
    device: &Device,
    path: &Path,
    device_info: &util::DeviceInfo,
) -> bool {
    let device_name = device.name().unwrap_or("(Unnamed device)");
    if name_filters.is_empty() {
        return true;
    }
    let matches: Vec<&Regex> = name_filters
        .iter()
        .filter(|p| p.is_match(device_name))
        .collect();
    let is_match = !matches.is_empty();
    if !is_match {
        util::log_device_info(
            device,
            path,
            device_info,
            "Ignoring device that doesn't match --device name filters",
            true,
        );
    }
    is_match
}

fn send_device_events(event: notify::Event, device_event_tx: &mpsc::UnboundedSender<DeviceEvent>) {
    match event.kind {
        notify::EventKind::Create(notify::event::CreateKind::File) => {
            debug!("File created: {:?}", event);
            for path in event.paths {
                // The only failure left on an unbounded channel is a closed
                // receiver: the watch loop is gone, i.e. we are shutting down.
                if let Err(e) = device_event_tx.send(DeviceEvent {
                    kind: DeviceEventKind::Created,
                    path,
                }) {
                    debug!("Dropping device create event (watch loop gone): {:?}", e);
                }
            }
        }
        notify::EventKind::Remove(notify::event::RemoveKind::File) => {
            debug!("File deleted: {:?}", event);
            for path in event.paths {
                if let Err(e) = device_event_tx.send(DeviceEvent {
                    kind: DeviceEventKind::Deleted,
                    path,
                }) {
                    debug!("Dropping device delete event (watch loop gone): {:?}", e);
                }
            }
        }
        _ => trace!("Other filesystem event: {:?}", event),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use evdev::{AbsoluteAxisCode, AttributeSet};

    fn abs_set(codes: &[AbsoluteAxisCode]) -> AttributeSet<AbsoluteAxisCode> {
        let mut set = AttributeSet::new();
        for code in codes {
            set.insert(*code);
        }
        set
    }

    fn key_set(codes: &[KeyCode]) -> AttributeSet<KeyCode> {
        let mut set = AttributeSet::new();
        for code in codes {
            set.insert(*code);
        }
        set
    }

    /// An accelerometer advertises EV_ABS with ABS_X/Y/Z and no keys: no
    /// pointer evidence, so it must not become a monux device (it would be
    /// classified as a touchpad and grabbed, injecting pointer jitter).
    #[test]
    fn an_accelerometer_shows_no_pointer_evidence() {
        let axes = abs_set(&[
            AbsoluteAxisCode::ABS_X,
            AbsoluteAxisCode::ABS_Y,
            AbsoluteAxisCode::ABS_Z,
        ]);
        assert!(!abs_axes_show_a_pointer(&axes, None));
        let keys = key_set(&[]);
        assert!(!abs_axes_show_a_pointer(&axes, Some(&keys)));
    }

    /// A multitouch position axis is pointer evidence on its own (a
    /// touchscreen may advertise no keys at all).
    #[test]
    fn a_multitouch_position_axis_is_pointer_evidence() {
        let axes = abs_set(&[
            AbsoluteAxisCode::ABS_MT_POSITION_X,
            AbsoluteAxisCode::ABS_MT_POSITION_Y,
        ]);
        assert!(abs_axes_show_a_pointer(&axes, None));
    }

    /// Single-touch ABS_X counts only alongside a touch or button key
    /// (touchpads: BTN_TOUCH/BTN_TOOL_FINGER; absolute mice: BTN_LEFT).
    #[test]
    fn single_touch_abs_x_needs_a_touch_or_button_key() {
        let axes = abs_set(&[AbsoluteAxisCode::ABS_X, AbsoluteAxisCode::ABS_Y]);
        assert!(!abs_axes_show_a_pointer(&axes, None));
        for key in [KeyCode::BTN_TOUCH, KeyCode::BTN_TOOL_FINGER, KeyCode::BTN_LEFT] {
            let keys = key_set(&[key]);
            assert!(
                abs_axes_show_a_pointer(&axes, Some(&keys)),
                "{:?} should count as pointer evidence",
                key
            );
        }
        // Keys outside the BTN_* block (ordinary KEY_* codes) do not.
        let keys = key_set(&[KeyCode::KEY_A, KeyCode::KEY_POWER]);
        assert!(!abs_axes_show_a_pointer(&axes, Some(&keys)));
    }
}
