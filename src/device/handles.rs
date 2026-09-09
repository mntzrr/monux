use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use evdev::{Device, EventStream};
use tokio::sync::watch;
use tokio::task;
use tracing::debug;

use crate::device;
use crate::device::util;

pub struct DeviceHandle {
    pub handle: task::JoinHandle<()>,
}

/// Trait for watching the addition and removal of devices from the machine
pub trait DeviceHandler: Send + 'static {
    fn handle_device_stream(
        &mut self,
        events: EventStream,
        state_rx: watch::Receiver<device::GrabState>,
        device_info: util::DeviceInfo,
        class: device::DeviceClass,
    ) -> Result<DeviceHandle>;
}

pub struct DeviceHandles<H: DeviceHandler> {
    /// Devices which support one or more keys specified in client switch key combos.
    /// These devices are always grabbed at the server (unless input is paused) so
    /// that we can consistently grab/"swallow" the key combo input when the local
    /// server is the active target.
    always_grabbed_devices: HashMap<PathBuf, DeviceHandle>,

    /// Devices which don't support one or more key combo keys, such as mice.
    /// When the local server is the active target, monux ungrabs the device and allows
    /// its input to pass through directly.
    toggled_devices: HashMap<PathBuf, DeviceHandle>,

    handler: H,

    /// Method for subscribing devices to grab state broadcasts
    grab_tx: watch::Sender<device::GrabState>,

    /// All distinct keys used in client switch key combos, for internal accounting.
    all_combo_keys: HashSet<u16>,
}

impl<H: DeviceHandler> DeviceHandles<H> {
    pub fn new(
        handler: H,
        grab_tx: watch::Sender<device::GrabState>,
        all_combo_keys: HashSet<u16>,
    ) -> DeviceHandles<H> {
        DeviceHandles {
            always_grabbed_devices: HashMap::<PathBuf, DeviceHandle>::new(),
            toggled_devices: HashMap::<PathBuf, DeviceHandle>::new(),
            handler,
            grab_tx,
            all_combo_keys,
        }
    }

    pub(crate) fn add(&mut self, path: &Path, device: Device) -> Result<()> {
        let device_info = util::DeviceInfo::new(&device, false);
        util::log_device_info(&device, path, &device_info, "Listening to device", true);
        let supports_any_keys = supports_any_keys(&device, &self.all_combo_keys);
        if supports_any_keys {
            debug!(
                "Device supports one or more configured combo keys: {}",
                device.name().unwrap_or("(Unnamed device)")
            );
        }
        // Both device classes subscribe to the grab-state broadcast: a pause
        // must ungrab keyboards too, not just toggled devices.
        let class = if supports_any_keys {
            // This device supports one or more keys configured for client switch key combinations.
            // We should grab/route its input via monux so that we can omit keypresses from the combos.
            device::DeviceClass::Keyboard
        } else {
            // This device doesn't support keys used in key combinations (e.g. a mouse).
            // When the server is the active input, we can ungrab the device,
            // letting its input pass through directly.
            device::DeviceClass::Toggled
        };
        let join_handle = self.handler.handle_device_stream(
            start_device_stream(device, path)?,
            self.grab_tx.subscribe(),
            device_info,
            class,
        )?;
        let displaced = match class {
            device::DeviceClass::Keyboard => {
                self.always_grabbed_devices.insert(path.to_path_buf(), join_handle)
            }
            device::DeviceClass::Toggled => self.toggled_devices.insert(path.to_path_buf(), join_handle),
        };
        if let Some(old) = displaced {
            debug!("Aborting displaced reader task for device {}", path.display());
            old.handle.abort();
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, path: &PathBuf) -> Option<DeviceHandle> {
        if let Some(handle) = self.always_grabbed_devices.remove(path) {
            return Some(handle);
        }
        self.toggled_devices.remove(path)
    }

    /// Whether this path already has a reader task that is still running.
    /// A path with no entry at all needs a reader; a path whose reader task
    /// has finished also needs one — a finished task means the device went
    /// away and its removal was missed, so the path's eventN number may
    /// already have been recycled for different hardware (the periodic rescan
    /// re-adds such paths; add() aborts the finished handle as it displaces
    /// it). Only a live reader must be left alone.
    pub(crate) fn has_live_reader(&self, path: &Path) -> bool {
        let handle = self
            .always_grabbed_devices
            .get(path)
            .or_else(|| self.toggled_devices.get(path));
        match handle {
            Some(handle) => !handle.handle.is_finished(),
            None => false,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.always_grabbed_devices.is_empty() && self.toggled_devices.is_empty()
    }
}

fn supports_any_keys(d: &Device, all_combo_keys: &HashSet<u16>) -> bool {
    if let Some(device_keys) = d.supported_keys() {
        for key in all_combo_keys.iter() {
            if device_keys.contains(evdev::KeyCode::new(*key)) {
                return true;
            }
        }
    }
    false
}

fn start_device_stream(device: Device, path: &Path) -> Result<EventStream> {
    device.into_event_stream().with_context(|| {
        format!(
            "Failed to initialize async fd for device: {}",
            path.to_string_lossy()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::pending;
    use std::time::Duration;
    use tokio::time;

    struct StubHandler;

    impl DeviceHandler for StubHandler {
        fn handle_device_stream(
            &mut self,
            _events: EventStream,
            _state_rx: watch::Receiver<device::GrabState>,
            _device_info: util::DeviceInfo,
            _class: device::DeviceClass,
        ) -> Result<DeviceHandle> {
            Ok(DeviceHandle {
                handle: task::spawn(pending()),
            })
        }
    }

    fn test_handles() -> DeviceHandles<StubHandler> {
        let (grab_tx, _grab_rx) = watch::channel(device::GrabState {
            client_active: false,
            paused: false,
        });
        DeviceHandles::new(StubHandler, grab_tx, HashSet::new())
    }

    /// The rescan's add/skip decision (see has_live_reader): a path with no
    /// entry, or one whose reader task has already finished, needs a reader;
    /// a live reader must not be touched.
    #[tokio::test]
    async fn has_live_reader_distinguishes_live_finished_and_absent() {
        let mut handles = test_handles();
        let live = PathBuf::from("/dev/input/event1");
        let finished = PathBuf::from("/dev/input/event2");
        let absent = PathBuf::from("/dev/input/event3");

        handles
            .always_grabbed_devices
            .insert(live.clone(), DeviceHandle { handle: task::spawn(pending()) });
        let done = DeviceHandle { handle: task::spawn(async {}) };
        // Let the finished task actually run to completion before asserting.
        time::sleep(Duration::from_millis(50)).await;
        assert!(done.handle.is_finished());
        handles.toggled_devices.insert(finished.clone(), done);

        assert!(handles.has_live_reader(&live));
        assert!(!handles.has_live_reader(&finished));
        assert!(!handles.has_live_reader(&absent));
    }
}
