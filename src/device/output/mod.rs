#[cfg(target_os = "linux")]
pub mod uinput;
#[cfg(target_os = "macos")]
pub mod macos;

use crate::msgs::event;
use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::Context;
use async_trait::async_trait;

/// Builds the platform's input-injection backend.
///
/// - Linux: the three uinput virtual devices (keyboard, mouse, touchpad).
/// - macOS: CGEvent injection into the window server (see macos.rs), plus
///   display wake-on-input (`wake_display`).
///
/// Errors carry platform-appropriate remediation text (input group / uinput
/// on Linux, the Accessibility TCC permission on macOS).
pub fn create(wake_display: bool) -> Result<std::boxed::Box<dyn OutputHandler>> {
    #[cfg(target_os = "linux")]
    {
        // Injected input already reaches the kernel's input layer like
        // physical input; displays wake on their own.
        let _ = wake_display;
        Ok(Box::new(uinput::VirtualUInputDevices::new().context(
            "Failed to create virtual devices for output, possible solutions:
- Add your user to the 'input' group and log back in: 'sudo usermod -aG input $USER'
- Enable uinput and/or evdev in the kernel, check for /dev/uinput and /dev/input/
- As a fallback, run as root with 'sudo -E monux client ...' (-E keeps clipboard support)",
        )?))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::MacOutputHandler::new(wake_display)?))
    }
}

/// Name prefix to use on monux-created devices that should not be consumed by monux
pub const VIRTUAL_DEVICE_NAME_PREFIX: &str = "monux virtual";

/// The daemons hold their backend behind a Box (see create()); this forwards
/// the trait through the box so generic paths (client::run<O>) accept one.
#[async_trait]
impl OutputHandler for Box<dyn OutputHandler> {
    async fn write(&mut self, event: Vec<event::InputEvent>) -> Result<()> {
        (**self).write(event).await
    }

    async fn write_classed(
        &mut self,
        class: event::DeviceClass,
        events: Vec<event::InputEvent>,
    ) -> Result<()> {
        (**self).write_classed(class, events).await
    }

    async fn release_all(&mut self) -> Result<()> {
        (**self).release_all().await
    }
}

/// Trait for watching the addition and removal of devices from the machine
#[async_trait]
pub trait OutputHandler: Send {
    async fn write(&mut self, event: Vec<event::InputEvent>) -> Result<()>;

    /// Writes a frame whose source device class is known (protocol v17+),
    /// which settles destinations that event codes alone leave ambiguous —
    /// a mouse and a touchpad both have BTN_LEFT. A handler that doesn't
    /// distinguish devices forwards this to write.
    async fn write_classed(
        &mut self,
        class: event::DeviceClass,
        events: Vec<event::InputEvent>,
    ) -> Result<()>;

    /// Releases all keys/buttons currently held on the output devices.
    /// Used to avoid stuck keys when the input stream ends or moves to another machine.
    async fn release_all(&mut self) -> Result<()>;
}
