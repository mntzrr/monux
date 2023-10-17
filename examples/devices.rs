use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use evdev::{AbsoluteAxisType, EventType, InputEvent, Key};
use regex::Regex;
use tokio::sync::broadcast;
use tokio::task;
use tracing::{error, info, warn};

use nikau::device::{output, util, watch};
use nikau::logging;

struct StubHandler {}

impl watch::DeviceHandler for StubHandler {
    fn handle_device_stream(
        &mut self,
        mut stream: evdev::EventStream,
        _grab_rx: broadcast::Receiver<watch::GrabEvent>,
        _device_info: util::DeviceInfo,
    ) -> Result<watch::DeviceHandle> {
        let handle = tokio::spawn(async move {
            let device_name = stream
                .device()
                .name()
                .unwrap_or("(Unnamed device)")
                .to_string();
            loop {
                match stream.next_event().await {
                    Ok(event) => {
                        info!("Event for {}: {:?}", device_name, event);
                    }
                    Err(e) => {
                        warn!("Error event for {}, removing device: {:?}", device_name, e);
                    }
                }
            }
        });
        Ok(watch::DeviceHandle { handle })
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    logging::init_logging();

    let devices = match std::env::var("DEVICES") {
        Ok(val) => val
            .split(",")
            .map(|s| Regex::new(s).expect("Bad 'DEVICES' pattern"))
            .collect::<Vec<Regex>>(),
        Err(_e) => vec![],
    };

    let (grab_tx, _grab_rx) = broadcast::channel(32);
    let handler = task::spawn(async move {
        if let Err(e) = watch::watch_loop(StubHandler {}, grab_tx, devices).await {
            error!("Input device watch failure: {:?}", e);
        }
    });

    let pid = std::process::id();
    let mut keyboard =
        output::keyboard(pid).context("Failed to init virtual device, are you root?")?;
    let mut mouse = output::mouse(pid)?;
    let mut touchpad = output::touchpad(pid)?;

    // Sleep for a bit, otherwise events can be missed. Devices need a bit of time to come up.
    thread::sleep(Duration::from_secs(1));

    for _ in 0..50 {
        keyboard
            .emit(&[InputEvent::new(EventType::KEY, Key::KEY_R.code(), 1)])
            .unwrap();
        keyboard
            .emit(&[InputEvent::new(EventType::KEY, Key::KEY_R.code(), 0)])
            .unwrap();
    }

    for _ in 0..50 {
        mouse
            .emit(&[
                InputEvent::new(EventType::RELATIVE, evdev::RelativeAxisType::REL_X.0, 5),
                InputEvent::new(EventType::RELATIVE, evdev::RelativeAxisType::REL_Y.0, 5),
            ])
            .unwrap();
        thread::sleep(Duration::from_micros(5_000));
    }

    for i in 100..200 {
        // Position (i * 100) is scaled to fit within SCALED_DIM_MIN/SCALED_DIM_MAX
        touchpad.emit(&[
            InputEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_X.0, i * 100),
            InputEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_Y.0, i * 100),
        ])?;
        thread::sleep(Duration::from_micros(5_000));
    }

    handler.await?;
    bail!("Exited prematurely");
}
