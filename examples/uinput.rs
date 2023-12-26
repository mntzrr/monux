use std::collections::HashSet;
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use evdev::{AbsoluteAxisType, EventType, Key};
use regex::Regex;
use tokio::sync::broadcast;
use tokio::task;
use tracing::{error, info, warn};

use nikau::device::output::{uinput, OutputHandler};
use nikau::device::{handles, util, watch, GrabEvent};
use nikau::logging;
use nikau::msgs::event;

struct StubHandler {}

impl handles::DeviceHandler for StubHandler {
    fn handle_device_stream(
        &mut self,
        mut stream: evdev::EventStream,
        _grab_rx: Option<broadcast::Receiver<GrabEvent>>,
        _device_info: util::DeviceInfo,
    ) -> Result<handles::DeviceHandle> {
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
        Ok(handles::DeviceHandle { handle })
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
    let handles = handles::DeviceHandles::new(StubHandler {}, grab_tx, HashSet::<Key>::new());
    let handler = task::spawn(async move {
        if let Err(e) = watch::watch_loop(handles, devices).await {
            error!("Input device watch failure: {:?}", e);
        }
    });

    let mut devices = uinput::VirtualUInputDevices::new()
        .context("Failed to init virtual devices, are you root?")?;

    // Sleep for a bit, otherwise events can be missed. Devices need a bit of time to come up.
    thread::sleep(Duration::from_secs(1));

    for _ in 0..50 {
        devices
            .write(vec![from_evdev(evdev::InputEvent::new(
                EventType::KEY,
                Key::KEY_R.code(),
                1,
            ))])
            .await?;
        devices
            .write(vec![from_evdev(evdev::InputEvent::new(
                EventType::KEY,
                Key::KEY_R.code(),
                0,
            ))])
            .await?;
    }

    for _ in 0..50 {
        devices
            .write(vec![
                from_evdev(evdev::InputEvent::new(
                    EventType::RELATIVE,
                    evdev::RelativeAxisType::REL_X.0,
                    5,
                )),
                from_evdev(evdev::InputEvent::new(
                    EventType::RELATIVE,
                    evdev::RelativeAxisType::REL_Y.0,
                    5,
                )),
            ])
            .await?;
        thread::sleep(Duration::from_micros(5_000));
    }

    for i in 100..200 {
        devices
            .write(vec![
                from_evdev(evdev::InputEvent::new(
                    EventType::ABSOLUTE,
                    AbsoluteAxisType::ABS_X.0,
                    i,
                )),
                from_evdev(evdev::InputEvent::new(
                    EventType::ABSOLUTE,
                    AbsoluteAxisType::ABS_Y.0,
                    i,
                )),
            ])
            .await?;
        thread::sleep(Duration::from_micros(5_000));
    }

    handler.await?;
    bail!("Exited prematurely");
}

fn from_evdev(event: evdev::InputEvent) -> event::InputEvent {
    if event.event_type() == EventType::ABSOLUTE {
        event::InputEvent {
            inputi32: None,
            inputf64: Some(event::InputF64::from_evdev(event, 0, 200)),
        }
    } else {
        event::InputEvent {
            inputi32: Some(event::InputI32::from_evdev(event)),
            inputf64: None,
        }
    }
}
