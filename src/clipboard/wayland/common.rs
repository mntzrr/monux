//! Derived from common.rs here, with modifications:
//! https://github.com/YaLTeR/wl-clipboard-rs/blob/master/src/common.rs
//! This code is dual-licensed MIT/Apache-2.0

use wayland_client::globals::GlobalList;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Dispatch, Proxy, QueueHandle};
use wayland_protocols::ext::data_control::v1::client::ext_data_control_manager_v1::ExtDataControlManagerV1;
use wayland_protocols_wlr::data_control::v1::client::zwlr_data_control_manager_v1::ZwlrDataControlManagerV1;

use crate::clipboard::wayland::data_control;

pub fn clipboard_manager<S>(globals: &GlobalList, qh: &QueueHandle<S>) -> Option<data_control::Manager>
where
    S: Dispatch<ZwlrDataControlManagerV1, ()> + 'static,
    S: Dispatch<ExtDataControlManagerV1, ()>,
{
    // Try ext-data-control, then wlr-data-control, then None
    let ext_manager = globals.bind(qh, 1..=1, ()).ok().map(data_control::Manager::Ext);
    ext_manager.or_else(|| {
        globals.bind(qh, 1..=2, ()).ok().map(data_control::Manager::Zwlr)
    })
}

pub fn seats<S>(globals: &GlobalList, qh: &QueueHandle<S>) -> Vec<WlSeat>
where
    S: Dispatch<WlSeat, ()> + 'static,
{
    let registry = globals.registry();
    globals.contents().with_list(|globals| {
        globals
            .iter()
            .filter(|global| global.interface == WlSeat::interface().name && global.version >= 2)
            .map(|global| registry.bind(global.name, 2, qh, ()))
            .collect()
    })
}
