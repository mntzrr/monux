use std::time::Duration;

use anyhow::Result;
use tracing::{info, warn};
use x11_clipboard::Clipboard;

use nikau::logging;

fn main() -> Result<()> {
    logging::init_logging();

    let mut clipboard = Clipboard::new()?;
    if let Err(e) = x11_fetch(&mut clipboard) {
        warn!("x11 fetch failed: {:?}", e);
    }
    if let Err(e) = x11_store(&mut clipboard) {
        warn!("x11 store failed, skipping x11 fetch: {:?}", e);
    }
    if let Err(e) = x11_fetch(&mut clipboard) {
        warn!("x11 fetch failed: {:?}", e);
    }

    Ok(())
}

fn x11_store(clipboard: &mut Clipboard) -> Result<()> {
    let val = "Hello xorg";
    clipboard.store(
        clipboard.setter.atoms.primary,
        clipboard.setter.atoms.utf8_string,
        val.clone(),
    )?;
    clipboard.store(
        clipboard.setter.atoms.clipboard,
        clipboard.setter.atoms.utf8_string,
        val,
    )?;
    info!("stored");
    Ok(())
}

fn x11_fetch(clipboard: &mut Clipboard) -> Result<()> {
    let val = clipboard.load(
        clipboard.setter.atoms.primary,
        clipboard.setter.atoms.utf8_string,
        clipboard.setter.atoms.property,
        Duration::from_secs(3),
    )?;
    info!("x11 fetch primary: {}", String::from_utf8_lossy(&val));

    let val = clipboard.load(
        clipboard.setter.atoms.clipboard,
        clipboard.setter.atoms.utf8_string,
        clipboard.setter.atoms.property,
        Duration::from_secs(3),
    )?;
    info!("x11 fetch clipboard: {}", String::from_utf8_lossy(&val));
    Ok(())
}
