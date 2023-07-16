use anyhow::Result;
use async_std::task;
use tracing::{error, info};

use nikau::{logging, x11clipboard};

fn main() -> Result<()> {
    logging::init_logging();

    task::block_on(async {
        if let Err(e) = do_thing().await {
            error!("failed: {}", e);
        }
    });

    Ok(())
}

async fn do_thing() -> Result<()> {
    let mut reader = x11clipboard::reader::ClipboardReader::new().await?;
    let kind = "UTF8_STRING";
    let mut writer = x11clipboard::writer::ClipboardWriter::new().await?;
    let store_val = "hello xorg";

    x11_fetch(&mut reader, kind).await?;
    x11_store(&mut writer, "UTF8_STRING", store_val).await?;
    x11_fetch(&mut reader, kind).await?;
    Ok(())
}

async fn x11_store(
    clipboard: &mut x11clipboard::writer::ClipboardWriter,
    kind: &str,
    val: &str,
) -> Result<()> {
    clipboard.store([kind.to_string()], val).await?;
    info!("stored sample into clipboard");
    Ok(())
}

async fn x11_fetch(
    clipboard: &mut x11clipboard::reader::ClipboardReader,
    kind: &str,
) -> Result<()> {
    info!("waiting for new clipboard content...");
    let types = clipboard.types_wait().await?;
    if types.contains(&"image/png".to_string()) {
        info!("sweet");
    }
    info!("x11 clipboard types: {:?}", types);
    let val = clipboard.read(kind, false).await?;
    if val.len() > 256 {
        info!("x11 fetch clipboard: {} bytes", val.len());
    } else {
        info!(
            "x11 fetch clipboard: {} bytes: [{}]",
            val.len(),
            String::from_utf8_lossy(&val)
        );
    }
    Ok(())
}
