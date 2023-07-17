use anyhow::Result;
use async_std::task;
use tracing::{error, info};

use nikau::{logging, x11clipboard};

fn main() -> Result<()> {
    logging::init_logging();

    task::block_on(async {
        if let Err(e) = do_thing().await {
            error!("failed: {:?}", e);
        }
    });

    Ok(())
}

async fn do_thing() -> Result<()> {
    let mut reader = x11clipboard::reader::ClipboardReader::new().await?;
    let type_ = "UTF8_STRING";
    let types = vec!["text/plain", "text/plain;charset=utf-8", "STRING", "TEXT", "COMPOUND_TEXT", type_];
    let (mut writer, fetch_rx) = x11clipboard::writer::ClipboardWriter::new().await?;
    task::spawn(async move {
        let store_val = "hello xorg";
        while let Ok(msg) = fetch_rx.recv().await {
            info!("serving clipboard fetch request: {}", msg.desired_type);
            msg.result.lock().await.replace(Ok(Some(x11clipboard::writer::ResolvedClipboardData{
                type_: msg.desired_type.clone(),
                data: store_val.clone().into()
            })));
            msg.result_barrier.wait().await;
        }
    });

    x11_fetch_types(&mut reader).await?;
    x11_fetch_data(&mut reader, type_).await?;

    x11_store_types(&mut writer, &types).await?;

    x11_fetch_types(&mut reader).await?;
    x11_fetch_data(&mut reader, type_).await?;
    x11_fetch_data(&mut reader, type_).await?;

    Ok(())
}

async fn x11_store_types(clipboard: &mut x11clipboard::writer::ClipboardWriter, types: &Vec<&str>) -> Result<()> {
    let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
    clipboard.store_types(types).await?;
    info!("stored types into clipboard");
    Ok(())
}

async fn x11_fetch_types(
    clipboard: &mut x11clipboard::reader::ClipboardReader,
) -> Result<()> {
    info!("waiting for new clipboard types...");
    let types = clipboard.types_wait().await?;
    if types.contains(&"image/png".to_string()) {
        info!("sweet");
    }
    info!("fetched clipboard types: {:?}", types);
    Ok(())
}

async fn x11_fetch_data(
    clipboard: &mut x11clipboard::reader::ClipboardReader,
    type_: &str,
) -> Result<()> {
    let val = clipboard.read(type_).await?;
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
