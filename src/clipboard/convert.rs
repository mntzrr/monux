use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use tokio::task;
use tracing::{debug, warn};

use crate::clipboard::limited;

/// Clipboard types for copying one or more files in a file manager.
/// In this case the payload is a list of paths, which doesn't work over the network.
const PATHS_TARGET_GNOME: &str = "x-special/gnome-copied-files";
const PATHS_TARGET_URIS: &str = "text/uri-list";

/// Clipboard types that should not be compressed by zstd (since it's a waste of time).
/// This is not meant to be an exhaustive list of compressed types, just ones often seen in clipboards.
const UNCOMPRESSIBLE_TYPES: &[&str] = &["image/png"];

/// data_type value for one or more files that are referenced by path.
/// Special handling to support cases where the clipboard is a set of local file paths:
/// The reader combines the file(s) as a single .zip payload to preserve their filenames.
/// The writer extracts the file(s) into a temp directory and advertises the paths in that directory.
const MONUX_COPIED_FILES_DATATYPE: &str = "application/zip+clipboard-paths";

/// data_type value for data that has been compressed using zstandard to improve clipboard transfer performance.
/// In practice this should be used for all payloads that aren't ZIPPED_FILES.
const MONUX_ZSTD_TARGET_DATATYPE: &str = "application/zstd";

/// Converts clipboard data received from a host application
/// to a payload and/or datatype suitable for sending to a Monux peer.
/// If the datatype String is None, then the data is being sent as-is.
pub async fn read(
    buf: Vec<u8>,
    max_compressed_size_bytes: u64,
    requested_type: &str,
) -> Result<(Vec<u8>, Option<String>)> {
    if requested_type == PATHS_TARGET_GNOME {
        let converted =
            task::spawn_blocking(move || read_gnome_file_paths(buf, max_compressed_size_bytes))
                .await??;
        Ok((
            converted,
            Some(MONUX_COPIED_FILES_DATATYPE.to_string()),
        ))
    } else if requested_type == PATHS_TARGET_URIS {
        let converted =
            task::spawn_blocking(move || read_uri_file_paths(buf, max_compressed_size_bytes))
                .await??;
        Ok((
            converted,
            Some(MONUX_COPIED_FILES_DATATYPE.to_string()),
        ))
    } else if buf.len() >= 100 && !UNCOMPRESSIBLE_TYPES.contains(&requested_type) {
        let requested_type = requested_type.to_string();
        let converted = task::spawn_blocking(move || {
            read_zstd(buf, max_compressed_size_bytes, &requested_type)
        })
        .await??;
        Ok((
            converted,
            Some(MONUX_ZSTD_TARGET_DATATYPE.to_string()),
        ))
    } else {
        // Don't bother compressing small or incompressible data
        Ok((buf, None))
    }
}

/// Whether a requested mime type is a file list, i.e. one whose payload names
/// local paths that a file manager will act on (copy, or MOVE for a "cut").
///
/// INVARIANT: a payload for one of these types must only ever reach a local
/// app after unpack_zip_payload has written the files under config_dir and the
/// paths have been rewritten to point there. read() always stamps
/// MONUX_COPIED_FILES_DATATYPE on them, so any other datatype — including a
/// missing one — is a peer contradicting its own protocol, and its raw bytes
/// would be a list of paths on OUR disk that we hand to the file manager. The
/// callers use this to refuse those payloads before they can be served.
pub fn is_file_list_type(requested_type: &str) -> bool {
    requested_type == PATHS_TARGET_GNOME || requested_type == PATHS_TARGET_URIS
}

/// Converts clipboard data received from another Monux peer over the network
/// to a payload suitable for sending to a host application.
pub async fn write(
    buf: Vec<u8>,
    max_uncompressed_size_bytes: u64,
    requested_type: &str,
    data_type: &str,
    config_dir: &Path,
) -> Result<Vec<u8>> {
    debug!("Converting clipboard data from data_type={} to requested_type={}", data_type, requested_type);
    // The file-list arms come first, and are followed by a bail for those
    // types under any other datatype: the zstd arm below binds requested_type
    // irrefutably, so ordering it first would let a peer satisfy a file-list
    // request with a zstd payload and have its decompressed bytes — a list of
    // paths on this machine — handed to the file manager unchanged (see
    // is_file_list_type).
    match (requested_type, data_type) {
        (PATHS_TARGET_GNOME, MONUX_COPIED_FILES_DATATYPE) => {
            let config_dir = config_dir.to_path_buf();
            let paths = task::spawn_blocking(move || {
                unpack_zip_payload(buf, max_uncompressed_size_bytes, &config_dir)
            })
            .await??;
            write_gnome_file_paths(paths)
        }
        (PATHS_TARGET_URIS, MONUX_COPIED_FILES_DATATYPE) => {
            let config_dir = config_dir.to_path_buf();
            let paths = task::spawn_blocking(move || {
                unpack_zip_payload(buf, max_uncompressed_size_bytes, &config_dir)
            })
            .await??;
            write_uri_file_paths(paths)
        }
        (PATHS_TARGET_GNOME | PATHS_TARGET_URIS, data_type) => {
            bail!(
                "Refusing clipboard file list for requested_type={} sent as data_type={}: only {} carries file lists",
                requested_type,
                data_type,
                MONUX_COPIED_FILES_DATATYPE
            )
        }
        (requested_type, MONUX_ZSTD_TARGET_DATATYPE) => {
            let requested_type = requested_type.to_string();
            task::spawn_blocking(move || {
                write_zstd(buf, max_uncompressed_size_bytes, &requested_type)
            })
            .await?
        }
        (requested_type, data_type) => {
            warn!("Clipboard data conversion from data_type={} to requested_type={} isn't supported, writing empty clipboard", data_type, requested_type);
            Ok(vec![])
        }
    }
}

/// Expected format depending on the operation:
///   copy\nfile:///path/to/file1\nfile:///path/to/file2
///   cut\n...
fn read_gnome_file_paths(buf: Vec<u8>, max_compressed_size_bytes: u64) -> Result<Vec<u8>> {
    let buf = String::from_utf8(buf)?;
    let mut lines: Vec<&str> = buf.split("\n").collect();
    // Remove the "cut"/"copy" operation line — but only when it IS one: some
    // sources omit it, and dropping an assumed first line would lose the
    // first URI of an operation-less payload.
    if lines.first().is_some_and(|first| *first == "cut" || *first == "copy") {
        lines.remove(0);
    }
    // Strip trailing empty entries from a trailing newline, mirroring
    // read_uri_file_paths — an empty entry fails url::Url::parse and would
    // abort the entire serve.
    if let Some(last) = lines.last() {
        if last.is_empty() {
            lines.pop();
        }
    }
    build_zip_payload(lines, max_compressed_size_bytes)
}

/// Inverse of read_gnome_file_paths
fn write_gnome_file_paths(paths: Vec<PathBuf>) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = vec![];
    buf.extend_from_slice(b"copy");
    for path in paths {
        let uri = url::Url::from_file_path(&path)
            .map_err(|_e| anyhow!("Failed to format path '{:?}' as uri", path))?;
        buf.extend_from_slice(format!("\n{}", uri).as_bytes());
    }
    Ok(buf)
}

/// Expected format:
///   file:///path/to/file1\r\nfile:///path/to/file2\r\n
fn read_uri_file_paths(buf: Vec<u8>, max_compressed_size_bytes: u64) -> Result<Vec<u8>> {
    let buf = String::from_utf8(buf)?;
    // Generic line boundaries: the spec says CRLF, but sources in the wild
    // send LF-only — splitting on "\r\n" alone turns such a payload into one
    // unparseable blob. Empty entries (a trailing blank line) are skipped by
    // build_zip_payload.
    let lines: Vec<&str> = buf.lines().collect();
    build_zip_payload(lines, max_compressed_size_bytes)
}

/// Inverse of read_uri_file_paths
fn write_uri_file_paths(paths: Vec<PathBuf>) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = vec![];
    for path in paths {
        let uri = url::Url::from_file_path(&path)
            .map_err(|_e| anyhow!("Failed to format path '{:?}' as uri", path))?;
        buf.extend_from_slice(format!("{}\r\n", uri).as_bytes());
    }
    Ok(buf)
}

/// Compresses the provided payload using zstd
fn read_zstd(
    mut buf: Vec<u8>,
    max_compressed_size_bytes: u64,
    requested_type: &str,
) -> Result<Vec<u8>> {
    let orig_len = buf.len();
    let mut limited = limited::LimitedCursor::new(max_compressed_size_bytes);
    zstd::stream::copy_encode(buf.as_slice(), &mut limited, 0)?;
    buf = limited.into_inner();
    debug!(
        "Compressed {}: {} => {} bytes",
        requested_type,
        orig_len,
        buf.len()
    );
    Ok(buf)
}

/// Decompresses the provided payload using zstd
fn write_zstd(
    mut buf: Vec<u8>,
    max_uncompressed_size_bytes: u64,
    requested_type: &str,
) -> Result<Vec<u8>> {
    let compressed_len = buf.len();
    let mut limited = limited::LimitedCursor::new(max_uncompressed_size_bytes);
    zstd::stream::copy_decode(buf.as_slice(), &mut limited)?;
    buf = limited.into_inner();
    debug!(
        "Decompressed {}: {} => {} bytes",
        requested_type,
        compressed_len,
        buf.len()
    );
    Ok(buf)
}

/// Sweeps stale clipboard-* unpack dirs under config_dir. Which dirs may go
/// depends entirely on WHOSE they are, because the id in the name is a
/// per-process counter and only its own process can interpret it:
///
/// - Ours: the generation window applies (keep the current unpack plus a few
///   prior ones, so a paste still referencing files from 2-3 unpacks ago isn't
///   deleted mid-paste). Our counter is the one those ids came from.
/// - Another LIVE monux sharing this config dir: never touched. Its counter
///   starts at 0 independently, so an id far behind ours can be that process's
///   just-created unpack dir — deleting it would lose the files being pasted.
/// - A DEAD owner (crash, restart, update): removed regardless of id. Nothing
///   can still reference those files — the wayland data source offering them
///   died with the process — and a window comparison would strand them
///   forever, since our counter restarts at 0 while theirs had run up.
///
/// The pid check must exempt our own pid: without that, `pid_is_running` is
/// trivially true for every dir WE created and a long-lived daemon never
/// reclaims a single one of them.
fn sweep_stale_unpack_dirs(config_dir: &Path, dir_id: usize) {
    let dir_prefix = "clipboard-";
    let generations_to_keep = 5;
    let our_pid = std::process::id();
    // The keep window as a checked subtraction: id < cutoff is swept. A
    // crafted clipboard-x-<usize::MAX> dir must not overflow the comparison
    // (id + generations_to_keep would panic in debug builds).
    let cutoff = dir_id.checked_sub(generations_to_keep);
    if let Ok(entries) = std::fs::read_dir(config_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(dir_prefix) else { continue };
            // suffix is "<pid>-<id>" — the id is after the last '-'.
            let Some((pid_str, id_str)) = suffix.rsplit_once('-') else { continue };
            let Ok(pid) = pid_str.parse::<u32>() else { continue };
            let Ok(id) = id_str.parse::<usize>() else { continue };
            if pid == our_pid {
                // Ours: only past the keep window.
                if !matches!(cutoff, Some(cutoff) if id < cutoff) {
                    continue;
                }
            } else if pid_is_running(pid) {
                // Another live monux's dir: its ids are not ours to judge.
                continue;
            }
            debug!("Removing stale temp directory: {}", entry.path().display());
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Whether a process with this pid exists. On probe failure (non-Linux, no
/// /proc) assume alive: never delete a possibly-live process's dirs.
fn pid_is_running(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Cap on the number of file entries in a clipboard zip payload.
const MAX_ZIP_ENTRIES: usize = 10_000;

/// Counter for giving each unpack its own unique temp directory.
static UNPACK_DIR_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Unzips a zip file to a temporary directory under config_dir and returns the list of files.
fn unpack_zip_payload(
    zipdata: Vec<u8>,
    mut max_uncompressed_size_bytes: u64,
    config_dir: &Path,
) -> Result<Vec<PathBuf>> {
    // Use a unique temp directory per unpack rather than wiping a shared one:
    // two unpacks may run at the same time.
    let dir_id = UNPACK_DIR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let clipboard_dir = config_dir.join(format!(
        "clipboard-{}-{}",
        std::process::id(),
        dir_id
    ));
    debug!("Creating temp directory: {}", clipboard_dir.display());
    std::fs::create_dir_all(&clipboard_dir)?;

    // Clean up old temp dirs (see sweep_stale_unpack_dirs).
    sweep_stale_unpack_dirs(config_dir, dir_id);

    // Unzip payload into temp directory
    let mut ziparchive = zip::read::ZipArchive::new(std::io::Cursor::new(zipdata))?;
    if ziparchive.len() > MAX_ZIP_ENTRIES {
        bail!(
            "Zip payload has {} entries, exceeding limit of {}",
            ziparchive.len(),
            MAX_ZIP_ENTRIES
        );
    }
    let mut files = vec![];
    for i in 0..ziparchive.len() {
        let mut zipfile = ziparchive.by_index(i)?;
        let mut destpath = clipboard_dir.clone();
        for component in Path::new(zipfile.name()).components() {
            if let std::path::Component::Normal(n) = component {
                destpath = destpath.join(n);
            }
        }
        debug!("Unpacking {} to {}", zipfile.name(), destpath.display());
        if destpath == clipboard_dir {
            bail!("Invalid path for file: {}", zipfile.name());
        }
        if let Some(parent) = destpath.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create temp directory: {}", parent.display())
            })?;
        }
        let outfile = File::create(&destpath)
            .with_context(|| format!("Failed to create temp file: {}", destpath.display()))?;
        let mut limited_outfile = limited::LimitedWrite::new(outfile, max_uncompressed_size_bytes);
        std::io::copy(&mut zipfile, &mut limited_outfile)
            .with_context(|| format!("Failed to unzip file: {}", destpath.display()))?;
        // Update remaining total max to reflect the bytes written by this file
        max_uncompressed_size_bytes = limited_outfile.remaining();
        files.push(destpath);
    }
    Ok(files)
}

fn build_zip_payload(file_uri_strs: Vec<&str>, max_compressed_size_bytes: u64) -> Result<Vec<u8>> {
    // Start by collecting all of the filenames, including any needed recursive scanning.
    let mut files_to_zip = vec![];
    for uri_str in file_uri_strs {
        if uri_str.is_empty() {
            continue;
        }
        if files_to_zip.len() >= MAX_ZIP_ENTRIES {
            bail!("Too many files in clipboard: exceeding limit of {}", MAX_ZIP_ENTRIES);
        }
        let uri = url::Url::parse(uri_str)?;
        let path = uri
            .to_file_path()
            .map_err(|_e| anyhow!("Invalid file entry: {}", uri))?;
        if path.is_dir() {
            // Recursively scan the directory, omitting the directory path itself
            for entry in walkdir::WalkDir::new(path).min_depth(1).into_iter() {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(e) => {
                        // Skip entries that vanished or can't be read mid-walk
                        warn!("Skipping unreadable directory entry: {}", e);
                        continue;
                    }
                };
                if entry.path().is_file() {
                    files_to_zip.push(entry.into_path());
                    if files_to_zip.len() >= MAX_ZIP_ENTRIES {
                        bail!("Too many files in clipboard: exceeding limit of {}", MAX_ZIP_ENTRIES);
                    }
                }
            }
        } else if path.is_file() {
            files_to_zip.push(path.to_path_buf());
        } else {
            warn!("Skipping path that isn't a file or directory: {:?}", path);
        }
    }
    // Then write the files to the zip file, aborting internally if the
    // compressed size gets too big, or if the UNCOMPRESSED total passes the
    // receive side's budget (main.rs derives it as 10x the configured
    // clipboard size): without that cap a huge compressible payload (e.g. a
    // 10GB sparse file) is fully read from disk on every paste request.
    let max_uncompressed_size_bytes = max_compressed_size_bytes.saturating_mul(10);
    let (uncompressed_len, zipdata) = zip_files(
        &files_to_zip,
        max_compressed_size_bytes,
        max_uncompressed_size_bytes,
    )?;
    debug!(
        "Zipped {} files ({} bytes) into {} bytes",
        files_to_zip.len(),
        uncompressed_len,
        zipdata.len()
    );
    Ok(zipdata)
}

fn zip_files(
    files_to_zip: &Vec<PathBuf>,
    max_compressed_size_bytes: u64,
    max_uncompressed_size_bytes: u64,
) -> Result<(usize, Vec<u8>)> {
    let mut uncompressed_len = 0;
    let mut cursor = limited::LimitedCursor::new(max_compressed_size_bytes);
    {
        let mut zipwriter = zip::ZipWriter::new(&mut cursor);
        let options =
            zip::write::FileOptions::<()>::default().compression_method(zip::CompressionMethod::ZSTD);
        let mut buf = vec![0; 65536];
        for file_to_zip in files_to_zip {
            let file_name = match file_to_zip.canonicalize() {
                Ok(path) => path.to_string_lossy().to_string(),
                Err(e) => {
                    // File vanished between listing and zipping: skip it instead of aborting
                    warn!("Skipping file that can't be read for zipping: {:?}: {}", file_to_zip, e);
                    continue;
                }
            };
            let mut file = match std::fs::File::open(file_to_zip) {
                Ok(file) => file,
                Err(e) => {
                    // File vanished between listing and zipping: skip it instead of aborting
                    warn!("Skipping file that can't be read for zipping: {:?}: {}", file_to_zip, e);
                    continue;
                }
            };
            zipwriter.start_file(file_name, options)?;
            loop {
                match file.read(&mut buf)? {
                    0 => {
                        // EOF
                        break;
                    }
                    len => {
                        uncompressed_len += len;
                        // Stop reading once the receive side's uncompressed
                        // budget is exceeded: the LimitedCursor only caps the
                        // COMPRESSED output, so without this check a huge
                        // compressible file is read to EOF per paste request.
                        if uncompressed_len as u64 > max_uncompressed_size_bytes {
                            bail!(
                                "Copied files exceed the maximum uncompressed clipboard size of {} bytes",
                                max_uncompressed_size_bytes
                            );
                        }
                        zipwriter.write_all(&buf[..len])?;
                    }
                }
            }
        }
        zipwriter.finish()?;
    }
    Ok((uncompressed_len, cursor.into_inner()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Big enough that no test payload gets anywhere near the caps.
    const GENEROUS_CAP: u64 = 100_000_000;

    fn temp_file(dir: &Path, name: &str, contents: &[u8]) -> PathBuf {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn file_uri(path: &Path) -> String {
        url::Url::from_file_path(path).unwrap().to_string()
    }

    /// Parses a write() gnome-paths result ("copy\nuri\nuri...") back into paths.
    fn gnome_output_paths(buf: &[u8]) -> Vec<PathBuf> {
        let text = String::from_utf8(buf.to_vec()).unwrap();
        let mut lines = text.split('\n');
        assert_eq!(lines.next(), Some("copy"));
        lines
            .map(|l| url::Url::parse(l).unwrap().to_file_path().unwrap())
            .collect()
    }

    /// Parses a write() uri-list result ("uri\r\nuri\r\n") back into paths.
    fn uri_list_output_paths(buf: &[u8]) -> Vec<PathBuf> {
        let text = String::from_utf8(buf.to_vec()).unwrap();
        // Every uri-list line is CRLF-terminated, including the last.
        assert!(text.ends_with("\r\n"));
        text.split("\r\n")
            .filter(|l| !l.is_empty())
            .map(|l| url::Url::parse(l).unwrap().to_file_path().unwrap())
            .collect()
    }

    /// Builds a zip payload in-memory with the given entry names and contents,
    /// bypassing the path canonicalization zip_files does (so traversal entries
    /// can be tested).
    fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(vec![]);
        {
            let mut zipwriter = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, contents) in entries {
                zipwriter.start_file(*name, options).unwrap();
                zipwriter.write_all(contents).unwrap();
            }
            zipwriter.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[tokio::test]
    async fn zstd_roundtrip_text_payload() {
        let text = "monux clipboard text — unicode ✓ ünïcödé\n".repeat(100);
        let original = text.into_bytes();
        assert!(original.len() >= 100);

        let (payload, data_type) = read(original.clone(), GENEROUS_CAP, "text/plain")
            .await
            .unwrap();
        // The wrapper datatype marks the payload as zstd-compressed, and the
        // repetitive text actually got smaller.
        assert_eq!(data_type.as_deref(), Some(MONUX_ZSTD_TARGET_DATATYPE));
        assert!(payload.len() < original.len());

        let restored = write(
            payload,
            GENEROUS_CAP,
            "text/plain",
            &data_type.unwrap(),
            &PathBuf::from("/nonexistent"),
        )
        .await
        .unwrap();
        assert_eq!(restored, original);
    }

    #[tokio::test]
    async fn zstd_roundtrip_binary_payload() {
        let original: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let (payload, data_type) = read(original.clone(), GENEROUS_CAP, "application/octet-stream")
            .await
            .unwrap();
        assert_eq!(data_type.as_deref(), Some(MONUX_ZSTD_TARGET_DATATYPE));

        let restored = write(
            payload,
            GENEROUS_CAP,
            "application/octet-stream",
            &data_type.unwrap(),
            &PathBuf::from("/nonexistent"),
        )
        .await
        .unwrap();
        assert_eq!(restored, original);
    }

    #[tokio::test]
    async fn uncompressible_type_passes_through_uncompressed() {
        // Compressing an already-compressed format is a waste of time.
        let png: Vec<u8> = (0..=255u8).cycle().take(500).collect();
        let (payload, data_type) = read(png.clone(), GENEROUS_CAP, "image/png").await.unwrap();
        assert_eq!(data_type, None);
        assert_eq!(payload, png);
    }

    #[tokio::test]
    async fn small_payload_passes_through_uncompressed() {
        // Under the 100-byte floor, compression doesn't pay for itself.
        let tiny = b"a small clipboard".to_vec();
        let (payload, data_type) = read(tiny.clone(), GENEROUS_CAP, "text/plain").await.unwrap();
        assert_eq!(data_type, None);
        assert_eq!(payload, tiny);
    }

    #[tokio::test]
    async fn compressed_payload_over_cap_errors() {
        // The LimitedCursor must error rather than write past the cap.
        let payload = "some text that will be compressed".repeat(20).into_bytes();
        assert!(read(payload, 4, "text/plain").await.is_err());
    }

    #[tokio::test]
    async fn decompressed_payload_over_cap_errors() {
        let original = "some text that will be compressed".repeat(20).into_bytes();
        let (compressed, data_type) = read(original.clone(), GENEROUS_CAP, "text/plain")
            .await
            .unwrap();
        // Decompressing with a cap smaller than the original errors instead
        // of producing a truncated clipboard.
        assert!(
            write(
                compressed,
                (original.len() - 1) as u64,
                "text/plain",
                &data_type.unwrap(),
                &PathBuf::from("/nonexistent"),
            )
            .await
            .is_err()
        );
    }

    /// A full file-clipboard round trip through one of the paths formats:
    /// source files -> zip payload -> unpack to a fresh dir -> paths output.
    /// Covers spaces and percent signs in filenames (URL encoding), directory
    /// recursion, and byte-exact content preservation.
    async fn file_paths_roundtrip(paths_target: &str) {
        let src = tempfile::tempdir().unwrap();
        let hello = temp_file(src.path(), "hello.txt", b"hello world");
        let spaced = temp_file(
            src.path(),
            "dir with space/100% certain.txt",
            b"bytes \x00\x01\x02 here",
        );
        let nested = temp_file(src.path(), "subdir/nested/deep.txt", b"deep content");

        let input = match paths_target {
            PATHS_TARGET_GNOME => format!(
                "copy\n{}\n{}\n{}",
                file_uri(&hello),
                file_uri(&spaced),
                file_uri(src.path().join("subdir").as_path())
            )
            .into_bytes(),
            PATHS_TARGET_URIS => format!(
                "{}\r\n{}\r\n{}\r\n",
                file_uri(&hello),
                file_uri(&spaced),
                file_uri(src.path().join("subdir").as_path())
            )
            .into_bytes(),
            other => panic!("unexpected paths target: {}", other),
        };

        let (zip_payload, data_type) = read(input, GENEROUS_CAP, paths_target).await.unwrap();
        assert_eq!(
            data_type.as_deref(),
            Some(MONUX_COPIED_FILES_DATATYPE)
        );

        let unpack_root = tempfile::tempdir().unwrap();
        let output = write(
            zip_payload,
            GENEROUS_CAP,
            paths_target,
            &data_type.unwrap(),
            unpack_root.path(),
        )
        .await
        .unwrap();

        let paths = match paths_target {
            PATHS_TARGET_GNOME => gnome_output_paths(&output),
            PATHS_TARGET_URIS => uri_list_output_paths(&output),
            other => panic!("unexpected paths target: {}", other),
        };

        // Three files (the directory was scanned recursively), all unpacked
        // under the target dir, with original filenames and exact contents.
        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(path.starts_with(unpack_root.path()));
        }
        let by_name: std::collections::HashMap<_, _> = paths
            .iter()
            .map(|p| (p.file_name().unwrap().to_str().unwrap().to_string(), p))
            .collect();
        assert_eq!(
            std::fs::read(by_name["hello.txt"]).unwrap(),
            b"hello world"
        );
        // The '%' and spaces survived the URL decode on both ends.
        assert_eq!(
            std::fs::read(by_name["100% certain.txt"]).unwrap(),
            b"bytes \x00\x01\x02 here"
        );
        // The recursively scanned file matches its source byte-for-byte.
        assert_eq!(
            std::fs::read(by_name["deep.txt"]).unwrap(),
            std::fs::read(&nested).unwrap()
        );
    }

    #[tokio::test]
    async fn gnome_copied_files_roundtrip() {
        file_paths_roundtrip(PATHS_TARGET_GNOME).await;
    }

    #[tokio::test]
    async fn uri_list_roundtrip() {
        file_paths_roundtrip(PATHS_TARGET_URIS).await;
    }

    #[test]
    fn gnome_parse_skips_cut_copy_line() {
        // "cut" is handled the same as "copy" on the read side.
        let src = tempfile::tempdir().unwrap();
        let file = temp_file(src.path(), "a.txt", b"a");
        let zip = read_gnome_file_paths(
            format!("cut\n{}", file_uri(&file)).into_bytes(),
            GENEROUS_CAP,
        )
        .unwrap();
        let unpack_root = tempfile::tempdir().unwrap();
        let paths = unpack_zip_payload(zip, GENEROUS_CAP, unpack_root.path())
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(std::fs::read(&paths[0]).unwrap(), b"a");
    }

    #[test]
    fn gnome_payload_without_operation_line_keeps_first_uri() {
        // Some sources omit the cut/copy line: the first URI must survive
        // (it used to be dropped as an assumed operation line).
        let src = tempfile::tempdir().unwrap();
        let a = temp_file(src.path(), "a.txt", b"a");
        let b = temp_file(src.path(), "b.txt", b"b");
        let zip = read_gnome_file_paths(
            format!("{}\n{}", file_uri(&a), file_uri(&b)).into_bytes(),
            GENEROUS_CAP,
        )
        .unwrap();
        let unpack_root = tempfile::tempdir().unwrap();
        let paths = unpack_zip_payload(zip, GENEROUS_CAP, unpack_root.path())
            .unwrap();
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn uri_list_accepts_lf_only_and_mixed_endings() {
        // The spec's CRLF is not universal: LF-only input must parse as two
        // URIs, not one unparseable blob.
        let src = tempfile::tempdir().unwrap();
        let a = temp_file(src.path(), "a.txt", b"a");
        let b = temp_file(src.path(), "b.txt", b"b");
        for payload in [
            format!("{}\n{}\n", file_uri(&a), file_uri(&b)),
            format!("{}\r\n{}\n", file_uri(&a), file_uri(&b)),
            format!("{}\r\n{}\r\n", file_uri(&a), file_uri(&b)),
        ] {
            let zip = read_uri_file_paths(payload.into_bytes(), GENEROUS_CAP).unwrap();
            let unpack_root = tempfile::tempdir().unwrap();
            let paths = unpack_zip_payload(zip, GENEROUS_CAP, unpack_root.path())
                .unwrap();
            assert_eq!(paths.len(), 2);
        }
    }

    #[test]
    fn sweep_reclaims_our_old_dirs_and_dead_owners_but_spares_live_peers() {
        let root = tempfile::tempdir().unwrap();
        let plant = |name: String| {
            let dir = root.path().join(name);
            std::fs::create_dir_all(&dir).unwrap();
            dir
        };
        // A pid guaranteed dead: spawn and reap a child, then use its pid.
        // (Reaping matters: /proc/<pid> still exists for an unreaped zombie.)
        let dead_pid = {
            let mut child = std::process::Command::new("sh")
                .arg("-c")
                .arg("exit 0")
                .spawn()
                .unwrap();
            let pid = child.id();
            child.wait().unwrap();
            pid
        };
        // A pid guaranteed alive and NOT ours, standing in for a second monux
        // process sharing this config dir. Killed after the sweep.
        let mut live_child = std::process::Command::new("sh")
            .arg("-c")
            .arg("sleep 30")
            .spawn()
            .unwrap();
        let other_live_pid = live_child.id();
        let our_pid = std::process::id();

        let ours_old = plant(format!("clipboard-{}-0", our_pid));
        let ours_recent = plant(format!("clipboard-{}-9", our_pid));
        let ours_crafted_max = plant(format!("clipboard-{}-{}", our_pid, usize::MAX));
        let other_live_old = plant(format!("clipboard-{}-0", other_live_pid));
        let dead_old = plant(format!("clipboard-{}-0", dead_pid));
        let dead_recent = plant(format!("clipboard-{}-9", dead_pid));
        let dead_crafted_max = plant(format!("clipboard-{}-{}", dead_pid, usize::MAX));
        let malformed = plant("clipboard-x-y".to_string());
        let unrelated = plant("some-other-dir".to_string());

        sweep_stale_unpack_dirs(root.path(), 10);

        let _ = live_child.kill();
        let _ = live_child.wait();

        // OURS, past the keep window: reclaimed. Exempting our own pid from
        // the liveness check is the whole point — `pid_is_running` is
        // trivially true for us, so without it a running daemon never deletes
        // any dir it created, and every pasted file accumulates forever.
        assert!(!ours_old.exists());
        // Ours, inside the window: a paste may still reference it.
        assert!(ours_recent.exists());
        // A crafted id must not overflow the window math (panic in debug):
        // usize::MAX is never < cutoff, so it is kept.
        assert!(ours_crafted_max.exists());
        // Another LIVE monux's dir: its counter is independent of ours, so its
        // id says nothing about age here — never touched, at any id.
        assert!(other_live_old.exists());
        // A DEAD owner's dirs go regardless of id: nothing can reference them,
        // and our counter restarts at 0, so a window comparison would strand
        // everything a previous run left behind.
        assert!(!dead_old.exists());
        assert!(!dead_recent.exists());
        assert!(!dead_crafted_max.exists());
        // Unparseable names and unrelated dirs are left alone.
        assert!(malformed.exists());
        assert!(unrelated.exists());
    }

    #[test]
    fn unpack_sanitizes_traversal_and_absolute_entries() {
        let unpack_root = tempfile::tempdir().unwrap();
        let zip = build_test_zip(&[
            ("../escape.txt", b"evil"),
            ("/absolute/path.txt", b"absolute"),
            ("ok.txt", b"fine"),
        ]);
        let paths = unpack_zip_payload(zip, GENEROUS_CAP, unpack_root.path())
            .unwrap();

        // Every entry was unpacked INSIDE the temp dir: the Normal-components
        // guard drops ParentDir/RootDir components, so traversal attempts land
        // harmlessly within the unpack dir instead of escaping it.
        assert_eq!(paths.len(), 3);
        for path in &paths {
            assert!(path.starts_with(unpack_root.path()));
        }
        assert!(
            !unpack_root
                .path()
                .parent()
                .unwrap()
                .join("escape.txt")
                .exists()
        );
        let by_name: std::collections::HashMap<_, _> = paths
            .iter()
            .map(|p| (p.file_name().unwrap().to_str().unwrap().to_string(), p))
            .collect();
        assert_eq!(std::fs::read(by_name["escape.txt"]).unwrap(), b"evil");
        assert_eq!(std::fs::read(by_name["path.txt"]).unwrap(), b"absolute");
        assert_eq!(std::fs::read(by_name["ok.txt"]).unwrap(), b"fine");
    }

    #[test]
    fn unpack_rejects_entry_with_no_normal_components() {
        let unpack_root = tempfile::tempdir().unwrap();
        // An entry whose path is pure traversal has no Normal components at
        // all: it would unpack onto the unpack dir itself, so it is rejected.
        let zip = build_test_zip(&[("..", b"evil"), ("ok.txt", b"fine")]);
        assert!(
            unpack_zip_payload(zip, GENEROUS_CAP, unpack_root.path()).is_err()
        );
    }

    #[test]
    fn unpack_enforces_size_cap() {
        // One file over the cap: the LimitedWrite errors mid-extraction
        // instead of writing the full payload.
        let unpack_root = tempfile::tempdir().unwrap();
        let big = vec![b'x'; 1000];
        let zip = build_test_zip(&[("big.txt", &big)]);
        assert!(unpack_zip_payload(zip, 100, unpack_root.path()).is_err());

        // The cap is cumulative across entries.
        let unpack_root = tempfile::tempdir().unwrap();
        let zip = build_test_zip(&[("a.txt", &big[..100]), ("b.txt", &big[..100])]);
        assert!(unpack_zip_payload(zip, 150, unpack_root.path()).is_err());
    }

    #[tokio::test]
    async fn file_list_types_accept_only_the_zip_datatype() {
        // The payload a hostile peer would send: paths on the RECEIVING
        // machine, with a "cut" operation, so a file manager acting on it
        // moves the user's own files. Long enough to clear read()'s 100-byte
        // compression floor, so it can also be offered as a zstd payload.
        let hostile = format!(
            "cut\n{}",
            "file:///home/victim/Documents\n".repeat(5)
        )
        .into_bytes();
        for requested_type in [PATHS_TARGET_GNOME, PATHS_TARGET_URIS] {
            // zstd used to satisfy these types because the zstd arm bound
            // requested_type irrefutably and came first: the decompressed
            // bytes went to the file manager verbatim.
            let (compressed, data_type) =
                read(hostile.clone(), GENEROUS_CAP, "text/plain").await.unwrap();
            assert_eq!(data_type.as_deref(), Some(MONUX_ZSTD_TARGET_DATATYPE));
            let unpack_root = tempfile::tempdir().unwrap();
            for (payload, data_type) in [
                (compressed, MONUX_ZSTD_TARGET_DATATYPE),
                (hostile.clone(), "text/plain"),
                (hostile.clone(), ""),
            ] {
                assert!(
                    write(
                        payload,
                        GENEROUS_CAP,
                        requested_type,
                        data_type,
                        unpack_root.path(),
                    )
                    .await
                    .is_err(),
                    "{} was accepted as data_type={}",
                    requested_type,
                    data_type
                );
            }
        }
    }

    #[tokio::test]
    async fn unsupported_datatype_for_an_ordinary_type_writes_empty() {
        // Only the file-list types are fatal: everything else keeps answering
        // with an empty clipboard rather than failing the serve.
        let out = write(
            b"whatever".to_vec(),
            GENEROUS_CAP,
            "text/plain",
            "application/x-unknown",
            &PathBuf::from("/nonexistent"),
        )
        .await
        .unwrap();
        assert!(out.is_empty());
    }

    #[tokio::test]
    async fn zip_build_over_cap_errors() {
        // The LimitedCursor caps the COMPRESSED zip size during the build.
        let src = tempfile::tempdir().unwrap();
        let file = temp_file(src.path(), "a.txt", b"some content to zip up");
        assert!(
            read(
                format!("copy\n{}", file_uri(&file)).into_bytes(),
                8,
                PATHS_TARGET_GNOME,
            )
            .await
            .is_err()
        );
    }

    #[test]
    fn zip_aborts_when_uncompressed_budget_is_exceeded() {
        let src = tempfile::tempdir().unwrap();
        let big = temp_file(src.path(), "big.bin", &vec![0u8; 1_000_000]);
        let files = vec![big];

        // Highly compressible zeros fit the COMPRESSED cap easily, but the
        // uncompressed budget aborts the zip mid-read with a clear error
        // instead of reading the whole payload per paste request.
        let err = zip_files(&files, GENEROUS_CAP, 500_000).unwrap_err();
        assert!(
            format!("{:#}", err).contains("uncompressed clipboard size"),
            "unexpected error: {:#}",
            err
        );

        // Within the budget the same file zips fine.
        let (uncompressed_len, zipdata) = zip_files(&files, GENEROUS_CAP, 1_000_000).unwrap();
        assert_eq!(uncompressed_len, 1_000_000);
        assert!(!zipdata.is_empty());
    }
}
