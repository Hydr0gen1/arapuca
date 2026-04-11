//! Disk usage monitoring for sandboxed processes.
//!
//! Polls the sandbox temp directory and workspace to detect excessive
//! disk usage. Complementary to RLIMIT_FSIZE — the rlimit prevents
//! individual large files, while disk quota monitoring catches the
//! aggregate across many files.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

/// Default polling interval for disk usage monitoring.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(30);

/// Calculate the disk usage of a directory in MB.
///
/// Walks the directory tree and sums file sizes. Returns 0 on error
/// or if the path doesn't exist.
pub fn usage_mb(path: &Path) -> u64 {
    dir_size_bytes(path) / (1024 * 1024)
}

/// Start a background thread that polls disk usage.
///
/// Calls `on_exceeded` if usage exceeds `limit_mb`. Returns a handle
/// that stops the monitor when dropped.
pub fn watch(
    path: impl AsRef<Path> + Send + 'static,
    limit_mb: u64,
    interval: Duration,
    on_exceeded: impl Fn(u64) + Send + 'static,
) -> WatchHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();

    let handle = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            let usage = usage_mb(path.as_ref());
            if usage > limit_mb {
                on_exceeded(usage);
            }
            thread::sleep(interval);
        }
    });

    WatchHandle {
        stop,
        _handle: handle,
    }
}

/// Handle for a disk usage monitor. Stops monitoring when dropped.
pub struct WatchHandle {
    stop: Arc<AtomicBool>,
    _handle: thread::JoinHandle<()>,
}

impl Drop for WatchHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Calculate the total size of a directory tree in bytes.
fn dir_size_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total += meta.len();
                }
            } else if ft.is_dir() {
                total += dir_size_bytes(&entry.path());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn usage_mb_empty_dir() {
        let dir = std::env::temp_dir().join("arapuca-diskquota-test-empty");
        let _ = fs::create_dir_all(&dir);
        assert_eq!(usage_mb(&dir), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_mb_with_files() {
        let dir = std::env::temp_dir().join("arapuca-diskquota-test-files");
        let _ = fs::create_dir_all(&dir);

        // Write a 1KB file.
        let file_path = dir.join("test.dat");
        let mut f = fs::File::create(&file_path).unwrap();
        f.write_all(&[0u8; 1024]).unwrap();

        // Should be 0 MB (less than 1 MB).
        assert_eq!(usage_mb(&dir), 0);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn usage_mb_nonexistent() {
        assert_eq!(usage_mb(Path::new("/nonexistent-xyz-123")), 0);
    }
}
