//! Data files the proxy reads at run time (the GeoLite2 databases, the JA3/JA4
//! fingerprint database), and whether one has changed since it was loaded.
//!
//! The weekly refresh (`scripts/refresh_fingerprint_db.sh`) writes new contents
//! at the same paths. They were reloaded only when a configuration reload
//! changed a path, which a refresh never does, so the script restarted the
//! proxy on every node to load them: each Sunday at 03:15 every listener
//! refused connections while the old process drained (34 s on web1 on
//! 2026-10-18). A reload now compares each file's identity with the one it
//! loaded and reloads what changed.

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

/// What identifies a file's contents as loaded.
///
/// Device and inode change when a refresh renames a new file into place; size
/// and modification time change when one rewrites the file in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileStamp {
    dev: u64,
    ino: u64,
    len: u64,
    modified: Option<SystemTime>,
}

/// The file's identity now, or `None` when it cannot be read.
pub fn file_stamp(path: &Path) -> Option<FileStamp> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let (dev, ino) = {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    };
    #[cfg(not(unix))]
    let (dev, ino) = (0, 0);
    Some(FileStamp {
        dev,
        ino,
        len: meta.len(),
        modified: meta.modified().ok(),
    })
}

/// A value loaded from a file, loaded again on first use after the file
/// changes.
pub struct Reloadable<T> {
    slot: parking_lot::Mutex<Option<(Option<FileStamp>, Option<Arc<T>>)>>,
}

impl<T> Reloadable<T> {
    pub const fn new() -> Self {
        Self {
            slot: parking_lot::Mutex::new(None),
        }
    }

    /// The value loaded from `path` by `load`, loaded first if this is the
    /// first use or the file has changed since the last load. A file that does
    /// not load is remembered as such until it changes.
    pub fn get(
        &self,
        path: Option<&Path>,
        load: impl FnOnce(&Path) -> Option<T>,
    ) -> Option<Arc<T>> {
        let path = path?;
        let stamp = file_stamp(path);
        let mut slot = self.slot.lock();
        if let Some((loaded, value)) = slot.as_ref() {
            if *loaded == stamp {
                return value.clone();
            }
        }
        let value = load(path).map(Arc::new);
        *slot = Some((stamp, value.clone()));
        value
    }
}

impl<T> Default for Reloadable<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A file replaced the way a refresh replaces one (a new file renamed over
    /// it) is a changed file, and loads again; an unchanged one does not.
    #[test]
    fn a_replaced_file_is_loaded_again() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("data.json");
        std::fs::write(&path, "one").expect("write");
        let loads = AtomicUsize::new(0);
        let cache: Reloadable<String> = Reloadable::new();
        let load = |p: &Path| {
            loads.fetch_add(1, Ordering::SeqCst);
            std::fs::read_to_string(p).ok()
        };

        assert_eq!(
            cache.get(Some(&path), load).as_deref().map(String::as_str),
            Some("one")
        );
        assert_eq!(
            cache.get(Some(&path), load).as_deref().map(String::as_str),
            Some("one")
        );
        assert_eq!(
            loads.load(Ordering::SeqCst),
            1,
            "unchanged: not loaded again"
        );

        let staged = dir.path().join("data.json.new");
        std::fs::write(&staged, "two, longer").expect("write");
        std::fs::rename(&staged, &path).expect("rename");
        assert_eq!(
            cache.get(Some(&path), load).as_deref().map(String::as_str),
            Some("two, longer")
        );
        assert_eq!(loads.load(Ordering::SeqCst), 2, "replaced: loaded again");

        assert!(file_stamp(&dir.path().join("absent")).is_none());
        assert!(cache.get(None, load).is_none());
    }
}
