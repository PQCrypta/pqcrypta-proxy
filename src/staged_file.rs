//! Files written beside their destination and put in place by a rename.
//!
//! A reader sees the old file or the new one, whole. A private file is created
//! readable by its owner alone: a key or a token is never on disk under any
//! other mode, not even for the moment before a chmod.

use std::fs;
use std::path::{Path, PathBuf};

/// A file written beside its destination and not yet in place.
pub struct Staged {
    tmp: PathBuf,
    path: PathBuf,
}

impl Staged {
    /// Write `content` to a sibling of `path` and sync it to disk. A
    /// `private` file is created readable by its owner alone, so a key is
    /// never on disk under another mode.
    pub fn write(path: &Path, content: &str, private: bool) -> anyhow::Result<Self> {
        use std::io::Write as _;
        let mut name = path.as_os_str().to_os_string();
        name.push(".tmp");
        let tmp = PathBuf::from(name);
        // What an interrupted write left behind has a mode of its own.
        let _ = fs::remove_file(&tmp);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        if private {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(not(unix))]
        let _ = private;
        let mut file = options.open(&tmp)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(Self {
            tmp,
            path: path.to_path_buf(),
        })
    }

    /// Put the file in place: a reader sees the old file or the new, whole.
    pub fn commit(self) -> anyhow::Result<()> {
        fs::rename(&self.tmp, &self.path)?;
        Ok(())
    }
}

/// Write one file atomically (see [`Staged`]).
pub fn write_atomic(path: &Path, content: &str, private: bool) -> anyhow::Result<()> {
    Staged::write(path, content, private)?.commit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_private_file_is_its_owners_alone_from_the_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_atomic(&path, "first", true).unwrap();
        write_atomic(&path, "second", true).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert!(!dir.path().join("secret.tmp").exists());
    }
}
