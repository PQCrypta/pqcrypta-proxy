//! Size-based rotating file writer for the tracing subscriber.
//!
//! `[logging] file` was parsed and read by nothing until 2026-08-15: a node whose
//! config asked for a log file got the journal instead, and its `max_size_mb`,
//! `max_backups` and `max_age_days` were not even struct fields, so they were
//! discarded silently. This is the writer that makes those four settings real.
//!
//! Rotation is by size rather than by time because that is what the config asks
//! for, and because a proxy's log volume tracks traffic, not the clock — a daily
//! rotation lets one busy day fill the disk while quiet days rotate nothing.
//!
//! Rotation failures never propagate. Losing a rotation is an inconvenience;
//! losing the log line that explains an outage is not, so on any rotation error
//! the writer keeps appending to the file it already holds.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Settings for a rotating log file, taken from the `[logging]` section.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub path: PathBuf,
    /// Rotate once the file reaches this many bytes. 0 disables size rotation.
    pub max_size_bytes: u64,
    /// How many rotated files to keep (`file.1` … `file.N`).
    pub max_backups: usize,
    /// Delete rotated files older than this. `None` disables age pruning.
    pub max_age: Option<Duration>,
}

/// A file writer that rotates on size and prunes old rotations.
pub struct RotatingFileWriter {
    config: RotationConfig,
    file: File,
    written: u64,
}

impl RotatingFileWriter {
    /// Open (or create) the log file, creating its parent directory if needed.
    ///
    /// Appends rather than truncates: a restart must not discard the log that
    /// explains why the process restarted.
    pub fn open(config: RotationConfig) -> io::Result<Self> {
        if let Some(parent) = config.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&config.path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            config,
            file,
            written,
        })
    }

    /// Shift `file` → `file.1` → `file.2` …, drop what falls off the end, then
    /// reopen a fresh `file`.
    fn rotate(&mut self) -> io::Result<()> {
        let path = &self.config.path;

        if self.config.max_backups == 0 {
            // No backups wanted: just start over.
            let _ = fs::remove_file(path);
        } else {
            let oldest = numbered_path(path, self.config.max_backups);
            let _ = fs::remove_file(&oldest);

            for index in (1..self.config.max_backups).rev() {
                let from = numbered_path(path, index);
                if from.exists() {
                    let to = numbered_path(path, index + 1);
                    let _ = fs::rename(&from, &to);
                }
            }

            fs::rename(path, numbered_path(path, 1))?;
        }

        self.file = OpenOptions::new().create(true).append(true).open(path)?;
        self.written = 0;
        self.prune_by_age();

        Ok(())
    }

    /// Delete rotated files older than `max_age`. Never touches the live file.
    fn prune_by_age(&self) {
        let Some(max_age) = self.config.max_age else {
            return;
        };
        let now = SystemTime::now();

        for index in 1..=self.config.max_backups {
            let candidate = numbered_path(&self.config.path, index);
            let Ok(metadata) = fs::metadata(&candidate) else {
                continue;
            };
            let Ok(modified) = metadata.modified() else {
                continue;
            };
            if now
                .duration_since(modified)
                .map(|age| age > max_age)
                .unwrap_or(false)
            {
                let _ = fs::remove_file(&candidate);
            }
        }
    }
}

fn numbered_path(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.config.max_size_bytes > 0
            && self.written + buf.len() as u64 > self.config.max_size_bytes
            && self.written > 0
        {
            // A failed rotation must not cost us the line being written.
            let _ = self.rotate();
        }

        let written = self.file.write(buf)?;
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("pqcrypta-log-test-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn rotates_when_the_size_limit_is_passed() {
        let dir = temp_dir("rotate");
        let path = dir.join("proxy.log");
        let mut writer = RotatingFileWriter::open(RotationConfig {
            path: path.clone(),
            max_size_bytes: 64,
            max_backups: 2,
            max_age: None,
        })
        .unwrap();

        for _ in 0..10 {
            writer.write_all(&[b'x'; 32]).unwrap();
        }
        writer.flush().unwrap();

        assert!(path.exists(), "live log file must exist");
        assert!(numbered_path(&path, 1).exists(), "first backup must exist");
        assert!(numbered_path(&path, 2).exists(), "second backup must exist");
        assert!(
            !numbered_path(&path, 3).exists(),
            "must not keep more than max_backups"
        );
        assert!(
            fs::metadata(&path).unwrap().len() <= 64,
            "live file must be under the size limit after rotating"
        );
    }

    #[test]
    fn appends_to_an_existing_file_instead_of_truncating() {
        let dir = temp_dir("append");
        let path = dir.join("proxy.log");
        fs::write(&path, b"earlier\n").unwrap();

        let mut writer = RotatingFileWriter::open(RotationConfig {
            path: path.clone(),
            max_size_bytes: 0,
            max_backups: 1,
            max_age: None,
        })
        .unwrap();
        writer.write_all(b"later\n").unwrap();
        writer.flush().unwrap();

        let contents = fs::read_to_string(&path).unwrap();
        assert!(contents.contains("earlier"), "must not truncate on open");
        assert!(contents.contains("later"));
    }

    #[test]
    fn size_zero_never_rotates() {
        let dir = temp_dir("nosize");
        let path = dir.join("proxy.log");
        let mut writer = RotatingFileWriter::open(RotationConfig {
            path: path.clone(),
            max_size_bytes: 0,
            max_backups: 3,
            max_age: None,
        })
        .unwrap();

        for _ in 0..50 {
            writer.write_all(&[b'y'; 64]).unwrap();
        }
        writer.flush().unwrap();

        assert!(!numbered_path(&path, 1).exists());
        assert_eq!(fs::metadata(&path).unwrap().len(), 50 * 64);
    }

    #[test]
    fn creates_a_missing_parent_directory() {
        let dir = temp_dir("mkdir");
        let path = dir.join("nested/deeper/proxy.log");
        let writer = RotatingFileWriter::open(RotationConfig {
            path: path.clone(),
            max_size_bytes: 0,
            max_backups: 1,
            max_age: None,
        });
        assert!(writer.is_ok(), "must create the parent directory");
        assert!(path.exists());
    }

    /// Exactly one rotation, with `max_backups` far from being reached: the
    /// stale file can only disappear because of its age. An earlier version of
    /// this test rotated repeatedly and proved nothing — the backup shuffle had
    /// recreated the path it asserted on, and count-pruning could have removed
    /// the file just as well as age-pruning.
    // clippy suggests `Duration::from_days` here, which is still unstable
    // (rust-lang/rust#120301) and does not compile on this toolchain. The
    // explicit arithmetic is the only spelling available, so silence the lint
    // rather than leave a suggestion that cannot be taken.
    // The pedantic `duration_suboptimal_units` lint wants `Duration::from_days`
    // here, which is still unstable (rust-lang/rust#120301) and does not compile
    // on this toolchain. The explicit arithmetic is the only spelling available,
    // so silence the lint rather than leave a suggestion that cannot be taken.
    #[allow(clippy::duration_suboptimal_units)]
    #[test]
    fn prunes_rotations_older_than_max_age() {
        let dir = temp_dir("age");
        let path = dir.join("proxy.log");
        let stale = numbered_path(&path, 1);
        fs::write(&stale, b"stale\n").unwrap();
        filetime_set(
            &stale,
            SystemTime::now() - Duration::from_secs(60 * 60 * 24 * 30),
        );

        let mut writer = RotatingFileWriter::open(RotationConfig {
            path: path.clone(),
            max_size_bytes: 32,
            max_backups: 3,
            max_age: Some(Duration::from_secs(60 * 60 * 24)),
        })
        .unwrap();

        // First write fills the file, second trips the size limit exactly once.
        writer.write_all(&[b'z'; 32]).unwrap();
        writer.write_all(&[b'z'; 32]).unwrap();
        writer.flush().unwrap();

        let surviving: Vec<String> = (1..=3)
            .map(|i| numbered_path(&path, i))
            .filter(|p| p.exists())
            .map(|p| fs::read_to_string(p).unwrap_or_default())
            .collect();
        assert!(
            !surviving.iter().any(|body| body.contains("stale")),
            "a rotation older than max_age must be deleted, found: {surviving:?}"
        );
        assert!(
            numbered_path(&path, 1).exists(),
            "the rotation just made must survive: age pruning must not be indiscriminate"
        );
    }

    /// Backdate a file's mtime without pulling in a dependency for it.
    fn filetime_set(path: &Path, when: SystemTime) {
        let file = OpenOptions::new().write(true).open(path).unwrap();
        file.set_modified(when).unwrap();
    }
}
