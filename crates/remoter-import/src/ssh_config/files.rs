//! Resolving `Include` directives.
//!
//! Reading files is behind a trait for two reasons. The obvious one is that a
//! test should not need a home directory. The load-bearing one is that the
//! fuzz targets parse a config without ever reaching a filesystem: a parser
//! that opened whatever path its input named would be a parser that could not
//! be fuzzed safely, and a hostile `Include /dev/urandom` is a real thing a
//! shared config can say.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use crate::error::{ImportError, ReadFailure};

/// Where an importer gets the files an `Include` names.
pub trait ConfigFiles {
    /// Reads one file.
    ///
    /// # Errors
    ///
    /// [`ImportError::ReadFailed`] with a [`ReadFailure`] the user can act on.
    fn read(&self, path: &Path) -> Result<Vec<u8>, ImportError>;

    /// Expands a path that may contain `*` or `?` in its last component,
    /// in sorted order. A path with no wildcard expands to itself.
    fn expand(&self, path: &Path) -> Vec<PathBuf>;

    /// The directory a relative `Include` is resolved against.
    ///
    /// `ssh` resolves relative includes against `~/.ssh` for a user config and
    /// `/etc/ssh` for the system one.
    fn base(&self) -> &Path;

    /// The home directory a leading `~` stands for.
    fn home(&self) -> &Path;
}

/// Files on the real filesystem, confined to one directory.
///
/// Confinement is not paranoia about the local user's own config; it is about
/// the config a colleague sent along with their exported connections.
/// `Include ../../../etc/shadow` is a line anyone can write.
#[derive(Debug, Clone)]
pub struct OsConfigFiles {
    root: PathBuf,
    home: PathBuf,
}

impl OsConfigFiles {
    /// Reads files under `root` only. `home` is what a leading `~` expands to,
    /// and must itself be under `root` for a `~` path to resolve.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>, home: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            home: home.into(),
        }
    }

    /// Reads files under `directory`, treating it as both the root and the
    /// home directory — the ordinary case of importing `~/.ssh/config`.
    #[must_use]
    pub fn rooted_at(directory: impl Into<PathBuf>) -> Self {
        let directory = directory.into();
        Self {
            root: directory.clone(),
            home: directory,
        }
    }

    fn confine(&self, path: &Path) -> Result<PathBuf, ImportError> {
        let normalised = normalise(path);
        if normalised.starts_with(&self.root) {
            Ok(normalised)
        } else {
            Err(ImportError::ReadFailed {
                path: path.display().to_string(),
                reason: ReadFailure::OutsideRoot,
            })
        }
    }
}

impl ConfigFiles for OsConfigFiles {
    fn read(&self, path: &Path) -> Result<Vec<u8>, ImportError> {
        let confined = self.confine(path)?;
        std::fs::read(&confined).map_err(|err| ImportError::ReadFailed {
            path: path.display().to_string(),
            reason: match err.kind() {
                std::io::ErrorKind::NotFound => ReadFailure::NotFound,
                std::io::ErrorKind::PermissionDenied => ReadFailure::PermissionDenied,
                _ => ReadFailure::Other,
            },
        })
    }

    fn expand(&self, path: &Path) -> Vec<PathBuf> {
        let Some(pattern) = path.file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        if !pattern.contains(['*', '?']) {
            return vec![path.to_path_buf()];
        }
        let Some(parent) = path.parent() else {
            return Vec::new();
        };
        let Ok(parent) = self.confine(parent) else {
            return Vec::new();
        };
        let Ok(entries) = std::fs::read_dir(&parent) else {
            return Vec::new();
        };
        let mut out: Vec<PathBuf> = entries
            .flatten()
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| super::pattern::matches(pattern, name))
            })
            .map(|entry| entry.path())
            .collect();
        out.sort();
        out
    }

    fn base(&self) -> &Path {
        &self.root
    }

    fn home(&self) -> &Path {
        &self.home
    }
}

/// Files held in memory, for tests and for importing a config the user pasted.
#[derive(Debug, Clone, Default)]
pub struct MemoryConfigFiles {
    files: BTreeMap<PathBuf, Vec<u8>>,
    base: PathBuf,
    home: PathBuf,
}

impl MemoryConfigFiles {
    /// An empty set whose relative includes resolve against `base`.
    #[must_use]
    pub fn new(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            files: BTreeMap::new(),
            home: base.clone(),
            base,
        }
    }

    /// Adds a file.
    #[must_use]
    pub fn with(mut self, path: impl Into<PathBuf>, contents: impl Into<Vec<u8>>) -> Self {
        self.files.insert(path.into(), contents.into());
        self
    }
}

impl ConfigFiles for MemoryConfigFiles {
    fn read(&self, path: &Path) -> Result<Vec<u8>, ImportError> {
        self.files
            .get(&normalise(path))
            .cloned()
            .ok_or_else(|| ImportError::ReadFailed {
                path: path.display().to_string(),
                reason: ReadFailure::NotFound,
            })
    }

    fn expand(&self, path: &Path) -> Vec<PathBuf> {
        let Some(pattern) = path.file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        if !pattern.contains(['*', '?']) {
            return vec![normalise(path)];
        }
        let parent = path.parent().map(normalise).unwrap_or_default();
        self.files
            .keys()
            .filter(|candidate| {
                candidate
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_default()
                    == parent
            })
            .filter(|candidate| {
                candidate
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| super::pattern::matches(pattern, name))
            })
            .cloned()
            .collect()
    }

    fn base(&self) -> &Path {
        &self.base
    }

    fn home(&self) -> &Path {
        &self.home
    }
}

/// Resolves an `Include` argument into a path, without touching the
/// filesystem.
///
/// `~` expands to the home directory the source reports, and a relative path
/// resolves against its base directory, as `ssh` does. `..` is removed here
/// rather than left for the filesystem, so that the confinement check in
/// [`OsConfigFiles`] sees the path the open will actually use.
pub(crate) fn resolve(argument: &str, files: &dyn ConfigFiles) -> PathBuf {
    let path = Path::new(argument);
    if let Ok(rest) = path.strip_prefix("~") {
        return normalise(&files.home().join(rest));
    }
    if path.is_absolute() {
        return normalise(path);
    }
    normalise(&files.base().join(path))
}

/// Removes `.` and `..` lexically. A `..` with nothing to pop is dropped, which
/// keeps the result inside whatever prefix it started with.
fn normalise(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;

    #[test]
    fn tilde_and_relative_includes_resolve_the_way_ssh_resolves_them() {
        let files = MemoryConfigFiles::new("/home/a/.ssh");
        assert_eq!(
            resolve("~/.ssh/conf.d/x", &files),
            Path::new("/home/a/.ssh/.ssh/conf.d/x")
        );
        assert_eq!(
            resolve("conf.d/x", &files),
            Path::new("/home/a/.ssh/conf.d/x")
        );
        assert_eq!(resolve("/etc/ssh/x", &files), Path::new("/etc/ssh/x"));
    }

    #[test]
    fn dot_dot_is_removed_before_the_path_is_used() {
        let files = MemoryConfigFiles::new("/home/a/.ssh");
        assert_eq!(
            resolve("../../../etc/shadow", &files),
            Path::new("/etc/shadow")
        );
        assert_eq!(resolve("./x", &files), Path::new("/home/a/.ssh/x"));
    }

    #[test]
    fn the_os_source_refuses_a_path_that_leaves_its_root() {
        let files = OsConfigFiles::rooted_at("/home/a/.ssh");
        let escape = resolve("../../../etc/shadow", &files);
        let Err(ImportError::ReadFailed { reason, .. }) = files.read(&escape) else {
            panic!("a path outside the root must be refused");
        };
        assert_eq!(reason, ReadFailure::OutsideRoot);
    }

    #[test]
    fn a_missing_file_is_reported_by_name() {
        let files = MemoryConfigFiles::new("/c");
        let Err(ImportError::ReadFailed { path, reason }) = files.read(Path::new("/c/nope")) else {
            panic!("expected a read failure");
        };
        assert_eq!(path, "/c/nope");
        assert_eq!(reason, ReadFailure::NotFound);
    }

    #[test]
    fn wildcards_expand_within_one_directory_only() {
        let files = MemoryConfigFiles::new("/c")
            .with("/c/conf.d/a.conf", "")
            .with("/c/conf.d/b.conf", "")
            .with("/c/conf.d/notes.txt", "")
            .with("/c/other/c.conf", "");
        assert_eq!(
            files.expand(Path::new("/c/conf.d/*.conf")),
            [
                PathBuf::from("/c/conf.d/a.conf"),
                PathBuf::from("/c/conf.d/b.conf")
            ]
        );
        assert_eq!(
            files.expand(Path::new("/c/conf.d/a.conf")),
            [PathBuf::from("/c/conf.d/a.conf")]
        );
    }
}
