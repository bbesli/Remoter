//! Files over the clipboard: MS-RDPECLIP file streams, in both directions.
//!
//! Text is small and crosses in one PDU. A file does not: the clipboard carries
//! a *list* of files (a `FileGroupDescriptorW`, §2.2.5.2.3) and then the bytes
//! of each one in pieces the receiving side asks for, by index and offset, with
//! File Contents Request and Response PDUs (§2.2.5.3, §2.2.5.4). This module is
//! both ends of that:
//!
//! - **This machine to the server** — [`LocalFileSet`]. The files the user
//!   copied here are walked once, when they are offered, into the list the
//!   server is shown, and each request the server then makes is answered from
//!   the file it names. Only the files in that list can be read: the index is
//!   the whole address, and there is no path in a request to widen it.
//! - **The server to this machine** — [`SaveJob`]. The list the server offers
//!   is shown to the user and nothing moves until they choose a folder. Then
//!   each file is asked for a megabyte at a time and written under a temporary
//!   name, and renamed only once its last byte is in.
//!
//! # What a hostile server can and cannot do here
//!
//! It chooses every name in the list it offers. `ironrdp-cliprdr` already
//! strips absolute prefixes and `..` from them (`sanitize_file_path`); this
//! module then treats each remaining component as untrusted text that has to
//! become one file name on *this* platform — separators, control characters and
//! the characters Windows reserves are replaced, a Windows device name is
//! prefixed so that it cannot open the device, and nothing is ever written
//! outside the folder the user picked. Nothing that already exists is
//! overwritten: a top-level name that is taken gets a number.
//!
//! It chooses the sizes too, and a size is not a promise. The bytes written for
//! a file stop at the size it declared, and a server that answers a request
//! with nothing is refused rather than asked again for ever.
//!
//! # What this side offers
//!
//! What the user copied, and nothing reachable from it by a link: a symbolic
//! link *inside* a copied folder is skipped rather than followed, so a folder
//! holding a link to `~/.ssh` does not send `~/.ssh`. The top-level entries are
//! followed, because those are the things the user pointed at.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use ironrdp::cliprdr::is_windows_device_name;
use ironrdp::cliprdr::pdu::{
    ClipboardFileAttributes, FileContentsFlags, FileContentsRequest, FileContentsResponse,
    FileDescriptor,
};
use parking_lot::Mutex;
use remoter_proto::{ClipboardFiles, RemoteFile};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

/// The most entries — files and folders — one offer of local files may hold.
///
/// Copying a folder with more than this in it is almost always a mistake made
/// with a mouse, and the file list goes to the server whole, at 592 bytes an
/// entry, before anything is pasted.
pub const MAX_LOCAL_ENTRIES: usize = 10_000;

/// How deep a copied folder is walked.
pub const MAX_LOCAL_DEPTH: usize = 32;

/// The most bytes one File Contents Response carries back to the server.
///
/// The server says how much it wants (`cbRequested`, §2.2.5.3), and it is a
/// number off the wire: answered as asked, a request for four gigabytes is a
/// four-gigabyte allocation here. Windows asks for far less than this.
pub const MAX_SERVE_BYTES: u32 = 8 * 1024 * 1024;

/// How much of a file a save asks for at a time.
pub const SAVE_CHUNK_BYTES: u32 = 1024 * 1024;

/// How many entries of an offered file list travel to the interface by name.
pub const OFFERED_LISTED: usize = 100;

/// The longest name a File Descriptor holds: 260 UTF-16 code units with the
/// terminator (§2.2.5.2.3.1).
const MAX_WIRE_NAME: usize = 259;

/// What a file is called while its bytes are still arriving.
pub const PART_SUFFIX: &str = ".remoter-part";

/// How often progress is reported during a save, in bytes.
const PROGRESS_EVERY_BYTES: u64 = 1024 * 1024;

/// Some copied entries could not be offered, and were left out.
pub const WARNING_FILES_SKIPPED: &str = "rdp.clipboard_files_skipped";
/// More was copied than one offer carries.
pub const WARNING_FILES_TOO_MANY: &str = "rdp.clipboard_files_too_many";
/// The server does not do file streams, so files cannot cross this session.
pub const WARNING_FILES_UNSUPPORTED: &str = "rdp.clipboard_files_unsupported";

/// The server stopped sending a file, or never started.
pub const SAVE_REFUSED: &str = "rdp.clipboard_save_refused";
/// A file could not be written into the chosen folder.
pub const SAVE_WRITE_FAILED: &str = "rdp.clipboard_save_write_failed";
/// The server's clipboard no longer holds files to save.
pub const SAVE_NOTHING: &str = "rdp.clipboard_save_nothing";
/// A save is already running in this tab.
pub const SAVE_BUSY: &str = "rdp.clipboard_save_busy";

// ─────────────────────────────────────────────────── this machine → server ──

/// One copied file or folder, as it is offered.
#[derive(Debug)]
struct LocalEntry {
    path: PathBuf,
    descriptor: FileDescriptor,
    directory: bool,
}

/// The files the user copied here, walked into the list the server is shown.
///
/// `Debug` names counts only: the paths are the user's.
pub struct LocalFileSet {
    entries: Vec<LocalEntry>,
    skipped: usize,
    /// Which entries the server has read to the end, so that each is reported
    /// once however many times it is pasted.
    reported: Mutex<BTreeSet<usize>>,
}

impl core::fmt::Debug for LocalFileSet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LocalFileSet")
            .field("entries", &self.entries.len())
            .field("skipped", &self.skipped)
            .finish_non_exhaustive()
    }
}

/// A file this session has open to answer the server's reads, kept between
/// requests so that a file read in a thousand pieces is opened once.
#[derive(Debug)]
pub struct OpenFile {
    set: usize,
    index: usize,
    file: tokio::fs::File,
}

impl LocalFileSet {
    /// Walks what the user copied.
    ///
    /// # Errors
    ///
    /// [`WARNING_FILES_TOO_MANY`] past [`MAX_LOCAL_ENTRIES`]. An entry that
    /// cannot be read, or whose name cannot be written into a File Descriptor,
    /// is left out and counted rather than failing the rest.
    pub async fn collect(paths: &[String]) -> Result<Self, &'static str> {
        let mut entries = Vec::new();
        let mut skipped = 0usize;

        for top in paths {
            let path = PathBuf::from(top);
            // Followed: the user pointed at this, link or not.
            let Ok(meta) = tokio::fs::metadata(&path).await else {
                skipped += 1;
                continue;
            };
            let Some(name) = path.file_name().and_then(OsStr::to_str) else {
                skipped += 1;
                continue;
            };
            if !representable(name) || !fits_on_the_wire(name) {
                skipped += 1;
                continue;
            }
            let directory = meta.is_dir();
            if !directory && !meta.is_file() {
                skipped += 1;
                continue;
            }
            entries.push(LocalEntry {
                descriptor: descriptor(name, None, &meta),
                path: path.clone(),
                directory,
            });
            if directory {
                walk(&path, name, &mut entries, &mut skipped).await?;
            }
            if entries.len() > MAX_LOCAL_ENTRIES {
                return Err(WARNING_FILES_TOO_MANY);
            }
        }

        Ok(Self {
            entries,
            skipped,
            reported: Mutex::new(BTreeSet::new()),
        })
    }

    /// Whether nothing survived the walk.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many copied entries were left out.
    #[must_use]
    pub const fn skipped(&self) -> usize {
        self.skipped
    }

    /// The list the server is shown, in the order its requests will index.
    #[must_use]
    pub fn descriptors(&self) -> Vec<FileDescriptor> {
        self.entries
            .iter()
            .map(|entry| entry.descriptor.clone())
            .collect()
    }

    /// Bytes that identify this offer — each entry's name, size and time —
    /// for the "the server already has this" check. Not the contents.
    #[must_use]
    pub fn identity(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in &self.entries {
            let descriptor = &entry.descriptor;
            if let Some(path) = &descriptor.relative_path {
                out.extend_from_slice(path.as_bytes());
                out.push(b'\\');
            }
            out.extend_from_slice(descriptor.name.as_bytes());
            out.push(0);
            out.extend_from_slice(&descriptor.file_size.unwrap_or(u64::MAX).to_le_bytes());
            out.extend_from_slice(&descriptor.last_write_time.unwrap_or_default().to_le_bytes());
        }
        out
    }

    /// Answers one File Contents Request (§3.1.5.4.6) from the file it names.
    ///
    /// Returns the response and, when this read reached the end of a file for
    /// the first time, the event that says so.
    pub async fn serve(
        &self,
        request: &FileContentsRequest,
        open: &mut Option<OpenFile>,
    ) -> (FileContentsResponse<'static>, Option<ClipboardFiles>) {
        let refuse = || (FileContentsResponse::new_error(request.stream_id), None);
        let Some((index, entry)) = usize::try_from(request.index)
            .ok()
            .and_then(|index| self.entries.get(index).map(|entry| (index, entry)))
        else {
            return refuse();
        };
        if entry.directory {
            return refuse();
        }

        if request.flags.contains(FileContentsFlags::SIZE) {
            return match tokio::fs::metadata(&entry.path).await {
                Ok(meta) => (
                    FileContentsResponse::new_size_response(request.stream_id, meta.len()),
                    None,
                ),
                Err(_) => refuse(),
            };
        }

        let set = core::ptr::from_ref(self).addr();
        let reuse = open
            .as_ref()
            .is_some_and(|held| held.set == set && held.index == index);
        if !reuse {
            *open = match tokio::fs::File::open(&entry.path).await {
                Ok(file) => Some(OpenFile { set, index, file }),
                Err(_) => return refuse(),
            };
        }
        let Some(held) = open.as_mut() else {
            return refuse();
        };

        let wanted = usize::try_from(request.requested_size.min(MAX_SERVE_BYTES)).unwrap_or(0);
        let mut data = vec![0u8; wanted];
        let read = async {
            held.file
                .seek(std::io::SeekFrom::Start(request.position))
                .await?;
            let mut filled = 0;
            while filled < wanted {
                let n = held.file.read(&mut data[filled..]).await?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            let length = held.file.metadata().await?.len();
            Ok::<_, std::io::Error>((filled, length))
        };
        let Ok((filled, length)) = read.await else {
            *open = None;
            return refuse();
        };
        data.truncate(filled);

        let end = request.position.saturating_add(filled as u64);
        let finished =
            (end >= length && self.reported.lock().insert(index)).then(|| ClipboardFiles::Sent {
                local: entry.path.display().to_string(),
                bytes: length,
            });
        (
            FileContentsResponse::new_data_response(request.stream_id, data),
            finished,
        )
    }
}

/// Walks one copied folder into `entries`, parents before children.
async fn walk(
    root: &Path,
    root_name: &str,
    entries: &mut Vec<LocalEntry>,
    skipped: &mut usize,
) -> Result<(), &'static str> {
    let mut pending = vec![(root.to_path_buf(), root_name.to_owned(), 1usize)];
    while let Some((directory, relative, depth)) = pending.pop() {
        if depth > MAX_LOCAL_DEPTH {
            *skipped += 1;
            continue;
        }
        let Ok(mut reader) = tokio::fs::read_dir(&directory).await else {
            *skipped += 1;
            continue;
        };
        let mut children = Vec::new();
        while let Ok(Some(child)) = reader.next_entry().await {
            children.push(child);
            if entries.len() + children.len() > MAX_LOCAL_ENTRIES {
                return Err(WARNING_FILES_TOO_MANY);
            }
        }
        // By name, so the same folder is the same offer twice and the check
        // against offering it again can see that.
        children.sort_by_key(tokio::fs::DirEntry::file_name);
        let mut folders = Vec::new();
        for child in children {
            let path = child.path();
            let Some(name) = path
                .file_name()
                .and_then(OsStr::to_str)
                .map(ToOwned::to_owned)
            else {
                *skipped += 1;
                continue;
            };
            // Not followed: a link inside a copied folder can point anywhere.
            let Ok(meta) = tokio::fs::symlink_metadata(&path).await else {
                *skipped += 1;
                continue;
            };
            let kind = meta.file_type();
            if kind.is_symlink() || !(kind.is_dir() || kind.is_file()) {
                *skipped += 1;
                continue;
            }
            let wire = format!("{relative}\\{name}");
            if !representable(&name) || !fits_on_the_wire(&wire) {
                *skipped += 1;
                continue;
            }
            entries.push(LocalEntry {
                descriptor: descriptor(&name, Some(&relative), &meta),
                path: path.clone(),
                directory: kind.is_dir(),
            });
            if kind.is_dir() {
                folders.push((path, wire, depth + 1));
            }
        }
        // Reversed onto a stack, so they come off in name order.
        pending.extend(folders.into_iter().rev());
    }
    Ok(())
}

/// A name that can be one component of a File Descriptor's `cFileName`.
///
/// The wire separates components with `\`, so a Unix file name containing one
/// would arrive as a folder that does not exist. And `ironrdp-cliprdr` drops a
/// descriptor it reads as an absolute path — `C:x` is one — *after* the list is
/// built, which would shift the index of every entry after it and serve the
/// server the wrong file. So those are left out here, where the indexes are
/// still this module's to decide.
fn representable(name: &str) -> bool {
    let mut chars = name.chars();
    let drive_like = matches!(
        (chars.next(), chars.next()),
        (Some(first), Some(':')) if first.is_ascii_alphabetic()
    );
    !name.is_empty()
        && name != "."
        && name != ".."
        && !drive_like
        && !name
            .chars()
            .any(|c| c == '\\' || c == '/' || c.is_control())
}

/// Whether a `relative\name` fits `cFileName`. Both counts are checked:
/// `ironrdp-cliprdr` filters on characters and encodes in UTF-16 code units,
/// and a name past either limit would be dropped by one and fail the other.
fn fits_on_the_wire(wire: &str) -> bool {
    wire.chars().count() <= MAX_WIRE_NAME && wire.encode_utf16().count() <= MAX_WIRE_NAME
}

fn descriptor(name: &str, relative: Option<&str>, meta: &std::fs::Metadata) -> FileDescriptor {
    let mut descriptor = FileDescriptor::new(name);
    if let Some(relative) = relative {
        descriptor = descriptor.with_relative_path(relative);
    }
    if meta.is_dir() {
        descriptor = descriptor.with_attributes(ClipboardFileAttributes::DIRECTORY);
    } else {
        descriptor = descriptor
            .with_attributes(ClipboardFileAttributes::ARCHIVE)
            .with_file_size(meta.len());
    }
    if let Some(time) = meta.modified().ok().and_then(filetime) {
        descriptor = descriptor.with_last_write_time(time);
    }
    descriptor
}

/// A time as a Windows `FILETIME`: 100-nanosecond intervals since 1601.
fn filetime(time: SystemTime) -> Option<u64> {
    const EPOCH_OFFSET_SECONDS: u64 = 11_644_473_600;
    let since = time.duration_since(UNIX_EPOCH).ok()?;
    since
        .as_secs()
        .checked_add(EPOCH_OFFSET_SECONDS)?
        .checked_mul(10_000_000)?
        .checked_add(u64::from(since.subsec_nanos()) / 100)
}

// ─────────────────────────────────────────────────── server → this machine ──

/// What the interface is told about a file list the server offered.
#[must_use]
pub fn offered(files: &[FileDescriptor]) -> ClipboardFiles {
    let total_bytes = files
        .iter()
        .filter(|file| !is_directory(file))
        .filter_map(|file| file.file_size)
        .fold(0u64, u64::saturating_add);
    ClipboardFiles::Offered {
        files: files
            .iter()
            .take(OFFERED_LISTED)
            .map(|file| RemoteFile {
                path: remote_path(file),
                size: file.file_size.filter(|_| !is_directory(file)),
                directory: is_directory(file),
            })
            .collect(),
        total_entries: u32::try_from(files.len()).unwrap_or(u32::MAX),
        total_bytes,
    }
}

fn is_directory(file: &FileDescriptor) -> bool {
    file.attributes
        .is_some_and(|attributes| attributes.contains(ClipboardFileAttributes::DIRECTORY))
}

/// A descriptor's place in what was copied, `/`-separated.
fn remote_path(file: &FileDescriptor) -> String {
    match &file.relative_path {
        Some(relative) if !relative.is_empty() => {
            format!("{}/{}", relative.replace('\\', "/"), file.name)
        }
        _ => file.name.clone(),
    }
}

/// One component of a name the server chose, made safe to create here.
///
/// `ironrdp-cliprdr` has already removed `.`, `..` and absolute prefixes. What
/// is left is still a string a server wrote, so anything that is a separator
/// or reserved on *some* platform becomes `_` — a file saved on Linux should
/// not become unopenable when the folder is copied to Windows — trailing dots
/// and spaces go, because Windows silently strips them and two names would
/// meet, and a device name gets a prefix so that it names a file.
#[must_use]
pub fn local_component(component: &str) -> String {
    let replaced: String = component
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                c
            }
        })
        .collect();
    let trimmed = replaced.trim_end_matches(['.', ' ']);
    let named = if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        String::from("_")
    } else {
        trimmed.to_owned()
    };
    if is_windows_device_name(&named) {
        format!("_{named}")
    } else {
        named
    }
}

/// `report.pdf` → `report (2).pdf`; `logs` → `logs (2)`.
fn numbered(name: &str, n: u32) -> String {
    match name.rfind('.') {
        Some(dot) if dot > 0 => format!("{} ({n}){}", &name[..dot], &name[dot..]),
        _ => format!("{name} ({n})"),
    }
}

/// One entry of a planned save.
#[derive(Debug)]
struct Item {
    index: i32,
    remote: String,
    local: PathBuf,
    directory: bool,
    size: Option<u64>,
}

/// The file whose bytes are arriving.
#[derive(Debug)]
struct Current {
    item: usize,
    part: PathBuf,
    file: tokio::fs::File,
    position: u64,
    size: Option<u64>,
    stream: u32,
}

/// What a save needs next.
#[derive(Debug)]
pub enum SaveStep {
    /// Ask the server for this.
    Request(FileContentsRequest),
    /// Nothing: every file is in. The event says what arrived.
    Finished(ClipboardFiles),
}

/// Saving the server's copied files into a folder the user chose.
#[derive(Debug)]
pub struct SaveJob {
    directory: PathBuf,
    items: Vec<Item>,
    next: usize,
    current: Option<Current>,
    clip_data_id: Option<u32>,
    next_stream: u32,
    done_bytes: u64,
    total_bytes: u64,
    done_files: u32,
    total_files: u32,
    reported_bytes: u64,
}

impl SaveJob {
    /// Plans where every entry goes.
    ///
    /// Top-level names that are already taken in `directory` — by a file, a
    /// folder, or another save's temporary file — are numbered. Everything
    /// below a top-level folder goes inside the one this save creates, so it
    /// cannot meet anything that already existed.
    ///
    /// # Errors
    ///
    /// [`SAVE_WRITE_FAILED`] if `directory` is not a folder, and
    /// [`SAVE_NOTHING`] if the list is empty.
    pub async fn plan(
        directory: &Path,
        files: &[FileDescriptor],
        clip_data_id: Option<u32>,
    ) -> Result<Self, &'static str> {
        match tokio::fs::metadata(directory).await {
            Ok(meta) if meta.is_dir() => {}
            _ => return Err(SAVE_WRITE_FAILED),
        }

        let mut renamed: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut taken: HashSet<String> = HashSet::new();
        let mut items = Vec::with_capacity(files.len());
        for (index, file) in files.iter().enumerate() {
            let Ok(index) = i32::try_from(index) else {
                break;
            };
            let mut components: Vec<String> = file
                .relative_path
                .as_deref()
                .unwrap_or_default()
                .split('\\')
                .filter(|part| !part.is_empty())
                .map(local_component)
                .collect();
            components.push(local_component(&file.name));
            let Some(top) = components.first().cloned() else {
                continue;
            };
            let local_top = if let Some(existing) = renamed.get(&top) {
                existing.clone()
            } else {
                let mut candidate = top.clone();
                let mut n = 2u32;
                while taken.contains(&candidate.to_lowercase())
                    || exists(&directory.join(&candidate)).await
                    || exists(&directory.join(format!("{candidate}{PART_SUFFIX}"))).await
                {
                    candidate = numbered(&top, n);
                    n = n.saturating_add(1);
                    if n > 10_000 {
                        return Err(SAVE_WRITE_FAILED);
                    }
                }
                taken.insert(candidate.to_lowercase());
                renamed.insert(top.clone(), candidate.clone());
                candidate
            };
            let mut local = directory.join(local_top);
            for component in components.iter().skip(1) {
                local.push(component);
            }
            let directory_entry = is_directory(file);
            items.push(Item {
                index,
                remote: remote_path(file),
                local,
                directory: directory_entry,
                size: if directory_entry {
                    None
                } else {
                    file.file_size
                },
            });
        }

        let total_files = items.iter().filter(|item| !item.directory).count();
        if items.is_empty() {
            return Err(SAVE_NOTHING);
        }
        Ok(Self {
            directory: directory.to_path_buf(),
            total_bytes: items
                .iter()
                .filter_map(|item| item.size)
                .fold(0u64, u64::saturating_add),
            total_files: u32::try_from(total_files).unwrap_or(u32::MAX),
            items,
            next: 0,
            current: None,
            clip_data_id,
            next_stream: 1,
            done_bytes: 0,
            done_files: 0,
            reported_bytes: 0,
        })
    }

    /// Whether a File Contents Response with this stream id is this save's.
    #[must_use]
    pub fn expects(&self, stream_id: u32) -> bool {
        self.current
            .as_ref()
            .is_some_and(|current| current.stream == stream_id)
    }

    /// Creates folders and empty files until a file needs bytes from the
    /// server, and asks for them.
    ///
    /// # Errors
    ///
    /// [`SAVE_WRITE_FAILED`] when the folder refuses a write.
    pub async fn advance(
        &mut self,
        events: &mut Vec<ClipboardFiles>,
    ) -> Result<SaveStep, &'static str> {
        while let Some(item) = self.items.get(self.next) {
            let position = self.next;
            let (directory, local, size, index) =
                (item.directory, item.local.clone(), item.size, item.index);
            let remote = item.remote.clone();
            self.next += 1;
            if directory {
                tokio::fs::create_dir_all(&local)
                    .await
                    .map_err(|_| SAVE_WRITE_FAILED)?;
                continue;
            }
            if let Some(parent) = local.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|_| SAVE_WRITE_FAILED)?;
            }
            if size == Some(0) {
                tokio::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&local)
                    .await
                    .map_err(|_| SAVE_WRITE_FAILED)?;
                self.done_files = self.done_files.saturating_add(1);
                events.push(ClipboardFiles::Saved {
                    remote,
                    local: local.display().to_string(),
                    bytes: 0,
                });
                continue;
            }

            let mut part = local.into_os_string();
            part.push(PART_SUFFIX);
            let part = PathBuf::from(part);
            let file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&part)
                .await
                .map_err(|_| SAVE_WRITE_FAILED)?;
            let stream = self.stream();
            self.current = Some(Current {
                item: position,
                part,
                file,
                position: 0,
                size,
                stream,
            });
            return Ok(SaveStep::Request(match size {
                // §2.2.5.3: a SIZE request asks for eight bytes at offset zero.
                None => FileContentsRequest {
                    stream_id: stream,
                    index,
                    flags: FileContentsFlags::SIZE,
                    position: 0,
                    requested_size: 8,
                    data_id: self.clip_data_id,
                },
                Some(size) => self.range(index, stream, 0, size),
            }));
        }
        Ok(SaveStep::Finished(ClipboardFiles::Finished {
            directory: self.directory.display().to_string(),
            files: self.done_files,
            bytes: self.done_bytes,
        }))
    }

    /// Takes one File Contents Response for the file in progress.
    ///
    /// # Errors
    ///
    /// [`SAVE_REFUSED`] when the server answered with a failure or with no
    /// bytes, and [`SAVE_WRITE_FAILED`] when the folder refused them. The
    /// temporary file is left for [`SaveJob::abandon`] to remove.
    pub async fn receive(
        &mut self,
        data: Option<&[u8]>,
        events: &mut Vec<ClipboardFiles>,
    ) -> Result<SaveStep, &'static str> {
        let stream = self.stream();
        let Some(current) = self.current.as_mut() else {
            return self.advance(events).await;
        };
        let Some(bytes) = data else {
            return Err(SAVE_REFUSED);
        };
        let Some(item) = self.items.get(current.item) else {
            return Err(SAVE_REFUSED);
        };
        let index = item.index;

        let Some(size) = current.size else {
            // The answer to a SIZE request: eight bytes, little-endian.
            let Ok(size) = <[u8; 8]>::try_from(bytes).map(u64::from_le_bytes) else {
                return Err(SAVE_REFUSED);
            };
            current.size = Some(size);
            current.stream = stream;
            self.total_bytes = self.total_bytes.saturating_add(size);
            if size == 0 {
                return self.finish_file(events).await;
            }
            return Ok(SaveStep::Request(self.range(index, stream, 0, size)));
        };

        // Nothing, before the end, is a server that will send nothing for
        // ever; asking again would loop.
        if bytes.is_empty() {
            return Err(SAVE_REFUSED);
        }
        let room = usize::try_from(size.saturating_sub(current.position)).unwrap_or(usize::MAX);
        let take = bytes.len().min(room);
        current
            .file
            .write_all(bytes.get(..take).unwrap_or_default())
            .await
            .map_err(|_| SAVE_WRITE_FAILED)?;
        current.position = current.position.saturating_add(take as u64);
        let position = current.position;
        let finished = position >= size;
        if !finished {
            current.stream = stream;
        }
        self.done_bytes = self.done_bytes.saturating_add(take as u64);
        if self.done_bytes.saturating_sub(self.reported_bytes) >= PROGRESS_EVERY_BYTES {
            self.reported_bytes = self.done_bytes;
            events.push(self.progress());
        }

        if finished {
            return self.finish_file(events).await;
        }
        Ok(SaveStep::Request(self.range(index, stream, position, size)))
    }

    /// Stops, removing the temporary file of the one in progress. Files that
    /// finished stay: they are whole, and the user asked for them.
    pub async fn abandon(mut self) {
        if let Some(current) = self.current.take() {
            drop(current.file);
            let _ = tokio::fs::remove_file(&current.part).await;
        }
    }

    async fn finish_file(
        &mut self,
        events: &mut Vec<ClipboardFiles>,
    ) -> Result<SaveStep, &'static str> {
        let Some(mut current) = self.current.take() else {
            return self.advance(events).await;
        };
        let flushed = current.file.flush().await;
        drop(current.file);
        let Some(item) = self.items.get(current.item) else {
            return Err(SAVE_WRITE_FAILED);
        };
        // Checked rather than trusted to `rename`, which replaces an existing
        // file on Unix. The name was free when the save was planned; this is
        // the moment it has to still be.
        let renamed = if flushed.is_ok() && !exists(&item.local).await {
            tokio::fs::rename(&current.part, &item.local).await.is_ok()
        } else {
            false
        };
        if !renamed {
            let _ = tokio::fs::remove_file(&current.part).await;
            return Err(SAVE_WRITE_FAILED);
        }
        self.done_files = self.done_files.saturating_add(1);
        events.push(ClipboardFiles::Saved {
            remote: item.remote.clone(),
            local: item.local.display().to_string(),
            bytes: current.position,
        });
        events.push(self.progress());
        self.advance(events).await
    }

    fn progress(&self) -> ClipboardFiles {
        ClipboardFiles::Saving {
            done_bytes: self.done_bytes,
            total_bytes: self.total_bytes,
            done_files: self.done_files,
            total_files: self.total_files,
        }
    }

    fn range(&self, index: i32, stream: u32, position: u64, size: u64) -> FileContentsRequest {
        let remaining = size.saturating_sub(position);
        FileContentsRequest {
            stream_id: stream,
            index,
            flags: FileContentsFlags::RANGE,
            position,
            requested_size: u32::try_from(remaining.min(u64::from(SAVE_CHUNK_BYTES)))
                .unwrap_or(SAVE_CHUNK_BYTES),
            data_id: self.clip_data_id,
        }
    }

    fn stream(&mut self) -> u32 {
        let stream = self.next_stream;
        self.next_stream = self.next_stream.wrapping_add(1).max(1);
        stream
    }
}

async fn exists(path: &Path) -> bool {
    tokio::fs::symlink_metadata(path).await.is_ok()
}

#[cfg(test)]
#[path = "clipboard_files_tests.rs"]
mod tests;
