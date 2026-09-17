//! PuTTY's saved sessions.
//!
//! PuTTY keeps one set of values per saved session: in the Windows registry
//! under `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\<name>`, and on
//! Unix as one file per session in `~/.putty/sessions`. KiTTY, a PuTTY fork,
//! keeps the same values under `Software\9bis.com\KiTTY\Sessions`. There is no
//! published specification of the values; their names and meanings are PuTTY's
//! own source (`settings.c`), and the session name is escaped the way
//! `mungestr` in its `storage.c` escapes it — `%XX` for a space, `\`, `*`, `?`,
//! `%`, a control character, anything past `~` and a leading `.`.
//!
//! Three ways in, one mapping:
//!
//! - [`parse_reg`] reads what `reg export` writes for the sessions key, which
//!   is how sessions move off a Windows machine.
//! - [`read_session_file`] reads one Unix session file, and [`parse_sessions`]
//!   maps any number of them — a whole `~/.putty/sessions` directory.
//! - [`read_directory`] reads a `~/.putty/sessions` directory, and
//!   `read_registry` — on Windows — the registry key itself, into
//!   [`Session`]s that [`parse_sessions`] maps the same way.
//!
//! | Value | Becomes |
//! |---|---|
//! | `HostName` | The host. A `user@` in front of it is the account. |
//! | `Protocol` | `ssh`; `telnet`, `rlogin`, `raw` and `supdup` keep their names and are reported, having no adapter here. A serial line is left out. |
//! | `PortNumber` | The port, when it is not the protocol's own. |
//! | `UserName`, `PublicKeyFile` | The credential: the account, and the key file as a reference. The key stays on disk. |
//! | `PingIntervalSecs` | The keep-alive interval. |
//! | `ProxyMethod` 6, `ProxyHost` | A gateway: the saved session of that name, a session for that host, or a jump host made for it. |
//! | `Folder` | KiTTY's folder, as a folder. |
//!
//! Connection-level values that differ from PuTTY's defaults — port
//! forwardings, a remote command, agent and X11 forwarding, compression — are
//! kept in `custom_fields` as `putty.<Value>`. The window's fonts, colours and
//! bell are not: they describe PuTTY's terminal, not the server.
//!
//! PuTTY saves no login passwords. The one password it does keep is a proxy's,
//! in the clear; a jump host's is imported like any recovered password, and any
//! other proxy's is dropped and reported.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use remoter_core::{
    ConnectionProps, CredentialRef, FolderProps, GatewayChain, GatewayHop, Inherited, NodeId,
    ProtocolId, SecretKind, validate_host,
};
use zeroize::Zeroize;

use crate::error::{ImportError, ReadFailure};
use crate::limits::Limits;
use crate::mapping::{CredentialPool, clean_name, custom_key, preserve, split_address};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::secret::ImportedSecret;
use crate::xml::as_text;

/// The registry keys PuTTY and KiTTY keep their sessions under, below
/// `HKEY_CURRENT_USER`.
pub const REGISTRY_KEYS: &[&str] = &[
    r"Software\SimonTatham\PuTTY\Sessions",
    r"Software\9bis.com\KiTTY\Sessions",
];

/// The registry key a path names, when it names one of [`REGISTRY_KEYS`]:
/// `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions`, or the same under
/// `HKCU`. Nothing else in the registry is ever read.
#[must_use]
pub fn registry_key(path: &str) -> Option<&'static str> {
    let (hive, key) = path.trim().split_once('\\')?;
    if !hive.eq_ignore_ascii_case("HKEY_CURRENT_USER") && !hive.eq_ignore_ascii_case("HKCU") {
        return None;
    }
    let key = key.trim_end_matches('\\');
    REGISTRY_KEYS
        .iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(key))
}

/// Reads every session file in a directory — PuTTY's `~/.putty/sessions` on
/// Unix, one file per session, named as the session is.
///
/// Only regular files are read, in name order. A link is not followed: the
/// directory is PuTTY's, and a link out of it is not a session PuTTY wrote.
///
/// # Errors
///
/// [`ImportError::ReadFailed`] for a directory or file that cannot be read,
/// [`ImportError::TooManyItems`] past [`Limits::max_nodes`] files, and
/// [`ImportError::TooLarge`] when the files together pass
/// [`Limits::max_input_bytes`].
pub fn read_directory(directory: &Path, limits: &Limits) -> Result<Vec<Session>, ImportError> {
    let failed = |path: &Path, err: &std::io::Error| ImportError::ReadFailed {
        path: path.display().to_string(),
        reason: match err.kind() {
            std::io::ErrorKind::NotFound => ReadFailure::NotFound,
            std::io::ErrorKind::PermissionDenied => ReadFailure::PermissionDenied,
            _ => ReadFailure::Other,
        },
    };
    let mut files = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(|err| failed(directory, &err))? {
        let entry = entry.map_err(|err| failed(directory, &err))?;
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        if files.len() >= limits.max_nodes {
            return Err(ImportError::TooManyItems {
                limit: limits.max_nodes,
                unit: "files",
            });
        }
        files.push(entry.path());
    }
    files.sort();

    let mut total = 0usize;
    let mut sessions = Vec::with_capacity(files.len());
    for path in files {
        let size = std::fs::metadata(&path)
            .map_err(|err| failed(&path, &err))
            .map(|metadata| usize::try_from(metadata.len()).unwrap_or(usize::MAX))?;
        total = total.saturating_add(size);
        if total > limits.max_input_bytes {
            return Err(ImportError::TooLarge {
                size: total,
                limit: limits.max_input_bytes,
            });
        }
        let bytes =
            zeroize::Zeroizing::new(std::fs::read(&path).map_err(|err| failed(&path, &err))?);
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        sessions.push(read_session_file(&bytes, &name, limits)?);
    }
    Ok(sessions)
}

/// Whether this Windows account has sessions under `key`.
#[cfg(windows)]
#[must_use]
pub fn registry_has_sessions(key: &str) -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(key)
        .is_ok_and(|sessions| sessions.enum_keys().next().is_some())
}

/// Reads the sessions under one of [`REGISTRY_KEYS`], as `reg export` would
/// have written them: text values as text, `REG_DWORD`s in decimal, and
/// nothing else.
///
/// # Errors
///
/// [`ImportError::ReadFailed`] when the key cannot be opened, and the same
/// ceilings a file is held to.
#[cfg(windows)]
pub fn read_registry(key: &str, limits: &Limits) -> Result<Vec<Session>, ImportError> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, REG_DWORD, REG_EXPAND_SZ, REG_SZ};
    use winreg::types::FromRegValue;

    let sessions_key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey(key)
        .map_err(|err| ImportError::ReadFailed {
            path: format!("HKEY_CURRENT_USER\\{key}"),
            reason: match err.kind() {
                std::io::ErrorKind::NotFound => ReadFailure::NotFound,
                std::io::ErrorKind::PermissionDenied => ReadFailure::PermissionDenied,
                _ => ReadFailure::Other,
            },
        })?;

    let mut total = 0usize;
    let mut values = 0usize;
    let mut sessions = Vec::new();
    for name in sessions_key.enum_keys() {
        // A key that vanished or refused between listing and reading is not
        // a session any more; the rest still are.
        let Ok(name) = name else { continue };
        let Ok(session_key) = sessions_key.open_subkey(&name) else {
            continue;
        };
        if sessions.len() >= limits.max_nodes {
            return Err(ImportError::TooManyItems {
                limit: limits.max_nodes,
                unit: "sessions",
            });
        }
        let mut session = Session {
            name: unescape_name(&name),
            values: Vec::new(),
        };
        for value in session_key.enum_values() {
            let Ok((value_name, mut raw)) = value else {
                continue;
            };
            values += 1;
            total = total.saturating_add(raw.bytes.len());
            if values > limits.max_items {
                return Err(ImportError::TooManyItems {
                    limit: limits.max_items,
                    unit: "values",
                });
            }
            if total > limits.max_input_bytes {
                return Err(ImportError::TooLarge {
                    size: total,
                    limit: limits.max_input_bytes,
                });
            }
            let text = match raw.vtype {
                REG_SZ | REG_EXPAND_SZ => String::from_reg_value(&raw).ok(),
                REG_DWORD => u32::from_reg_value(&raw)
                    .ok()
                    .map(|number| number.to_string()),
                _ => None,
            };
            // The raw bytes of a proxy password are a copy of it.
            zeroize::Zeroize::zeroize(&mut raw.bytes);
            if let Some(text) = text.filter(|text| text.len() <= limits.max_value_bytes) {
                session.values.push((value_name, text));
            }
        }
        sessions.push(session);
    }
    Ok(sessions)
}

/// The session PuTTY keeps its defaults in. Not a server.
const DEFAULT_SETTINGS: &str = "Default Settings";

/// The folder jump hosts made for a proxy setting go into.
const JUMP_FOLDER: &str = "Jump hosts";

/// The external provider a key file reference is recorded under.
const KEY_FILE_PROVIDER: &str = "putty-key-file";

/// Values kept in `custom_fields` when they differ from PuTTY's default.
const KEPT: &[(&str, &str)] = &[
    ("PortForwardings", ""),
    ("RemoteCommand", ""),
    ("Compression", "0"),
    ("AgentFwd", "0"),
    ("X11Forward", "0"),
    ("TerminalType", "xterm"),
    ("LocalPortAcceptAll", "0"),
    ("RemotePortAcceptAll", "0"),
    ("TCPKeepalives", "0"),
    ("LogHost", ""),
    ("DetachedCertificate", ""),
    ("LocalUserName", ""),
];

/// Proxy values kept when the proxy itself cannot be used. Never the password.
const PROXY_KEPT: &[&str] = &[
    "ProxyMethod",
    "ProxyHost",
    "ProxyPort",
    "ProxyUsername",
    "ProxyTelnetCommand",
];

/// One saved session: its name, unescaped, and its values as text.
///
/// A `REG_DWORD` is carried as its decimal spelling, which is how the Unix
/// files write the same value. The values wipe themselves: one of them can be
/// a proxy password PuTTY stored in the clear.
#[derive(Default)]
pub struct Session {
    /// The name PuTTY lists the session under.
    pub name: String,
    /// Values in the order they were read. A later value of the same name wins.
    pub values: Vec<(String, String)>,
}

impl Drop for Session {
    fn drop(&mut self) {
        for (_, value) in &mut self.values {
            value.zeroize();
        }
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Values are not printed: one of them may be a password.
        f.debug_struct("Session")
            .field("name", &self.name)
            .field("values", &self.values.len())
            .finish()
    }
}

impl Session {
    fn get(&self, key: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }

    fn text(&self, key: &str) -> &str {
        self.get(key).map_or("", str::trim)
    }

    fn number(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|value| value.trim().parse().ok())
    }
}

/// Undoes PuTTY's escaping of a session name.
///
/// The bytes a `%XX` stands for are the machine's own code page on Windows, so
/// a sequence that is not UTF-8 is read one byte to one character — right for
/// Latin-1, and never a refusal.
#[must_use]
pub fn unescape_name(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let hex = bytes
                .get(index + 1..index + 3)
                .and_then(|pair| core::str::from_utf8(pair).ok())
                .and_then(|pair| u8::from_str_radix(pair, 16).ok());
            if let Some(decoded) = hex {
                out.push(decoded);
                index += 3;
                continue;
            }
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out)
        .unwrap_or_else(|err| err.into_bytes().into_iter().map(char::from).collect())
}

/// Reads a `reg export` of PuTTY's or KiTTY's sessions.
///
/// # Errors
///
/// [`ImportError::WrongFormat`] when the file is not a registry export, and the
/// usual bounded-parse refusals. An export with no sessions in it is an empty
/// preview.
pub fn parse_reg(bytes: &[u8], limits: &Limits) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let sessions = read_reg(&text, limits)?;
    parse_sessions(sessions, limits)
}

/// Reads a file that holds PuTTY sessions: a registry export, or one Unix
/// session file named `file_name`.
///
/// # Errors
///
/// As [`parse_reg`] for an export, and the bounded-parse refusals for a
/// session file.
pub fn parse_file(
    bytes: &[u8],
    file_name: &str,
    limits: &Limits,
) -> Result<ImportPreview, ImportError> {
    let head = crate::xml::sniff_head(&bytes[..bytes.len().min(crate::SNIFF_BYTES)]);
    if looks_like_reg(&head) || head.trim_start().starts_with("Windows Registry Editor") {
        return parse_reg(bytes, limits);
    }
    let session = read_session_file(bytes, file_name, limits)?;
    parse_sessions(vec![session], limits)
}

/// Reads one Unix session file: `Key=Value` lines, named by `file_name`.
///
/// # Errors
///
/// The bounded-parse refusals.
pub fn read_session_file(
    bytes: &[u8],
    file_name: &str,
    limits: &Limits,
) -> Result<Session, ImportError> {
    let text = as_text(bytes, limits)?;
    let mut session = Session {
        name: unescape_name(file_name),
        values: Vec::new(),
    };
    for (index, line) in text.lines().enumerate() {
        if index >= limits.max_items {
            return Err(ImportError::TooManyItems {
                limit: limits.max_items,
                unit: "lines",
            });
        }
        if line.len() > limits.max_value_bytes {
            return Err(ImportError::ValueTooLong {
                limit: limits.max_value_bytes,
                unit: "line",
            });
        }
        if let Some((key, value)) = line.split_once('=') {
            if !key.trim().is_empty() {
                session
                    .values
                    .push((key.trim().to_owned(), value.to_owned()));
            }
        }
    }
    Ok(session)
}

/// Maps saved sessions onto the tree they would create.
///
/// # Errors
///
/// The node ceiling, or a value the domain model refuses to build — both
/// failures of the whole parse. A session that cannot be a connection is
/// reported, not raised.
pub fn parse_sessions(
    sessions: Vec<Session>,
    limits: &Limits,
) -> Result<ImportPreview, ImportError> {
    let mut builder = PreviewBuilder::new(SourceFormat::Putty, *limits);
    let mut mapper = Mapper::new();
    let mut sort = 0i64;
    for session in &sessions {
        if mapper.session(&mut builder, session, sort)? {
            sort += 1;
        }
    }
    mapper.finish(&mut builder)?;
    Ok(builder.finish())
}

/// The sessions a registry export holds.
fn read_reg(text: &str, limits: &Limits) -> Result<Vec<Session>, ImportError> {
    let mut lines = text.lines().enumerate().peekable();
    let header = loop {
        match lines.next() {
            Some((_, line)) if line.trim().is_empty() => {}
            Some((_, line)) => break line.trim().trim_start_matches('\u{feff}').to_owned(),
            None => break String::new(),
        }
    };
    if header != "Windows Registry Editor Version 5.00" && header != "REGEDIT4" {
        return Err(ImportError::WrongFormat {
            expected: "a registry export of PuTTY's sessions",
        });
    }

    let mut sessions: Vec<Session> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut current: Option<usize> = None;
    while let Some((index, line)) = lines.next() {
        if index >= limits.max_items {
            return Err(ImportError::TooManyItems {
                limit: limits.max_items,
                unit: "lines",
            });
        }
        if line.len() > limits.max_value_bytes {
            return Err(ImportError::ValueTooLong {
                limit: limits.max_value_bytes,
                unit: "line",
            });
        }
        let trimmed = line.trim();
        if let Some(key) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = session_name(key).map(|name| {
                *by_name.entry(name.clone()).or_insert_with(|| {
                    sessions.push(Session {
                        name,
                        values: Vec::new(),
                    });
                    sessions.len() - 1
                })
            });
            continue;
        }
        // A binary or expandable value runs on over lines ending in `\`. None
        // of PuTTY's values is one; the continuation is read past, not read.
        if trimmed.ends_with('\\') && !trimmed.contains("=\"") {
            while let Some((_, next)) = lines.peek() {
                let next = next.trim();
                lines.next();
                if !next.ends_with('\\') {
                    break;
                }
            }
            continue;
        }
        let Some(session) = current.and_then(|at| sessions.get_mut(at)) else {
            continue;
        };
        if let Some((name, value)) = reg_value(trimmed) {
            session.values.push((name, value));
        }
    }
    Ok(sessions)
}

/// The session a registry key path names, if it names one.
fn session_name(key: &str) -> Option<String> {
    if key.starts_with('-') {
        return None;
    }
    let parts: Vec<&str> = key.split('\\').collect();
    let at = parts
        .iter()
        .position(|part| part.eq_ignore_ascii_case("Sessions"))?;
    let (vendor, product) = (parts.get(at.checked_sub(2)?)?, parts.get(at - 1)?);
    let known = (vendor.eq_ignore_ascii_case("SimonTatham")
        && product.eq_ignore_ascii_case("PuTTY"))
        || (vendor.eq_ignore_ascii_case("9bis.com") && product.eq_ignore_ascii_case("KiTTY"));
    // Exactly one level below `Sessions`: deeper keys are a session's own
    // subkeys, not sessions.
    (known && parts.len() == at + 2).then(|| unescape_name(parts[at + 1]))
}

/// One `"Name"=value` line, with a string unescaped and a `dword` in decimal.
fn reg_value(line: &str) -> Option<(String, String)> {
    let (name, rest) = quoted(line.strip_prefix('"')?)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    if let Some(string) = rest.strip_prefix('"') {
        let (value, _) = quoted(string)?;
        return Some((name, value));
    }
    let hex = rest.strip_prefix("dword:")?;
    let value = u32::from_str_radix(hex.trim(), 16).ok()?;
    Some((name, value.to_string()))
}

/// A quoted string's content up to its closing quote, and what follows it.
/// `\\` and `\"` are the two escapes `reg export` writes.
fn quoted(text: &str) -> Option<(String, &str)> {
    let mut value = String::new();
    let mut chars = text.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return Some((value, &text[at + 1..])),
            '\\' => match chars.next() {
                Some((_, escaped)) => value.push(escaped),
                None => return None,
            },
            c => value.push(c),
        }
    }
    None
}

/// Whether a document's head reads as a registry export of PuTTY's sessions.
pub(crate) fn looks_like_reg(head: &str) -> bool {
    let first = head
        .lines()
        .map(|line| line.trim().trim_start_matches('\u{feff}'))
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    if first != "Windows Registry Editor Version 5.00" && first != "REGEDIT4" {
        return false;
    }
    head.lines()
        .filter_map(|line| line.trim().strip_prefix('['))
        .any(|key| session_name(key.trim_end_matches(']')).is_some())
}

/// Whether a document's head reads as one Unix session file.
pub(crate) fn looks_like_session_file(head: &str) -> bool {
    let starts = |prefix: &str| head.lines().any(|line| line.starts_with(prefix));
    starts("HostName=") && starts("Protocol=")
}

/// A proxy setting on a session that named a jump host.
struct PendingJump {
    connection: NodeId,
    connection_name: String,
    target: String,
    port: Option<u16>,
    username: String,
    password: Option<ImportedSecret>,
}

struct Mapper {
    credentials: CredentialPool,
    folders: HashMap<String, NodeId>,
    next_folder_sort: i64,
    by_name: HashMap<String, NodeId>,
    /// Sessions by the host and port they reach, for a proxy host that names a
    /// machine rather than a session.
    by_address: HashMap<(String, u16), NodeId>,
    pending: Vec<PendingJump>,
    secrets: usize,
}

impl Mapper {
    fn new() -> Self {
        Self {
            credentials: CredentialPool::new("Imported credentials"),
            folders: HashMap::new(),
            next_folder_sort: 0,
            by_name: HashMap::new(),
            by_address: HashMap::new(),
            pending: Vec::new(),
            secrets: 0,
        }
    }

    /// Maps one session. Returns whether it became a node.
    fn session(
        &mut self,
        builder: &mut PreviewBuilder,
        session: &Session,
        sort: i64,
    ) -> Result<bool, ImportError> {
        let limits = *builder.limits();
        if session.name == DEFAULT_SETTINGS {
            return Ok(false);
        }
        let name = clean_name(&session.name);
        let skip = |builder: &mut PreviewBuilder, item: String, reason| {
            builder.report_mut().counts_mut().skipped += 1;
            builder
                .report_mut()
                .push(&limits, Finding::SkippedItem { item, reason });
        };
        if name.is_empty() {
            skip(builder, String::from("?"), SkipReason::UnusableName);
            return Ok(false);
        }

        let raw_protocol = session.text("Protocol").to_ascii_lowercase();
        let raw_protocol = if raw_protocol.is_empty() {
            String::from("ssh")
        } else {
            raw_protocol
        };
        if raw_protocol == "serial" {
            skip(builder, name, SkipReason::UnsupportedKind);
            return Ok(false);
        }
        let Ok(protocol) = ProtocolId::new(raw_protocol.as_str()) else {
            skip(builder, name, SkipReason::UnsupportedKind);
            return Ok(false);
        };

        let written = session.text("HostName");
        let (account, address) = match written.rsplit_once('@') {
            Some((account, address)) => (account.trim(), address.trim()),
            None => ("", written),
        };
        let Some((host, address_port)) =
            split_address(address).filter(|(host, _)| validate_host(host).is_ok())
        else {
            let reason = if written.is_empty() {
                SkipReason::Empty
            } else {
                SkipReason::UnusableHost
            };
            skip(builder, name, reason);
            return Ok(false);
        };

        let own_port = default_port(&raw_protocol);
        let port = address_port.or_else(|| {
            session
                .number("PortNumber")
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port != 0 && Some(*port) != own_port)
        });
        let parent = self.folder(builder, session.text("Folder"), &limits)?;

        let mut props = ConnectionProps::new(protocol.as_str(), host.clone())?;
        props.port = port.map_or(Inherited::Inherit, Inherited::Explicit);
        props.credential = self.credential(builder, session, &name, account, &protocol)?;
        let keepalive = session
            .number("PingIntervalSecs")
            .filter(|secs| *secs > 0)
            .or_else(|| {
                session
                    .number("PingInterval")
                    .filter(|minutes| *minutes > 0)
                    .map(|minutes| minutes.saturating_mul(60))
            })
            .and_then(|secs| u32::try_from(secs).ok());
        props.keepalive_secs = keepalive.map_or(Inherited::Inherit, Inherited::Explicit);

        let id = NodeId::new();
        let mut node =
            PreviewNode::new(id, name.clone(), PreviewKind::Connection(props)).under(parent, sort);
        let mut kept = 0usize;
        if raw_protocol != "ssh" {
            builder.report_mut().push(
                &limits,
                Finding::UnknownProtocol {
                    item: name.clone(),
                    protocol: clean_name(&raw_protocol),
                    mapped_to: protocol.as_str().to_owned(),
                },
            );
            kept += usize::from(keep(&mut node, "Protocol", &raw_protocol, &limits));
        }
        for (key, default) in KEPT {
            let value = session.text(key);
            if !value.is_empty() && value != *default {
                kept += usize::from(keep(&mut node, key, value, &limits));
            }
        }
        kept += self.proxy(builder, session, &mut node, &name, &limits);
        if kept > 0 {
            builder.report_mut().push(
                &limits,
                Finding::SettingsPreserved {
                    item: name.clone(),
                    count: kept,
                },
            );
        }

        builder.push(node)?;
        self.by_name.entry(name).or_insert(id);
        self.by_address
            .entry((host.to_ascii_lowercase(), port.or(own_port).unwrap_or(0)))
            .or_insert(id);
        Ok(true)
    }

    /// The session's account and key file, as a credential reference.
    fn credential(
        &mut self,
        builder: &mut PreviewBuilder,
        session: &Session,
        name: &str,
        account: &str,
        protocol: &ProtocolId,
    ) -> Result<Inherited<CredentialRef>, ImportError> {
        let username = match session.text("UserName") {
            "" => account,
            written => written,
        };
        let key_file = session.text("PublicKeyFile");
        if username.is_empty() && key_file.is_empty() {
            return Ok(Inherited::Inherit);
        }
        let secret = if !key_file.is_empty() {
            PreviewSecret::Unsealed(SecretKind::External {
                provider: KEY_FILE_PROVIDER.to_owned(),
                reference: key_file.to_owned(),
            })
        } else if protocol.as_str() == "ssh" {
            // PuTTY tries Pageant first unless told not to, and with no key
            // named the agent is what answers.
            PreviewSecret::Unsealed(SecretKind::Agent {
                comment_filter: None,
            })
        } else {
            PreviewSecret::not_carried(b"")
        };
        let reference = self.credentials.intern(
            builder,
            name,
            username.to_owned(),
            None,
            secret,
            vec![protocol.clone()],
        )?;
        Ok(Inherited::Explicit(reference))
    }

    /// Reads the session's proxy setting. Returns how many values it kept.
    fn proxy(
        &mut self,
        builder: &mut PreviewBuilder,
        session: &Session,
        node: &mut PreviewNode,
        name: &str,
        limits: &Limits,
    ) -> usize {
        let method = session.number("ProxyMethod").or_else(|| {
            // Before PuTTY 0.77 the setting was `ProxyType`, with SOCKS's
            // version in a value of its own.
            Some(match session.number("ProxyType")? {
                1 => 3,
                2 if session.number("ProxySOCKSVersion") == Some(4) => 1,
                2 => 2,
                3 => 4,
                4 => 5,
                _ => 0,
            })
        });
        let host = session.text("ProxyHost");
        let password = session.text("ProxyPassword");
        let kind = match method {
            None | Some(0) => return 0,
            Some(1) => "socks4",
            Some(2) => "socks5",
            Some(3) => "http",
            Some(4) => "telnet",
            Some(5) => "command",
            Some(6) => {
                if host.is_empty() {
                    return 0;
                }
                self.pending.push(PendingJump {
                    connection: node.id,
                    connection_name: name.to_owned(),
                    target: host.to_owned(),
                    port: session
                        .number("ProxyPort")
                        .and_then(|port| u16::try_from(port).ok())
                        .filter(|port| *port != 0),
                    username: session.text("ProxyUsername").to_owned(),
                    password: (!password.is_empty()).then(|| ImportedSecret::from(password)),
                });
                return 0;
            }
            Some(7) => "ssh-exec",
            Some(8) => "ssh-subsystem",
            Some(_) => "unknown",
        };
        let shown = if kind == "command" {
            session.text("ProxyTelnetCommand")
        } else {
            host
        };
        builder.report_mut().push(
            limits,
            Finding::ProxyNotSupported {
                item: name.to_owned(),
                proxy: kind.to_owned(),
                host: clean_name(shown),
            },
        );
        if !password.is_empty() {
            builder.report_mut().push(
                limits,
                Finding::SecretNotMapped {
                    item: name.to_owned(),
                    field: String::from("ProxyPassword"),
                },
            );
        }
        PROXY_KEPT
            .iter()
            .filter(|key| !session.text(key).is_empty())
            .filter(|key| keep(node, key, session.text(key), limits))
            .count()
    }

    /// The folder KiTTY filed a session under, made on first use.
    fn folder(
        &mut self,
        builder: &mut PreviewBuilder,
        path: &str,
        limits: &Limits,
    ) -> Result<Option<NodeId>, ImportError> {
        let mut parent = None;
        let mut prefix = String::new();
        for (depth, segment) in path.split(['/', '\\']).enumerate() {
            let segment = clean_name(segment);
            if segment.is_empty() {
                continue;
            }
            if depth >= limits.max_depth {
                return Err(ImportError::TooDeep {
                    limit: limits.max_depth,
                });
            }
            prefix.push('/');
            prefix.push_str(&segment);
            parent = Some(match self.folders.get(&prefix) {
                Some(id) => *id,
                None => {
                    let node = PreviewNode::new(
                        NodeId::new(),
                        segment,
                        PreviewKind::Folder(FolderProps::default()),
                    )
                    .under(parent, self.next_folder_sort);
                    self.next_folder_sort += 1;
                    let id = builder.push(node)?;
                    self.folders.insert(prefix.clone(), id);
                    id
                }
            });
        }
        Ok(parent)
    }

    /// Resolves the jump hosts the proxy settings named.
    fn finish(mut self, builder: &mut PreviewBuilder) -> Result<(), ImportError> {
        let limits = *builder.limits();
        let mut jump_folder = None;
        let mut made: BTreeMap<(String, u16, String), NodeId> = BTreeMap::new();
        let mut jump_sort = 0i64;
        for jump in core::mem::take(&mut self.pending) {
            let port = jump.port.unwrap_or(22);
            let named = self.by_name.get(&clean_name(&jump.target)).copied();
            let target = split_address(&jump.target);
            let addressed = target.as_ref().and_then(|(host, own)| {
                self.by_address
                    .get(&(host.to_ascii_lowercase(), own.unwrap_or(port)))
                    .copied()
            });
            let hop = match named.or(addressed) {
                Some(hop) if hop != jump.connection => {
                    builder.report_mut().push(
                        &limits,
                        Finding::GatewayMapped {
                            item: jump.connection_name,
                            hops: 1,
                        },
                    );
                    hop
                }
                Some(_) => continue,
                None => {
                    let Some((host, own)) = target.filter(|(host, _)| validate_host(host).is_ok())
                    else {
                        builder.report_mut().push(
                            &limits,
                            Finding::GatewayUnresolved {
                                item: jump.connection_name,
                                target: clean_name(&jump.target),
                            },
                        );
                        continue;
                    };
                    let port = own.unwrap_or(port);
                    let key = (host.to_ascii_lowercase(), port, jump.username.clone());
                    let hop = match made.get(&key) {
                        Some(hop) => *hop,
                        None => {
                            let folder = match jump_folder {
                                Some(folder) => folder,
                                None => {
                                    let node = PreviewNode::new(
                                        NodeId::new(),
                                        JUMP_FOLDER.to_owned(),
                                        PreviewKind::Folder(FolderProps::default()),
                                    )
                                    .under(None, i64::MAX - 1);
                                    let id = builder.push(node)?;
                                    jump_folder = Some(id);
                                    id
                                }
                            };
                            let hop_name = clean_name(&host);
                            let mut props = ConnectionProps::new("ssh", host)?;
                            props.port = if port == 22 {
                                Inherited::Inherit
                            } else {
                                Inherited::Explicit(port)
                            };
                            if !jump.username.is_empty() || jump.password.is_some() {
                                let secret = match jump.password {
                                    Some(password) => {
                                        self.secrets += 1;
                                        PreviewSecret::Password(password)
                                    }
                                    None => PreviewSecret::Unsealed(SecretKind::Agent {
                                        comment_filter: None,
                                    }),
                                };
                                props.credential = Inherited::Explicit(self.credentials.intern(
                                    builder,
                                    &hop_name,
                                    jump.username.clone(),
                                    None,
                                    secret,
                                    vec![ProtocolId::new("ssh")?],
                                )?);
                            }
                            let id = NodeId::new();
                            let node =
                                PreviewNode::new(id, hop_name, PreviewKind::Connection(props))
                                    .under(Some(folder), jump_sort);
                            jump_sort += 1;
                            builder.push(node)?;
                            made.insert(key, id);
                            id
                        }
                    };
                    builder.report_mut().push(
                        &limits,
                        Finding::GatewaySynthesised {
                            item: jump.connection_name,
                            target: clean_name(&jump.target),
                        },
                    );
                    hop
                }
            };
            builder.set_gateway(
                jump.connection,
                Inherited::Explicit(GatewayChain {
                    hops: vec![GatewayHop::new(hop)],
                }),
            );
        }
        if self.secrets > 0 {
            builder.report_mut().push(
                &limits,
                Finding::SecretsRecovered {
                    count: self.secrets,
                },
            );
        }
        self.credentials.finish(builder);
        Ok(())
    }
}

/// The port a protocol listens on when PuTTY is not told otherwise.
fn default_port(protocol: &str) -> Option<u16> {
    match protocol {
        "ssh" => Some(22),
        "telnet" => Some(23),
        "rlogin" => Some(513),
        "supdup" => Some(95),
        _ => None,
    }
}

/// Keeps one value in `custom_fields` as `putty.<key>`.
fn keep(node: &mut PreviewNode, key: &str, value: &str, limits: &Limits) -> bool {
    custom_key("putty", key)
        .is_some_and(|key| preserve(node, key, value.to_owned(), limits.max_custom_fields))
}

#[cfg(test)]
#[path = "putty_tests.rs"]
mod tests;
