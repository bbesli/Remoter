//! The OpenSSH config writer: one `Host` block per SSH or SFTP connection.
//!
//! What `ssh` would need to reach the same machine the same way: `HostName`,
//! `Port`, `User`, `IdentityFile`, `ProxyJump`, `ConnectTimeout` and
//! `ServerAliveInterval` — the keywords [`crate::ssh_config`] reads back — from
//! each connection's effective values. There is no `Host *` block: a folder's
//! defaults are written into every connection that inherits them, because a
//! block of defaults would also apply to every host in the user's own config
//! that this file is `Include`d beside.
//!
//! # Aliases
//!
//! A `Host` line takes patterns, not names. `*`, `?`, `!` and `,` mean
//! something there, whitespace separates patterns, and `ssh` lowercases the
//! host it was given before matching — so a block for `Web 01` could never be
//! selected. Each connection gets an alias made of lowercase ASCII letters,
//! digits, `.`, `_` and `-`, made unique with a numeric suffix, and a
//! connection whose alias is more than its name lowercased is named in the
//! report.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use remoter_core::{CoreError, GatewayChain, Node, NodeId, SecretKind, Tree};

use super::{ExportNote, ExportReport, GatewayProblem, Scope};

/// The first lines of the file.
const HEADER: &str = "\
# OpenSSH client configuration, written by Remoter.
#
# No password, private key or passphrase is in this file. An IdentityFile line
# is the path of a key file that was already on disk, not the key itself.
";

/// Whether `ssh` itself would make this connection. SFTP rides on an SSH
/// connection and reads the same config.
fn speaks_ssh(protocol: &remoter_core::ProtocolId) -> bool {
    matches!(protocol.as_str(), "ssh" | "sftp")
}

/// The port `ssh` uses when none is given, so the one not worth writing.
const SSH_PORT: u16 = 22;

/// The provider the importer gives a credential that is an `IdentityFile`
/// path. Kept in step with `crate::ssh_config::credential`.
const IDENTITY_FILE_PROVIDER: &str = "openssh-identity-file";

pub(super) fn write(
    tree: &Tree,
    scope: &Scope<'_>,
    report: &mut ExportReport,
) -> Result<Vec<u8>, CoreError> {
    let mut connections: Vec<&Node> = Vec::new();
    for node in scope.connections() {
        let Some(props) = node.kind.as_connection() else {
            continue;
        };
        if speaks_ssh(&props.protocol) {
            connections.push(node);
        } else {
            report.skipped += 1;
            report.note(ExportNote::UnsupportedProtocol {
                item: node.name.clone(),
                protocol: props.protocol.as_str().to_owned(),
            });
        }
    }

    let aliases = assign_aliases(&connections, report);
    let mut out = String::from(HEADER);
    for node in connections {
        let Some(alias) = aliases.get(&node.id) else {
            continue;
        };
        let effective = tree.effective_connection(node.id)?;

        out.push('\n');
        line(&mut out, "Host", alias);
        line(&mut out, "HostName", &host_name(&effective.host));
        if let Some(port) = effective.port.value.filter(|port| *port != SSH_PORT) {
            line(&mut out, "Port", &port.to_string());
        }
        if let Some(user) = effective
            .username
            .value
            .as_deref()
            .filter(|u| !u.is_empty())
        {
            // `%` is a token in `User` on current OpenSSH and a literal on
            // older ones; there is no spelling both read the same way.
            match argument(user).filter(|_| !user.contains('%')) {
                Some(user) => line(&mut out, "User", &user),
                None => value_not_written(report, node, "user"),
            }
        }
        if let Some(path) = identity_file(tree, &effective) {
            match argument(path) {
                Some(path) => line(&mut out, "IdentityFile", &path),
                None => value_not_written(report, node, "identity-file"),
            }
        }
        if let Some(jump) = proxy_jump(tree, node, &effective.gateway.value, &aliases, report)? {
            line(&mut out, "ProxyJump", &jump);
        }
        if let Some(ms) = effective.connect_timeout_ms.value.filter(|ms| *ms > 0) {
            line(&mut out, "ConnectTimeout", &ms.div_ceil(1000).to_string());
        }
        if let Some(secs) = effective.keepalive_secs.value.filter(|secs| *secs > 0) {
            line(&mut out, "ServerAliveInterval", &secs.to_string());
        }
        report.written += 1;
    }

    Ok(out.into_bytes())
}

fn line(out: &mut String, keyword: &str, value: &str) {
    let indent = if keyword == "Host" { "" } else { "    " };
    // Writing to a `String` cannot fail.
    let _ = writeln!(out, "{indent}{keyword} {value}");
}

fn value_not_written(report: &mut ExportReport, node: &Node, field: &str) {
    report.note(ExportNote::ValueNotWritten {
        item: node.name.clone(),
        field: field.to_owned(),
    });
}

/// Gives every connection a `Host` alias no other one has.
fn assign_aliases(connections: &[&Node], report: &mut ExportReport) -> HashMap<NodeId, String> {
    let mut taken: HashSet<String> = HashSet::new();
    let mut aliases = HashMap::new();
    for node in connections {
        let host = node
            .kind
            .as_connection()
            .map_or("", |props| props.host.as_str());
        let mut base = alias_of(&node.name);
        if base.is_empty() {
            base = alias_of(host);
        }
        if base.is_empty() {
            base = String::from("host");
        }
        let mut alias = base.clone();
        let mut suffix = 2u32;
        while !taken.insert(alias.clone()) {
            alias = format!("{base}-{suffix}");
            suffix = suffix.saturating_add(1);
        }
        if !alias.eq_ignore_ascii_case(&node.name) {
            report.note(ExportNote::Renamed {
                item: node.name.clone(),
                written: alias.clone(),
            });
        }
        aliases.insert(node.id, alias);
    }
    aliases
}

/// A name reduced to the characters a `Host` pattern can hold literally.
///
/// Accented Latin letters lose their accents rather than vanishing — `Üretim`
/// becomes `uretim`, not `retim` — and runs of anything else become one `-`,
/// with none left at either end.
fn alias_of(name: &str) -> String {
    let mut alias = String::new();
    for c in name.chars().flat_map(char::to_lowercase) {
        let folded = fold(c);
        if let Some(plain) = folded {
            alias.push_str(plain);
        } else if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
            alias.push(c);
        } else if c == '\u{307}' {
            // The combining dot `İ` lowercases into, after its `i`.
        } else if !alias.is_empty() && !alias.ends_with('-') {
            alias.push('-');
        }
    }
    while alias.ends_with('-') {
        alias.pop();
    }
    alias
}

/// The unaccented spelling of a lowercase Latin letter, for the letters the
/// ten shipped languages and their neighbours write.
const fn fold(c: char) -> Option<&'static str> {
    Some(match c {
        'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'ą' | 'ă' => "a",
        'æ' => "ae",
        'ç' | 'ć' | 'č' => "c",
        'ď' | 'đ' => "d",
        'è' | 'é' | 'ê' | 'ë' | 'ę' | 'ě' => "e",
        'ğ' => "g",
        'ì' | 'í' | 'î' | 'ï' | 'ı' => "i",
        'ł' => "l",
        'ñ' | 'ń' | 'ň' => "n",
        'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'ő' => "o",
        'œ' => "oe",
        'ř' => "r",
        'ś' | 'ş' | 'š' | 'ș' => "s",
        'ß' => "ss",
        'ť' | 'ț' => "t",
        'ù' | 'ú' | 'û' | 'ü' | 'ů' | 'ű' => "u",
        'ý' | 'ÿ' => "y",
        'ź' | 'ż' | 'ž' => "z",
        _ => return None,
    })
}

/// `HostName` as `ssh` wants it: an IPv6 literal without the brackets the
/// domain model keeps it in, and a `%` doubled so it is not read as a token.
fn host_name(host: &str) -> String {
    let bare = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    bare.replace('%', "%%")
}

/// An argument quoted if it has to be, or `None` if it cannot be.
///
/// `readconf.c` keeps a double-quoted argument together and has no escape for
/// a `"` inside one, so a value with a quote in it cannot be written. A control
/// character would end the line or hide in it.
fn argument(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('"') || value.chars().any(char::is_control) {
        return None;
    }
    if value.contains(|c: char| c.is_whitespace() || c == '#' || c == '=') {
        Some(format!("\"{value}\""))
    } else {
        Some(value.to_owned())
    }
}

/// The key file path a connection's credential names, if it names one.
fn identity_file<'t>(
    tree: &'t Tree,
    effective: &remoter_core::EffectiveConnection,
) -> Option<&'t str> {
    let reference = effective.credential.value.as_ref()?;
    if reference.is_deleted() {
        return None;
    }
    match &tree.get(reference.id())?.kind.as_credential()?.secret {
        SecretKind::External {
            provider,
            reference,
        } if provider == IDENTITY_FILE_PROVIDER => Some(reference.as_str()),
        _ => None,
    }
}

/// The `ProxyJump` value for a connection's route.
///
/// A hop that is itself in the file is named by its alias, so its own `User`
/// and `Port` apply to it. A hop that is not is written out in full as
/// `[user@]host[:port]`.
fn proxy_jump(
    tree: &Tree,
    node: &Node,
    chain: &GatewayChain,
    aliases: &HashMap<NodeId, String>,
    report: &mut ExportReport,
) -> Result<Option<String>, CoreError> {
    let mut hops: Vec<String> = Vec::new();
    let mut hop_credential = false;
    for hop in &chain.hops {
        let target = tree
            .get(hop.node.id())
            .filter(|target| !hop.node.is_deleted() && target.deleted_at.is_none());
        let Some(target) = target else {
            gateway_not_written(report, node, GatewayProblem::DeletedHop);
            return Ok(None);
        };
        let is_ssh = target
            .kind
            .as_connection()
            .is_some_and(|props| speaks_ssh(&props.protocol));
        if !is_ssh {
            gateway_not_written(report, node, GatewayProblem::HopNotSsh);
            return Ok(None);
        }
        hop_credential |= hop.credential.is_some();

        // `aliases` holds exactly the connections in the file.
        if let Some(alias) = aliases.get(&target.id) {
            hops.push(alias.clone());
            continue;
        }
        let effective = tree.effective_connection(target.id)?;
        let mut spec = String::new();
        if let Some(user) = effective
            .username
            .value
            .as_deref()
            .filter(|u| !u.is_empty())
        {
            if user.contains(|c: char| c.is_whitespace() || c.is_control() || ",\"#%".contains(c)) {
                value_not_written(report, node, "proxy-jump-user");
            } else {
                spec.push_str(user);
                spec.push('@');
            }
        }
        // The brackets stay here: in `host:port` they are what tells the colons
        // of the address from the one before the port.
        spec.push_str(&effective.host);
        if let Some(port) = effective.port.value.filter(|port| *port != SSH_PORT) {
            spec.push(':');
            spec.push_str(&port.to_string());
        }
        hops.push(spec);
    }
    if hop_credential {
        gateway_not_written(report, node, GatewayProblem::HopCredential);
    }
    Ok((!hops.is_empty()).then(|| hops.join(",")))
}

fn gateway_not_written(report: &mut ExportReport, node: &Node, reason: GatewayProblem) {
    report.note(ExportNote::GatewayNotWritten {
        item: node.name.clone(),
        reason,
    });
}
