//! OpenSSH's `known_hosts`, read into host keys for the trust store.
//!
//! The format is sshd(8)'s *SSH_KNOWN_HOSTS FILE FORMAT*: one key per line, as
//! an optional marker, a comma-separated list of host names, the key type, the
//! base64 key and an optional comment. A name is a host, or `[host]:port` for
//! a port other than 22, or a pattern with `*`, `?` and a negating `!`; or it
//! is hashed — `|1|salt|hash`, where the hash is HMAC-SHA1 over the name keyed
//! with the salt — so that a stolen file does not list the machines it trusts.
//!
//! A hashed name and a pattern name no host by themselves. They are compared
//! against the hosts the caller hands in — the vault's connections — which is
//! the same question `ssh` asks of them, one host at a time. A plain name needs
//! nothing to be compared with and is taken as written.
//!
//! What this module does not decide is what to trust. It hands back every key
//! the file vouches for, and the IPC layer compares each with what the vault
//! already trusts: a key the vault holds a *different* one for is never
//! replaced by an import.
//!
//! Lines marked `@cert-authority` trust a certificate authority rather than a
//! key, and are counted rather than read. A key marked `@revoked` is never
//! returned, however many other lines vouch for it.

use std::collections::{HashMap, HashSet};

use data_encoding::BASE64;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::error::ImportError;
use crate::limits::Limits;
use crate::ssh_config::pattern;
use crate::xml::as_text;

/// How many hashed-name comparisons one parse may make, per line the limits
/// allow.
///
/// Each hashed line is compared with every host handed in, and each comparison
/// is an HMAC. Three hundred connections against a thousand hashed lines is
/// three hundred thousand; the default limits allow two million, which is well
/// under a second, and a file past that ends in a count rather than a hang.
const HASH_CHECKS_PER_LINE: usize = 10;

/// The port a name without one means.
const SSH_PORT: u16 = 22;

/// One key the file vouches for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// The host: a DNS name or IPv4 address as written, or a bracketed IPv6
    /// literal. Lower case.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The key's type, as the file names it and the key's own bytes confirm:
    /// `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`.
    pub algorithm: String,
    /// The public key blob. Public by definition.
    pub blob: Vec<u8>,
}

/// What a `known_hosts` file holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownHostsFile {
    /// Every key the file vouches for, one per host, port and key type, in
    /// file order.
    pub keys: Vec<HostKey>,
    /// Lines that are entries, as opposed to blank lines and comments.
    pub entries: usize,
    /// Hashed names that matched none of the hosts they were compared with.
    pub hashed_unmatched: usize,
    /// Hashed names left uncompared because the comparison budget ran out.
    pub hashed_unchecked: usize,
    /// Pattern names that matched none of the hosts they were compared with.
    pub patterns_unmatched: usize,
    /// Keys the file marks `@revoked`.
    pub revoked: usize,
    /// Lines marked `@cert-authority`.
    pub certificate_authorities: usize,
    /// A host, port and key type the file vouches for twice, with different
    /// keys. The first is kept.
    pub conflicting: usize,
    /// Lines that are not an entry this reader understands: a missing field,
    /// base64 that is not, a key whose bytes name another type than the line.
    pub malformed: usize,
}

/// Reads a `known_hosts` file.
///
/// `hosts` are the host and port pairs hashed and pattern names are compared
/// with, hosts as the vault stores them.
///
/// # Errors
///
/// The bounded-parse refusals. A line this reader cannot use is counted, not
/// raised.
pub fn parse(
    bytes: &[u8],
    hosts: &[(String, u16)],
    limits: &Limits,
) -> Result<KnownHostsFile, ImportError> {
    let text = as_text(bytes, limits)?;
    // What OpenSSH looks each host up by: `host`, or `[host]:port` off port
    // 22, with an IPv6 literal unbracketed inside either.
    let subjects: Vec<(String, String, u16)> = hosts
        .iter()
        .map(|(host, port)| {
            let host = host.to_ascii_lowercase();
            (subject_of(&host, *port), host, *port)
        })
        .collect();

    let mut file = KnownHostsFile::default();
    let mut revoked: HashSet<Vec<u8>> = HashSet::new();
    let mut seen: HashMap<(String, u16, String), usize> = HashMap::new();
    let mut hash_checks = 0usize;
    let hash_budget = limits.max_items.saturating_mul(HASH_CHECKS_PER_LINE);

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
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        file.entries += 1;

        let mut fields = line.split_whitespace();
        let mut first = fields.next().unwrap_or_default();
        let marker = first.strip_prefix('@');
        if marker.is_some() {
            first = fields.next().unwrap_or_default();
        }
        let (Some(algorithm), Some(encoded)) = (fields.next(), fields.next()) else {
            file.malformed += 1;
            continue;
        };
        let names = first;
        let Some(blob) = key_blob(algorithm, encoded) else {
            file.malformed += 1;
            continue;
        };
        match marker {
            None => {}
            Some("revoked") => {
                file.revoked += 1;
                revoked.insert(blob);
                continue;
            }
            Some("cert-authority") => {
                file.certificate_authorities += 1;
                continue;
            }
            Some(_) => {
                file.malformed += 1;
                continue;
            }
        }

        let mut vouched: Vec<(String, u16)> = Vec::new();
        let patterns: Vec<&str> = names.split(',').filter(|name| !name.is_empty()).collect();
        let is_pattern = |name: &str| name.contains(['*', '?']) || name.starts_with('!');

        for name in &patterns {
            if let Some(hashed) = name.strip_prefix("|1|") {
                let Some((salt, hash)) = hashed.split_once('|').and_then(|(salt, hash)| {
                    Some((
                        BASE64.decode(salt.as_bytes()).ok()?,
                        BASE64.decode(hash.as_bytes()).ok()?,
                    ))
                }) else {
                    file.malformed += 1;
                    continue;
                };
                if hash_checks.saturating_add(subjects.len()) > hash_budget {
                    file.hashed_unchecked += 1;
                    continue;
                }
                hash_checks += subjects.len();
                let before = vouched.len();
                for (subject, host, port) in &subjects {
                    if hashes_to(&salt, subject, &hash) {
                        vouched.push((host.clone(), *port));
                    }
                }
                if vouched.len() == before {
                    file.hashed_unmatched += 1;
                }
            } else if is_pattern(name) {
                if name.starts_with('!') {
                    // A negation narrows the rest of the list, below.
                    continue;
                }
                let before = vouched.len();
                for (subject, host, port) in &subjects {
                    if pattern::matches_list(patterns.iter().copied(), subject) {
                        vouched.push((host.clone(), *port));
                    }
                }
                if vouched.len() == before {
                    file.patterns_unmatched += 1;
                }
            } else if let Some((host, port)) = literal(name) {
                // A negation in the same list can still take a plain name out.
                let subject = subject_of(&host, port);
                let negated = patterns.iter().any(|other| {
                    other
                        .strip_prefix('!')
                        .is_some_and(|negated| pattern::matches(negated, &subject))
                });
                if !negated {
                    vouched.push((host, port));
                }
            } else {
                file.malformed += 1;
            }
        }

        for (host, port) in vouched {
            let key = (host.clone(), port, algorithm.to_owned());
            match seen.get(&key) {
                Some(at) => {
                    if file.keys.get(*at).is_some_and(|kept| kept.blob != blob) {
                        file.conflicting += 1;
                    }
                }
                None => {
                    seen.insert(key, file.keys.len());
                    file.keys.push(HostKey {
                        host,
                        port,
                        algorithm: algorithm.to_owned(),
                        blob: blob.clone(),
                    });
                }
            }
        }
    }

    if !revoked.is_empty() {
        file.keys.retain(|key| !revoked.contains(&key.blob));
    }
    Ok(file)
}

/// The name OpenSSH looks a host up by.
fn subject_of(host: &str, port: u16) -> String {
    let bare = unbracketed(host);
    if port == SSH_PORT {
        bare.to_owned()
    } else {
        format!("[{bare}]:{port}")
    }
}

/// A name that is one host: `host`, `[host]:port`, or a bare IPv6 literal.
/// The host comes back lower case, and bracketed when it is an IPv6 literal.
fn literal(name: &str) -> Option<(String, u16)> {
    let name = name.to_ascii_lowercase();
    if let Some(inner) = name.strip_prefix('[') {
        let (host, rest) = inner.split_once(']')?;
        let port = match rest.strip_prefix(':') {
            Some(port) => port.parse::<u16>().ok().filter(|port| *port != 0)?,
            None if rest.is_empty() => SSH_PORT,
            None => return None,
        };
        return Some((bracketed(host), port));
    }
    if name.is_empty() || name.contains(['|', '[', ']']) {
        return None;
    }
    Some((bracketed(&name), SSH_PORT))
}

/// An IPv6 literal in brackets, anything else as it was.
fn bracketed(host: &str) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// A host without the brackets an IPv6 literal carries.
fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// The key's bytes, when they are base64 and name the type the line does.
///
/// An SSH public key blob opens with its type as an RFC 4251 §5 `string`: a
/// big-endian length, then that many bytes.
fn key_blob(algorithm: &str, encoded: &str) -> Option<Vec<u8>> {
    let blob = BASE64.decode(encoded.as_bytes()).ok()?;
    let length = blob.get(..4)?;
    let length = usize::try_from(u32::from_be_bytes([
        length[0], length[1], length[2], length[3],
    ]))
    .ok()?;
    let name = blob.get(4..4usize.checked_add(length)?)?;
    (name == algorithm.as_bytes()).then_some(blob)
}

/// Whether HMAC-SHA1 of `subject` keyed with `salt` is `hash`, compared in
/// constant time.
fn hashes_to(salt: &[u8], subject: &str, hash: &[u8]) -> bool {
    let Ok(mut mac) = <Hmac<Sha1> as KeyInit>::new_from_slice(salt) else {
        return false;
    };
    mac.update(subject.as_bytes());
    mac.verify_slice(hash).is_ok()
}

#[cfg(test)]
#[path = "known_hosts_tests.rs"]
mod tests;
