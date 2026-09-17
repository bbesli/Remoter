//! Pieces every importer needs: cleaning values the domain model will accept,
//! preserving the ones it will not, and turning per-connection credentials into
//! shared credential nodes.
//!
//! The credential pool is the part worth reading. mRemoteNG and CSV both store
//! a username and a password on every connection; Remoter stores credentials as
//! nodes and references them. Importing four hundred connections that all use
//! one service account should produce one credential, not four hundred, and
//! `docs/architecture/data-model.md` says why: "That is what makes them
//! shareable between hundreds of connections without duplication."

use std::collections::HashMap;

use remoter_core::{
    CredentialRef, FolderProps, MAX_NAME_LEN, NodeId, ProtocolId, SecretKind, ValidationError,
};
use sha1::{Digest, Sha1};

use crate::error::ImportError;
use crate::preview::{PreviewBuilder, PreviewCredential, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::Finding;

/// Longest description the domain model accepts, in characters.
const MAX_DESCRIPTION_LEN: usize = 4096;

/// Trims a name down to something [`remoter_core::validate_node`] will accept.
///
/// Control characters are removed rather than escaped: a name is rendered in a
/// tree, and a name carrying `\r` or a bidirectional override is a name that
/// renders as something other than what the file says. Returns the empty string
/// when nothing usable is left, which is the caller's cue to fall back or skip.
pub(crate) fn clean_name(raw: &str) -> String {
    let stripped: String = raw.chars().filter(|c| !c.is_control()).collect();
    stripped.trim().chars().take(MAX_NAME_LEN).collect()
}

/// Trims a description to the length the domain model accepts.
pub(crate) fn clean_description(raw: &str) -> String {
    raw.chars().take(MAX_DESCRIPTION_LEN).collect()
}

/// Parses a port, rejecting zero and anything that is not a number.
pub(crate) fn parse_port(raw: &str) -> Option<u16> {
    raw.trim().parse::<u16>().ok().filter(|port| *port != 0)
}

/// Splits an address that may carry a port — `host`, `host:3390`,
/// `[2001:db8::1]:3390` — into the host the domain model stores and the port.
///
/// A bare IPv6 literal has more than one colon and no port, and comes back
/// bracketed, which is the only spelling of one [`remoter_core::validate_host`]
/// accepts. `None` when a port is there and is not one.
pub(crate) fn split_address(raw: &str) -> Option<(String, Option<u16>)> {
    let raw = raw.trim();
    if let Some(inner) = raw.strip_prefix('[') {
        let (address, rest) = inner.split_once(']')?;
        let host = format!("[{address}]");
        return match rest.strip_prefix(':') {
            Some(port) => Some((host, Some(parse_port(port)?))),
            None if rest.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match raw.matches(':').count() {
        0 => Some((raw.to_owned(), None)),
        1 => {
            let (host, port) = raw.split_once(':')?;
            Some((host.to_owned(), Some(parse_port(port)?)))
        }
        _ if raw.parse::<std::net::Ipv6Addr>().is_ok() => Some((format!("[{raw}]"), None)),
        _ => None,
    }
}

/// Reads one of the several spellings of "true" these formats use.
pub(crate) fn parse_bool(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "true" | "yes" | "1" | "on"
    )
}

/// Whether `key` is one [`remoter_core`] will accept as a custom-field key.
///
/// Checked by construction rather than by catching the rejection, because the
/// rejection is a whole-import failure and a badly named column is not.
fn is_valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.chars().count() <= 128
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        && !key.starts_with('.')
        && !key.ends_with('.')
}

/// Builds a namespaced custom-field key, or `None` if the source's own name for
/// the field cannot be expressed as one.
pub(crate) fn custom_key(namespace: &str, name: &str) -> Option<String> {
    let key = format!("{namespace}.{name}");
    is_valid_key(&key).then_some(key)
}

/// Adds a preserved value to a node, up to the per-node ceiling.
///
/// Returns whether it was kept, so the caller can count what it preserved for
/// the report.
pub(crate) fn preserve(
    node: &mut PreviewNode,
    key: String,
    value: String,
    max_fields: usize,
) -> bool {
    if node.custom_fields.len() >= max_fields || node.custom_fields.contains_key(&key) {
        return false;
    }
    node.custom_fields.insert(key, value);
    true
}

/// Identity of a credential, for deduplication.
///
/// The secret is held as a SHA-1 digest rather than as plaintext so that the
/// index does not accumulate a second copy of every password in the file. A
/// digest collision would merge two different credentials, so a hit on the
/// index is confirmed by comparing the candidate against the credential the
/// index points at; the digest only decides which one to compare against.
type CredentialKey = (String, Option<String>, String, [u8; 20]);

/// Turns per-connection credentials into shared credential nodes.
pub(crate) struct CredentialPool {
    folder: Option<NodeId>,
    folder_name: String,
    index: HashMap<CredentialKey, NodeId>,
    next_sort: i64,
    references: usize,
}

impl CredentialPool {
    /// A pool whose credential nodes go into a folder named `folder_name`,
    /// created only if the import turns out to have any.
    pub(crate) fn new(folder_name: impl Into<String>) -> Self {
        Self {
            folder: None,
            folder_name: folder_name.into(),
            index: HashMap::new(),
            next_sort: 0,
            references: 0,
        }
    }

    /// Returns a reference to a credential node for this identity, creating one
    /// if this is the first time it has been seen.
    ///
    /// # Errors
    ///
    /// [`ImportError::TooManyNodes`] if the node ceiling is reached, or
    /// [`ImportError::Validation`] for a username the domain model rejects.
    pub(crate) fn intern(
        &mut self,
        builder: &mut PreviewBuilder,
        name: &str,
        username: String,
        domain: Option<String>,
        secret: PreviewSecret,
        allowed_protocols: Vec<ProtocolId>,
    ) -> Result<CredentialRef, ImportError> {
        if username.chars().any(char::is_control)
            || domain
                .as_ref()
                .is_some_and(|d| d.chars().any(char::is_control))
        {
            return Err(ImportError::Validation(
                ValidationError::IdentityControlChar,
            ));
        }

        let protocol_key = allowed_protocols
            .iter()
            .map(ProtocolId::as_str)
            .collect::<Vec<_>>()
            .join(",");
        let key = (
            username.clone(),
            domain.clone(),
            protocol_key,
            digest(&secret),
        );

        self.references += 1;
        if let Some(existing) = self.index.get(&key).copied() {
            if self.matches(builder, existing, &username, domain.as_deref(), &secret) {
                return Ok(CredentialRef::live(existing));
            }
        }

        let parent = self.folder(builder)?;
        let credential = PreviewNode::new(
            NodeId::new(),
            credential_name(name, &username, domain.as_deref()),
            PreviewKind::Credential(PreviewCredential {
                username,
                domain,
                secret,
                allowed_protocols,
            }),
        )
        .under(Some(parent), self.next_sort);
        self.next_sort += 1;
        let id = builder.push(credential)?;
        self.index.insert(key, id);
        Ok(CredentialRef::live(id))
    }

    /// Confirms that the node the digest pointed at really is this credential.
    fn matches(
        &self,
        builder: &mut PreviewBuilder,
        id: NodeId,
        username: &str,
        domain: Option<&str>,
        secret: &PreviewSecret,
    ) -> bool {
        matches!(
            builder.node_mut(id).map(|node| &node.kind),
            Some(PreviewKind::Credential(existing))
                if existing.username == username
                    && existing.domain.as_deref() == domain
                    && existing.secret == *secret
        )
    }

    fn folder(&mut self, builder: &mut PreviewBuilder) -> Result<NodeId, ImportError> {
        if let Some(folder) = self.folder {
            return Ok(folder);
        }
        // Placed after the imported tree rather than inside it: the source's
        // own structure is what the user recognises, and a folder Remoter
        // invented should not appear in the middle of it.
        let folder = PreviewNode::new(
            NodeId::new(),
            self.folder_name.clone(),
            PreviewKind::Folder(FolderProps::default()),
        )
        .under(None, i64::MAX);
        let id = builder.push(folder)?;
        self.folder = Some(id);
        Ok(id)
    }

    /// Records how much deduplication happened, if any did.
    pub(crate) fn finish(self, builder: &mut PreviewBuilder) {
        if self.index.is_empty() {
            return;
        }
        let limits = *builder.limits();
        builder.report_mut().push(
            &limits,
            Finding::CredentialsDeduplicated {
                credentials: self.index.len(),
                connections: self.references,
            },
        );
    }
}

/// Names a credential node after the account it holds, falling back to the
/// connection it came from when the account name is empty.
fn credential_name(source: &str, username: &str, domain: Option<&str>) -> String {
    let named = match (domain, username) {
        (Some(domain), user) if !domain.is_empty() && !user.is_empty() => {
            format!("{domain}\\{user}")
        }
        (_, user) if !user.is_empty() => user.to_owned(),
        // No account name at all: a key-only or agent-only credential. Named
        // after whatever referred to it, which is the only thing left that a
        // user would recognise in a tree.
        _ => clean_name(source),
    };
    let cleaned = clean_name(&named);
    if cleaned.is_empty() {
        "Imported credential".to_owned()
    } else if username.is_empty() && domain.is_none_or(str::is_empty) {
        format!("{cleaned} credentials")
    } else {
        cleaned
    }
}

/// A digest that distinguishes one secret from another without keeping a second
/// copy of it.
///
/// Domain-separated by a leading tag so that a password whose text happens to
/// equal an agent filter cannot collide with it.
fn digest(secret: &PreviewSecret) -> [u8; 20] {
    let mut hasher = Sha1::new();
    match secret {
        PreviewSecret::Password(password) => {
            hasher.update(b"password\0");
            hasher.update(password.expose().as_bytes());
        }
        PreviewSecret::PasswordNotCarried(identity) => {
            hasher.update(b"not-carried\0");
            hasher.update(identity);
        }
        PreviewSecret::Unsealed(SecretKind::Agent { comment_filter }) => {
            hasher.update(b"agent\0");
            hasher.update(comment_filter.as_deref().unwrap_or("").as_bytes());
        }
        PreviewSecret::Unsealed(SecretKind::External {
            provider,
            reference,
        }) => {
            hasher.update(b"external\0");
            hasher.update(provider.as_bytes());
            hasher.update(b"\0");
            hasher.update(reference.as_bytes());
        }
        // No other kind is produced by this crate: a private key or a
        // certificate arrives already sealed, which an importer cannot do.
        PreviewSecret::Unsealed(other) => {
            hasher.update(b"other\0");
            hasher.update(other.to_string_lossy().as_bytes());
        }
    }
    hasher.finalize().into()
}

/// A stable discriminator for the secret kinds this crate does not itself
/// produce, so that `digest` stays total without formatting anything secret.
trait SecretDiscriminator {
    fn to_string_lossy(&self) -> &'static str;
}

impl SecretDiscriminator for SecretKind {
    fn to_string_lossy(&self) -> &'static str {
        match self {
            Self::Password { .. } => "password",
            Self::PrivateKey { .. } => "private-key",
            Self::Agent { .. } => "agent",
            Self::External { .. } => "external",
            Self::Certificate { .. } => "certificate",
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;
    use crate::limits::Limits;
    use crate::report::SourceFormat;
    use crate::secret::ImportedSecret;

    fn pool_builder() -> (CredentialPool, PreviewBuilder) {
        (
            CredentialPool::new("Imported credentials"),
            PreviewBuilder::new(SourceFormat::MRemoteNg, Limits::new()),
        )
    }

    #[test]
    fn names_are_cleaned_not_escaped() {
        assert_eq!(clean_name("  web-01\r\n  "), "web-01");
        assert_eq!(clean_name("a\u{202e}b"), "a\u{202e}b");
        assert_eq!(clean_name("\u{7}\u{7}"), "");
        assert_eq!(clean_name(&"x".repeat(1000)).chars().count(), MAX_NAME_LEN);
    }

    #[test]
    fn ports_and_booleans_are_read_the_way_these_formats_write_them() {
        assert_eq!(parse_port(" 22 "), Some(22));
        assert_eq!(parse_port("0"), None);
        assert_eq!(parse_port("70000"), None);
        assert_eq!(parse_port("ssh"), None);
        assert!(parse_bool("True"));
        assert!(parse_bool("yes"));
        assert!(parse_bool("1"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool(""));
    }

    #[test]
    fn an_address_gives_up_its_port_and_keeps_an_ipv6_literal_whole() {
        assert_eq!(split_address("dc01"), Some(("dc01".to_owned(), None)));
        assert_eq!(
            split_address(" dc01.contoso.com:3390 "),
            Some(("dc01.contoso.com".to_owned(), Some(3390)))
        );
        assert_eq!(
            split_address("[2001:db8::1]:3390"),
            Some(("[2001:db8::1]".to_owned(), Some(3390)))
        );
        assert_eq!(
            split_address("[2001:db8::1]"),
            Some(("[2001:db8::1]".to_owned(), None))
        );
        assert_eq!(
            split_address("2001:db8::1"),
            Some(("[2001:db8::1]".to_owned(), None))
        );
        assert_eq!(split_address("dc01:rdp"), None);
        assert_eq!(split_address("dc01:0"), None);
        assert_eq!(split_address("[2001:db8::1]x"), None);
        assert_eq!(split_address("a:b:c"), None);
    }

    #[test]
    fn custom_keys_that_the_domain_model_would_reject_are_not_built() {
        assert_eq!(
            custom_key("mremoteng", "RedirectDiskDrives").as_deref(),
            Some("mremoteng.RedirectDiskDrives")
        );
        assert_eq!(custom_key("csv", "a column"), None);
        assert_eq!(custom_key("csv", "a/b"), None);
        assert_eq!(custom_key("csv", ""), None);
    }

    #[test]
    fn preserved_fields_stop_at_the_per_node_ceiling() {
        let mut node = PreviewNode::new(
            NodeId::new(),
            "n".to_owned(),
            PreviewKind::Folder(FolderProps::default()),
        );
        assert!(preserve(&mut node, "a.b".to_owned(), "1".to_owned(), 2));
        assert!(preserve(&mut node, "a.c".to_owned(), "1".to_owned(), 2));
        assert!(!preserve(&mut node, "a.d".to_owned(), "1".to_owned(), 2));
        // A repeated key does not displace the first value.
        assert!(!preserve(&mut node, "a.b".to_owned(), "2".to_owned(), 8));
        assert_eq!(node.custom_fields.get("a.b").map(String::as_str), Some("1"));
    }

    #[test]
    fn one_account_used_twice_becomes_one_credential() {
        let (mut pool, mut builder) = pool_builder();
        let first = pool
            .intern(
                &mut builder,
                "web-01",
                "svc-deploy".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("hunter2")),
                Vec::new(),
            )
            .unwrap();
        let second = pool
            .intern(
                &mut builder,
                "web-02",
                "svc-deploy".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("hunter2")),
                Vec::new(),
            )
            .unwrap();
        assert_eq!(first.id(), second.id());
        pool.finish(&mut builder);
        let preview = builder.finish();
        // One credential, one folder to hold it.
        assert_eq!(preview.report().counts().credentials, 1);
        assert_eq!(preview.report().counts().folders, 1);
        assert!(
            preview
                .report()
                .findings()
                .contains(&Finding::CredentialsDeduplicated {
                    credentials: 1,
                    connections: 2
                })
        );
    }

    #[test]
    fn the_same_account_with_a_different_password_stays_separate() {
        let (mut pool, mut builder) = pool_builder();
        let first = pool
            .intern(
                &mut builder,
                "web-01",
                "root".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("a")),
                Vec::new(),
            )
            .unwrap();
        let second = pool
            .intern(
                &mut builder,
                "web-02",
                "root".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("b")),
                Vec::new(),
            )
            .unwrap();
        assert_ne!(first.id(), second.id());
    }

    #[test]
    fn a_purpose_restriction_keeps_two_credentials_apart() {
        let (mut pool, mut builder) = pool_builder();
        let ssh = pool
            .intern(
                &mut builder,
                "a",
                "admin".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("p")),
                vec![ProtocolId::new("ssh").unwrap()],
            )
            .unwrap();
        let rdp = pool
            .intern(
                &mut builder,
                "b",
                "admin".to_owned(),
                None,
                PreviewSecret::Password(ImportedSecret::from("p")),
                vec![ProtocolId::new("rdp").unwrap()],
            )
            .unwrap();
        assert_ne!(ssh.id(), rdp.id());
    }

    #[test]
    fn a_credential_is_named_after_the_account_it_holds() {
        assert_eq!(
            credential_name("web-01", "admin", Some("CONTOSO")),
            "CONTOSO\\admin"
        );
        assert_eq!(credential_name("web-01", "admin", None), "admin");
        assert_eq!(credential_name("web-01", "", None), "web-01 credentials");
        assert_eq!(credential_name("\u{7}", "", None), "Imported credential");
    }

    #[test]
    fn a_control_character_in_an_identity_is_refused_rather_than_carried() {
        let (mut pool, mut builder) = pool_builder();
        let err = pool.intern(
            &mut builder,
            "n",
            "ad\u{0}min".to_owned(),
            None,
            PreviewSecret::Unsealed(SecretKind::Agent {
                comment_filter: None,
            }),
            Vec::new(),
        );
        assert!(matches!(err, Err(ImportError::Validation(_))));
    }

    #[test]
    fn an_unused_pool_creates_no_folder_and_says_nothing() {
        let (pool, mut builder) = pool_builder();
        pool.finish(&mut builder);
        let preview = builder.finish();
        assert_eq!(preview.nodes().len(), 0);
        assert_eq!(preview.report().findings().len(), 0);
    }
}
