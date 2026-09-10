//! The two bridges from the vault to the protocol layer.
//!
//! `remoter-proto` deliberately does not depend on `remoter-vault` — the
//! layering rule points downward only — so it declares
//! [`CredentialProvider`](remoter_proto::CredentialProvider) and
//! [`TrustStore`](remoter_proto::TrustStore) as traits and lets whoever owns
//! the storage implement them. This crate owns the open vault, so this is
//! where they are implemented.
//!
//! Two rules shape everything here.
//!
//! **A secret is lent, never handed over.** `CredentialProvider` hands its
//! bytes to a closure and returns nothing derived from them, and this
//! implementation honours that: the material lives in a
//! [`Secret`](remoter_vault::Secret), which redacts in `Debug` and zeroizes on
//! drop, and `borrow_*` passes a `&[u8]` into the caller's closure. Nothing
//! here clones it out, formats it, or puts it in a struct that outlives the
//! connection attempt — the provider itself is dropped the moment
//! authentication finishes, which is stage 6 of
//! `docs/architecture/session-pipeline.md`.
//!
//! **The trust store lives inside the encrypted vault**, not in a plaintext
//! `known_hosts` (`docs/security/transport-security.md`). Poisoning it
//! therefore requires opening the vault.

use std::sync::Arc;

use parking_lot::Mutex;
use remoter_core::{CredentialRef, NodeKind, ProtocolId, SecretKind};
use remoter_proto::{
    CredentialKind, CredentialProvider, Fingerprint, HostPort, KeyBorrow, KnownKey, ProtocolError,
    TrustSource, TrustStore,
};
use remoter_vault::{ExposeSecret as _, Purpose, Secret};
use serde::{Deserialize, Serialize};

use crate::error::IpcError;
use crate::state::Inner;

/// The `kind` column the vault's trust store files SSH host keys under. TLS
/// certificates will use a different one, which is why the column exists.
const TRUST_KIND: &str = "ssh_hostkey";

/// Who accepted a key, as recorded in the `accepted_by` column. Not a user
/// name: the vault has one operator, and what matters for the audit trail is
/// whether a person was shown the fingerprint or an importer supplied it.
const ACCEPTED_BY_PROMPT: &str = "prompted";

// ============================================================= credentials ==

/// One connection's credential, borrowed from the vault for one attempt.
///
/// Constructed by [`acquire`] at stage 3 of the pipeline and dropped when the
/// attempt ends, which is what zeroizes the material. It is deliberately not
/// `Clone`: a second copy of a password is a second thing to wipe.
pub(crate) struct VaultCredentials {
    username: Option<String>,
    domain: Option<String>,
    agent_filter: Option<String>,
    kind: CredentialKind,
    password: Option<Secret<Vec<u8>>>,
    private_key: Option<Secret<Vec<u8>>>,
    passphrase: Option<Secret<Vec<u8>>>,
}

impl VaultCredentials {
    /// The account name, for the audit entry and the session list. A user name
    /// is an identifier, not a secret — it is shown in the connection editor.
    pub(crate) fn account(&self) -> Option<&str> {
        self.username.as_deref()
    }
}

impl std::fmt::Debug for VaultCredentials {
    /// Hand-written, and it stays hand-written. A `#[derive(Debug)]` on a
    /// struct holding key material is one `tracing::debug!` away from putting a
    /// private key in a log file; the presence of a secret is printed, never
    /// its length and never its bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultCredentials")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("kind", &self.kind)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl CredentialProvider for VaultCredentials {
    fn username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn kind(&self) -> CredentialKind {
        self.kind
    }

    fn borrow_password(&self, f: &mut dyn FnMut(&[u8])) -> bool {
        // The borrow, and the whole borrow: `f` sees the bytes for exactly the
        // length of this call and nothing leaves with them.
        match &self.password {
            Some(secret) => {
                f(secret.expose_secret());
                true
            }
            None => false,
        }
    }

    fn borrow_private_key(&self, f: &mut KeyBorrow<'_>) -> bool {
        // Key and passphrase are lent together because every key parser needs
        // both at once, and fetching the passphrase separately would keep it
        // alive longer than the parse.
        match &self.private_key {
            Some(key) => {
                let passphrase = self
                    .passphrase
                    .as_ref()
                    .map(|p| p.expose_secret().as_slice());
                f(key.expose_secret(), passphrase);
                true
            }
            None => false,
        }
    }

    fn domain(&self) -> Option<&str> {
        self.domain.as_deref()
    }

    fn agent_filter(&self) -> Option<&str> {
        self.agent_filter.as_deref()
    }
}

/// Stage 3 · Acquire. Borrows `credential` from the open vault, scoped to one
/// connection attempt.
///
/// The purpose is stated so the vault can check it against the credential's own
/// restriction and record it: a credential marked "SSH only" cannot be borrowed
/// for RDP, which is what stops an importer mistake spraying a password at the
/// wrong service (`docs/architecture/session-pipeline.md` §3).
///
/// `subject` is the connection's name, so a failure names the connection the
/// user was trying to open rather than a node id.
pub(crate) fn acquire(
    inner: &mut Inner,
    credential: &CredentialRef,
    protocol: &ProtocolId,
    subject: &str,
) -> Result<VaultCredentials, IpcError> {
    if credential.is_deleted() {
        return Err(IpcError::new(
            "session.credential-deleted",
            format!(
                "The credential `{subject}` used was deleted. Choose another, or enter one now."
            ),
        )
        .with_actions(["Choose a credential", "Enter a credential for this attempt"]));
    }

    let id = *credential.id().as_uuid();
    let vault = inner.vault_mut()?;
    let node = vault
        .node(id)
        .map_err(|err| IpcError::from_vault(&err, subject))?
        .ok_or_else(|| {
            IpcError::new(
                "session.credential-deleted",
                format!(
                    "The credential `{subject}` used is no longer in this vault. Choose another, \
                     or enter one now."
                ),
            )
            .with_actions(["Choose a credential", "Enter a credential for this attempt"])
        })?;

    let NodeKind::Credential(props) = node.kind else {
        return Err(IpcError::new(
            "session.credential-not-a-credential",
            format!(
                "`{}` is not a credential, so `{subject}` cannot use it.",
                node.name
            ),
        )
        .with_actions(["Choose a credential"]));
    };

    if !props.permits(protocol) {
        // The taxonomy's "this credential is restricted to SSH and cannot be
        // used for RDP", with the real lists in it.
        let allowed = props
            .allowed_protocols
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(IpcError::new(
            "session.credential-purpose",
            format!(
                "The credential `{}` is restricted to {allowed} and cannot be used for `{}`.",
                node.name,
                protocol.as_str()
            ),
        )
        .with_actions(["Choose a credential", "Open the credential's settings"]));
    }

    let username = Some(props.username.clone()).filter(|u| !u.trim().is_empty());
    let domain = props.domain.clone();

    match props.secret {
        SecretKind::Password { .. } => {
            let password = vault
                .borrow_secret(id, "password", Purpose::SshPassword)
                .map_err(|err| IpcError::from_vault(&err, subject))?;
            Ok(VaultCredentials {
                username,
                domain,
                agent_filter: None,
                kind: CredentialKind::Password,
                password: Some(password),
                private_key: None,
                passphrase: None,
            })
        }
        SecretKind::PrivateKey { .. } => {
            let material = vault
                .borrow_private_key(id, Purpose::SshPrivateKey)
                .map_err(|err| IpcError::from_vault(&err, subject))?;
            // `PrivateKeyMaterial` owns its `Secret`s and has no way to hand
            // them over, so they are moved out of it field by field; the
            // material is dropped — and zeroized — at the end of this scope
            // either way.
            let key = Secret::new(material.key().expose_secret().clone());
            let passphrase = material
                .passphrase()
                .map(|p| Secret::new(p.expose_secret().clone()));
            Ok(VaultCredentials {
                username,
                domain,
                agent_filter: None,
                kind: CredentialKind::PrivateKey,
                password: None,
                private_key: Some(key),
                passphrase,
            })
        }
        SecretKind::Agent { comment_filter } => Ok(VaultCredentials {
            username,
            domain,
            agent_filter: comment_filter,
            kind: CredentialKind::Agent,
            password: None,
            private_key: None,
            passphrase: None,
        }),
        SecretKind::External { provider, .. } => Err(IpcError::new(
            "session.credential-external",
            format!(
                "The credential `{}` is held by `{provider}`, and this build has no plugin that \
                 can fetch it.",
                node.name
            ),
        )
        .with_actions(["Choose a credential", "Enter a credential for this attempt"])),
        SecretKind::Certificate { .. } => Err(IpcError::new(
            "session.credential-unsupported",
            format!(
                "The credential `{}` is a certificate, which `{}` sessions do not use.",
                node.name,
                protocol.as_str()
            ),
        )
        .with_actions(["Choose a credential"])),
    }
}

// ============================================================ trust store ==

/// One trusted host key, as it is cached beside the vault's `trust_store` row.
///
/// The row itself is the authority on *whether* a key is trusted — that is the
/// table `docs/security/transport-security.md` names, and it holds the
/// fingerprint the user accepted. But
/// [`TrustStore::lookup`](remoter_proto::TrustStore::lookup) is required to
/// return the key **blob**, because `verify_host_key` compares the bytes it
/// trusts rather than the digest it displays, and `Vault::trust_lookup` reads
/// back only the fingerprint column. So the blob, the timestamp and the
/// provenance travel in the vault's own settings table under a key derived from
/// the host — inside the same encrypted body, never in a file of its own — and
/// every read is cross-checked against the `trust_store` fingerprint. A cache
/// entry that does not match the row it belongs to is ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedKey {
    algorithm: String,
    blob: Vec<u8>,
    added_at_ms: i64,
    source: TrustSource,
}

/// The settings key one host's key is cached under.
fn cache_key(host: &HostPort, algorithm: &str) -> String {
    // The canonical form, as the trait requires: `DB-01.internal`,
    // `db-01.internal` and `db-01.internal.` are one machine, and storing them
    // separately would walk past a decision the user already made.
    format!("trust.ssh_hostkey.{}.{algorithm}", host.canonical())
}

/// The trust store, backed by the open vault.
///
/// Holds the same `Inner` every command holds, so a key accepted mid-handshake
/// is written to the vault that is open right now — and a vault that has been
/// locked underneath a running session refuses the write rather than silently
/// dropping it.
pub(crate) struct VaultTrustStore {
    inner: Arc<Mutex<Inner>>,
}

impl VaultTrustStore {
    pub(crate) const fn new(inner: Arc<Mutex<Inner>>) -> Self {
        Self { inner }
    }
}

impl std::fmt::Debug for VaultTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultTrustStore")
    }
}

impl TrustStore for VaultTrustStore {
    fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
        let mut guard = self.inner.lock();
        let vault = guard.vault_ref().ok()?;

        // The row is the decision. No row means nothing is trusted for this
        // host and algorithm — "unknown", which is a prompt, not a failure.
        let fingerprint = vault
            .trust_lookup(&host.canonical_host(), host.port(), TRUST_KIND, algorithm)
            .ok()
            .flatten()?;

        let cached = vault.setting(&cache_key(host, algorithm)).ok().flatten()?;
        let cached: CachedKey = serde_json::from_slice(&cached).ok()?;

        // The cross-check. If the cached blob does not hash to the fingerprint
        // the trust_store row holds, the cache is stale or wrong and the row
        // wins by refusing to answer: reporting a key we cannot prove was the
        // one accepted would be worse than asking again.
        if Fingerprint::sha256(&cached.blob).digest().as_slice() != fingerprint.as_slice() {
            tracing::warn!(
                host = %host,
                algorithm,
                "a cached host key does not match the fingerprint pinned for it; ignoring the cache"
            );
            return None;
        }

        Some(KnownKey::new(
            cached.algorithm,
            cached.blob,
            cached.added_at_ms,
            cached.source,
        ))
    }

    fn remember(&self, host: &HostPort, key: &KnownKey) -> Result<(), ProtocolError> {
        let mut guard = self.inner.lock();
        let vault = guard.vault_mut().map_err(|_| ProtocolError::TrustStore {
            operation: "record a host key",
            detail: "no vault is open",
        })?;

        let fingerprint = key.fingerprint();
        vault
            .trust_pin(
                &host.canonical_host(),
                host.port(),
                TRUST_KIND,
                &key.algorithm,
                fingerprint.digest(),
                &key.blob,
                ACCEPTED_BY_PROMPT,
            )
            .map_err(|_| ProtocolError::TrustStore {
                operation: "record a host key",
                detail: "the vault refused the write",
            })?;

        let cached = CachedKey {
            algorithm: key.algorithm.clone(),
            blob: key.blob.clone(),
            added_at_ms: key.added_at_ms,
            source: key.source,
        };
        let encoded = serde_json::to_vec(&cached).map_err(|_| ProtocolError::TrustStore {
            operation: "record a host key",
            detail: "the key could not be encoded",
        })?;
        vault
            .set_setting(&cache_key(host, &key.algorithm), &encoded)
            .map_err(|_| ProtocolError::TrustStore {
                operation: "record a host key",
                detail: "the vault refused the write",
            })?;

        // Written through to disk here rather than at the next mutation. A user
        // who accepted a key and is asked again after a crash will start
        // clicking through the prompt, which is the failure this whole
        // mechanism exists to prevent.
        vault.save().map_err(|_| ProtocolError::TrustStore {
            operation: "save the vault after recording a host key",
            detail: "the vault file could not be written",
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code, per the workspace convention"
)]
mod tests {
    use super::*;
    use remoter_proto::{CredentialProviderExt as _, HostKeyOutcome, OfferedKey, verify_host_key};

    fn host() -> HostPort {
        HostPort::new("db-01.internal", 22).unwrap()
    }

    #[test]
    fn a_password_is_readable_only_inside_the_closure() {
        let creds = VaultCredentials {
            username: Some(String::from("ada")),
            domain: None,
            agent_filter: None,
            kind: CredentialKind::Password,
            password: Some(Secret::new(b"correct horse".to_vec())),
            private_key: None,
            passphrase: None,
        };
        // The closure computes *over* the secret and returns a derived value;
        // the caller never sees the bytes.
        assert_eq!(creds.with_password(&mut |bytes| bytes.len()), Some(13));
        assert_eq!(creds.username(), Some("ada"));
        assert!(creds.with_private_key(&mut |_, _| ()).is_none());
    }

    #[test]
    fn a_private_key_is_lent_with_its_passphrase() {
        let creds = VaultCredentials {
            username: Some(String::from("ada")),
            domain: None,
            agent_filter: None,
            kind: CredentialKind::PrivateKey,
            password: None,
            private_key: Some(Secret::new(b"key-material".to_vec())),
            passphrase: Some(Secret::new(b"pass".to_vec())),
        };
        let seen =
            creds.with_private_key(&mut |key, passphrase| (key.len(), passphrase.map(<[u8]>::len)));
        assert_eq!(seen, Some((12, Some(4))));
        assert!(creds.with_password(&mut |_| ()).is_none());
    }

    #[test]
    fn an_agent_credential_lends_nothing_and_still_names_its_identity() {
        let creds = VaultCredentials {
            username: Some(String::from("ada")),
            domain: None,
            agent_filter: Some(String::from("work laptop")),
            kind: CredentialKind::Agent,
            password: None,
            private_key: None,
            passphrase: None,
        };
        assert_eq!(creds.kind(), CredentialKind::Agent);
        assert_eq!(creds.agent_filter(), Some("work laptop"));
        assert!(creds.with_password(&mut |_| ()).is_none());
        assert!(creds.with_private_key(&mut |_, _| ()).is_none());
    }

    /// Chosen so they cannot appear in a field name, a type name or the word
    /// "redacted". See the comment in the test.
    const SENTINEL_PASSWORD: &[u8] = b"zzq-pw-9f13a7";
    const SENTINEL_KEY: &[u8] = b"zzq-key-4b81c2";
    const SENTINEL_PASSPHRASE: &[u8] = b"zzq-pp-6d24e5";

    #[test]
    fn debug_never_prints_the_material() {
        let creds = VaultCredentials {
            username: Some(String::from("ada")),
            domain: None,
            agent_filter: None,
            kind: CredentialKind::Password,
            password: Some(Secret::new(SENTINEL_PASSWORD.to_vec())),
            private_key: Some(Secret::new(SENTINEL_KEY.to_vec())),
            passphrase: Some(Secret::new(SENTINEL_PASSPHRASE.to_vec())),
        };
        let rendered = format!("{creds:?}");

        // The sentinels are deliberately unlike any field name. An earlier
        // version of this test looked for "phrase", which is a substring of the
        // field name `passphrase` — so it failed while the redaction was
        // working perfectly. A security test that cries wolf is worse than no
        // test: the obvious way to make it pass is to weaken what it checks.
        for sentinel in [SENTINEL_PASSWORD, SENTINEL_KEY, SENTINEL_PASSPHRASE] {
            let text = std::str::from_utf8(sentinel).unwrap_or("");
            assert!(!rendered.contains(text), "{text} leaked into {rendered}");
        }

        // And confirm we are looking at the output we think we are: all three
        // fields present, each redacted. Without this the test would still pass
        // if Debug stopped rendering the fields at all.
        assert_eq!(rendered.matches("<redacted>").count(), 3, "{rendered}");
        for field in ["password", "private_key", "passphrase"] {
            assert!(rendered.contains(field), "{field} missing from {rendered}");
        }
    }

    #[test]
    fn the_cache_key_folds_two_spellings_of_one_machine_together() {
        let upper = HostPort::new("DB-01.Internal", 22).unwrap();
        let dotted = HostPort::new("db-01.internal.", 22).unwrap();
        assert_eq!(
            cache_key(&upper, "ssh-ed25519"),
            cache_key(&dotted, "ssh-ed25519")
        );
        assert_eq!(
            cache_key(&host(), "ssh-ed25519"),
            "trust.ssh_hostkey.db-01.internal:22.ssh-ed25519"
        );
        // A different port is a different endpoint, and gets its own entry.
        let other_port = HostPort::new("db-01.internal", 2222).unwrap();
        assert_ne!(
            cache_key(&host(), "ssh-ed25519"),
            cache_key(&other_port, "ssh-ed25519")
        );
    }

    #[test]
    fn a_cached_key_round_trips_through_its_encoding() {
        let key = KnownKey::new("ssh-ed25519", b"blob".to_vec(), 42, TrustSource::Prompted);
        let cached = CachedKey {
            algorithm: key.algorithm.clone(),
            blob: key.blob.clone(),
            added_at_ms: key.added_at_ms,
            source: key.source,
        };
        let encoded = serde_json::to_vec(&cached).unwrap();
        let decoded: CachedKey = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.blob, b"blob".to_vec());
        assert_eq!(decoded.added_at_ms, 42);
        assert_eq!(decoded.source, TrustSource::Prompted);
    }

    /// The property the cross-check protects: `verify_host_key` compares the
    /// bytes, so a store that returned a key whose blob did not match would
    /// report a *changed* key for a host that had not changed — the single most
    /// damaging false positive this code can produce.
    #[test]
    fn a_blob_that_matches_is_trusted_and_one_that_does_not_is_changed() {
        struct Fixed(KnownKey);
        impl TrustStore for Fixed {
            fn lookup(&self, _host: &HostPort, _algorithm: &str) -> Option<KnownKey> {
                Some(self.0.clone())
            }
            fn remember(&self, _host: &HostPort, _key: &KnownKey) -> Result<(), ProtocolError> {
                Ok(())
            }
        }

        let stored = KnownKey::new("ssh-ed25519", b"blob".to_vec(), 1, TrustSource::Prompted);
        let store = Fixed(stored);
        let same = OfferedKey::new("ssh-ed25519", b"blob".to_vec());
        let other = OfferedKey::new("ssh-ed25519", b"different".to_vec());
        assert!(matches!(
            verify_host_key(&store, &host(), &same),
            HostKeyOutcome::Trusted
        ));
        assert!(matches!(
            verify_host_key(&store, &host(), &other),
            HostKeyOutcome::Changed(_)
        ));
    }
}
