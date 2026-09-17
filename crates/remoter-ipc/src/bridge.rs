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

use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::Mutex;
use remoter_core::{CredentialRef, NodeKind, ProtocolId, SecretKind};
use remoter_proto::{
    CredentialKind, CredentialProvider, Fingerprint, HostPort, KeyBorrow, KnownKey, ProtocolError,
    TrustSource, TrustStore,
};
use remoter_proto_rdp::RDP_ID;
use remoter_proto_ssh::SSH_ID;
use remoter_proto_ssh::sftp::SFTP_ID;
use remoter_proto_vnc::VNC_ID;
use remoter_vault::{
    AuditEvent, AuditOutcome, ExposeSecret as _, Purpose, Secret, Vault, VaultError,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::IpcError;
use crate::state::Inner;

/// The `kind` column the vault's trust store files SSH host keys under. TLS
/// certificates will use a different one, which is why the column exists.
const TRUST_KIND: &str = "ssh_hostkey";

/// Who accepted a key, as recorded in the `accepted_by` column. Not a user
/// name: the vault has one operator, and what matters for the audit trail is
/// whether a person was shown the fingerprint or an importer supplied it.
const ACCEPTED_BY_PROMPT: &str = "prompted";

/// The same column for a key an importer supplied — one read out of
/// `known_hosts`, which nobody was shown in Remoter.
const ACCEPTED_BY_IMPORT: &str = "import";

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

/// The purpose a stored password is borrowed under, for the protocol the
/// session is actually opening.
///
/// **The purpose is a security control, not a label.** It is what the vault
/// checks the credential's own restriction against
/// (`docs/architecture/session-pipeline.md` §3), so it has to name the protocol
/// in front of the user. A constant here — every borrow asking for
/// `SshPassword` — meant an RDP, VNC or SFTP session asked the vault for an SSH
/// password, and a credential the importer had correctly restricted to RDP
/// refused its own connection.
///
/// `None` for a protocol no purpose names: the caller refuses rather than
/// falling back, because a fallback is a restriction check asked about the
/// wrong protocol, which is the defect this function exists to remove.
fn password_purpose(protocol: &ProtocolId) -> Option<Purpose> {
    match protocol.as_str() {
        SSH_ID => Some(Purpose::SshPassword),
        SFTP_ID => Some(Purpose::SftpPassword),
        RDP_ID => Some(Purpose::RdpCredentials),
        VNC_ID => Some(Purpose::VncPassword),
        _ => None,
    }
}

/// The same, for private key material.
///
/// Only the two SSH-transport protocols have one: RDP and VNC authenticate with
/// a password or a ticket, never with a stored private key, so a key credential
/// on one of those is refused rather than borrowed and thrown away at the
/// handshake.
fn private_key_purpose(protocol: &ProtocolId) -> Option<Purpose> {
    match protocol.as_str() {
        SSH_ID => Some(Purpose::SshPrivateKey),
        SFTP_ID => Some(Purpose::SftpPrivateKey),
        _ => None,
    }
}

/// The external providers that are a private key file on this computer rather
/// than a secret store: an `IdentityFile` read out of an OpenSSH config, and a
/// `PublicKeyFile` out of a PuTTY session. `remoter-import` writes both names,
/// and nothing else in the build reads a file a credential points at.
const KEY_FILE_PROVIDERS: &[&str] = &["openssh-identity-file", "putty-key-file"];

/// The largest file lent as a private key.
///
/// A 16 384-bit RSA key — the largest `ssh-keygen` makes — is under 13 KiB in
/// either OpenSSH's container or PuTTY's, so this is room to spare for a key
/// and a refusal for anything else: a log, a disk image, a device a link was
/// pointed at.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// Why a referenced key file could not be lent.
///
/// Each is a fixed phrase. Nothing from the file and nothing from the
/// operating system's error reaches the message: an imported credential can
/// point anywhere, and the only thing a path the user did not choose may learn
/// about a file is that it is not a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyFileProblem {
    NotAbsolute,
    NotFound,
    Denied,
    NotAFile,
    TooLarge,
    Unreadable,
    NotAKey,
}

impl KeyFileProblem {
    const fn phrase(self) -> &'static str {
        match self {
            Self::NotAbsolute => "is not a full path on this computer",
            Self::NotFound => "does not exist",
            Self::Denied => "cannot be opened by this account",
            Self::NotAFile => "is not a file",
            Self::TooLarge => "is too large to be a private key",
            Self::Unreadable => "could not be read",
            Self::NotAKey => "is not a private key Remoter can read",
        }
    }

    fn of(error: &std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound => Self::NotFound,
            std::io::ErrorKind::PermissionDenied => Self::Denied,
            _ => Self::Unreadable,
        }
    }
}

/// The home directory a leading `~` stands for.
///
/// `USERPROFILE` first on Windows, which is where OpenSSH for Windows and PuTTY
/// both keep `.ssh`; a `HOME` there is usually a Unix shell's idea of one.
fn home_directory() -> Option<PathBuf> {
    #[cfg(windows)]
    const VARIABLES: &[&str] = &["USERPROFILE", "HOME"];
    #[cfg(not(windows))]
    const VARIABLES: &[&str] = &["HOME"];
    VARIABLES
        .iter()
        .filter_map(std::env::var_os)
        .find(|home| !home.is_empty())
        .map(PathBuf::from)
}

/// The path a credential's reference names, with a leading `~` expanded.
///
/// `~` and `~/…` — or `~\…` — only. `~user` is another account's home, which
/// this process has no business resolving, and is left as written; it is then
/// not a full path and is refused as one.
fn expand_key_path(reference: &str, home: Option<&Path>) -> PathBuf {
    let rest = if reference == "~" {
        Some("")
    } else {
        reference
            .strip_prefix("~/")
            .or_else(|| reference.strip_prefix("~\\"))
    };
    match (rest, home) {
        (Some(rest), Some(home)) => home.join(rest),
        _ => PathBuf::from(reference),
    }
}

/// Reads a private key file a credential points at.
///
/// The read is bounded and lands in a buffer that wipes itself, reserved up
/// front so a growing buffer never leaves a copy of the key behind on the heap.
/// Anything that is not a regular file — a directory, a FIFO that would block
/// the read, a device — is refused before it is opened. What comes back has
/// been recognised as a key container and nothing more: an encrypted key is
/// lent as it is, and the SSH adapter asks for its passphrase.
///
/// Small and local, and read here under the state lock beside the vault's own
/// reads for the same attempt; a key on a stalled network share stalls that
/// attempt the way an unreachable vault file would.
fn read_key_file(path: &Path) -> Result<Secret<Vec<u8>>, KeyFileProblem> {
    if !path.is_absolute() {
        return Err(KeyFileProblem::NotAbsolute);
    }
    let metadata = std::fs::metadata(path).map_err(|err| KeyFileProblem::of(&err))?;
    if !metadata.is_file() {
        return Err(KeyFileProblem::NotAFile);
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(KeyFileProblem::TooLarge);
    }

    let file = std::fs::File::open(path).map_err(|err| KeyFileProblem::of(&err))?;
    let limit = usize::try_from(MAX_KEY_FILE_BYTES).unwrap_or(usize::MAX);
    let mut bytes = Zeroizing::new(Vec::with_capacity(limit.saturating_add(1)));
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| KeyFileProblem::Unreadable)?;
    // Checked again after the read: the file can grow between the two looks.
    if bytes.len() > limit {
        return Err(KeyFileProblem::TooLarge);
    }
    if remoter_proto_ssh::keyfmt::detect_key_format(&bytes).is_none() {
        return Err(KeyFileProblem::NotAKey);
    }
    Ok(Secret::new(std::mem::take(&mut *bytes)))
}

/// "The key file `/home/alex/.ssh/deploy` that the credential `deploy` points
/// at does not exist."
fn key_file_failure(path: &Path, credential: &str, problem: KeyFileProblem) -> IpcError {
    IpcError::new(
        "session.key-file-unreadable",
        format!(
            "The key file `{}` that the credential `{credential}` points at {}.",
            path.display(),
            problem.phrase()
        ),
    )
    .with_actions(["Choose a credential", "Open the credential's settings"])
}

/// "The credential `db-01 root` is restricted to ssh and cannot be used for
/// `rdp`" — the failure taxonomy's purpose mismatch, with the real lists in it.
///
/// One function, because the same statement is reached two ways: this crate
/// checks the restriction before it asks the vault, and the vault checks it
/// again as it opens the field. Both name the credential and both name the
/// protocol, so which one fired is not something the user has to care about.
fn purpose_refused(credential: &str, allowed: &[ProtocolId], attempted: &ProtocolId) -> IpcError {
    let list = allowed
        .iter()
        .map(ProtocolId::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let attempted = attempted.as_str();
    // An empty list means "unrestricted", which cannot reach here — but saying
    // "restricted to  and cannot be used" if it ever did would be worse than a
    // slightly vaguer sentence.
    let message = if list.is_empty() {
        format!(
            "The credential `{credential}` is restricted to other protocols and cannot be used \
             for `{attempted}`."
        )
    } else {
        format!(
            "The credential `{credential}` is restricted to {list} and cannot be used for \
             `{attempted}`."
        )
    };
    IpcError::new("session.credential-purpose", message)
        .with_actions(["Choose a credential", "Open the credential's settings"])
}

/// A failure from opening a secret field, as the interface should read it.
///
/// `PurposeRefused` is special-cased because the vault's own error carries only
/// a [`Purpose`]: rendered as it stands it says "this credential is restricted
/// and may not be used this way", with `SshPassword` as the diagnostic, which
/// names neither the credential nor the connection the user was opening. Here
/// both are known, so the statement is the same one the pre-check makes.
fn borrow_failure(
    err: &VaultError,
    credential: &str,
    allowed: &[ProtocolId],
    attempted: &ProtocolId,
    subject: &str,
) -> IpcError {
    match err {
        VaultError::PurposeRefused(_) => purpose_refused(credential, allowed, attempted),
        other => IpcError::from_vault(other, subject),
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
        return Err(purpose_refused(
            &node.name,
            &props.allowed_protocols,
            protocol,
        ));
    }

    let username = Some(props.username.clone()).filter(|u| !u.trim().is_empty());
    let domain = props.domain.clone();
    // Moved out before `props.secret` is, so the restriction is still to hand
    // when a borrow comes back refused.
    let allowed = props.allowed_protocols;

    match props.secret {
        SecretKind::Password { .. } => {
            let Some(purpose) = password_purpose(protocol) else {
                return Err(IpcError::new(
                    "session.protocol-unsupported",
                    format!(
                        "Nothing in this build knows how to present a password to a `{}` service, \
                         so the credential `{}` was not opened.",
                        protocol.as_str(),
                        node.name
                    ),
                )
                .with_actions(["Open its settings"]));
            };
            let password = vault
                .borrow_secret(id, "password", purpose)
                .map_err(|err| borrow_failure(&err, &node.name, &allowed, protocol, subject))?;
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
            let Some(purpose) = private_key_purpose(protocol) else {
                return Err(IpcError::new(
                    "session.credential-unsupported",
                    format!(
                        "The credential `{}` holds a private key, which `{}` sessions do not use.",
                        node.name,
                        protocol.as_str()
                    ),
                )
                .with_actions(["Choose a credential"]));
            };
            let material = vault
                .borrow_private_key(id, purpose)
                .map_err(|err| borrow_failure(&err, &node.name, &allowed, protocol, subject))?;
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
        // A key file on disk, recorded by an importer rather than moved into the
        // vault. The restriction was checked above; this is the same "does the
        // protocol use a key at all" question the stored-key arm asks.
        SecretKind::External {
            provider,
            reference,
        } if KEY_FILE_PROVIDERS.contains(&provider.as_str()) => {
            if private_key_purpose(protocol).is_none() {
                return Err(IpcError::new(
                    "session.credential-unsupported",
                    format!(
                        "The credential `{}` points at a private key file, which `{}` sessions do \
                         not use.",
                        node.name,
                        protocol.as_str()
                    ),
                )
                .with_actions(["Choose a credential"]));
            }
            let path = expand_key_path(&reference, home_directory().as_deref());
            let key = read_key_file(&path)
                .map_err(|problem| key_file_failure(&path, &node.name, problem))?;
            // Recorded the way a stored key's borrow is: which credential, for
            // what, and never what was in it.
            vault
                .audit_in_session(
                    AuditEvent::SecretUsed,
                    AuditOutcome::Success,
                    Some(id),
                    None,
                    Some("key_file"),
                )
                .map_err(|err| IpcError::from_vault(&err, subject))?;
            Ok(VaultCredentials {
                username,
                domain,
                agent_filter: None,
                kind: CredentialKind::PrivateKey,
                password: None,
                private_key: Some(key),
                // An encrypted key asks: the SSH adapter reads the container's
                // own header and raises the passphrase prompt.
                passphrase: None,
            })
        }
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

/// The fingerprint the vault's trust store row holds for a host and key type.
///
/// The row is the decision: this is what an import compares a key with before
/// it writes anything, because a cache that went missing is not a reason to
/// replace a key somebody accepted.
pub(crate) fn trusted_fingerprint(
    vault: &Vault,
    host: &HostPort,
    algorithm: &str,
) -> Option<Vec<u8>> {
    vault
        .trust_lookup(&host.canonical_host(), host.port(), TRUST_KIND, algorithm)
        .ok()
        .flatten()
}

/// Records `key` as trusted for `host`: the `trust_store` row and the cached
/// blob beside it. The caller saves the vault.
///
/// # Errors
///
/// A short, fixed description of which write failed. Nothing from the key.
pub(crate) fn pin_key(
    vault: &mut Vault,
    host: &HostPort,
    key: &KnownKey,
) -> Result<(), &'static str> {
    let accepted_by = match key.source {
        TrustSource::ImportedKnownHosts => ACCEPTED_BY_IMPORT,
        _ => ACCEPTED_BY_PROMPT,
    };
    let fingerprint = key.fingerprint();
    vault
        .trust_pin(
            &host.canonical_host(),
            host.port(),
            TRUST_KIND,
            &key.algorithm,
            fingerprint.digest(),
            &key.blob,
            accepted_by,
        )
        .map_err(|_| "the vault refused the write")?;

    let cached = CachedKey {
        algorithm: key.algorithm.clone(),
        blob: key.blob.clone(),
        added_at_ms: key.added_at_ms,
        source: key.source,
    };
    let encoded = serde_json::to_vec(&cached).map_err(|_| "the key could not be encoded")?;
    vault
        .set_setting(&cache_key(host, &key.algorithm), &encoded)
        .map_err(|_| "the vault refused the write")
}

impl TrustStore for VaultTrustStore {
    fn lookup(&self, host: &HostPort, algorithm: &str) -> Option<KnownKey> {
        let mut guard = self.inner.lock();
        let vault = guard.vault_ref().ok()?;

        // The row is the decision. No row means nothing is trusted for this
        // host and algorithm — "unknown", which is a prompt, not a failure.
        let fingerprint = trusted_fingerprint(vault, host, algorithm)?;

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

        pin_key(vault, host, key).map_err(|detail| ProtocolError::TrustStore {
            operation: "record a host key",
            detail,
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
    use remoter_core::{CredentialProps, KeyFormat, Node};
    use remoter_proto::{CredentialProviderExt as _, HostKeyOutcome, OfferedKey, verify_host_key};
    use remoter_vault::Vault;

    use crate::state::AppState;
    use crate::test_support::{Scratch, open_vault};

    fn host() -> HostPort {
        HostPort::new("db-01.internal", 22).unwrap()
    }

    fn protocol(id: &str) -> ProtocolId {
        ProtocolId::new(id).unwrap()
    }

    /// Puts one credential in the open vault, restricted to `allowed`, and
    /// returns the reference a connection would carry.
    ///
    /// `field` and `material` are the secret it holds: `password` for a
    /// password credential, `private_key` for a key one — the field names
    /// `Vault::borrow_secret` and `Vault::borrow_private_key` read.
    fn credential(
        state: &AppState,
        name: &str,
        allowed: &[&str],
        secret: SecretKind,
        field: &str,
        material: &[u8],
    ) -> CredentialRef {
        let mut guard = state.lock();
        let vault = guard.vault_mut().unwrap();
        let mut tree = vault.tree().unwrap();
        let mut props = CredentialProps::new("administrator", secret);
        props.allowed_protocols = allowed.iter().map(|id| protocol(id)).collect();
        let node = Node::new(NodeKind::Credential(props), name, 1_700_000_000_000);
        let id = node.id;
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();
        vault
            .set_secret(*id.as_uuid(), field, Secret::new(material.to_vec()))
            .unwrap();
        CredentialRef::live(id)
    }

    fn password_credential(state: &AppState, name: &str, allowed: &[&str]) -> CredentialRef {
        credential(
            state,
            name,
            allowed,
            SecretKind::Password {
                sealed: Vault::sealed_placeholder(),
            },
            "password",
            b"zzq-pw-9f13a7",
        )
    }

    fn key_credential(state: &AppState, name: &str, allowed: &[&str]) -> CredentialRef {
        credential(
            state,
            name,
            allowed,
            SecretKind::PrivateKey {
                sealed_key: Vault::sealed_placeholder(),
                sealed_passphrase: None,
                format: KeyFormat::Pkcs8,
            },
            "private_key",
            b"zzq-key-4b81c2",
        )
    }

    /// The defect the first Windows run hit: every borrow asked the vault for
    /// `Purpose::SshPassword`, so a credential the importer had restricted to
    /// the protocol it came from refused its own session — RDP, VNC and SFTP
    /// alike, with `SshPassword` as the only clue on screen.
    #[test]
    fn a_session_borrows_its_password_for_the_protocol_it_is_opening() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };

        for id in ["rdp", "vnc", "sftp", "ssh"] {
            let reference = password_credential(&state, &format!("{id} account"), &[id]);
            let mut guard = state.lock();
            let borrowed = acquire(&mut guard, &reference, &protocol(id), "WIN-DC01");
            assert!(
                borrowed.is_ok(),
                "a credential restricted to {id} refused a {id} session: {}",
                borrowed.err().map(|e| e.message).unwrap_or_default()
            );
            let Ok(borrowed) = borrowed else { continue };
            assert_eq!(borrowed.kind(), CredentialKind::Password);
            assert_eq!(borrowed.with_password(&mut |bytes| bytes.len()), Some(13));
        }
    }

    /// The other half of the same control: the restriction still has to hold.
    /// A purpose derived from the protocol is only an improvement if it can
    /// still say no.
    #[test]
    fn a_credential_restricted_to_ssh_refuses_an_rdp_session() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let reference = password_credential(&state, "ssh only", &["ssh"]);

        let mut guard = state.lock();
        let refused = acquire(&mut guard, &reference, &protocol("rdp"), "WIN-DC01");
        let Err(failure) = refused else {
            panic!("an SSH-only credential opened an RDP session");
        };
        assert_eq!(failure.code, "session.credential-purpose");
        // Both protocols named, and the credential with them: "restricted" on
        // its own leaves the user to guess which of the two to change.
        assert!(failure.message.contains("ssh only"), "{}", failure.message);
        assert!(failure.message.contains("ssh"), "{}", failure.message);
        assert!(failure.message.contains("rdp"), "{}", failure.message);
    }

    /// SFTP rides on an SSH transport, so the key is an SSH key — but the
    /// restriction the user wrote says `sftp`, and that is the question the
    /// vault has to be asked.
    #[test]
    fn an_sftp_file_pane_borrows_a_key_against_the_sftp_restriction() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let reference = key_credential(&state, "sftp key", &["sftp"]);

        let mut guard = state.lock();
        let borrowed = acquire(&mut guard, &reference, &protocol("sftp"), "files on db-01");
        assert!(
            borrowed.is_ok(),
            "an SFTP-only key refused an SFTP session: {}",
            borrowed.err().map(|e| e.message).unwrap_or_default()
        );
        let Ok(borrowed) = borrowed else { return };
        assert_eq!(borrowed.kind(), CredentialKind::PrivateKey);
    }

    /// A key credential on a protocol that has no use for one is refused where
    /// the user can still read why, rather than borrowed, carried through the
    /// pipeline and thrown away at a handshake that cannot use it.
    #[test]
    fn a_private_key_is_not_borrowed_for_a_protocol_that_cannot_use_one() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let reference = key_credential(&state, "a key", &[]);

        let mut guard = state.lock();
        let refused = acquire(&mut guard, &reference, &protocol("rdp"), "WIN-DC01");
        let Err(failure) = refused else {
            panic!("a private key was borrowed for an RDP session");
        };
        assert_eq!(failure.code, "session.credential-unsupported");
        assert!(failure.message.contains("rdp"), "{}", failure.message);
    }

    /// Every purpose the two mappings hand out names the protocol being
    /// opened. A constant, or a fallback for a protocol with no purpose of its
    /// own, would put the restriction check on the wrong protocol.
    #[test]
    fn a_purpose_is_never_borrowed_from_another_protocol() {
        assert_eq!(
            password_purpose(&protocol("rdp")),
            Some(Purpose::RdpCredentials)
        );
        assert_eq!(
            password_purpose(&protocol("vnc")),
            Some(Purpose::VncPassword)
        );
        assert_eq!(
            password_purpose(&protocol("sftp")),
            Some(Purpose::SftpPassword)
        );
        assert_eq!(
            password_purpose(&protocol("ssh")),
            Some(Purpose::SshPassword)
        );
        assert_eq!(password_purpose(&protocol("telnet")), None);

        assert_eq!(
            private_key_purpose(&protocol("ssh")),
            Some(Purpose::SshPrivateKey)
        );
        assert_eq!(
            private_key_purpose(&protocol("sftp")),
            Some(Purpose::SftpPrivateKey)
        );
        assert_eq!(private_key_purpose(&protocol("rdp")), None);
        assert_eq!(private_key_purpose(&protocol("vnc")), None);
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

    /// A credential an importer recorded as a path to a key file, with nothing
    /// stored in the vault for it.
    fn key_file_credential(
        state: &AppState,
        name: &str,
        allowed: &[&str],
        provider: &str,
        reference: &str,
    ) -> CredentialRef {
        let mut guard = state.lock();
        let vault = guard.vault_mut().unwrap();
        let mut tree = vault.tree().unwrap();
        let mut props = CredentialProps::new(
            "deploy",
            SecretKind::External {
                provider: provider.to_owned(),
                reference: reference.to_owned(),
            },
        );
        props.allowed_protocols = allowed.iter().map(|id| protocol(id)).collect();
        let node = Node::new(NodeKind::Credential(props), name, 1_700_000_000_000);
        let id = node.id;
        let patch = tree.insert(node).unwrap();
        vault.apply(&tree, &patch).unwrap();
        CredentialRef::live(id)
    }

    /// A real Ed25519 key in OpenSSH's container, made now: no key file is
    /// committed, even for a test.
    fn openssh_key(passphrase: Option<&str>) -> (russh::keys::PrivateKey, String) {
        use russh::keys::ssh_key::{Algorithm, LineEnding};
        let key =
            russh::keys::PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
                .unwrap();
        let stored = match passphrase {
            Some(passphrase) => key
                .encrypt(&mut russh::keys::key::safe_rng(), passphrase)
                .unwrap(),
            None => key.clone(),
        };
        let text = stored.to_openssh(LineEnding::LF).unwrap().to_string();
        (key, text)
    }

    #[test]
    fn a_key_file_an_import_pointed_at_is_lent_as_the_private_key() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let (key, text) = openssh_key(None);
        let file = scratch.join("id_ed25519");
        std::fs::write(&file, &text).unwrap();

        for (provider, id) in [("openssh-identity-file", "ssh"), ("putty-key-file", "sftp")] {
            let reference = key_file_credential(
                &state,
                provider,
                &[id],
                provider,
                &file.display().to_string(),
            );
            let mut guard = state.lock();
            let borrowed = acquire(&mut guard, &reference, &protocol(id), "web-01")
                .unwrap_or_else(|err| panic!("{provider}: {} — {}", err.code, err.message));
            assert_eq!(borrowed.kind(), CredentialKind::PrivateKey);
            assert_eq!(borrowed.username(), Some("deploy"));
            // What the SSH adapter does with it: parse the container it was
            // lent, with the passphrase it was lent — none.
            let parsed = borrowed
                .with_private_key(&mut |bytes, passphrase| {
                    assert!(passphrase.is_none());
                    remoter_proto_ssh::keyfmt::parse_private_key(bytes, passphrase)
                })
                .unwrap_or_else(|| panic!("{provider}: no key was lent"))
                .unwrap_or_else(|err| panic!("{provider}: the key did not parse: {err:?}"));
            assert_eq!(parsed.public_key(), key.public_key());

            let recent = guard.vault_ref().unwrap().audit_recent(5).unwrap();
            assert!(
                recent
                    .iter()
                    .any(|(_, event, outcome, detail)| event == "secret_used"
                        && outcome == "success"
                        && detail.as_deref() == Some("key_file")),
                "{provider}: the use was not recorded: {recent:?}"
            );
        }
    }

    #[test]
    fn an_encrypted_key_file_is_lent_without_a_passphrase_so_the_adapter_asks() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let (_, text) = openssh_key(Some("correct horse"));
        let file = scratch.join("id_encrypted");
        std::fs::write(&file, &text).unwrap();
        let reference = key_file_credential(
            &state,
            "encrypted",
            &["ssh"],
            "openssh-identity-file",
            &file.display().to_string(),
        );

        let mut guard = state.lock();
        let borrowed = acquire(&mut guard, &reference, &protocol("ssh"), "web-01").unwrap();
        let outcome = borrowed
            .with_private_key(&mut |bytes, passphrase| {
                assert!(remoter_proto_ssh::keyfmt::needs_passphrase(bytes));
                remoter_proto_ssh::keyfmt::parse_private_key(bytes, passphrase)
            })
            .unwrap();
        // The shape the authentication ladder turns into a passphrase prompt.
        assert!(
            matches!(&outcome, Err(ProtocolError::CredentialMissing { name }) if name == "key passphrase"),
            "{outcome:?}"
        );
    }

    #[test]
    fn a_key_file_that_cannot_be_lent_says_which_file_and_why_and_nothing_else() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let not_a_key = scratch.join("shadow-like");
        std::fs::write(
            &not_a_key,
            "root:$6$saltsalt$zzq-hash-7c1e:19000:0:99999:7:::\n",
        )
        .unwrap();
        let too_large = scratch.join("huge");
        std::fs::write(&too_large, vec![b'A'; 70_000]).unwrap();
        let missing = scratch.join("gone");

        let cases = [
            (missing.display().to_string(), "does not exist"),
            (
                not_a_key.display().to_string(),
                "is not a private key Remoter can read",
            ),
            (
                too_large.display().to_string(),
                "is too large to be a private key",
            ),
            (scratch.join("").display().to_string(), "is not a file"),
            (
                String::from("keys/id_ed25519"),
                "is not a full path on this computer",
            ),
            (
                String::from(r"C:relative\id"),
                "is not a full path on this computer",
            ),
        ];
        for (path, reason) in cases {
            let reference =
                key_file_credential(&state, "imported", &[], "openssh-identity-file", &path);
            let mut guard = state.lock();
            let Err(failure) = acquire(&mut guard, &reference, &protocol("ssh"), "web-01") else {
                panic!("{path}: a key was lent");
            };
            assert_eq!(failure.code, "session.key-file-unreadable", "{path}");
            assert!(
                failure.message.contains(reason),
                "{path}: {}",
                failure.message
            );
            assert!(failure.message.contains("imported"), "{}", failure.message);
            assert_eq!(
                failure.actions,
                ["Choose a credential", "Open the credential's settings"]
            );
            // Nothing from the file and nothing from the operating system.
            let everything = format!("{} {:?}", failure.message, failure.detail);
            for leak in ["zzq-hash", "root:", "os error", "No such file", "AAAA"] {
                assert!(!everything.contains(leak), "{path}: {everything}");
            }
        }
    }

    #[test]
    fn a_key_file_is_never_read_for_a_protocol_that_cannot_use_one_or_against_its_restriction() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        // A path that does not exist: had it been read, the failure would say so.
        let path = scratch.join("never-read").display().to_string();

        let unrestricted = key_file_credential(&state, "any", &[], "putty-key-file", &path);
        let mut guard = state.lock();
        let Err(failure) = acquire(&mut guard, &unrestricted, &protocol("rdp"), "WIN-DC01") else {
            panic!("a key file was lent to an RDP session");
        };
        assert_eq!(failure.code, "session.credential-unsupported");
        drop(guard);

        let sftp_only =
            key_file_credential(&state, "sftp only", &["sftp"], "putty-key-file", &path);
        let mut guard = state.lock();
        let Err(failure) = acquire(&mut guard, &sftp_only, &protocol("ssh"), "web-01") else {
            panic!("a key file restricted to SFTP was lent to SSH");
        };
        assert_eq!(failure.code, "session.credential-purpose");
    }

    #[test]
    fn any_other_external_provider_is_still_not_fetched() {
        let scratch = Scratch::new();
        let Some(state) = open_vault(&scratch) else {
            panic!("the vault could not be created");
        };
        let reference =
            key_file_credential(&state, "vaulted", &[], "hashicorp-vault", "/etc/passwd");
        let mut guard = state.lock();
        let Err(failure) = acquire(&mut guard, &reference, &protocol("ssh"), "web-01") else {
            panic!("an unknown provider's reference was read as a file");
        };
        assert_eq!(failure.code, "session.credential-external");
    }

    #[test]
    fn a_leading_tilde_is_this_accounts_home_and_nothing_else_is() {
        let home = Path::new("/home/alex");
        assert_eq!(
            expand_key_path("~", Some(home)),
            PathBuf::from("/home/alex")
        );
        assert_eq!(
            expand_key_path("~/.ssh/id_ed25519", Some(home)),
            PathBuf::from("/home/alex/.ssh/id_ed25519")
        );
        assert_eq!(
            expand_key_path("~\\.ssh\\id", Some(home)),
            home.join(".ssh\\id")
        );
        // Another account's home is not resolved, and no home leaves `~` as it is.
        assert_eq!(
            expand_key_path("~bob/.ssh/id", Some(home)),
            PathBuf::from("~bob/.ssh/id")
        );
        assert_eq!(
            expand_key_path("~/.ssh/id", None),
            PathBuf::from("~/.ssh/id")
        );
        assert_eq!(
            expand_key_path("/etc/ssh/key", Some(home)),
            PathBuf::from("/etc/ssh/key")
        );
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
