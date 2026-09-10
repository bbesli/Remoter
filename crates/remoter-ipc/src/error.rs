//! The failure shape the interface receives.
//!
//! Every command returns `Result<T, IpcError>`, and every `IpcError` carries a
//! machine-readable `code`, a sentence that names *what* failed and *where*,
//! and the actions the interface should offer next. That is the failure
//! taxonomy in `docs/architecture/session-pipeline.md`: a message that only
//! says something went wrong forces the user to reproduce the problem with a
//! command-line tool.
//!
//! Two rules constrain what may go in one:
//!
//! 1. **No secret.** Not in `message`, not in `detail`. The mappings below
//!    take their text from the lower crates' `Display`, which is written under
//!    the same rule, plus context the caller supplies — a path, a node name, a
//!    protocol. Never a password, a key or a decrypted field.
//! 2. **No pre-unlock detail.** Until a key slot has unwrapped the master key,
//!    a failure must not say which factor was wrong. [`UnlockError`] enforces
//!    that by construction and [`IpcError::from_unlock`] preserves it: the
//!    generic case becomes exactly "That did not unlock the vault." with no
//!    detail attached.

use std::fmt;
use std::path::Path;

use remoter_core::{CoreError, ValidationError};
use remoter_import::ImportError;
use remoter_vault::{UnlockError, VaultError};
use serde::Serialize;

/// A structured failure, serialised to the `IpcFailure` interface in
/// `apps/desktop/ui/src/lib/ipc.ts`.
#[derive(Debug, Clone, Serialize)]
pub struct IpcError {
    /// Stable, dotted, ASCII. The interface branches on this; it is never
    /// shown to the user and never translated.
    pub code: String,
    /// One sentence naming what failed and where. Shown as-is.
    pub message: String,
    /// The underlying diagnostic, for the "copy details" affordance.
    pub detail: Option<String>,
    /// Suggested next actions, in the order the interface should offer them.
    pub actions: Vec<String>,
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for IpcError {}

impl IpcError {
    /// A failure with a code and a message and nothing else yet.
    #[must_use]
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            message: message.into(),
            detail: None,
            actions: Vec::new(),
        }
    }

    /// Attaches the underlying diagnostic.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attaches the next actions, in the order to offer them.
    #[must_use]
    pub fn with_actions<I, S>(mut self, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.actions = actions.into_iter().map(Into::into).collect();
        self
    }

    // ------------------------------------------------------------- state ---

    /// No vault is open.
    pub(crate) fn locked() -> Self {
        Self::new(
            "vault.locked",
            "No vault is open. Unlock one to see your connections.",
        )
        .with_actions(["Unlock a vault"])
    }

    /// The vault locked itself after the configured idle period.
    pub(crate) fn auto_locked(minutes: u32) -> Self {
        Self::new(
            "vault.auto-locked",
            format!(
                "The vault locked itself after {minutes} minutes without activity. \
                 Unlock it to carry on."
            ),
        )
        .with_actions(["Unlock the vault", "Change the timeout in settings"])
    }

    /// The vault locked itself because an operating-system event happened and
    /// this vault is configured to lock on it.
    ///
    /// `because` is a clause — "the machine had been suspended" — so the
    /// sentence names the event rather than a policy name the user never
    /// chose.
    pub(crate) fn locked_by_trigger(because: &str) -> Self {
        Self::new(
            "vault.locked-by-trigger",
            format!("The vault locked itself because {because}. Unlock it to carry on."),
        )
        .with_actions(["Unlock the vault", "Change what locks it in vault settings"])
    }

    /// The request itself was wrong — a field the frontend must supply was
    /// missing or unparseable. A bug in the caller rather than the user's
    /// doing, so the message says which field.
    pub(crate) fn invalid_request(field: &str, why: impl Into<String>) -> Self {
        Self::new(
            "request.invalid",
            format!(
                "The `{field}` value in that request is not usable: {}",
                why.into()
            ),
        )
        .with_actions(["Report this — the interface sent something the core cannot read"])
    }

    /// A path the user chose cannot be used.
    pub(crate) fn bad_path(path: &Path, why: impl Into<String>) -> Self {
        Self::new(
            "path.unusable",
            format!("{} cannot be used: {}", path.display(), why.into()),
        )
        .with_actions(["Choose another location"])
    }

    /// A local file could not be read or written. `operation` reads as a
    /// gerund phrase — "writing the key file" — so the sentence names the act
    /// and the file.
    pub(crate) fn io(operation: &str, path: &Path, source: &std::io::Error) -> Self {
        Self::new(
            "io.failed",
            format!("{} failed for {}.", capitalise(operation), path.display()),
        )
        .with_detail(source.to_string())
        .with_actions([
            "Check the path exists and is writable",
            "Choose another location",
        ])
    }

    /// The operating system's random number generator refused. Nothing that
    /// needs entropy may proceed on a fallback.
    pub(crate) fn csprng() -> Self {
        Self::new(
            "system.csprng",
            "The operating system's random number generator is unavailable, so \
             nothing random can be generated safely.",
        )
        .with_actions(["Restart Remoter", "Report this if it persists"])
    }

    // ------------------------------------------------------------ unlock ---

    /// Maps an unlock failure, preserving the rule that a pre-unwrap failure
    /// says nothing about which factor was wrong.
    pub(crate) fn from_unlock(err: &UnlockError, subject: &str) -> Self {
        match err {
            // Exactly this sentence, with no detail and no hint about which
            // half of a two-factor unlock was wrong. See the module docs.
            UnlockError::NotUnlocked => {
                Self::new("vault.unlock-failed", "That did not unlock the vault.").with_actions([
                    "Try again",
                    "Check the key file, if this vault uses one",
                    "Use your recovery key",
                ])
            }
            UnlockError::HeaderTampered => Self::new(
                "vault.header-tampered",
                format!(
                    "The header of {subject} has been modified since it was written, \
                     so its contents cannot be trusted."
                ),
            )
            .with_detail(err.to_string())
            .with_actions([
                "Open a backup beside the vault",
                "Check whether a sync client rewrote the file",
            ]),
            UnlockError::BodyCorrupt => Self::new(
                "vault.body-corrupt",
                format!("The contents of {subject} could not be decrypted. The file is damaged."),
            )
            .with_detail(err.to_string())
            .with_actions([
                "Open a backup beside the vault",
                "Check the drive the vault is stored on",
            ]),
            UnlockError::NoSuchMethod(kind) => Self::new(
                "vault.no-such-method",
                format!("{subject} has no {kind} unlock method."),
            )
            .with_actions(["Choose one of the methods this vault offers"]),
            UnlockError::Fido2Unsupported => Self::new(
                "vault.fido2-unsupported",
                "Hardware key unlock is not implemented in this version of Remoter.",
            )
            .with_actions(["Unlock with a password or your recovery key"]),
            UnlockError::Vault(inner) => Self::from_vault(inner, subject),
        }
    }

    // ------------------------------------------------------------- vault ---

    /// Maps a vault failure. `subject` names the file or the vault in the
    /// user's terms — a path for a file that is not open yet, "this vault"
    /// for one that is.
    #[allow(clippy::too_many_lines)] // one arm per variant; splitting it hides the mapping
    pub(crate) fn from_vault(err: &VaultError, subject: &str) -> Self {
        match err {
            VaultError::Io {
                operation,
                path,
                source,
            } => Self::io(operation, path, source),
            VaultError::Csprng => Self::csprng(),
            VaultError::NotAVault => Self::new(
                "vault.not-a-vault",
                format!("{subject} is not a Remoter vault."),
            )
            .with_actions(["Choose a .rvault file", "Create a new vault"]),
            VaultError::UnsupportedFormat(version) => Self::new(
                "vault.unsupported-format",
                format!(
                    "{subject} uses vault format version {version}, which this build of \
                     Remoter does not read."
                ),
            )
            .with_actions(["Update Remoter", "Open the vault on the machine that wrote it"]),
            VaultError::Malformed | VaultError::HeaderDecode | VaultError::NotADatabase => {
                Self::new(
                    "vault.corrupt",
                    format!("{subject} is damaged: its structure could not be read."),
                )
                .with_detail(err.to_string())
                .with_actions(["Open a backup beside the vault"])
            }
            VaultError::CorruptRow(what) => Self::new(
                "vault.corrupt-row",
                format!("{subject} holds a record this build of Remoter cannot read: {what}."),
            )
            .with_actions(["Open a backup beside the vault", "Update Remoter"]),
            VaultError::HeaderEncode => Self::new(
                "vault.header-encode",
                format!("The header for {subject} could not be encoded, so it was not written."),
            )
            .with_detail(err.to_string())
            .with_actions(["Report this — the vault on disk is unchanged"]),
            VaultError::KeyDerivation | VaultError::Aead => Self::new(
                "vault.crypto",
                format!("A cryptographic step on {subject} failed, so the operation was abandoned."),
            )
            .with_detail(err.to_string())
            .with_actions(["Try again", "Report this if it persists"]),
            VaultError::KdfParamsTooWeak => Self::new(
                "vault.kdf-too-weak",
                "Those Argon2id parameters are below the floor Remoter accepts, and a \
                 weaker vault is not an acceptable trade for a faster unlock.",
            )
            .with_actions(["Use the calibrated parameters"]),
            VaultError::KdfParamsRefused {
                parameter,
                declared,
                limit,
            } => Self::new(
                "vault.kdf-params-refused",
                format!(
                    "{subject} declares an Argon2id {parameter} of {declared}, and this build \
                     will not attempt anything above {limit}. Nothing was derived."
                ),
            )
            .with_actions([
                "Open the vault on the machine that wrote it",
                "Update Remoter",
                "Open a backup beside the vault",
            ]),
            VaultError::NoSuchSlot(index) => Self::new(
                "vault.no-such-slot",
                format!("{subject} has no key slot {index}."),
            )
            .with_actions(["Reload the slot list"]),
            VaultError::NoSlotOfKind(kind) => Self::new(
                "vault.no-slot-of-kind",
                format!("{subject} has no {kind} slot."),
            )
            .with_actions(["Add that unlock method first"]),
            VaultError::SlotTableFull(max) => Self::new(
                "vault.slot-table-full",
                format!("{subject} already holds the maximum of {max} key slots."),
            )
            .with_actions(["Remove an unlock method you no longer use"]),
            VaultError::LastSlot => Self::new(
                "vault.last-slot",
                format!("That is the only way into {subject}; removing it would lock you out permanently."),
            )
            .with_actions(["Add another unlock method first"]),
            VaultError::WrongSlotKind {
                index,
                expected,
                found,
            } => Self::new(
                "vault.wrong-slot-kind",
                format!(
                    "Key slot {index} is a {found} slot, not a {expected} slot, so that \
                     operation does not apply to it."
                ),
            )
            .with_actions(["Reload the slot list", "Choose a slot of the right kind"]),
            VaultError::SlotCredentialMissing(index) => Self::new(
                "vault.slot-credential-missing",
                format!(
                    "Key slot {index} cannot be re-wrapped without its password, and \
                     dropping it silently would take away someone's way in. Nothing was \
                     changed."
                ),
            )
            .with_actions([
                "Enter the password for that slot",
                "Drop that slot from the rotation deliberately",
            ]),
            VaultError::SlotCredentialRejected(index) => Self::new(
                "vault.slot-credential-rejected",
                format!(
                    "That does not open key slot {index}, so the slot was left exactly as \
                     it was."
                ),
            )
            .with_actions([
                "Try again",
                "Check the key file, if that slot uses one",
                "Use your recovery key",
            ]),
            VaultError::NotAPrivateKey => Self::new(
                "key.not-a-private-key",
                "That file is not a private key. A public key, a certificate or an \
                 unrelated file cannot authenticate a connection.",
            )
            .with_actions([
                "Choose the private key rather than its .pub companion",
                "Use the platform SSH agent instead",
            ]),
            VaultError::UnsupportedKeyFormat(what) => Self::new(
                "key.unsupported-format",
                format!(
                    "That key is in {what} format, which this build does not store. \
                     Nothing was written."
                ),
            )
            .with_actions([
                "Convert it with `ssh-keygen -p -m PKCS8 -f <file>`",
                "Use the platform SSH agent instead",
            ]),
            VaultError::NotAPrivateKeyCredential(id) => Self::new(
                "credential.not-a-private-key",
                "That item is not a credential holding a private key, so there is no key \
                 to read or replace on it.",
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Select a credential", "Choose a key file for it first"]),
            VaultError::Fido2Unsupported => Self::new(
                "vault.fido2-unsupported",
                "Hardware key slots are not implemented in this version of Remoter.",
            )
            .with_actions(["Use a password or recovery slot"]),
            VaultError::Keychain => Self::new(
                "vault.keychain",
                "This machine's credential store is unavailable, or holds no token for \
                 this vault.",
            )
            .with_actions(["Unlock with your password", "Re-enrol this device afterwards"]),
            VaultError::RecoveryKeyMalformed => Self::new(
                "vault.recovery-key-malformed",
                "That is not a recovery key: a recovery key is fourteen groups of four \
                 characters.",
            )
            .with_actions(["Check you pasted the whole key"]),
            VaultError::RecoveryKeyChecksum => Self::new(
                "vault.recovery-key-checksum",
                "That recovery key looks mistyped — its check group does not match the rest.",
            )
            .with_actions(["Compare it against the copy you saved", "Try again"]),
            VaultError::Keyfile => Self::new(
                "vault.keyfile",
                "The key file could not be read.",
            )
            .with_actions([
                "Check the file is where it was when the vault was created",
                "Mount the drive it lives on",
            ]),
            VaultError::Database(inner) => Self::new(
                "vault.database",
                format!("The database inside {subject} rejected the operation."),
            )
            .with_detail(inner.to_string())
            .with_actions(["Try again", "Open a backup beside the vault"]),
            VaultError::SchemaTooNew { found, supported } => Self::new(
                "vault.schema-too-new",
                format!(
                    "{subject} was written by a newer version of Remoter: it uses schema \
                     version {found} and this build understands {supported}."
                ),
            )
            .with_actions(["Update Remoter"]),
            VaultError::Migration(version) => Self::new(
                "vault.migration-failed",
                format!(
                    "{subject} could not be migrated to schema version {version}; the file \
                     was left as it was."
                ),
            )
            .with_actions(["Open a backup beside the vault", "Report this"]),
            VaultError::NoSuchNode(id) => Self::new(
                "node.not-found",
                format!("That item is no longer in {subject}; it was probably deleted elsewhere."),
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Reload the tree"]),
            VaultError::NoSuchSecret { node, field } => Self::new(
                "secret.not-found",
                format!("That credential has no {field} stored."),
            )
            .with_detail(format!("node {node}"))
            .with_actions(["Enter it now", "Choose another credential"]),
            VaultError::StaleSecret => Self::new(
                "secret.stale",
                "The stored secret does not match the current version of its record, so it \
                 was refused rather than used.",
            )
            .with_actions(["Re-enter the secret", "Open a backup beside the vault"]),
            VaultError::PurposeRefused(purpose) => Self::new(
                "credential.purpose-refused",
                "This credential is restricted and may not be used this way.",
            )
            .with_detail(format!("{purpose:?}"))
            .with_actions(["Choose another credential", "Widen the credential's restriction"]),
            VaultError::Core(inner) => Self::from_core(inner),
        }
    }

    // ------------------------------------------------------------ import ---

    /// Maps an importer failure. `subject` is the file the user chose, named
    /// as they named it.
    ///
    /// Nothing here quotes file content back: a message that echoed a line of
    /// the document would print a password out of an mRemoteNG file the moment
    /// the password happened to be on the line that failed to parse.
    #[allow(clippy::too_many_lines)] // one arm per variant; splitting it hides the mapping
    pub(crate) fn from_import(err: &ImportError, subject: &str) -> Self {
        match err {
            ImportError::TooLarge { size, limit } => Self::new(
                "import.too-large",
                format!(
                    "{subject} is {size} bytes and this build reads at most {limit}. \
                     Nothing was parsed."
                ),
            )
            .with_actions(["Split the file", "Import the parts separately"]),
            ImportError::NotUtf8 { offset } => Self::new(
                "import.not-utf8",
                format!(
                    "{subject} is not UTF-8 text: byte {offset} is not part of a valid \
                     character."
                ),
            )
            .with_actions([
                "Re-save the file as UTF-8",
                "Check this is the file you meant to choose",
            ]),
            ImportError::MalformedXml { offset } => Self::new(
                "import.malformed-xml",
                format!("{subject} is not well-formed XML: it breaks at byte {offset}."),
            )
            .with_actions([
                "Export the file again from the application that wrote it",
                "Check this is the file you meant to choose",
            ]),
            ImportError::DoctypeRefused => Self::new(
                "import.doctype-refused",
                format!(
                    "{subject} carries a document type declaration, which Remoter refuses \
                     to process: it is how an XML file is made to read other files on this \
                     machine."
                ),
            )
            .with_actions([
                "Remove the DOCTYPE line and try again",
                "Export the file again from the application that wrote it",
            ]),
            ImportError::EntityRefused => Self::new(
                "import.entity-refused",
                format!(
                    "{subject} defines its own XML entities, which Remoter refuses to \
                     expand: that is the shape of a file written to exhaust memory."
                ),
            )
            .with_actions(["Export the file again from the application that wrote it"]),
            ImportError::TooDeep { limit } => Self::new(
                "import.too-deep",
                format!("{subject} nests folders deeper than {limit} levels."),
            )
            .with_actions(["Flatten the deepest folders in the source application"]),
            ImportError::TooManyItems { limit, unit } => Self::new(
                "import.too-many-items",
                format!("{subject} holds more than {limit} {unit}, which is this build's limit."),
            )
            .with_actions(["Split the file", "Import the parts separately"]),
            ImportError::ValueTooLong { limit, unit } => Self::new(
                "import.value-too-long",
                format!("{subject} holds a {unit} longer than {limit} bytes."),
            )
            .with_actions(["Shorten it in the source application, then export again"]),
            ImportError::Truncated { unit } => Self::new(
                "import.truncated",
                format!("{subject} ends in the middle of a {unit}: the file is incomplete."),
            )
            .with_actions([
                "Copy the file again from where it came from",
                "Export it again from the application that wrote it",
            ]),
            ImportError::WrongFormat { expected } => Self::new(
                "import.wrong-format",
                format!("{subject} is not {expected}, which is what that importer reads."),
            )
            .with_actions(["Choose the source format yourself", "Choose another file"]),
            ImportError::PasswordRequired => Self::new(
                "import.password-required",
                format!("{subject} is encrypted and needs its document password to be read."),
            )
            .with_actions(["Enter the document password", "Choose another file"]),
            ImportError::WrongPassword => Self::new(
                "import.wrong-password",
                format!("That is not the password {subject} was encrypted with."),
            )
            .with_actions([
                "Try again",
                "Check whether the file uses the source application's default password",
            ]),
            ImportError::UnsupportedCipher { mode } => Self::new(
                "import.unsupported-cipher",
                format!("{subject} is encrypted with `{mode}`, which Remoter cannot read."),
            )
            .with_actions([
                "Export the file again without encryption, then import it",
                "Re-save it from a newer version of the source application",
            ]),
            ImportError::MalformedCiphertext => Self::new(
                "import.malformed-ciphertext",
                format!(
                    "The encrypted part of {subject} is damaged: it decrypts to nothing \
                     usable."
                ),
            )
            .with_actions([
                "Copy the file again from where it came from",
                "Export it again from the application that wrote it",
            ]),
            ImportError::TooManyNodes { limit } => Self::new(
                "import.too-many-nodes",
                format!("{subject} would create more than {limit} items, which is the limit."),
            )
            .with_actions(["Split the file", "Import the parts separately"]),
            ImportError::MissingColumn { column } => Self::new(
                "import.missing-column",
                format!("{subject} has no `{column}` column, and the importer needs one."),
            )
            .with_actions([
                "Add the column header and try again",
                "Check the first row is the header row",
            ]),
            ImportError::DuplicateColumn { column } => Self::new(
                "import.duplicate-column",
                format!(
                    "{subject} names the `{column}` column twice, so which one holds the \
                     value is undecidable."
                ),
            )
            .with_actions(["Remove or rename the repeated column"]),
            ImportError::ReadFailed { path, reason } => Self::new(
                "import.read-failed",
                format!("{path} could not be read while following an include: {reason}."),
            )
            .with_actions([
                "Check the file exists and is readable",
                "Remove the Include line and import again",
            ]),
            ImportError::IncludeTooDeep { limit } => Self::new(
                "import.include-too-deep",
                format!("{subject} includes files more than {limit} levels deep."),
            )
            .with_actions(["Flatten the Include chain and import again"]),
            ImportError::Validation(inner) => Self::from_validation(inner),
            // `ImportError` is `#[non_exhaustive]`: a variant added upstream
            // must not stop this crate compiling, and it must not arrive
            // without a sentence either.
            other => Self::new("import.failed", format!("{subject} could not be imported."))
                .with_detail(other.to_string())
                .with_actions(["Choose another file", "Report this"]),
        }
    }

    // -------------------------------------------------------------- core ---

    /// Maps a domain-model failure.
    pub(crate) fn from_core(err: &CoreError) -> Self {
        match err {
            CoreError::Validation(inner) => Self::from_validation(inner),
            CoreError::NodeNotFound(id) => Self::new(
                "node.not-found",
                "That item is no longer in the tree; it was probably deleted in another window.",
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Reload the tree"]),
            CoreError::ParentNotFound(id) => Self::new(
                "node.parent-not-found",
                "The folder you dropped that into no longer exists.",
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Reload the tree", "Choose another folder"]),
            CoreError::DuplicateNodeId(id) => Self::new(
                "node.duplicate",
                "An item with that identifier is already in the tree.",
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Reload the tree"]),
            CoreError::NotAContainer(id) => {
                Self::new("node.not-a-container", "Only folders can hold other items.")
                    .with_detail(format!("node {id}"))
                    .with_actions(["Drop it into a folder", "Drop it at the top level"])
            }
            CoreError::Cycle { node, parent } => {
                Self::new("node.cycle", "A folder cannot be moved inside itself.")
                    .with_detail(format!("node {node} under {parent}"))
                    .with_actions(["Choose a destination outside that folder"])
            }
            CoreError::DepthExceeded { depth } => Self::new(
                "node.too-deep",
                format!(
                    "That move would nest the tree {depth} levels deep; the limit is {max}.",
                    max = remoter_core::MAX_TREE_DEPTH
                ),
            )
            .with_actions([
                "Move it nearer the top level",
                "Flatten the folders above it",
            ]),
            CoreError::ParentChanged { node } => Self::new(
                "node.parent-changed",
                "An edit cannot re-parent an item; move it instead.",
            )
            .with_detail(format!("node {node}"))
            .with_actions(["Drag it to the new folder"]),
            CoreError::NotAConnection(id) => Self::new(
                "node.not-a-connection",
                "Only connections have resolved settings to show.",
            )
            .with_detail(format!("node {id}"))
            .with_actions(["Select a connection"]),
            CoreError::CorruptTree => Self::new(
                "tree.corrupt",
                "The item tree in this vault does not terminate: a parent chain loops.",
            )
            .with_actions(["Open a backup beside the vault", "Report this"]),
        }
    }

    /// Maps a validation failure. These are the user's own input being wrong,
    /// so the sentence names the field and the rule.
    #[allow(clippy::too_many_lines)] // one arm per rule; splitting it hides the mapping
    pub(crate) fn from_validation(err: &ValidationError) -> Self {
        match err {
            ValidationError::NameEmpty => {
                Self::new("validation.name-empty", "That item needs a name.")
                    .with_actions(["Type a name"])
            }
            ValidationError::NameTooLong { len } => Self::new(
                "validation.name-too-long",
                format!(
                    "That name is {len} characters; the limit is {max}.",
                    max = remoter_core::MAX_NAME_LEN
                ),
            )
            .with_actions(["Shorten the name"]),
            ValidationError::NameControlChar | ValidationError::IdentityControlChar => Self::new(
                "validation.control-char",
                "That value contains control characters, which cannot be stored.",
            )
            .with_actions(["Retype it", "Paste it as plain text"]),
            ValidationError::DescriptionTooLong { len, max } => Self::new(
                "validation.description-too-long",
                format!("That description is {len} characters; the limit is {max}."),
            )
            .with_actions(["Shorten the description"]),
            ValidationError::HostEmpty => Self::new(
                "validation.host-empty",
                "This connection has no address. Add a hostname or an IP address.",
            )
            .with_actions(["Enter a hostname or IP address"]),
            ValidationError::InvalidHost { host } => Self::new(
                "validation.host-invalid",
                format!("`{host}` is not a hostname, an IPv4 address or a bracketed IPv6 address."),
            )
            .with_actions(["Check the spelling", "Wrap an IPv6 address in [brackets]"]),
            ValidationError::PortOutOfRange => {
                Self::new("validation.port", "A port has to be between 1 and 65535.").with_actions(
                    [
                        "Enter a port in range",
                        "Leave it empty to use the protocol default",
                    ],
                )
            }
            ValidationError::InvalidTag { tag } => {
                Self::new("validation.tag", format!("`{tag}` is not a usable tag."))
                    .with_actions(["Use letters, digits, dashes and dots"])
            }
            ValidationError::InvalidProtocolId { id } => Self::new(
                "validation.protocol",
                format!("`{id}` is not a protocol Remoter recognises."),
            )
            .with_actions(["Choose a protocol from the list"]),
            ValidationError::InvalidSettingKey { key } => Self::new(
                "validation.setting-key",
                format!("`{key}` is not a usable protocol setting name."),
            )
            .with_actions(["Use letters, digits, dashes and dots"]),
            ValidationError::InvalidCustomFieldKey { key } => Self::new(
                "validation.custom-field-key",
                format!("`{key}` is not a usable custom field name."),
            )
            .with_actions(["Use letters, digits, dashes and dots"]),
            ValidationError::InvalidColour { colour } => Self::new(
                "validation.colour",
                format!("`{colour}` is not a colour; expected #rrggbb or #rrggbbaa."),
            )
            .with_actions(["Pick a colour from the swatches"]),
            ValidationError::InvalidIcon => Self::new(
                "validation.icon",
                "That icon reference is empty or contains control characters.",
            )
            .with_actions(["Pick an icon from the list"]),
            ValidationError::GatewayTooLong { hops } => Self::new(
                "validation.gateway-too-long",
                format!(
                    "That gateway chain has {hops} hops; the limit is {max}.",
                    max = remoter_core::MAX_GATEWAY_HOPS
                ),
            )
            .with_actions(["Remove a hop"]),
            ValidationError::GatewayCycle { hop } => Self::new(
                "validation.gateway-cycle",
                "The gateway chain loops back on itself: one host appears twice.",
            )
            .with_detail(format!("node {hop}"))
            .with_actions(["Remove the repeated hop"]),
            ValidationError::GatewayHopUnknown { hop } => Self::new(
                "validation.gateway-hop-unknown",
                "One of the gateway hops points at an item that is no longer in this vault.",
            )
            .with_detail(format!("node {hop}"))
            .with_actions(["Choose another gateway", "Connect directly"]),
            ValidationError::GatewayHopNotAConnection { hop } => Self::new(
                "validation.gateway-hop-kind",
                "A gateway hop has to be a connection; a folder cannot forward traffic.",
            )
            .with_detail(format!("node {hop}"))
            .with_actions(["Choose a connection as the gateway"]),
            ValidationError::CredentialUnknown { credential } => Self::new(
                "validation.credential-unknown",
                "The credential this uses was deleted. Choose another, or enter one now.",
            )
            .with_detail(format!("node {credential}"))
            .with_actions(["Choose another credential", "Enter one now"]),
            ValidationError::CredentialNotACredential { credential } => Self::new(
                "validation.credential-kind",
                "That item is not a credential.",
            )
            .with_detail(format!("node {credential}"))
            .with_actions(["Choose a credential"]),
            ValidationError::CredentialAttachedElsewhere {
                credential,
                connection,
            } => Self::new(
                "validation.credential-attached",
                "That credential belongs to another connection. Sharing it would mean \
                 editing it in one place changed the other.",
            )
            .with_detail(format!("node {credential}, attached to {connection}"))
            .with_actions([
                "Choose a shared credential",
                "Type a username and password here instead",
            ]),
            ValidationError::CredentialAttachmentUnknown {
                credential,
                connection,
            }
            | ValidationError::CredentialAttachmentNotAConnection {
                credential,
                connection,
            } => Self::new(
                "validation.credential-attachment",
                "A credential in this vault belongs to a connection that is not there. \
                 Nothing was changed.",
            )
            .with_detail(format!("node {credential}, attached to {connection}"))
            .with_actions(["Reload the vault", "Restore from a backup"]),
            ValidationError::CredentialPurpose {
                credential,
                protocol,
            } => Self::new(
                "validation.credential-purpose",
                format!("This credential is restricted and cannot be used for {protocol}."),
            )
            .with_detail(format!("node {credential}"))
            .with_actions([
                "Choose another credential",
                "Widen the credential's restriction",
            ]),
            ValidationError::UsernameTooLong { len, max } => Self::new(
                "validation.username-too-long",
                format!("That username is {len} characters; the limit is {max}."),
            )
            .with_actions(["Shorten the username"]),
            ValidationError::ExternalCredentialIncomplete => Self::new(
                "validation.external-credential",
                "An external credential needs both a provider and a reference.",
            )
            .with_actions(["Fill in both fields"]),
            ValidationError::SealedMaterialEmpty => Self::new(
                "validation.secret-empty",
                "A credential needs a secret; an empty envelope is not a credential.",
            )
            .with_actions(["Enter a password", "Choose a key file"]),
            ValidationError::InvalidLayout => Self::new(
                "validation.layout",
                "A grid layout needs at least one row and one column.",
            )
            .with_actions(["Set rows and columns to 1 or more"]),
            ValidationError::GroupMemberUnknown { member } => Self::new(
                "validation.group-member",
                "One of this group's members is no longer in the vault.",
            )
            .with_detail(format!("node {member}"))
            .with_actions(["Remove the missing member"]),
            ValidationError::EmptyAction => Self::new(
                "validation.empty-action",
                "A connect or disconnect action cannot be an empty line.",
            )
            .with_actions(["Remove the blank line"]),
            ValidationError::InvalidReconnectPolicy => Self::new(
                "validation.reconnect-policy",
                "Automatic reconnection needs at least one attempt and a backoff that does \
                 not shrink.",
            )
            .with_actions(["Set the maximum backoff at or above the first"]),
            ValidationError::NonPositiveInterval => Self::new(
                "validation.interval",
                "Timeouts and keep-alive intervals have to be greater than zero.",
            )
            .with_actions(["Enter a positive number", "Clear the field to inherit it"]),
        }
    }
}

/// Upper-cases the first character of a gerund phrase such as
/// "reading the vault", so it can start a sentence.
fn capitalise(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

impl From<&VaultError> for IpcError {
    fn from(err: &VaultError) -> Self {
        Self::from_vault(err, "this vault")
    }
}

impl From<&CoreError> for IpcError {
    fn from(err: &CoreError) -> Self {
        Self::from_core(err)
    }
}

impl From<&ImportError> for IpcError {
    fn from(err: &ImportError) -> Self {
        Self::from_import(err, "that file")
    }
}
