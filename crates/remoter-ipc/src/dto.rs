//! Data transfer objects.
//!
//! Every type here is mirrored by a TypeScript interface in
//! `apps/desktop/ui/src/lib/ipc.ts`. When you change one, change both in the
//! same commit — a silently diverged DTO produces a runtime `undefined` in the
//! interface, which is the worst kind of bug to track down.
//!
//! All fields are `camelCase` on the wire.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------- vault ----

/// A vault the user has opened before, as shown on the picker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecentVaultDto {
    pub path: String,
    pub label: String,
    /// Unix seconds. `None` if never opened on this machine.
    pub last_opened: Option<i64>,
    /// Slot kinds this vault carries, so the picker can show which unlock
    /// methods exist before the user commits to one.
    pub slots: Vec<String>,
    /// `false` when the file is missing — an unmounted USB key, say. Such a
    /// vault stays visible and disabled with a reason; hiding it would look
    /// like data loss.
    pub reachable: bool,
    /// The English sentence for [`Self::unreachable_kind`].
    ///
    /// **Not for rendering.** It is the fallback for a kind the interface does
    /// not know yet, exactly as `IpcError::message` is the fallback for a code
    /// the `errors` catalogue has no entry for. The picker composes the
    /// sentence its reader needs from `vault:picker.unreachable.*`.
    pub unreachable_reason: Option<String>,
    /// Why the vault cannot be reached, as a stable identifier rather than a
    /// sentence: `"missing"`, `"unreadable"`, `"not-a-file"` — the variants of
    /// `UnreachableKind` in `recents.rs`.
    ///
    /// `None` when the file is there but does not read as a vault; that case
    /// carries [`Self::unreachable_code`] instead, because the vault error
    /// already has a code and a translated sentence of its own.
    pub unreachable_kind: Option<String>,
    /// The underlying diagnostic for [`Self::unreachable_kind`] — an operating
    /// system error string. English on purpose, like `IpcError::detail`: it is
    /// what a reader copies into a bug report.
    pub unreachable_detail: Option<String>,
    /// The `IpcError::code` of the probe failure, when the file exists but is
    /// not a readable vault. The interface renders the already-translated
    /// sentence for it from `locales/<lang>/errors.json`.
    pub unreachable_code: Option<String>,
    /// The English sentence for [`Self::sync_provider`].
    ///
    /// **Not for rendering**, for the reason above. See
    /// `vault:detail.syncWarning`.
    pub sync_warning: Option<String>,
    /// The cloud-sync provider whose folder this vault sits in, if any:
    /// `"Dropbox"`, `"OneDrive"`, `"iCloud Drive"`. A brand name, so it is
    /// never translated — it is the *value* the interface's sentence is
    /// composed around.
    pub sync_provider: Option<String>,
    pub size_bytes: Option<u64>,
}

/// What can be learned from a vault's header without any key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultProbeDto {
    pub path: String,
    pub label: String,
    pub format_version: u16,
    pub created_at: i64,
    pub modified_at: i64,
    pub size_bytes: u64,
    pub slots: Vec<SlotDto>,
    pub backups: Vec<BackupDto>,
    /// The English sentence for [`Self::sync_provider`]. **Not for rendering**
    /// — see [`RecentVaultDto::sync_warning`].
    pub sync_warning: Option<String>,
    /// The cloud-sync provider whose folder this vault sits in, if any. A
    /// brand name, never translated; the interface's sentence is composed
    /// around it. See [`RecentVaultDto::sync_provider`].
    pub sync_provider: Option<String>,
    /// The key file this vault was last opened with, if one is remembered on
    /// this machine and still on disk. The path is not a secret; the file's
    /// contents are. Offering it back removes an easy and unhelpful mistake:
    /// the browser opens in the vault's own folder, the `.rvault` is the
    /// obvious file in it, and picking it fails with a message that is
    /// deliberately unable to explain itself.
    pub remembered_keyfile: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotDto {
    pub index: u8,
    /// `"password" | "recovery" | "fido2" | "keychain"`
    pub kind: String,
    pub label: String,
    pub created_at: i64,
    pub last_used: Option<i64>,
    /// True when this slot's password also requires a key file.
    pub requires_keyfile: bool,
    /// The key-derivation cost, for the password slot only.
    pub kdf: Option<KdfParamsDto>,
}

/// What a slot cost to derive, as numbers.
///
/// This used to be one English sentence — "Argon2id, 256 MiB, 3 passes, 4
/// lanes" — composed in `remoter-vault` and printed verbatim by six screens
/// that are otherwise fully translated. "passes" and "lanes" are English
/// words, so no catalogue could reach them and no reader of the other nine
/// languages ever saw their own.
///
/// The parameters cross as numbers and the interface composes its own line
/// (`features/vault/kdf.ts`), which is also what lets the digits follow the
/// locale's numbering system and the memory carry a unit the reader's `Intl`
/// formatted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParamsDto {
    /// The function's name: `"Argon2id"`. A proper name, never translated
    /// (`docs/features/i18n.md`), and sent rather than hardcoded in the
    /// interface so that the core stays the authority on what it actually ran.
    pub algorithm: String,
    /// Memory cost, in kibibytes — Argon2's `m`.
    pub memory_kib: u32,
    /// Iterations — Argon2's `t`.
    pub passes: u32,
    /// Degree of parallelism — Argon2's `p`.
    pub lanes: u32,
}

impl From<remoter_vault::KdfParams> for KdfParamsDto {
    fn from(params: remoter_vault::KdfParams) -> Self {
        Self {
            // The only KDF this build derives with; `remoter-vault` has no
            // other, and the version number is a format detail the interface
            // has no use for.
            algorithm: String::from("Argon2id"),
            memory_kib: params.m_cost,
            passes: params.t_cost,
            lanes: params.p_cost,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupDto {
    pub path: String,
    pub modified_at: i64,
    pub size_bytes: u64,
}

/// How the user is unlocking. Mirrors `remoter_vault::UnlockMethod`.
///
/// **Review note (CLAUDE.md §5).** This type carries a master password and a
/// recovery key in the clear, so it derives neither `Clone` nor `Serialize`:
/// it only ever travels inward, and a copy or a serialisation of it would be a
/// copy or a serialisation of a secret. `Debug` is written by hand below and
/// redacts both fields, so that a `tracing::debug!(?method)` added while
/// diagnosing a failed unlock cannot put the password in a log file.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum UnlockRequestDto {
    #[serde(rename_all = "camelCase")]
    Password {
        password: String,
        keyfile_path: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Recovery { key: String },
    #[serde(rename_all = "camelCase")]
    Keychain,
}

/// **Review note (CLAUDE.md §5).** Carries the master password; see
/// [`UnlockRequestDto`] for why the derives are what they are.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequestDto {
    pub path: String,
    pub label: String,
    pub password: String,
    pub keyfile_path: Option<String>,
    /// When set, a fresh random key file is written here and used.
    pub generate_keyfile_at: Option<String>,
}

/// Returned once, at creation. The recovery key is displayed and then dropped;
/// there is no command that can ask for it again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultResultDto {
    pub path: String,
    /// Fourteen groups of four characters, Crockford Base32 (thirteen of key, one of checksum). Eight groups of four would be 160 bits and cannot carry a 256-bit key.
    pub recovery_key_groups: Vec<String>,
    /// Which group the transcription check will ask the user to retype.
    pub confirm_group_index: usize,
    /// What the new vault's password slot cost to derive. `None` only if the
    /// vault somehow has no password slot — the sheet then omits the line
    /// rather than printing a half-sentence.
    pub kdf: Option<KdfParamsDto>,
}

/// The recovery sheet the screen composed, and where the user chose to put it.
///
/// The text travels inward because the sheet is a translated document — the
/// core has no catalogue and cannot write "Your recovery key" in the reader's
/// language. What it carries, though, is the recovery key itself, so this is
/// secret-bearing in the direction this crate normally only sees passwords
/// travel.
///
/// `Debug` is written by hand for that reason: a derived one would print the
/// key the moment a caller formatted the request into a trace or an error
/// (CLAUDE.md §0.2). `Clone` is deliberately absent — one copy is enough, and
/// the command wraps it in `Secret` on arrival so it is zeroized on every exit
/// path.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySheetDto {
    pub path: String,
    pub text: String,
}

impl fmt::Debug for RecoverySheetDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverySheetDto")
            .field("path", &self.path)
            .field("text", &"<redacted>")
            .finish()
    }
}

/// What was written, so the screen can name the file it just created rather
/// than saying "done".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySheetWrittenDto {
    pub path: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStateDto {
    pub unlocked: bool,
    pub path: Option<String>,
    pub label: Option<String>,
    pub connection_count: usize,
    pub credential_count: usize,
    /// Seconds until auto-lock, or `None` when auto-lock is off.
    pub locks_in_seconds: Option<u64>,
    /// True when a password slot's Argon2id parameters are below the current
    /// cost floor. `docs/security/vault-format.md` promises the upgrade is
    /// offered on the next successful unlock, and this is what the interface
    /// reads to offer it.
    pub kdf_upgrade_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStrengthDto {
    /// 0–4, zxcvbn-style.
    pub score: u8,
    pub entropy_bits: f64,
    /// `"Weak" | "Fair" | "Good" | "Strong"`
    pub label: String,
    /// Plain-language consequence, e.g. "Centuries of guessing at a billion
    /// attempts a second." — the docs are explicit that a bit count alone does
    /// not change behaviour.
    pub explanation: String,
    pub acceptable: bool,
}

// ----------------------------------------------------------------- tree ----

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeDto {
    pub id: String,
    pub parent_id: Option<String>,
    pub sort_order: i64,
    /// `"folder" | "connection" | "credential" | "group" | "separator"`
    pub kind: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub colour: Option<String>,
    /// Connections only.
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    /// The account name. Set on a credential, and on a connection that has a
    /// credential of its own — a connection has no username field in the data
    /// model, so what the editor shows and edits is its attached credential's.
    /// `None` on a connection whose credential is inherited or shared;
    /// `node_resolve` is where the inherited value and its source come from.
    pub username: Option<String>,
    /// `"password" | "privateKey" | "agent" | "external" | "certificate"` —
    /// what the credential authenticates with, so the editor opens on the right
    /// tab without asking for the secret itself. Set on the same nodes
    /// [`NodeDto::username`] is.
    pub secret_kind: Option<String>,
    /// Private-key credentials only: `"openssh" | "pkcs8" | "putty-ppk"`.
    pub key_format: Option<String>,
    /// Private-key credentials only: whether a passphrase is stored beside the
    /// key. The passphrase itself never crosses this boundary.
    pub has_passphrase: bool,
    /// Agent credentials only: the comment substring that narrows which of the
    /// agent's identities is used.
    pub agent_comment_filter: Option<String>,
    /// Connections and folders: the credential set **on this node**, if one is.
    /// `None` when the credential is inherited — `node_resolve` is where the
    /// inherited value and its source come from.
    pub credential_id: Option<String>,
    /// Connections: the credential this connection owns, if it has one.
    ///
    /// Equal to [`NodeDto::credential_id`] when set. The two are separate
    /// because they mean different things to the editor: an attached
    /// credential is this connection's own username and secret, shown inline,
    /// while a shared one is a credential the user picked and is named as such.
    pub attached_credential_id: Option<String>,
    /// Connections and folders: the gateway chain set **on this node**, hop by
    /// hop, when one is. `None` when it is inherited; `Some(vec![])` when this
    /// node explicitly connects directly, overriding a chain above it.
    /// `node_resolve` is where the effective chain and its provenance are.
    pub gateway: Option<Vec<GatewayHopDto>>,
    /// Credentials: the connection this credential belongs to, or `None` for a
    /// shared one.
    ///
    /// An attached credential is part of its connection, not a separate entry:
    /// `tree_list` and `tree_search` leave them out, so in practice this is
    /// `None` on everything the sidebar draws.
    pub attached_to: Option<String>,
    /// What an edit did to the connection's own credential, when it did
    /// something the interface has to be able to explain:
    ///
    /// - `"created"` — the connection had no credential; it has one now.
    /// - `"updated"` — its own credential was edited in place.
    /// - `"overridesInherited"` — it was using a folder's credential; it now
    ///   has its own, which overrides it. The folder's is untouched.
    /// - `"detachedFromShared"` — it pointed at a shared credential. That one
    ///   is untouched — other connections use it — and this connection was
    ///   given its own.
    /// - `"removed"` — its own credential was cleared; whatever it inherits
    ///   applies again.
    ///
    /// Only ever set on the node returned by `node_create` and `node_update`.
    pub credential_change: Option<String>,
    /// How many nodes inherit something from this one; shown as "inherits 3".
    pub inherited_field_count: usize,
    pub updated_at: i64,
}

/// One hop of a gateway chain: the SSH connection traffic is forwarded
/// through, and optionally the credential to authenticate to it with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GatewayHopDto {
    /// The connection node that forwards. Must be an SSH connection.
    pub node_id: String,
    /// The credential node to authenticate this hop with. `None` uses the
    /// hop connection's own resolved credential.
    pub credential_id: Option<String>,
}

/// How a credential authenticates, as the editor sends it.
///
/// Mirrors the domain model's `SecretKind`, narrowed to the three the
/// connection editor can create. A private key is named by the path it is read
/// from; the bytes are stored in the vault, so the user is not tied to that
/// file afterwards.
///
/// **Review note (CLAUDE.md §5).** Carries a password and a key passphrase, so
/// it derives neither `Clone` nor `Serialize`; see [`UnlockRequestDto`].
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum CredentialInputDto {
    Password {
        password: String,
    },
    #[serde(rename_all = "camelCase")]
    PrivateKey {
        /// The file to read the key out of. Read once, at this call.
        path: String,
        /// Needed only when the key file says it is encrypted; see
        /// [`PrivateKeyInfoDto::encrypted`].
        passphrase: Option<String>,
    },
    #[serde(rename_all = "camelCase")]
    Agent {
        comment_filter: Option<String>,
    },
}

/// What a candidate private key file is, without any of what is in it.
///
/// The format is read from the file's content, never from its name: a `.pem`
/// holding an OpenSSH container is ordinary. `encrypted` is what lets the
/// editor ask for a passphrase only when one is needed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyInfoDto {
    pub path: String,
    /// `"openssh" | "pkcs8" | "putty-ppk"`
    ///
    /// The container the vault would *store* the key in, which for a legacy
    /// PKCS#1 RSA or SEC 1 EC `.pem` is `"pkcs8"` rather than the banner the
    /// file carries: those are re-enveloped on import so the vault holds one
    /// representation. Saying what will be stored is what makes this field
    /// agree with the credential the editor is about to create.
    pub format: String,
    /// The container's name as a person would say it: "OpenSSH", "PKCS#8",
    /// "PuTTY PPK".
    pub format_label: String,
    pub encrypted: bool,
    pub size_bytes: u64,
}

/// **Review note (CLAUDE.md §5).** Carries a credential's password; see
/// [`UnlockRequestDto`] for why the derives are what they are.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNodeDto {
    pub parent_id: Option<String>,
    pub kind: String,
    pub name: String,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    /// The account name. On a credential it is the credential's own; on a
    /// connection it creates a credential attached to that connection, which is
    /// what makes typing a username and a password on one server just work.
    pub username: Option<String>,
    /// Only ever travels frontend → core, never back. Shorthand for
    /// `credential: { kind: "password" }`; sending both is refused rather than
    /// guessed at.
    pub password: Option<String>,
    /// How the new credential authenticates. Absent means "no secret yet".
    pub credential: Option<CredentialInputDto>,
    /// Connections and folders: the credential node to authenticate with. This
    /// is how a connection reaches a private key or the agent — the key lives
    /// on a credential, and the connection points at it.
    pub credential_id: Option<String>,
    /// Connections and folders: a gateway chain to set on the new node. Absent
    /// inherits; an empty list connects directly.
    #[serde(default)]
    pub gateway: Option<Vec<GatewayHopDto>>,
}

/// **Review note (CLAUDE.md §5).** Carries a credential's password; see
/// [`UnlockRequestDto`] for why the derives are what they are.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNodeDto {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub colour: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    /// The account name.
    ///
    /// On a credential it is that credential's own. On a connection it lands on
    /// the connection's own credential: the existing one if it has one,
    /// otherwise a new one that overrides — never edits — whatever it was
    /// inheriting or sharing. Sending an empty username with no secret removes
    /// the connection's own credential, so it inherits again.
    pub username: Option<String>,
    pub password: Option<String>,
    /// Replaces how this credential authenticates. Switching from a password to
    /// a key — or to the agent — deletes the secrets the old method stored, so
    /// a key credential does not keep a stale password behind it. On a
    /// connection it lands on the connection's own credential, as `username`
    /// does.
    pub credential: Option<CredentialInputDto>,
    /// Connections and folders: the credential node to authenticate with.
    /// Clearing it — going back to the inherited one — is
    /// `clearOverrides: ["credential"]`, which also removes the connection's
    /// own credential if it had one.
    ///
    /// Sending this together with `username`, `password` or `credential` on a
    /// connection is refused: one says "use that shared credential" and the
    /// other says "have one of your own", and guessing between them is not
    /// something this layer may do.
    pub credential_id: Option<String>,
    /// Connections and folders: the gateway chain to set on this node, hop by
    /// hop. An empty list is an explicit direct connection, overriding any
    /// chain above; going back to the inherited chain is
    /// `clearOverrides: ["gateway"]`.
    #[serde(default)]
    pub gateway: Option<Vec<GatewayHopDto>>,
    /// Field names to reset to `Inherited::Inherit`.
    pub clear_overrides: Option<Vec<String>>,
    /// Protocol settings to write on this node, one entry per key touched.
    ///
    /// A sparse patch, and the two cases are different instructions:
    /// `Some(value)` sets the key on this node, and `None` **removes** this
    /// node's own entry so the key inherits again — the settings equivalent of
    /// [`Self::clear_overrides`], which cannot serve here because it names
    /// whole inheritable fields and a settings map inherits key by key.
    ///
    /// Keys the patch does not mention are left exactly as they are, which is
    /// what lets a form send only what the user touched and what keeps a key
    /// written by a newer build from being dropped by an older one.
    ///
    /// Values are typed against the adapter's own schema before anything is
    /// written; see `commands::apply_settings`.
    pub settings: Option<BTreeMap<String, Option<String>>>,
}

/// One resolved field, carrying where its value came from — the provenance the
/// interface shows inline next to every inherited field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFieldDto {
    pub field: String,
    pub value: Option<String>,
    /// `"own" | "inherited" | "default"`
    pub origin: String,
    /// Name of the ancestor the value came from, when inherited.
    pub source_name: Option<String>,
    pub source_id: Option<String>,
    /// The value this one overrides, when it shadows an inherited value.
    pub overrides: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EffectiveConnectionDto {
    pub node_id: String,
    pub protocol: String,
    pub fields: Vec<ResolvedFieldDto>,
    pub gateway_chain: Vec<String>,
    pub tags: Vec<String>,
    /// Whether the resolved credential belongs to this connection alone.
    ///
    /// True means the `username` field is this connection's own to edit; false
    /// means it comes from a credential others may share, and editing it here
    /// would change theirs.
    pub credential_attached: bool,
}

// ------------------------------------------------------ protocol schemas ----

/// What one protocol's settings are, as the adapter itself declares them.
///
/// **Read from the adapter, never restated here.** A second list would agree
/// with the first until the day somebody adds a setting — which is exactly the
/// drift `ConnectionEditor.tsx` already carries a comment about. See
/// `commands::protocol_schemas`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolSchemaDto {
    /// `"ssh"`, `"rdp"`, `"vnc"` — the same identifier a connection stores.
    pub protocol: String,
    /// In the order the form should show them, which is the adapter's order.
    pub settings: Vec<SettingFieldDto>,
}

/// One settings field.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingFieldDto {
    /// The key it is stored under, and the key the resolved view carries after
    /// its `settings.` prefix. A wire identifier: shown as it is, never
    /// translated.
    pub key: String,
    /// The message catalogue key for its label.
    pub label: String,
    /// What it holds, with the bounds that go with it.
    pub kind: SettingKindDto,
    /// The value used when nothing on the inheritance path sets one.
    pub default: Option<String>,
    /// Where [`Self::default`] came from: `"fixed"`, `"detected"` or
    /// `"guessed"`. **A `"guessed"` default must be said out loud** — it means
    /// this build could not determine the value and put a stand-in there.
    pub default_origin: String,
    pub required: bool,
    /// The values this field offers by name, empty where there are none.
    ///
    /// For a `choice` these are the whole of what it accepts; for anything
    /// else they are the ones worth listing out of a larger space. See
    /// [`Self::options_are_closed`].
    pub options: Vec<SettingOptionDto>,
    /// Whether a value outside [`Self::options`] is refused.
    ///
    /// False for the keyboard layout, deliberately: Microsoft publishes
    /// several hundred identifiers and the list holds the ones worth showing,
    /// so the form needs a way to type one in.
    pub options_are_closed: bool,
}

/// One offered value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingOptionDto {
    /// The value as stored — the string that goes back on the wire, not a
    /// rendering of it.
    pub value: String,
    /// What to call it.
    pub label: SettingOptionLabelDto,
}

/// How an option is named.
///
/// Two cases, because a settings value is named two different ways: a keyboard
/// layout is prose a translator owns, and an RFB version is a wire token
/// nobody owns.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SettingOptionLabelDto {
    /// Put `key` through `t()`.
    Message { key: String },
    /// Show `text` as it stands. Never translated.
    Verbatim { text: String },
}

/// What a field holds, and within what bounds.
///
/// A `choice`'s permitted values are **not** here: they are in
/// [`SettingFieldDto::options`] with a label each, so that the form has one
/// list to render rather than two shapes to reconcile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum SettingKindDto {
    /// Free text, up to `max_len` characters.
    #[serde(rename_all = "camelCase")]
    Text { max_len: usize },
    /// A whole number, inclusive of both bounds.
    Integer { min: i64, max: i64 },
    /// `"true"` or `"false"`, stored as those strings.
    Boolean,
    /// One of [`SettingFieldDto::options`], and nothing else.
    Choice,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchHitDto {
    pub node: NodeDto,
    /// Breadcrumb, e.g. "Datacentre EU-West / Web tier".
    pub path: String,
    /// Character ranges in `node.name` that matched, for highlighting.
    pub name_matches: Vec<(usize, usize)>,
    /// The hit's second line.
    ///
    /// For a connection or a credential this is an address or a login — a
    /// value, not a sentence, and the palette renders it as it stands. For a
    /// folder or a group it is a count, and the English form ("3 items") is
    /// **not for rendering**: it is the fallback for a
    /// [`Self::subtitle_kind`] the interface does not know, the same
    /// arrangement `IpcError`'s code and message use.
    pub subtitle: String,
    /// `"items"` or `"members"` when [`Self::subtitle`] is a counted sentence
    /// the interface should compose itself — the variants of
    /// `SubtitleKind` in `commands.rs`. `None` when the subtitle is a value.
    pub subtitle_kind: Option<String>,
    /// The number [`Self::subtitle_kind`] counts. Sent as a number so the
    /// interface can put it through an ICU plural and the locale's digits.
    pub subtitle_count: Option<u64>,
    pub score: i64,
}

// ------------------------------------------------------- vault settings ----

/// The key slots of the open vault, for the Vault settings screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSlotsDto {
    pub slots: Vec<SlotDto>,
    /// The slot this session was opened through, so the screen can mark it and
    /// warn before it is revoked.
    pub opened_with: Option<u8>,
    pub backup_count: usize,
}

/// **Review note (CLAUDE.md §5).** Carries a password; see
/// [`UnlockRequestDto`] for why the derives are what they are.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddPasswordSlotDto {
    pub label: String,
    pub password: String,
    pub keyfile_path: Option<String>,
}

/// **Review note (CLAUDE.md §5).** Carries two passwords; see
/// [`UnlockRequestDto`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordDto {
    /// The slot to re-wrap. Absent means slot 0, the master password.
    pub slot_index: Option<u8>,
    pub current_password: String,
    pub current_keyfile_path: Option<String>,
    pub new_password: String,
    /// The key file the slot will require from now on. Absent drops the key
    /// file requirement; the current one is not carried over silently.
    pub new_keyfile_path: Option<String>,
}

/// One password slot's credential, for a master key rotation.
///
/// **Review note (CLAUDE.md §5).** Carries a password; see
/// [`UnlockRequestDto`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotCredentialDto {
    pub index: u8,
    pub password: String,
    pub keyfile_path: Option<String>,
}

/// **Review note (CLAUDE.md §5).** Carries passwords; see
/// [`UnlockRequestDto`].
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotateMasterKeyDto {
    /// One entry per password slot that is to survive the rotation.
    pub credentials: Vec<SlotCredentialDto>,
    /// Slots to discard rather than re-wrap — a hardware key that is not to
    /// hand, a password nobody remembers. A slot that is in neither list is a
    /// refusal, not a silent deletion.
    pub drop_slots: Vec<u8>,
}

/// A recovery key, returned exactly once. The same shape `vault_create` uses.
///
/// Nothing in the vault file can reproduce this; there is no command that asks
/// for it again.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryKeyDto {
    pub slot_index: u8,
    /// Fourteen groups of four characters, Crockford Base32.
    pub recovery_key_groups: Vec<String>,
    /// Which group the transcription check should ask the user to retype.
    pub confirm_group_index: usize,
}

/// What a master key rotation did.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationOutcomeDto {
    /// Slot indices re-wrapped around the new master key.
    pub rewrapped: Vec<u8>,
    /// Slot indices the plan discarded.
    pub dropped: Vec<u8>,
    /// One per recovery slot, each shown exactly once.
    pub recovery_keys: Vec<RecoveryKeyDto>,
    pub secrets_resealed: usize,
}

/// How well this build, on this machine, can see each of the three
/// operating-system lock triggers.
///
/// Every field is `"observed"`, `"on_resume"` or `"unobserved"`. Nothing in
/// here belongs to the vault — it describes the computer the vault happens to
/// be open on — but it rides with [`VaultSettingsDto`] because the Vault
/// settings screen is the one place it is needed, and it is needed *there*: a
/// switch this build cannot honour has to be disabled and explained rather
/// than left persisting a value nothing reads.
///
/// The stored switch is still shown, and still written where a switch is
/// honoured, because the value travels with the vault file: a trigger this
/// machine cannot see is one another machine may.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LockTriggerSupportDto {
    pub screen_lock: String,
    pub suspend: String,
    pub minimise: String,
}

/// The settings that travel with the vault file rather than with the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSettingsDto {
    /// Zero means never.
    ///
    /// This is the timeout the countdown actually uses while this vault is
    /// open: `Inner::effective_auto_lock_minutes` prefers it over the
    /// application setting, so the screen that edits it is the screen that
    /// changes behaviour.
    pub auto_lock_minutes: u32,
    pub lock_on_screen_lock: bool,
    pub lock_on_suspend: bool,
    pub lock_on_minimise: bool,
    /// Which of the three switches above this build can actually honour here.
    pub lock_triggers: LockTriggerSupportDto,
    /// `"keep_running" | "freeze_input" | "disconnect_all"`
    pub session_on_lock: String,
    /// `"never" | "on_request" | "always"`
    pub recording: String,
    /// Rolling backups kept beside the vault file. Stored in the header, which
    /// is readable before the body is decrypted — which is the situation the
    /// backups exist for.
    pub backup_count: usize,
}

/// A partial [`VaultSettingsDto`]. An absent field is left alone.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VaultSettingsPatchDto {
    pub auto_lock_minutes: Option<u32>,
    pub lock_on_screen_lock: Option<bool>,
    pub lock_on_suspend: Option<bool>,
    pub lock_on_minimise: Option<bool>,
    pub session_on_lock: Option<String>,
    pub recording: Option<String>,
    pub backup_count: Option<usize>,
}

// ---------------------------------------------------------------- audit ----

/// Which audit entries to read, and which page of them.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AuditQueryDto {
    /// Milliseconds since the epoch; entries at or after it.
    pub since: Option<i64>,
    /// Milliseconds since the epoch; entries strictly before it. Half-open, so
    /// paging by day cannot show one entry twice.
    pub until: Option<i64>,
    /// `"vault" | "node" | "secret" | "connection" | "warning"`, combined with
    /// "or" — the screen's filter chips.
    pub categories: Option<Vec<String>>,
    /// `"success" | "failure" | "denied"`, combined with "or".
    pub outcomes: Option<Vec<String>>,
    pub node_id: Option<String>,
    pub session_id: Option<String>,
    /// Only entries written under this identity — an `AuditActorDto::id`.
    pub actor_id: Option<i64>,
    /// Zero-based. Defaults to the first page.
    pub page: Option<usize>,
    /// Defaults to 100, capped at 1000.
    pub page_size: Option<usize>,
}

/// One row of the audit log. Never carries a secret: `detail` is a short
/// plain-language note written under the same rule as everything else here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntryDto {
    pub id: i64,
    /// Milliseconds since the epoch.
    pub at: i64,
    /// The event name as stored, so a row written by a newer build survives.
    pub event: String,
    pub outcome: String,
    /// `None` when this build does not know the event name.
    pub category: Option<String>,
    /// Whether the row belongs in the "warnings" filter — the rows an incident
    /// review scrolls for.
    pub warning: bool,
    pub node_id: Option<String>,
    /// The node's name at the time of reading, when it is still in the tree.
    pub node_name: Option<String>,
    pub session_id: Option<String>,
    pub detail: Option<String>,
    /// The operating-system account and machine the entry was written from.
    /// `None` for an entry written before this was recorded, or by a process
    /// that could not say who it was running as.
    pub actor: Option<AuditActorDto>,
}

/// Who wrote an audit entry: what the operating system reported to the process
/// that wrote it. Attribution between the people who can open a vault, not a
/// proof of identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditActorDto {
    pub id: i64,
    pub machine: String,
    /// The account without its domain.
    pub user: String,
    /// Present only when it says something the machine name does not.
    pub domain: Option<String>,
    /// `DOMAIN\user`, or the bare account — ready to show.
    pub account: String,
    /// `"linux" | "windows" | "macos"` …
    pub os: String,
}

/// One identity that has written to this vault's audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditActorSummaryDto {
    pub actor: AuditActorDto,
    /// How many entries carry it.
    pub entries: usize,
    /// Milliseconds since the epoch of its newest entry.
    pub last_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditPageDto {
    pub entries: Vec<AuditEntryDto>,
    /// How many entries match the filter, ignoring the paging.
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
}

/// The filter vocabulary, so the interface's chips cannot drift from the log's
/// own spellings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditFiltersDto {
    pub categories: Vec<String>,
    pub outcomes: Vec<String>,
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportDto {
    pub path: String,
    /// `"json" | "csv"`
    pub format: String,
    /// The same filter the screen is showing. Absent exports everything.
    pub query: Option<AuditQueryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditExportResultDto {
    pub path: String,
    pub format: String,
    pub entries: usize,
    pub bytes: u64,
}

// --------------------------------------------------------------- export ----

/// Which part of the tree to write, where, and as what.
///
/// **Review note (CLAUDE.md §5).** Carries the password a `.rmtr` archive is
/// sealed with; see [`UnlockRequestDto`] for why the derives are what they are.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeExportDto {
    pub path: String,
    /// `"remoter-archive" | "csv" | "ssh-config" | "json"`
    pub format: String,
    /// The folder or connection to export with everything under it. Absent
    /// exports the whole vault.
    pub root_id: Option<String>,
    /// The archive's password. Only ever travels frontend → core, and only for
    /// `remoter-archive`.
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeExportResultDto {
    pub path: String,
    pub bytes: u64,
    /// The format written.
    pub format: String,
    /// For the flat formats: what went into the file and what could not.
    /// Names and hosts only.
    pub report: Option<remoter_import::export::ExportReport>,
    /// For an archive: what it carries.
    pub archive: Option<ArchiveExportDto>,
}

/// What a `.rmtr` archive carries. Counts and names, never a secret.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveExportDto {
    pub folders: usize,
    pub connections: usize,
    pub credentials: usize,
    /// Secret fields sealed into the archive: passwords, keys, passphrases.
    pub secrets: usize,
    /// Nodes from outside the chosen folder that came along because something
    /// in it depends on them.
    pub dependencies: Vec<String>,
}

// --------------------------------------------------------------- import ----

/// What a file appears to be, before anything is parsed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportDetectionDto {
    pub path: String,
    pub size_bytes: u64,
    /// `"mremoteng" | "ssh-config" | "csv"`, or `None` when the content
    /// matches no importer.
    pub format: Option<String>,
    /// The format's name as a person would say it.
    pub format_label: Option<String>,
    /// Whether parsing will need the document password.
    pub password_required: bool,
    /// mRemoteNG only: what the document says about itself.
    pub document: Option<ImportDocumentDto>,
}

/// The `<Connections>` header of an mRemoteNG document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportDocumentDto {
    pub name: String,
    pub conf_version: Option<String>,
    /// `"gcm" | "cbc"`
    pub cipher: String,
    /// Set for GCM, which is the only mode that carries one.
    pub kdf_iterations: Option<u32>,
    /// True for AES-CBC with an MD5-derived key: readable, and a reason to
    /// treat every credential in the file as exposed.
    pub legacy_cipher: bool,
    pub full_file_encryption: bool,
    pub password_required: bool,
}

/// The tree an import would create, and the report that goes with it.
///
/// The preview itself stays in the core: it holds the passwords recovered from
/// the file in plaintext, and nothing here carries one. `import_id` is the
/// handle the commit call uses; the preview is dropped — and its secrets
/// zeroized — when the import is committed, cancelled, or the vault locks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportPreviewDto {
    pub import_id: String,
    /// `"mremoteng" | "ssh-config" | "csv"`
    pub source: String,
    pub source_label: String,
    pub nodes: Vec<ImportNodeDto>,
    pub report: ImportReportDto,
}

/// One node an import would create, with everything secret removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportNodeDto {
    /// The identity the node will be created with; already allocated, so the
    /// preview's own references resolve. This is what `excludedIds` names.
    pub id: String,
    /// `None` for a node that lands at the destination's top level.
    pub parent_id: Option<String>,
    pub sort_order: i64,
    pub name: String,
    /// `"folder" | "connection" | "credential"`
    pub kind: String,
    pub protocol: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub port_inherited: bool,
    pub username: Option<String>,
    pub domain: Option<String>,
    /// Whether the vault will have to seal a password for this node.
    pub has_secret: bool,
    pub credential_inherited: bool,
    pub gateway_hops: usize,
    pub custom_fields: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReportDto {
    pub source: String,
    pub counts: ImportCountsDto,
    pub findings: Vec<ImportFindingDto>,
    /// True when a limit stopped the parse before the end of the file.
    pub truncated: bool,
    /// True when any finding is a warning or an alert.
    pub needs_attention: bool,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCountsDto {
    pub folders: usize,
    pub connections: usize,
    pub credentials: usize,
    pub secrets: usize,
    pub skipped: usize,
}

/// One thing the importer wants the user to know.
///
/// The finding's own fields are flattened alongside `severity`, so the object
/// on the wire is `{ severity, kind, ...the finding's fields }` — `kind` being
/// the snake_case variant name from `remoter_import::Finding`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportFindingDto {
    /// `"info" | "warning" | "alert"`
    pub severity: String,
    #[serde(flatten)]
    pub finding: remoter_import::Finding,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportCommitDto {
    pub import_id: String,
    /// The folder to import into. Absent means the top level of the vault.
    pub destination_id: Option<String>,
    /// Nodes the user unticked. Excluding a folder excludes everything under
    /// it; nothing is written for any of them.
    pub excluded_ids: Option<Vec<String>>,
    /// `"keep-both" | "skip" | "replace"`: what to do with an item the vault
    /// already has where the import would put it. Absent keeps both.
    #[serde(default)]
    pub conflict_policy: Option<String>,
}

/// What an import would collide with, at a destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportConflictsRequestDto {
    pub import_id: String,
    pub destination_id: Option<String>,
    pub excluded_ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportConflictsDto {
    /// How many imported items already exist where they would land.
    pub total: usize,
    /// The first of them, for the list on screen.
    pub items: Vec<ImportConflictDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportConflictDto {
    pub name: String,
    /// `"folder" | "connection" | "credential" | "group" | "separator"`
    pub kind: String,
    /// The breadcrumb of the folder the existing item is in; empty at the top.
    pub path: String,
}

/// What a committed import wrote. One transaction: either all of this reached
/// the vault file or none of it did.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResultDto {
    /// `"mremoteng" | "ssh-config" | "csv"`
    pub source: String,
    pub imported: usize,
    pub skipped: usize,
    pub folders: usize,
    pub connections: usize,
    pub credentials: usize,
    /// How many passwords were sealed into the vault.
    pub secrets_stored: usize,
    /// Items the vault already had that took the imported one's properties.
    pub replaced: usize,
    /// Items the vault already had that were left as they were.
    pub unchanged: usize,
    /// Imported folders that went into one the vault already had.
    pub merged: usize,
    /// Findings the report rates warning or alert — the "needs a look" count
    /// on the final step.
    pub needs_attention: usize,
    /// The ids of the nodes that landed directly in the destination folder.
    pub root_ids: Vec<String>,
}

// ------------------------------------------------------------- settings ----

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettingsDto {
    /// `"system" | "light" | "dark" | "hc-light" | "hc-dark"`
    pub theme: String,
    pub locale: String,
    pub auto_lock_minutes: Option<u32>,
    pub lock_on_screen_lock: bool,
    pub lock_on_suspend: bool,
    pub sidebar_width: u32,
    pub inspector_open: bool,
    /// Opt-in, off by default. When it is off nothing leaves this machine, and
    /// nothing about the user is sent when it is on either: the check asks for
    /// a version number and says nothing about who is asking.
    #[serde(default)]
    pub update_check_enabled: bool,
    /// `"stable" | "beta"`
    #[serde(default = "default_update_channel")]
    pub update_channel: String,
    /// Unix seconds of the last check, or `None` if none has run.
    #[serde(default)]
    pub update_last_checked_at: Option<i64>,
    /// The modifier a shortcut is prefixed with inside a focused terminal,
    /// where almost every keystroke belongs to the remote host.
    #[serde(default = "default_terminal_prefix")]
    pub terminal_prefix: String,
    /// Action id to accelerator. Only the bindings that differ from the
    /// defaults are stored, so a changed default reaches everyone who has not
    /// overridden it.
    #[serde(default)]
    pub shortcuts: BTreeMap<String, String>,
    /// The terminal's palette, per-colour overrides and font.
    ///
    /// `#[serde(default)]`, like every field added after version 1 of the
    /// settings file: a file written before this existed loads with the
    /// defaults rather than being rejected, which is what lets the schema
    /// version stay at 1 and existing users keep their settings.
    #[serde(default)]
    pub terminal: TerminalAppearanceDto,
    /// The folder the file manager last downloaded into, as this platform
    /// writes it. `None` until one has been chosen.
    ///
    /// Stored because the local side of the file manager had no memory at all:
    /// every pane started with no destination, and every download began by
    /// opening a folder picker — including the second download into the folder
    /// the first one went to. It is a path on this machine and travels with the
    /// machine, which is why it is here rather than in the vault.
    #[serde(default)]
    pub file_download_folder: Option<String>,
}

/// How the terminal is painted and set.
///
/// Separate from the interface theme on purpose — `docs/ui/design-system.md`:
/// "a user may want a light interface and a dark terminal". The palette ids
/// and colour keys live in the frontend's `lib/terminalPalette.ts`; what is
/// validated here is that a value *is* one of the names this build knows and
/// *is* a colour, so that a hand-edited settings file cannot leave a session
/// with no foreground.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalAppearanceDto {
    /// A built-in palette id, or `"auto"` to follow the interface theme.
    pub palette: String,
    /// Colour key to `#rrggbb` or `#rrggbbaa`. Only the colours the user
    /// changed, so switching palette moves everything that was left alone.
    #[serde(default)]
    pub overrides: BTreeMap<String, String>,
    /// Empty means the interface's own mono stack.
    #[serde(default)]
    pub font_family: String,
    pub font_size: u32,
}

impl Default for TerminalAppearanceDto {
    /// `"auto"` with nothing overridden — which resolves to the palette the
    /// application drew with before any of this was configurable, so an
    /// existing installation sees no change on upgrade.
    fn default() -> Self {
        Self {
            palette: String::from("auto"),
            overrides: BTreeMap::new(),
            font_family: String::new(),
            font_size: 13,
        }
    }
}

/// Serde default for [`AppSettingsDto::update_channel`].
fn default_update_channel() -> String {
    String::from("stable")
}

/// Serde default for [`AppSettingsDto::terminal_prefix`].
fn default_terminal_prefix() -> String {
    String::from("ctrl+alt")
}

// ---------------------------------------------------------- update check ----

/// One published release, as the update check found it.
///
/// Everything here except `url` is text the release author wrote and the
/// network delivered. It is untrusted: the interface renders it as text and
/// never as markup. `url` is the exception because it is *not* taken from the
/// response — the core builds it from the tag, so a substituted endpoint
/// cannot hand the system browser a `javascript:` or `file://` address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateReleaseDto {
    /// The git tag, as GitHub holds it — `v0.3.0`. The semantic version is
    /// parsed from this on the interface side, which is where the comparison
    /// and its tests live.
    pub tag: String,
    /// The release's own title. Empty when the author gave it none.
    pub name: String,
    /// The release notes as Markdown source. Rendered as text, not as markup.
    pub notes: String,
    /// The release page to open, built from the tag by the core.
    pub url: String,
    /// Whether the author marked this a pre-release.
    pub prerelease: bool,
    /// RFC 3339, as GitHub returns it. `None` when the release is unpublished.
    pub published_at: Option<String>,
}

/// What one update check found.
///
/// The core does not decide whether an update is available: it fetches the
/// list and says what this build is. Which release counts as newer — and
/// whether a pre-release counts at all — is compared in
/// `apps/desktop/ui/src/features/settings/version.ts`, where it is tested.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckDto {
    /// The version this build reports. The same number the release process
    /// bumps in `Cargo.toml`.
    pub current_version: String,
    /// Published releases, newest first as GitHub orders them. Drafts and
    /// releases with an unusable tag are dropped before this crosses out.
    pub releases: Vec<UpdateReleaseDto>,
    /// Unix seconds this check completed. Also written to the settings file,
    /// so it survives a restart.
    pub checked_at: i64,
}

/// One editable keyboard binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShortcutDto {
    /// Stable, dotted, ASCII. The interface's translation key hangs off it.
    pub id: String,
    /// `"universal"` — works even inside a focused terminal — or
    /// `"application"`, which is reached through the terminal prefix while a
    /// session has focus.
    pub scope: String,
    pub accelerator: String,
    pub default_accelerator: String,
    pub customised: bool,
    /// How many consecutive keys the binding covers: 9 for "jump to tab 1–9",
    /// 1 for everything else.
    pub series_len: u8,
    /// Set when this binding cannot be relied on as typed:
    /// `"duplicate"` — another Remoter action has it too;
    /// `"terminal-reserved"` — the remote host owns those keys;
    /// `"desktop"` — the desktop environment takes it first, and wins.
    pub conflict: Option<String>,
    /// The other action ids sharing this accelerator, for `"duplicate"`.
    pub conflicts_with: Vec<String>,
}

// -------------------------------------------------------------- redaction --

/// Stands in for a secret field in a `Debug` rendering.
///
/// A unit struct rather than a `&str` so that the placeholder prints without
/// quotation marks and cannot be mistaken for the value itself.
struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Whether an optional secret is present, without saying what it is. Renders as
/// `Some(<redacted>)` or `None`.
fn redacted(value: Option<&String>) -> Option<Redacted> {
    value.map(|_| Redacted)
}

impl fmt::Debug for UnlockRequestDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password { keyfile_path, .. } => f
                .debug_struct("UnlockRequestDto::Password")
                .field("password", &Redacted)
                .field("keyfile_path", keyfile_path)
                .finish(),
            // The recovery key permanently unlocks the vault, so it is redacted
            // exactly as the password is.
            Self::Recovery { .. } => f
                .debug_struct("UnlockRequestDto::Recovery")
                .field("key", &Redacted)
                .finish(),
            Self::Keychain => f.write_str("UnlockRequestDto::Keychain"),
        }
    }
}

impl fmt::Debug for CreateVaultRequestDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateVaultRequestDto")
            .field("path", &self.path)
            .field("label", &self.label)
            .field("password", &Redacted)
            .field("keyfile_path", &self.keyfile_path)
            .field("generate_keyfile_at", &self.generate_keyfile_at)
            .finish()
    }
}

impl fmt::Debug for CredentialInputDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Password { .. } => f
                .debug_struct("CredentialInputDto::Password")
                .field("password", &Redacted)
                .finish(),
            // The path is not a secret and is most of what makes a log line
            // useful; the passphrase that opens the key is.
            Self::PrivateKey { path, passphrase } => f
                .debug_struct("CredentialInputDto::PrivateKey")
                .field("path", path)
                .field("passphrase", &redacted(passphrase.as_ref()))
                .finish(),
            Self::Agent { comment_filter } => f
                .debug_struct("CredentialInputDto::Agent")
                .field("comment_filter", comment_filter)
                .finish(),
        }
    }
}

impl fmt::Debug for AddPasswordSlotDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddPasswordSlotDto")
            .field("label", &self.label)
            .field("password", &Redacted)
            .field("keyfile_path", &self.keyfile_path)
            .finish()
    }
}

impl fmt::Debug for ChangePasswordDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChangePasswordDto")
            .field("slot_index", &self.slot_index)
            .field("current_password", &Redacted)
            .field("current_keyfile_path", &self.current_keyfile_path)
            .field("new_password", &Redacted)
            .field("new_keyfile_path", &self.new_keyfile_path)
            .finish()
    }
}

impl fmt::Debug for SlotCredentialDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlotCredentialDto")
            .field("index", &self.index)
            .field("password", &Redacted)
            .field("keyfile_path", &self.keyfile_path)
            .finish()
    }
}

impl fmt::Debug for RotateMasterKeyDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RotateMasterKeyDto")
            .field("credentials", &self.credentials)
            .field("drop_slots", &self.drop_slots)
            .finish()
    }
}

impl fmt::Debug for CreateNodeDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateNodeDto")
            .field("parent_id", &self.parent_id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("protocol", &self.protocol)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redacted(self.password.as_ref()))
            .field("credential", &self.credential)
            .field("credential_id", &self.credential_id)
            .finish()
    }
}

impl fmt::Debug for UpdateNodeDto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateNodeDto")
            .field("name", &self.name)
            .field("description", &self.description)
            .field("tags", &self.tags)
            .field("colour", &self.colour)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &redacted(self.password.as_ref()))
            .field("credential", &self.credential)
            .field("credential_id", &self.credential_id)
            .field("clear_overrides", &self.clear_overrides)
            // Keys, never values. There is no `Secret` kind in a settings
            // schema, but a settings map is exactly where a mistyped password
            // ends up — which is why `SettingField::validate` names the key
            // and withholds the value, and this follows it.
            .field("settings", &setting_keys(self.settings.as_ref()))
            .finish()
    }
}

/// The keys of a settings patch, without any of its values.
fn setting_keys(settings: Option<&BTreeMap<String, Option<String>>>) -> Option<Vec<&str>> {
    settings.map(|map| map.keys().map(String::as_str).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "correct-horse-battery-staple";

    #[test]
    fn an_unlock_request_never_debug_prints_its_password() {
        let request = UnlockRequestDto::Password {
            password: String::from(PASSWORD),
            keyfile_path: Some(String::from("/media/stick/vault.key")),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"), "rendered: {rendered}");
        // The non-secret half stays visible: it is what makes the line useful.
        assert!(rendered.contains("vault.key"), "rendered: {rendered}");
    }

    #[test]
    fn a_recovery_request_never_debug_prints_its_key() {
        let request = UnlockRequestDto::Recovery {
            key: String::from("RMTR-4K7P-2M9X"),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("4K7P"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"), "rendered: {rendered}");
    }

    #[test]
    fn a_create_vault_request_never_debug_prints_its_password() {
        let request = CreateVaultRequestDto {
            path: String::from("/tmp/test.rvault"),
            label: String::from("Test vault"),
            password: String::from(PASSWORD),
            keyfile_path: None,
            generate_keyfile_at: None,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"), "rendered: {rendered}");
    }

    #[test]
    fn node_requests_never_debug_print_their_password() {
        let create = CreateNodeDto {
            parent_id: None,
            kind: String::from("credential"),
            name: String::from("root@web"),
            protocol: None,
            host: None,
            port: None,
            username: Some(String::from("root")),
            password: Some(String::from(PASSWORD)),
            credential: None,
            credential_id: None,
            gateway: None,
        };
        let rendered = format!("{create:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(
            rendered.contains("Some(<redacted>)"),
            "rendered: {rendered}"
        );

        let update = UpdateNodeDto {
            name: None,
            description: None,
            tags: None,
            colour: None,
            host: None,
            port: None,
            username: None,
            password: Some(String::from(PASSWORD)),
            credential: None,
            credential_id: None,
            clear_overrides: None,
            settings: None,
            gateway: None,
        };
        let rendered = format!("{update:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(
            rendered.contains("Some(<redacted>)"),
            "rendered: {rendered}"
        );
    }

    #[test]
    fn an_absent_password_is_distinguishable_from_a_present_one() {
        let update = UpdateNodeDto {
            name: Some(String::from("web-1")),
            description: None,
            tags: None,
            colour: None,
            host: None,
            port: None,
            username: None,
            password: None,
            credential: None,
            credential_id: None,
            clear_overrides: None,
            settings: None,
            gateway: None,
        };
        let rendered = format!("{update:?}");
        assert!(rendered.contains("password: None"), "rendered: {rendered}");
    }

    /// The wire shape is the frontend contract in
    /// `apps/desktop/ui/src/lib/ipc.ts`; only the derives changed.
    #[test]
    fn the_inbound_wire_shape_is_unchanged() {
        let parsed = serde_json::from_str::<UnlockRequestDto>(
            r#"{"kind":"password","password":"s","keyfilePath":null}"#,
        );
        assert!(matches!(parsed, Ok(UnlockRequestDto::Password { .. })));

        let parsed = serde_json::from_str::<UpdateNodeDto>(r#"{"clearOverrides":["port"]}"#);
        assert!(parsed.is_ok_and(|patch| patch.clear_overrides.is_some()));
    }

    #[test]
    fn a_credential_input_never_debug_prints_its_secret() {
        let password = CredentialInputDto::Password {
            password: String::from(PASSWORD),
        };
        let rendered = format!("{password:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"), "rendered: {rendered}");

        let key = CredentialInputDto::PrivateKey {
            path: String::from("/home/ada/.ssh/id_ed25519"),
            passphrase: Some(String::from(PASSWORD)),
        };
        let rendered = format!("{key:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        // The path is not a secret, and it is most of what makes the line
        // useful while diagnosing a key that will not load.
        assert!(rendered.contains("id_ed25519"), "rendered: {rendered}");

        let agent = CredentialInputDto::Agent {
            comment_filter: Some(String::from("deploy@")),
        };
        assert!(format!("{agent:?}").contains("deploy@"));
    }

    #[test]
    fn the_slot_requests_never_debug_print_their_passwords() {
        let add = AddPasswordSlotDto {
            label: String::from("Laptop"),
            password: String::from(PASSWORD),
            keyfile_path: None,
        };
        let rendered = format!("{add:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(rendered.contains("Laptop"), "rendered: {rendered}");

        let change = ChangePasswordDto {
            slot_index: Some(0),
            current_password: String::from(PASSWORD),
            current_keyfile_path: None,
            new_password: String::from("another-one-entirely"),
            new_keyfile_path: None,
        };
        let rendered = format!("{change:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(
            !rendered.contains("another-one-entirely"),
            "rendered: {rendered}"
        );

        let rotate = RotateMasterKeyDto {
            credentials: vec![SlotCredentialDto {
                index: 0,
                password: String::from(PASSWORD),
                keyfile_path: Some(String::from("/media/stick/vault.key")),
            }],
            drop_slots: vec![2],
        };
        let rendered = format!("{rotate:?}");
        assert!(!rendered.contains(PASSWORD), "rendered: {rendered}");
        assert!(rendered.contains("vault.key"), "rendered: {rendered}");
    }

    /// Every field of the change-password request has to survive the crossing.
    ///
    /// `current_keyfile_path` is `Option`, so a name the interface spells
    /// differently does not fail to deserialise — it arrives as `None`, the
    /// key-encryption key is then derived from the password alone, and the
    /// slot rejects the credential that opens it. The key file is a Windows
    /// path because that is the shape reported, and backslashes are the one
    /// character JSON escapes.
    #[test]
    fn the_change_password_request_reads_the_shape_the_dialog_sends() {
        let parsed = serde_json::from_str::<ChangePasswordDto>(
            r#"{"slotIndex":0,
                "currentPassword":"the-master-password",
                "currentKeyfilePath":"D:\\Remoter_Vault\\devoplus.keyfile",
                "newPassword":"the-new-password",
                "newKeyfilePath":"D:\\Remoter_Vault\\devoplus.keyfile"}"#,
        );
        let Ok(parsed) = parsed else {
            unreachable!("the dialog's own shape must deserialise: {parsed:?}")
        };
        assert_eq!(parsed.slot_index, Some(0));
        assert_eq!(parsed.current_password, "the-master-password");
        assert_eq!(
            parsed.current_keyfile_path.as_deref(),
            Some(r"D:\Remoter_Vault\devoplus.keyfile"),
            "the key file the slot is keyed to must reach the core intact"
        );
        assert_eq!(parsed.new_password, "the-new-password");
        assert_eq!(
            parsed.new_keyfile_path.as_deref(),
            Some(r"D:\Remoter_Vault\devoplus.keyfile")
        );
    }

    #[test]
    fn the_credential_input_reads_the_shape_the_editor_sends() {
        let parsed = serde_json::from_str::<CredentialInputDto>(
            r#"{"kind":"privateKey","path":"/k","passphrase":null}"#,
        );
        assert!(matches!(
            parsed,
            Ok(CredentialInputDto::PrivateKey {
                passphrase: None,
                ..
            })
        ));

        let parsed = serde_json::from_str::<CredentialInputDto>(
            r#"{"kind":"agent","commentFilter":"deploy@"}"#,
        );
        assert!(matches!(parsed, Ok(CredentialInputDto::Agent { .. })));

        let parsed = serde_json::from_str::<CreateNodeDto>(
            r#"{"kind":"credential","name":"svc","credential":{"kind":"password","password":"s"}}"#,
        );
        assert!(parsed.is_ok_and(|input| input.credential.is_some()));
    }

    #[test]
    fn a_finding_flattens_its_own_fields_beside_the_severity() {
        let finding = ImportFindingDto {
            severity: String::from("alert"),
            finding: remoter_import::Finding::DefaultFilePassword,
        };
        let rendered = serde_json::to_string(&finding).unwrap_or_default();
        assert!(
            rendered.contains("\"severity\":\"alert\""),
            "rendered: {rendered}"
        );
        assert!(
            rendered.contains("\"kind\":\"default_file_password\""),
            "rendered: {rendered}"
        );

        let finding = ImportFindingDto {
            severity: String::from("info"),
            finding: remoter_import::Finding::SecretsRecovered { count: 27 },
        };
        let rendered = serde_json::to_string(&finding).unwrap_or_default();
        assert!(rendered.contains("\"count\":27"), "rendered: {rendered}");
    }

    #[test]
    fn the_audit_query_reads_an_empty_object_as_everything() {
        let parsed = serde_json::from_str::<AuditQueryDto>("{}");
        assert!(parsed.is_ok_and(|query| query.categories.is_none() && query.page.is_none()));

        let parsed = serde_json::from_str::<AuditQueryDto>(
            r#"{"categories":["warning"],"pageSize":25,"nodeId":null}"#,
        );
        assert!(parsed.is_ok_and(|query| query.page_size == Some(25)));
    }
}
