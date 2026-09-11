/**
 * Typed wrappers around the Tauri command surface.
 *
 * This is the ONLY file in the frontend that may call `invoke`. A component
 * calling it directly is a review rejection — the wrapper is what keeps the
 * Rust and TypeScript sides in step.
 *
 * Every type here mirrors a struct in `crates/remoter-ipc/src/dto.rs`. When you
 * change one, change both in the same commit.
 *
 * A secret never crosses this boundary. There is no command that returns a
 * password, a recovery key that has already been shown, or any key material;
 * the frontend asks for an action and the core performs it. Types that carry a
 * secret inward — `UnlockRequest`, `CreateVaultRequest`, `CredentialInput`,
 * `AddPasswordSlot`, `ChangePassword`, `SlotCredential` — travel one way only.
 * Do not put one in a query cache, a Zustand store or a log line.
 *
 * Argument names matter. Tauri matches command parameters by name, and a
 * mismatch is a runtime failure the type system cannot catch: the Rust side
 * sees an absent argument and the command fails to deserialise. Rust
 * `snake_case` parameters are `camelCase` here — `import_id` is `importId`.
 */

import { Channel, invoke } from "@tauri-apps/api/core";

// ---------------------------------------------------------- string unions ----

export type SlotKind = "password" | "recovery" | "fido2" | "keychain";
export type NodeKind = "folder" | "connection" | "credential" | "group" | "separator";
export type ThemeName = "system" | "light" | "dark" | "hc-light" | "hc-dark";
export type FieldOrigin = "own" | "inherited" | "default";

/** What a credential authenticates with. Mirrors the domain model's `SecretKind`. */
export type SecretKind = "password" | "privateKey" | "agent" | "external" | "certificate";

/** A private key's container, read from the file's content and never its name. */
export type KeyFormat = "openssh" | "pkcs8" | "putty-ppk";

/** What a session does while the vault is locked. */
export type SessionOnLock = "keep_running" | "freeze_input" | "disconnect_all";

/** Whether sessions are recorded. */
export type RecordingPolicy = "never" | "on_request" | "always";

/**
 * How well this build, on this machine, can see one of the operating-system
 * events the vault can lock on.
 *
 * `"observed"` — seen as it happens. `"on_resume"` — seen only afterwards, when
 * the machine comes back. `"unobserved"` — this build cannot see it here at
 * all, and the switch for it must be disabled and explained rather than left
 * persisting a value nothing reads.
 */
export type LockTriggerObservation = "observed" | "on_resume" | "unobserved";

/** Which update stream the update check asks about. */
export type UpdateChannel = "stable" | "beta";

/** An audit row's category — the audit screen's filter chips. */
export type AuditCategory = "vault" | "node" | "secret" | "connection" | "warning";

/** How an audited action ended. */
export type AuditOutcome = "success" | "failure" | "denied";

/** The formats an audit export writes. */
export type AuditExportFormat = "json" | "csv";

/** The importers this build has. */
export type ImportSource = "mremoteng" | "ssh-config" | "csv";

/** How much attention an import finding needs. */
export type FindingSeverity = "info" | "warning" | "alert";

/**
 * A shortcut's reach.
 *
 * `"universal"` works even inside a focused terminal; `"application"` is
 * reached through the terminal prefix while a session has focus.
 */
export type ShortcutScope = "universal" | "application";

/**
 * Why a binding cannot be relied on as typed.
 *
 * `"duplicate"` — another Remoter action has it too; `"terminal-reserved"` —
 * the remote host owns those keys; `"desktop"` — the desktop environment takes
 * it first, and wins.
 */
export type ShortcutConflict = "duplicate" | "terminal-reserved" | "desktop";

// ---------------------------------------------------------------- vault ----

export interface RecentVault {
  path: string;
  label: string;
  /** Unix seconds. `null` if never opened on this machine. */
  lastOpened: number | null;
  /**
   * Slot kinds this vault carries, so the picker can show which unlock methods
   * exist before the user commits to one.
   */
  slots: SlotKind[];
  /**
   * `false` when the file is missing — an unmounted USB key, say. Such a vault
   * stays visible and disabled with a reason; hiding it would look like data
   * loss.
   */
  reachable: boolean;
  /**
   * The English sentence for {@link unreachableKind}, from the core.
   *
   * **Do not render this** when a kind or a code is set. It is the fallback
   * for a kind the interface has not learned yet, exactly as an `IpcFailure`'s
   * `message` is the fallback for a code the `errors` catalogue has no entry
   * for. The picker composes the sentence its reader needs from
   * `vault:picker.unreachable.*`; see `unreachableText` in
   * `@/features/vault/VaultPicker`.
   */
  unreachableReason: string | null;
  /**
   * Why the vault cannot be reached, as a stable identifier rather than a
   * sentence. `null` when the file is there but does not read as a vault —
   * that case carries {@link unreachableCode} instead.
   */
  unreachableKind: UnreachableKind | null;
  /**
   * The underlying diagnostic: an operating-system error string. English on
   * purpose, like an `IpcFailure`'s `detail` — it is what a reader copies into
   * a bug report, and a translated one is no use to whoever reads it.
   */
  unreachableDetail: string | null;
  /**
   * The `IpcFailure.code` of the probe failure, when the file exists but is
   * not a readable vault. Joined to the `errors` catalogue, which already has
   * a translated sentence for every code the core can raise.
   */
  unreachableCode: string | null;
  /**
   * The English sentence for {@link syncProvider}.
   *
   * **Do not render this** either, and for the same reason —
   * `vault:detail.syncWarning` is the sentence, composed around the provider.
   */
  syncWarning: string | null;
  /**
   * The cloud-sync provider whose folder this vault sits in: `"Dropbox"`,
   * `"OneDrive"`, `"iCloud Drive"`. A brand name, so it is never translated
   * (docs/features/i18n.md, "What is never translated"); it is the *value*
   * the warning is composed around.
   */
  syncProvider: string | null;
  sizeBytes: number | null;
}

/**
 * Why a remembered vault cannot be opened.
 *
 * Stable identifiers from `UnreachableKind` in
 * `crates/remoter-ipc/src/recents.rs`, and the keys of
 * `vault:picker.unreachable.*`. `composed.catalogue.test.ts` reads the Rust
 * and fails if either side drifts.
 */
export type UnreachableKind = "missing" | "unreadable" | "not-a-file";

export interface Slot {
  index: number;
  kind: SlotKind;
  label: string;
  createdAt: number;
  lastUsed: number | null;
  /** True when this slot's password also requires a key file. */
  requiresKeyfile: boolean;
  /** What this slot cost to derive. `null` for the kinds that use HKDF. */
  kdf: KdfParams | null;
}

/**
 * What a key slot cost to derive, as numbers.
 *
 * The core used to send one English sentence here — "Argon2id, 256 MiB, 3
 * passes, 4 lanes" — and six translated screens printed it word for word. The
 * parameters now cross as numbers and `kdfSummary` in
 * `@/features/vault/kdf.ts` composes the line, so the digits follow the
 * reader's numbering system and the memory carries a unit `Intl` wrote.
 */
export interface KdfParams {
  /**
   * The function's name, `"Argon2id"`. A proper name and never translated
   * (docs/features/i18n.md); it comes from the core so that the interface is
   * not the thing asserting which function ran.
   */
  algorithm: string;
  /** Memory cost in kibibytes — Argon2's `m`. */
  memoryKib: number;
  /** Iterations — Argon2's `t`. */
  passes: number;
  /** Degree of parallelism — Argon2's `p`. */
  lanes: number;
}

export interface Backup {
  path: string;
  modifiedAt: number;
  sizeBytes: number;
}

export interface VaultProbe {
  path: string;
  label: string;
  formatVersion: number;
  createdAt: number;
  modifiedAt: number;
  sizeBytes: number;
  slots: Slot[];
  backups: Backup[];
  /**
   * The English sentence for {@link syncProvider}. **Do not render this** — see
   * {@link RecentVault.syncWarning}.
   */
  syncWarning: string | null;
  /**
   * The cloud-sync provider whose folder this vault sits in. A brand name,
   * never translated; the sentence in `vault:detail.syncWarning` is composed
   * around it.
   */
  syncProvider: string | null;
  /**
   * The key file this vault was last opened with, if one is remembered on this
   * machine and still on disk. The path is not a secret; the file's contents
   * are. Offering it back removes an easy mistake: the browser opens in the
   * vault's own folder, the `.rvault` is the obvious file in it, and picking it
   * fails with a message that is deliberately unable to explain itself.
   */
  rememberedKeyfile: string | null;
}

/**
 * How the user is unlocking.
 *
 * Carries a master password or a recovery key in the clear. It travels inward
 * only — never store one, never put one in a query key.
 */
export type UnlockRequest =
  | { kind: "password"; password: string; keyfilePath: string | null }
  | { kind: "recovery"; key: string }
  | { kind: "keychain" };

/** Carries the master password; see {@link UnlockRequest}. */
export interface CreateVaultRequest {
  path: string;
  label: string;
  password: string;
  keyfilePath: string | null;
  /** When set, a fresh random key file is written here and used. */
  generateKeyfileAt: string | null;
}

/**
 * Returned once, at creation. The recovery key is displayed and then dropped;
 * there is no command that can ask for it again.
 */
export interface CreateVaultResult {
  path: string;
  /** Fourteen groups of four characters, Crockford Base32 (thirteen of key, one of checksum). Eight groups of four would be 160 bits and cannot carry a 256-bit key. */
  recoveryKeyGroups: string[];
  /** Which group the transcription check will ask the user to retype. */
  confirmGroupIndex: number;
  /**
   * What the new vault's password slot cost to derive. `null` only if it
   * somehow has no password slot, in which case the sheet omits the line
   * rather than printing half a sentence.
   */
  kdf: KdfParams | null;
}

export interface VaultState {
  unlocked: boolean;
  path: string | null;
  label: string | null;
  connectionCount: number;
  credentialCount: number;
  /** Seconds until auto-lock, or `null` when auto-lock is off. */
  locksInSeconds: number | null;
  /**
   * True when a password slot's Argon2id parameters are below the current cost
   * floor. `docs/security/vault-format.md` promises the upgrade is offered on
   * the next successful unlock, and this is what the interface reads to offer
   * it — `ipc.upgradeKdf` is the acceptance.
   */
  kdfUpgradeAvailable: boolean;
}

export interface PasswordStrength {
  /** 0–4, zxcvbn-style. */
  score: number;
  entropyBits: number;
  /**
   * `"Weak" | "Fair" | "Good" | "Strong"` — English, from the core.
   *
   * **Do not render this.** Pass `entropyBits` to `useStrengthText` from
   * `@/i18n` instead: it derives the same word from the same bits through the
   * catalogue, so a reader who chose another language is not told about their
   * password in English. The field stays because the DTO in
   * `crates/remoter-ipc/src/dto.rs` still carries it.
   */
  label: string;
  /**
   * Plain-language consequence, e.g. "Centuries of guessing at a billion
   * attempts a second." A bit count alone changes nobody's behaviour, so this
   * sentence is the point.
   *
   * **Do not render this** either, and for the same reason — `useStrengthText`
   * returns it as `explanation`, translated, with the number as an ICU plural
   * so it inflects and its digits follow the locale.
   */
  explanation: string;
  acceptable: boolean;
}

// ----------------------------------------------------------------- tree ----

export interface TreeNode {
  id: string;
  parentId: string | null;
  sortOrder: number;
  kind: NodeKind;
  name: string;
  description: string;
  tags: string[];
  colour: string | null;
  /** Connections only. */
  protocol: string | null;
  host: string | null;
  port: number | null;
  /**
   * The account name. Set on a credential, and on a connection that has a
   * credential of its own — a connection has no username field in the data
   * model, so what the editor shows and edits is its attached credential's.
   * `null` on a connection whose credential is inherited or shared;
   * {@link Ipc.resolveNode} is where the inherited value and its source come
   * from.
   */
  username: string | null;
  /**
   * What the credential authenticates with, so the editor opens on the right
   * tab without asking for the secret itself. Set on the same nodes
   * {@link TreeNode.username} is.
   */
  secretKind: SecretKind | null;
  /** Private-key credentials only. */
  keyFormat: KeyFormat | null;
  /**
   * Private-key credentials only: whether a passphrase is stored beside the
   * key. The passphrase itself never crosses this boundary.
   */
  hasPassphrase: boolean;
  /**
   * Agent credentials only: the comment substring that narrows which of the
   * agent's identities is used.
   */
  agentCommentFilter: string | null;
  /**
   * Connections and folders: the credential set **on this node**, if one is.
   * `null` when the credential is inherited — `ipc.resolveNode` is where the
   * inherited value and its source come from.
   */
  credentialId: string | null;
  /**
   * Connections: the credential this connection owns, if it has one.
   *
   * Equal to {@link TreeNode.credentialId} when set. The two are separate
   * because they mean different things to the editor: an attached credential
   * is this connection's own username and secret, shown inline, while a shared
   * one is a credential the user picked and is named as such.
   */
  attachedCredentialId: string | null;
  /**
   * Credentials: the connection this credential belongs to, or `null` for a
   * shared one.
   *
   * An attached credential is part of its connection, not a separate entry:
   * `listTree` and `searchTree` leave them out, so in practice this is `null`
   * on everything the sidebar draws.
   */
  attachedTo: string | null;
  /**
   * What an edit did to the connection's own credential, when it did something
   * the interface has to be able to explain. Only ever set on the node
   * returned by {@link Ipc.createNode} and {@link Ipc.updateNode}.
   */
  credentialChange: CredentialChange | null;
  /** How many nodes inherit something from this one; shown as "inherits 3". */
  inheritedFieldCount: number;
  updatedAt: number;
}

/**
 * What an edit did to a connection's own credential.
 *
 * - `"created"` — the connection had no credential; it has one now.
 * - `"updated"` — its own credential was edited in place.
 * - `"overridesInherited"` — it was using a folder's credential; it now has
 *   its own, which overrides it. The folder's is untouched, and so is every
 *   other connection under it.
 * - `"detachedFromShared"` — it pointed at a shared credential. That one is
 *   untouched — other connections use it — and this connection was given one
 *   of its own. Worth telling the user: it is the one case where saving a
 *   username does not change what they were looking at.
 * - `"removed"` — its own credential was cleared; whatever it inherits applies
 *   again.
 */
export type CredentialChange =
  | "created"
  | "updated"
  | "overridesInherited"
  | "detachedFromShared"
  | "removed";

/**
 * How a credential authenticates, as the editor sends it.
 *
 * A private key is named by the path it is read from; the bytes are stored in
 * the vault, so the user is not tied to that file afterwards.
 *
 * Carries a password and a key passphrase. It travels inward only; see
 * {@link UnlockRequest}.
 */
export type CredentialInput =
  | { kind: "password"; password: string }
  | {
      kind: "privateKey";
      /** The file to read the key out of. Read once, at this call. */
      path: string;
      /**
       * Needed only when the key file says it is encrypted — which is what
       * {@link PrivateKeyInfo.encrypted} is for.
       */
      passphrase: string | null;
    }
  | { kind: "agent"; commentFilter: string | null };

/**
 * What a candidate private key file is, without any of what is in it.
 *
 * The format is read from the file's content, never from its name: a `.pem`
 * holding an OpenSSH container is ordinary. `encrypted` is what lets the editor
 * ask for a passphrase only when one is needed.
 */
export interface PrivateKeyInfo {
  path: string;
  format: KeyFormat;
  /** The container's name as a person would say it: "OpenSSH", "PKCS#8", "PuTTY PPK". */
  formatLabel: string;
  encrypted: boolean;
  sizeBytes: number;
}

/** Carries a credential's password; see {@link UnlockRequest}. */
export interface CreateNode {
  parentId: string | null;
  kind: NodeKind;
  name: string;
  protocol: string | null;
  host: string | null;
  port: number | null;
  /**
   * The account name. On a credential it is the credential's own; on a
   * connection it creates a credential attached to that connection, which is
   * what makes typing a username and a password on one server just work.
   */
  username: string | null;
  /**
   * Shorthand for `credential: { kind: "password" }`. Sending both is refused
   * rather than guessed at.
   */
  password: string | null;
  /** How the new credential authenticates. Absent means "no secret yet". */
  credential?: CredentialInput | null;
  /**
   * Connections and folders: the credential node to authenticate with. This is
   * how a connection reaches a private key or the agent — the key lives on a
   * credential, and the connection points at it.
   */
  credentialId?: string | null;
}

/** Carries a credential's password; see {@link UnlockRequest}. */
export interface UpdateNode {
  name?: string;
  description?: string;
  tags?: string[];
  colour?: string;
  host?: string;
  port?: number;
  /**
   * The account name.
   *
   * On a credential it is that credential's own. On a connection it lands on
   * the connection's own credential: the existing one if it has one, otherwise
   * a new one that overrides — never edits — whatever it was inheriting or
   * sharing. Sending an empty username with no secret removes the connection's
   * own credential, so it inherits again.
   */
  username?: string;
  password?: string;
  /**
   * Replaces how this credential authenticates. Switching from a password to a
   * key — or to the agent — deletes the secrets the old method stored, so a key
   * credential does not keep a stale password behind it. On a connection it
   * lands on the connection's own credential, as `username` does.
   */
  credential?: CredentialInput;
  /**
   * Connections and folders: the credential node to authenticate with. Clearing
   * it — going back to the inherited one — is `clearOverrides: ["credential"]`,
   * which also removes the connection's own credential if it had one.
   *
   * Sending this together with `username`, `password` or `credential` on a
   * connection is refused: one says "use that shared credential" and the other
   * says "have one of your own", and guessing between them is not something
   * the core may do.
   */
  credentialId?: string;
  /** Field names to reset to inherited. */
  clearOverrides?: string[];
  /**
   * Protocol settings to write, one entry per key the user touched.
   *
   * A sparse patch, and the two cases are different instructions: a string
   * sets the key on this node, and `null` **removes** this node's own entry so
   * the key inherits again — the settings equivalent of `clearOverrides`,
   * which cannot serve here because it names whole inheritable fields and a
   * settings map inherits key by key.
   *
   * Keys this object does not mention are left exactly as they are, so a
   * setting an importer wrote, or one a newer build knows about, survives a
   * save from a form that never showed it.
   *
   * Values are typed against the adapter's own schema before anything is
   * written, and a value outside its bounds comes back as
   * `session.setting-invalid`, naming the key and never the value.
   */
  settings?: Record<string, string | null>;
}

/**
 * One resolved field, carrying where its value came from — the provenance the
 * interface shows inline next to every inherited field.
 */
export interface ResolvedField {
  field: string;
  value: string | null;
  origin: FieldOrigin;
  /** Name of the ancestor the value came from, when inherited. */
  sourceName: string | null;
  sourceId: string | null;
  /** The value this one overrides, when it shadows an inherited value. */
  overrides: string | null;
}

export interface EffectiveConnection {
  nodeId: string;
  protocol: string;
  /**
   * One entry per inheritable field, `"username"` among them: it resolves with
   * the credential that holds it, so its origin is `"own"` when the credential
   * belongs to this connection and `"inherited"` — with `sourceName` — when it
   * comes from a folder.
   */
  fields: ResolvedField[];
  gatewayChain: string[];
  tags: string[];
  /**
   * Whether the resolved credential belongs to this connection alone.
   *
   * True means the `username` field is this connection's own to edit; false
   * means it comes from a credential others may share, and editing it here
   * would change theirs — which is why saving one creates a credential of this
   * connection's own instead.
   */
  credentialAttached: boolean;
}

// --------------------------------------------------- protocol schemas ----

/**
 * Where a setting's default value came from.
 *
 * `"fixed"` — the adapter chose it. `"detected"` — it was read off this
 * machine. `"guessed"` — the core tried to read it off this machine and could
 * not, so what is there is a stand-in.
 *
 * **A `"guessed"` default has to be said out loud.** The case it exists for is
 * the RDP keyboard layout: the server decodes this client's scancodes with the
 * layout the connection names, so a wrong one types the wrong characters and
 * reports no error at all. A user typing Turkish into a session that assumed
 * US English needs to be told that the client guessed.
 */
export type DefaultOrigin = "fixed" | "detected" | "guessed";

/** What a setting holds, and within what bounds. */
export type SettingKind =
  | { type: "text"; maxLen: number }
  | { type: "integer"; min: number; max: number }
  | { type: "boolean" }
  /** The permitted values are in `SettingField.options`, not here. */
  | { type: "choice" };

/**
 * How an offered value is named.
 *
 * Two cases, because a settings value is named two different ways. A keyboard
 * layout is prose and belongs to a translator; an RFB version is a wire token
 * and belongs to nobody. `kind: "message"` goes through `t()`; `kind:
 * "verbatim"` is shown as it stands and never translated.
 */
export type SettingOptionLabel = { kind: "message"; key: string } | { kind: "verbatim"; text: string };

/** One value a setting offers by name. */
export interface SettingOption {
  /** The value as stored — what goes back on the wire, not a rendering of it. */
  value: string;
  label: SettingOptionLabel;
}

/** One settings field, as its adapter declares it. */
export interface SettingField {
  /**
   * The key it is stored under — `keyboard_layout`, `rfb_version_min`. The
   * same key the resolved view carries after its `settings.` prefix, which is
   * what joins this schema to `EffectiveConnection.fields`. A wire identifier:
   * never translated.
   */
  key: string;
  /** Catalogue key for the label. Put it through `t()`. */
  label: string;
  kind: SettingKind;
  /** Used when nothing on the inheritance path sets a value. */
  default: string | null;
  defaultOrigin: DefaultOrigin;
  required: boolean;
  /**
   * The values worth offering by name. Empty where there are none — a domain
   * or a working directory has no list.
   */
  options: SettingOption[];
  /**
   * Whether a value outside `options` is refused.
   *
   * True for a `choice`. False for the keyboard layout on purpose: Microsoft
   * publishes several hundred identifiers, `options` holds the ones worth
   * listing, and a form has to let the rest be typed in.
   */
  optionsAreClosed: boolean;
}

/**
 * One protocol's settings, read from the adapter that implements it.
 *
 * The editor is meant to render its form from this rather than list the fields
 * itself: RDP's schema names eight and VNC's names six, and a second list
 * would agree with the first only until somebody adds a setting.
 */
export interface ProtocolSchema {
  /** `"ssh"`, `"rdp"`, `"vnc"` — the identifier a connection stores. */
  protocol: string;
  /** In the order the form should show them. */
  settings: SettingField[];
}

export interface SearchHit {
  node: TreeNode;
  /** Breadcrumb, e.g. "Datacentre EU-West / Web tier". */
  path: string;
  /** Character ranges in `node.name` that matched, for highlighting. */
  nameMatches: [number, number][];
  /**
   * The hit's second line: an address for a connection, a login for a
   * credential — values, rendered as they stand.
   *
   * For a folder or a group it is a count, and then this is English prose
   * ("3 items") that **must not be rendered**: pass {@link subtitleKind} and
   * {@link subtitleCount} through `connections:palette.subtitle.*` instead, so
   * the phrase inflects and its digits follow the locale. This field stays as
   * the fallback for a kind the interface does not know.
   */
  subtitle: string;
  /**
   * Set when {@link subtitle} is a counted phrase the interface should compose
   * itself. From `SubtitleKind` in `crates/remoter-ipc/src/commands.rs`.
   */
  subtitleKind: SubtitleKind | null;
  /** The number {@link subtitleKind} counts. */
  subtitleCount: number | null;
  score: number;
}

/**
 * The two search-hit subtitles that are a sentence rather than a value.
 *
 * Stable identifiers from `SubtitleKind` in
 * `crates/remoter-ipc/src/commands.rs`, and the keys of
 * `connections:palette.subtitle.*`.
 */
export type SubtitleKind = "items" | "members";

// ------------------------------------------------- vault administration ----

/** The key slots of the open vault, for the Vault settings screen. */
export interface VaultSlots {
  slots: Slot[];
  /**
   * The slot this session was opened through, so the screen can mark it and
   * warn before it is revoked.
   */
  openedWith: number | null;
  backupCount: number;
}

/** Carries a password; see {@link UnlockRequest}. */
export interface AddPasswordSlot {
  label: string;
  password: string;
  keyfilePath: string | null;
}

/** Carries two passwords; see {@link UnlockRequest}. */
export interface ChangePassword {
  /** The slot to re-wrap. `null` means slot 0, the master password. */
  slotIndex: number | null;
  currentPassword: string;
  currentKeyfilePath: string | null;
  newPassword: string;
  /**
   * The key file the slot will require from now on. `null` drops the key file
   * requirement; the current one is not carried over silently.
   */
  newKeyfilePath: string | null;
}

/** One password slot's credential, for a master key rotation. */
export interface SlotCredential {
  index: number;
  password: string;
  keyfilePath: string | null;
}

/** Carries passwords; see {@link UnlockRequest}. */
export interface RotateMasterKey {
  /** One entry per password slot that is to survive the rotation. */
  credentials: SlotCredential[];
  /**
   * Slots to discard rather than re-wrap — a hardware key that is not to hand,
   * a password nobody remembers. A slot that is in neither list is a refusal,
   * not a silent deletion.
   */
  dropSlots: number[];
}

/**
 * A recovery key, returned exactly once.
 *
 * Nothing in the vault file can reproduce this; there is no command that asks
 * for it again. Show it, let the user record it, then let it go — do not cache
 * it and do not put it in a query.
 */
export interface RecoveryKey {
  slotIndex: number;
  /** Fourteen groups of four characters, Crockford Base32. */
  recoveryKeyGroups: string[];
  /** Which group the transcription check should ask the user to retype. */
  confirmGroupIndex: number;
}

/** What a master key rotation did. */
export interface RotationOutcome {
  /** Slot indices re-wrapped around the new master key. */
  rewrapped: number[];
  /** Slot indices the plan discarded. */
  dropped: number[];
  /** One per recovery slot, each shown exactly once. */
  recoveryKeys: RecoveryKey[];
  secretsResealed: number;
}

/**
 * Which of the three lock triggers this build can honour on this computer.
 *
 * Mirrors `LockTriggerSupportDto`. It describes the machine rather than the
 * vault, and travels with the vault settings because the Vault settings screen
 * is the one place it is needed.
 */
export interface LockTriggerSupport {
  screenLock: LockTriggerObservation;
  suspend: LockTriggerObservation;
  minimise: LockTriggerObservation;
}

/** The settings that travel with the vault file rather than with the machine. */
export interface VaultSettings {
  /**
   * Zero means never.
   *
   * This is the timeout the core actually counts down while this vault is
   * open; the application-level one is only the default for the next vault.
   */
  autoLockMinutes: number;
  lockOnScreenLock: boolean;
  lockOnSuspend: boolean;
  lockOnMinimise: boolean;
  /**
   * Optional only so a test fixture need not restate a machine capability —
   * the core sends it with every read and every write. A screen that finds it
   * absent has no grounds to claim a switch does nothing, so it renders them
   * as ordinary switches.
   */
  lockTriggers?: LockTriggerSupport;
  sessionOnLock: SessionOnLock;
  recording: RecordingPolicy;
  /**
   * Rolling backups kept beside the vault file. Stored in the header, which is
   * readable before the body is decrypted — which is the situation the backups
   * exist for.
   */
  backupCount: number;
}

/** A partial {@link VaultSettings}. An absent field is left alone. */
export interface VaultSettingsPatch {
  autoLockMinutes?: number;
  lockOnScreenLock?: boolean;
  lockOnSuspend?: boolean;
  lockOnMinimise?: boolean;
  sessionOnLock?: SessionOnLock;
  recording?: RecordingPolicy;
  backupCount?: number;
}

// ---------------------------------------------------------------- audit ----

/** Which audit entries to read, and which page of them. */
export interface AuditQuery {
  /** Milliseconds since the epoch; entries at or after it. */
  since?: number;
  /**
   * Milliseconds since the epoch; entries strictly before it. Half-open, so
   * paging by day cannot show one entry twice.
   */
  until?: number;
  /** Combined with "or" — the screen's filter chips. */
  categories?: AuditCategory[];
  /** Combined with "or". */
  outcomes?: AuditOutcome[];
  nodeId?: string;
  sessionId?: string;
  /** Zero-based. Defaults to the first page. */
  page?: number;
  /** Defaults to 100, capped at 1000. */
  pageSize?: number;
}

/**
 * One row of the audit log. Never carries a secret: `detail` is a short
 * plain-language note written under the same rule as everything else here.
 */
export interface AuditEntry {
  id: number;
  /** Milliseconds since the epoch. */
  at: number;
  /**
   * The event name as stored, so a row written by a newer build survives. Not a
   * closed union for that reason — render an unrecognised name as itself rather
   * than dropping the row.
   */
  event: string;
  outcome: AuditOutcome;
  /** `null` when this build does not know the event name. */
  category: AuditCategory | null;
  /**
   * Whether the row belongs in the "warnings" filter — the rows an incident
   * review scrolls for.
   */
  warning: boolean;
  nodeId: string | null;
  /** The node's name at the time of reading, when it is still in the tree. */
  nodeName: string | null;
  sessionId: string | null;
  detail: string | null;
}

export interface AuditPage {
  entries: AuditEntry[];
  /** How many entries match the filter, ignoring the paging. */
  total: number;
  page: number;
  pageSize: number;
}

/**
 * The filter vocabulary, so the interface's chips cannot drift from the log's
 * own spellings.
 */
export interface AuditFilters {
  categories: AuditCategory[];
  outcomes: AuditOutcome[];
  /** Open-ended: see {@link AuditEntry.event}. */
  events: string[];
}

export interface AuditExport {
  path: string;
  format: AuditExportFormat;
  /**
   * The same filter the screen is showing. Absent exports everything. The
   * paging in it is ignored — an export of page three of a filter is not what
   * anybody means by "export".
   */
  query?: AuditQuery | null;
}

export interface AuditExportResult {
  path: string;
  format: AuditExportFormat;
  entries: number;
  bytes: number;
}

// --------------------------------------------------------------- import ----

/** What a file appears to be, before anything is parsed. */
export interface ImportDetection {
  path: string;
  sizeBytes: number;
  /** `null` when the content matches no importer. */
  format: ImportSource | null;
  /** The format's name as a person would say it. */
  formatLabel: string | null;
  /** Whether parsing will need the document password. */
  passwordRequired: boolean;
  /** mRemoteNG only: what the document says about itself. */
  document: ImportDocument | null;
}

/** The `<Connections>` header of an mRemoteNG document. */
export interface ImportDocument {
  name: string;
  confVersion: string | null;
  cipher: "gcm" | "cbc";
  /** Set for GCM, which is the only mode that carries one. */
  kdfIterations: number | null;
  /**
   * True for AES-CBC with an MD5-derived key: readable, and a reason to treat
   * every credential in the file as exposed.
   */
  legacyCipher: boolean;
  fullFileEncryption: boolean;
  passwordRequired: boolean;
}

/**
 * The tree an import would create, and the report that goes with it.
 *
 * The preview itself stays in the core: it holds the passwords recovered from
 * the file in plaintext, and nothing here carries one. `importId` is the handle
 * `ipc.commitImport` uses; the preview is dropped — and its secrets zeroized —
 * when the import is committed, cancelled, or the vault locks. One preview is
 * held at a time, so a second parse wipes the first.
 */
export interface ImportPreview {
  importId: string;
  source: ImportSource;
  sourceLabel: string;
  nodes: ImportNode[];
  report: ImportReport;
}

/** One node an import would create, with everything secret removed. */
export interface ImportNode {
  /**
   * The identity the node will be created with; already allocated, so the
   * preview's own references resolve. This is what
   * {@link ImportCommit.excludedIds} names.
   */
  id: string;
  /** `null` for a node that lands at the destination's top level. */
  parentId: string | null;
  sortOrder: number;
  name: string;
  kind: "folder" | "connection" | "credential";
  protocol: string | null;
  host: string | null;
  port: number | null;
  portInherited: boolean;
  username: string | null;
  domain: string | null;
  /** Whether the vault will have to seal a password for this node. */
  hasSecret: boolean;
  credentialInherited: boolean;
  gatewayHops: number;
  customFields: number;
}

export interface ImportReport {
  source: ImportSource;
  counts: ImportCounts;
  findings: ImportFinding[];
  /** True when a limit stopped the parse before the end of the file. */
  truncated: boolean;
  /** True when any finding is a warning or an alert. */
  needsAttention: boolean;
}

export interface ImportCounts {
  folders: number;
  connections: number;
  credentials: number;
  secrets: number;
  skipped: number;
}

/** Why an item did not make it into the preview. */
export type SkipReason = "unusable_host" | "unusable_name" | "unsupported_kind" | "empty";

/**
 * One thing the importer wants the user to know.
 *
 * `remoter_import::Finding` is flattened alongside `severity`, so the object on
 * the wire is `{ severity, kind, ...the finding's own fields }`. Those inner
 * field names are `snake_case`, not camelCase: serde's `rename_all` on an enum
 * renames its variants and leaves struct-variant fields alone, and this mirrors
 * what actually arrives rather than what the rest of the file looks like.
 *
 * Nothing here holds secret material — findings end up on screen, and a
 * password that reached one would be on screen too.
 */
export type ImportFinding =
  /** The file was encrypted with mRemoteNG's published default password. */
  | { severity: FindingSeverity; kind: "default_file_password" }
  /**
   * The pre-1.75 AES-CBC scheme: unsalted MD5 of the password for a key, and
   * unauthenticated ciphertext.
   */
  | { severity: FindingSeverity; kind: "legacy_cbc_encryption" }
  | { severity: FindingSeverity; kind: "full_file_encryption" }
  | { severity: FindingSeverity; kind: "secrets_recovered"; count: number }
  | {
      severity: FindingSeverity;
      kind: "credentials_deduplicated";
      credentials: number;
      connections: number;
    }
  | {
      severity: FindingSeverity;
      kind: "unknown_protocol";
      item: string;
      protocol: string;
      mapped_to: string;
    }
  | { severity: FindingSeverity; kind: "skipped_item"; item: string; reason: SkipReason }
  | { severity: FindingSeverity; kind: "unmapped_proxy_command"; item: string; command: string }
  | { severity: FindingSeverity; kind: "gateway_mapped"; item: string; hops: number }
  | { severity: FindingSeverity; kind: "gateway_synthesised"; item: string; target: string }
  | { severity: FindingSeverity; kind: "gateway_unresolved"; item: string; target: string }
  /** A secret in a field with no home in the domain model. Dropped, not preserved. */
  | { severity: FindingSeverity; kind: "secret_not_mapped"; item: string; field: string }
  | {
      severity: FindingSeverity;
      kind: "match_block_not_applied";
      criteria: string;
      options: number;
    }
  | {
      severity: FindingSeverity;
      kind: "pattern_block_applied";
      pattern: string;
      connections: number;
    }
  | { severity: FindingSeverity; kind: "settings_preserved"; item: string; count: number }
  | { severity: FindingSeverity; kind: "unknown_column"; column: string }
  /** What ran out: `custom_fields`, `findings` or `nodes`. */
  | { severity: FindingSeverity; kind: "limit_reached"; limit: string };

export interface ImportCommit {
  importId: string;
  /** The folder to import into. Absent means the top level of the vault. */
  destinationId?: string | null;
  /**
   * Nodes the user unticked. Excluding a folder excludes everything under it;
   * nothing is written for any of them.
   */
  excludedIds?: string[] | null;
}

/**
 * What a committed import wrote. One transaction: either all of this reached
 * the vault file or none of it did.
 */
export interface ImportResult {
  source: ImportSource;
  imported: number;
  skipped: number;
  folders: number;
  connections: number;
  credentials: number;
  /** How many passwords were sealed into the vault. */
  secretsStored: number;
  /**
   * Findings the report rates warning or alert — the "needs a look" count on
   * the final step.
   */
  needsAttention: number;
  /** The ids of the nodes that landed directly in the destination folder. */
  rootIds: string[];
}

// ------------------------------------------------------------- settings ----

/**
 * How the terminal is painted and set.
 *
 * Mirrors `TerminalAppearanceDto`. The palette ids and the colour keys are not
 * repeated here — `lib/terminalPalette.ts` holds them, along with the palettes
 * themselves and the contrast arithmetic, and both sides validate against the
 * same list of names. Keeping the wire types loose (`string`) is deliberate:
 * the core stores what the interface sends and the interface drops what it
 * does not recognise, so a settings file written by a newer build does not
 * make an older one refuse to start.
 */
export interface TerminalAppearance {
  /** A built-in palette id, or `"auto"` to follow the interface theme. */
  palette: string;
  /**
   * Colour key to `#rrggbb` (or `#rrggbbaa`). Only the colours the user
   * actually changed are stored, so switching palette moves everything that
   * was left alone.
   */
  overrides: Record<string, string>;
  /** Empty means the interface's own mono stack. */
  fontFamily: string;
  fontSize: number;
}

export interface AppSettings {
  theme: ThemeName;
  locale: string;
  autoLockMinutes: number | null;
  lockOnScreenLock: boolean;
  lockOnSuspend: boolean;
  sidebarWidth: number;
  inspectorOpen: boolean;
  /**
   * Opt-in, off by default. When it is off nothing leaves this machine, and
   * nothing about the user is sent when it is on either: the check asks for a
   * version number and says nothing about who is asking.
   */
  updateCheckEnabled: boolean;
  updateChannel: UpdateChannel;
  /** Unix seconds of the last check, or `null` if none has run. */
  updateLastCheckedAt: number | null;
  /**
   * The modifier a shortcut is prefixed with inside a focused terminal, where
   * almost every keystroke belongs to the remote host.
   */
  terminalPrefix: string;
  /**
   * Action id to accelerator. Only the bindings that differ from the defaults
   * are stored, so a changed default reaches everyone who has not overridden it.
   */
  shortcuts: Record<string, string>;
  /** The terminal's palette, overrides and font. */
  terminal: TerminalAppearance;
}

/**
 * A partial {@link AppSettings}. An absent field is left alone.
 *
 * `autoLockMinutes` and `updateLastCheckedAt` are absent-or-null on purpose:
 * absent means "leave it alone" and `null` means "turn it off" / "never
 * checked". Collapsing the two would make auto-lock impossible to switch off.
 */
export interface AppSettingsPatch {
  theme?: ThemeName;
  locale?: string;
  autoLockMinutes?: number | null;
  lockOnScreenLock?: boolean;
  lockOnSuspend?: boolean;
  sidebarWidth?: number;
  inspectorOpen?: boolean;
  updateCheckEnabled?: boolean;
  updateChannel?: UpdateChannel;
  updateLastCheckedAt?: number | null;
  terminalPrefix?: string;
  /** A `null` accelerator restores that action's shipped default. */
  shortcuts?: Record<string, string | null>;
  /**
   * Replaced whole rather than merged field by field.
   *
   * The palette and its overrides are one decision — clearing an override and
   * changing palette in the same edit has to arrive as one value, or the core
   * would briefly hold overrides belonging to a palette that is no longer
   * selected.
   */
  terminal?: TerminalAppearance;
}

// --------------------------------------------------------- update check ----

/**
 * One published release, as the update check found it.
 *
 * `name` and `notes` are text a release author wrote and the network
 * delivered. Treat them as untrusted remote content: render them as text,
 * never as markup.
 *
 * `url` is the exception. The core does not take it from the response — it
 * builds it from the tag — so it always points at this repository's own
 * release page and can safely be handed to the system browser.
 */
export interface UpdateRelease {
  /** The git tag, as GitHub holds it: `v0.3.0`. */
  tag: string;
  /** The release's own title. Empty when the author gave it none. */
  name: string;
  /** The release notes, as Markdown source. */
  notes: string;
  /** The release page to open. */
  url: string;
  /** Whether the author marked this a pre-release. */
  prerelease: boolean;
  /** RFC 3339, or `null` when the release is unpublished. */
  publishedAt: string | null;
}

/**
 * What one update check found.
 *
 * The core reports; it does not judge. Which release counts as newer — and
 * whether a pre-release counts at all — is decided in
 * `features/settings/version.ts`, which is where that comparison is tested.
 */
export interface UpdateCheck {
  /** The version this build reports. */
  currentVersion: string;
  /** Published releases, newest first. Drafts are already excluded. */
  releases: UpdateRelease[];
  /** Unix seconds the check completed. Also written to the settings file. */
  checkedAt: number;
}

/** One editable keyboard binding. */
export interface Shortcut {
  /** Stable, dotted, ASCII. The interface's translation key hangs off it. */
  id: string;
  scope: ShortcutScope;
  accelerator: string;
  defaultAccelerator: string;
  customised: boolean;
  /**
   * How many consecutive keys the binding covers: 9 for "jump to tab 1–9", 1
   * for everything else.
   */
  seriesLen: number;
  /** `null` when the binding works as typed. */
  conflict: ShortcutConflict | null;
  /** The other action ids sharing this accelerator, for `"duplicate"`. */
  conflictsWith: string[];
}

// ------------------------------------------------------------- sessions ----

/** What kind of surface a session renders into. */
export type SessionKind = "terminal" | "framebuffer" | "file_transfer";

/** What clipboard traffic a protocol carries. */
export type ClipboardSupport = "none" | "text" | "text_and_files";

/** Where a session is in its life. */
export type SessionState = "connecting" | "running" | "closing";

/** Which of the nine pipeline stages a failure belongs to. */
export type SessionStage =
  | "resolve"
  | "authorise"
  | "acquire"
  | "transport"
  | "handshake"
  | "authenticate"
  | "attach"
  | "run"
  | "terminate";

/** Why a session ended. */
export type CloseReason =
  | "disconnected"
  | "closed_by_user"
  | "application_exit"
  | "failed"
  | "panicked"
  | "aborted";

/**
 * What the adapter says it can do.
 *
 * The tab reads this rather than hardcoding "SSH has no clipboard button" — a
 * plugin protocol gets the same treatment as a built-in one.
 */
export interface Capabilities {
  kind: SessionKind;
  resizable: boolean;
  clipboard: ClipboardSupport;
  fileTransfer: boolean;
  audio: boolean;
  printing: boolean;
  multiMonitor: boolean;
  recordable: boolean;
}

/** A session that authenticated and is attached to a tab. */
export interface SessionOpened {
  sessionId: number;
  nodeId: string;
  name: string;
  protocol: string;
  /** `host:port`, as connected. */
  target: string;
  /** The account it authenticated as. An identifier, never a secret. */
  username: string;
  /** How authentication succeeded — `"publickey"`, `"agent"`, `"password"`,
   * `"keyboard-interactive"`. Never what was sent. */
  authMethod: string;
  /** Gateway names traversed, outermost first. Empty for a direct connection. */
  via: string[];
  capabilities: Capabilities;
  startedAtMs: number;
  /**
   * The resolved recording policy, so the tab can show the notice **before**
   * anything is recorded. This build has no recorder; the policy is surfaced,
   * not honoured.
   */
  recording: RecordingPolicy;
}

/** One row of the session list. */
export interface SessionSummary {
  sessionId: number;
  nodeId: string;
  name: string;
  protocol: string;
  target: string;
  username: string;
  capabilities: Capabilities;
  startedAtMs: number;
  state: SessionState;
  /** True while the vault is locked and its policy is `freeze_input`. */
  frozen: boolean;
}

/** The key a host was already trusted with. */
export interface TrustedHostKey {
  fingerprint: string;
  randomart: string;
  firstTrustedAtMs: number;
}

/**
 * A suspended host key handshake.
 *
 * `status` is the whole point of this type. `"unknown"` is a first-use question
 * the user may answer with a click; `"changed"` is a possible
 * man-in-the-middle, and the core refuses to accept it through the first-use
 * path. Render the two differently — the changed one is the red, blocking
 * dialog that shows both fingerprints side by side and asks for
 * `confirmationLen` characters of the offered one to be typed.
 */
export interface HostKeyPrompt {
  promptId: number;
  /** `host:port`. */
  host: string;
  /** The key algorithm, as named on the wire. Peer-supplied: text, not markup. */
  algorithm: string;
  /** `SHA256:…` — the value the user compares out of band. */
  fingerprint: string;
  randomart: string;
  status: "unknown" | "changed";
  /** Present only when `status` is `"changed"`. */
  previouslyTrusted: TrustedHostKey | null;
  /** How many characters of `fingerprint` the replacement demands. `null` for
   * an unknown key, which needs no typing. */
  confirmationLen: number | null;
}

/**
 * Anything else the server asked for mid-handshake.
 *
 * `certificate` is the odd one, and the only one this build can answer. It is
 * not a request for a value — it is a **first-use trust decision** about the
 * certificate an RDP server presented, and it is answered with
 * {@link ipc.decideHostKey} rather than by sending text: `accept` to pin it,
 * `reject` to end the attempt. `replace` is refused on it, because a
 * certificate that contradicts a pinned one never arrives this way — the
 * adapter raises that one as a {@link HostKeyPrompt}, which is the only shape
 * that can carry both fingerprints for the side-by-side comparison.
 *
 * The other three kinds have no command behind them in this build.
 */
export interface SessionPrompt {
  promptId: number;
  kind: "password" | "key_passphrase" | "keyboard_interactive" | "certificate";
  /** The server's text: the challenge for keyboard-interactive, the address
   * for a certificate. Untrusted: never markup. */
  text: string;
  /** Whether the answer may be echoed. Honour it — the server marks its own
   * secret questions (RFC 4256 §3.3). */
  echo: boolean;
  /** `SHA256:…` for the certificate being offered, and `null` for every other
   * kind. The one value in the prompt the user can check against something the
   * far end did not also supply, so a certificate dialog shows it or offers no
   * accept at all. */
  fingerprint: string | null;
  /** Why the certificate is not trusted: `self-signed`, `untrusted root`,
   * `expired`, `name mismatch`, `revoked`, `malformed`, `changed`. A closed
   * set from the core, so it is translated rather than printed. `null` for
   * every other kind. */
  reason: string | null;
}

/** Progress on something long-running. */
export interface SessionProgress {
  operation: string;
  done: number;
  total: number | null;
  detail: string | null;
}

/** Why a session ended, with everything the tab shows. */
export interface SessionFailure {
  code: string;
  message: string;
  detail: string | null;
  actions: string[];
  stage: SessionStage;
  /** Always `false` for a changed host key, so auto-reconnect cannot retry a
   * possible man-in-the-middle. */
  retryable: boolean;
}

/**
 * A control event on a session's channel.
 *
 * Terminal output does **not** appear here. It arrives on the same channel as a
 * raw `ArrayBuffer`, one message per coalesced frame; see {@link sessionChannel}.
 */
export type SessionMessage =
  | { event: "opening"; sessionId: number }
  | ({ event: "ready" } & SessionOpened)
  | { event: "resized"; width: number; height: number }
  | { event: "clipboardOffer"; text: boolean; files: boolean }
  | ({ event: "hostKey" } & HostKeyPrompt)
  | ({ event: "prompt" } & SessionPrompt)
  | ({ event: "progress" } & SessionProgress)
  | {
      event: "warning";
      /** `unencrypted_transport` | `weak_algorithm` | `recording_started` |
       * `output_throttled` | `banner` | `other` */
      kind: string;
      detail: string | null;
    }
  | { event: "closed"; reason: CloseReason; failure: SessionFailure | null };

/**
 * The answer to a suspended host key handshake.
 *
 * Three variants, not one boolean, and deliberately so. `accept` is refused on
 * a **changed** key: that one is a possible man-in-the-middle and only
 * `replace` gets past it, carrying the tail of the offered fingerprint copied
 * off the screen. Do not offer an "accept" button on a changed-key dialog.
 */
export type HostKeyDecision =
  | { decision: "accept"; promptId: number }
  | { decision: "reject"; promptId: number }
  | { decision: "replace"; promptId: number; confirmation: string };

/** What one session's channel delivers: terminal bytes, or a control event. */
export type SessionChannelMessage = ArrayBuffer | SessionMessage;

/**
 * Builds the channel a session pushes into. Subscribe once per session, before
 * calling {@link ipc.openSession}; the core pushes for the life of the session.
 *
 * Terminal output arrives raw — an `ArrayBuffer`, never JSON — because base64
 * inside JSON costs about 40 % in size plus a parse on the render thread, on
 * the one path with a 30 ms budget (docs/architecture/rendering.md). It is
 * already coalesced at the frame interval by the core: write each chunk to
 * xterm.js as it arrives and do **not** re-batch it, which is what makes a
 * fast-scrolling terminal usable.
 */
export function sessionChannel(handlers: {
  onData: (bytes: Uint8Array) => void;
  onMessage: (message: SessionMessage) => void;
}): Channel<SessionChannelMessage> {
  const channel = new Channel<SessionChannelMessage>();
  channel.onmessage = (message) => {
    if (message instanceof ArrayBuffer) {
      handlers.onData(new Uint8Array(message));
      return;
    }
    // A large raw frame comes back through the fetch path, which may hand over
    // a view rather than the buffer itself.
    if (ArrayBuffer.isView(message)) {
      const view = message as ArrayBufferView;
      handlers.onData(new Uint8Array(view.buffer, view.byteOffset, view.byteLength));
      return;
    }
    handlers.onMessage(message);
  };
  return channel;
}

// -------------------------------------------------------------- tunnels ----

/** Which way a forward points. */
export type ForwardDirection = "local" | "remote" | "dynamic";

/** How far a listener can be reached from. `"network"` carries the warning badge. */
export type Exposure = "loopback" | "network";

/**
 * A forward to open.
 *
 * `bindAddress` absent or `null` means the loopback default. A non-loopback
 * address additionally requires `exposed: true`: a warning shown on a listener
 * that is already open has arrived too late, so the core refuses it before the
 * socket is bound rather than reporting it after.
 */
export type TunnelSpec =
  | {
      direction: "local";
      bindAddress?: string | null;
      bindPort: number;
      destinationHost: string;
      destinationPort: number;
      exposed?: boolean;
    }
  | {
      direction: "remote";
      bindAddress?: string | null;
      bindPort: number;
      destinationHost: string;
      destinationPort: number;
      exposed?: boolean;
    }
  | {
      direction: "dynamic";
      bindAddress?: string | null;
      bindPort: number;
      exposed?: boolean;
    };

/** One running forward, with its live counters. */
export interface Tunnel {
  tunnelId: number;
  nodeId: string;
  name: string;
  direction: ForwardDirection;
  /** Where it listens, as configured. */
  bind: string;
  /** Where it sends traffic. `null` for a SOCKS5 proxy, which decides per
   * connection. */
  destination: string | null;
  exposure: Exposure;
  /** The socket actually bound. `null` for a remote forward, whose listener is
   * on the server. */
  listening: string | null;
  /** The port the server chose, for a remote forward that asked for 0. */
  remotePort: number | null;
  active: number;
  connections: number;
  bytes: number;
  running: boolean;
}

// ----------------------------------------------------------------- sftp ----

/**
 * The file manager's command surface, mirroring `crates/remoter-ipc/src/sftp.rs`.
 *
 * Two rules govern every type below, and both come from
 * `docs/architecture/sftp-command-surface.md`:
 *
 * **Every string the server chose arrives twice.** The raw form is what goes
 * back on the wire; the `display*` form is what a human reads. They are never
 * interchanged — rendering the raw one lets a file called
 * `annex` + U+202E + `txt.exe` draw itself as `annexexe.txt`, and addressing the
 * escaped one asks the server for a path it never sent.
 *
 * **Progress is pushed, not polled.** A running transfer reports every 512 KiB
 * through the session's own channel as a `progress` message. `listTransfers`
 * is for the first paint and for reconciling after a tab switch.
 */

/** What is wrong with a name the far end chose. None of these hides the row. */
export interface NameRisks {
  /** Holds a control character: truncates a log line, rewrites a terminal row. */
  control: boolean;
  /** Holds a bidirectional override — Trojan Source (CVE-2021-42574) in a listing. */
  bidi: boolean;
  /** Holds a zero-width character, so two rows can look identical and not be. */
  invisible: boolean;
  /** Is not a single path component. The core refuses to build a path from it. */
  separator: boolean;
}

/** A file pane, once it is attached to a session. */
export interface SftpPane {
  paneId: number;
  /** The session it runs on. Closing that session closes this pane. */
  sessionId: number;
  /** The server's idea of where the user starts, canonicalised. Raw. */
  home: string;
  /** The same, escaped for display. */
  homeDisplay: string;
}

/** What a directory entry is. `"other"` covers sockets, FIFOs and devices. */
export type EntryKind = "file" | "directory" | "symlink" | "other";

/**
 * One row of the remote pane.
 *
 * `name` and `path` are what the interface sends back; `displayName` and
 * `displayPath` are what it draws. A component that renders `name` is a defect,
 * not a shortcut.
 */
export interface DirectoryEntry {
  name: string;
  displayName: string;
  path: string;
  displayPath: string;
  /** A string rather than {@link EntryKind} would let a new kind crash a switch. */
  kind: EntryKind;
  size: number | null;
  /** The POSIX mode bits, where the server reported them. */
  permissions: number | null;
  /** The same as `drwxr-xr-x`, rendered once by the core so every pane agrees. */
  mode: string | null;
  uid: number | null;
  /** The owning user's name, already escaped: it is server-supplied text too. */
  user: string | null;
  gid: number | null;
  /** The owning group's name, already escaped. */
  group: string | null;
  /** Last modification, in seconds since the Unix epoch. */
  modified: number | null;
  risks: NameRisks;
}

/** One thing a removal could not remove. */
export interface SftpDeleteFailure {
  /** Where it was, escaped for display. */
  path: string;
  /** The stable code from the failure taxonomy, for `errors.json`. */
  code: string;
  /** The core's English. Render the catalogue's sentence for `code` instead. */
  message: string;
}

/**
 * What a removal actually did.
 *
 * A file manager that says "done" after removing nine of twelve files has
 * lied, which is why this is a report and not a bare `void`.
 */
export interface SftpDeleteReport {
  filesRemoved: number;
  directoriesRemoved: number;
  failures: SftpDeleteFailure[];
  /** True if the user stopped it part way through. */
  cancelled: boolean;
  /** True if it stopped at the walk's own limit rather than at the end. */
  limitReached: boolean;
  /** True only when everything asked for is gone. */
  complete: boolean;
}

/** Which way a transfer moves. */
export type TransferDirection = "upload" | "download";

/**
 * A transfer to queue.
 *
 * A download names its destination one of two ways and exactly one: `local` is
 * a file path a save-as picker produced, `localDirectory` is a folder and the
 * file name is then derived by the core from the remote path. Never join a
 * server-supplied name onto a folder here — that is the one thing the command
 * surface is most emphatic must not happen.
 */
export interface TransferRequest {
  direction: TransferDirection;
  /** The remote path, `/`-separated whatever the server runs on. */
  remote: string;
  local?: string | null;
  /** Downloads only. The core derives the file name. */
  localDirectory?: string | null;
  /** Ask to continue rather than start over. Honoured only where it is safe. */
  resume?: boolean;
}

/**
 * What a transfer settled before it moved a byte.
 *
 * `note` is the core's English sentence and is **not** rendered: the interface
 * composes its own from `resumeDeclined` and `total`, the same way a failure's
 * sentence comes from the catalogue rather than from the core. It stays on the
 * DTO as the fallback for a case the interface has not learned.
 */
export interface TransferStart {
  resumeRequested: boolean;
  /** Where it began. Zero unless a resume was honoured. */
  resumeFrom: number;
  /** The source's size, where the source reported one. */
  total: number | null;
  /** True when a resume was asked for and refused. */
  resumeDeclined: boolean;
  /** Not for rendering. See above. */
  note: string | null;
}

/** Why a transfer ended badly. The shape `SessionFailure` has, minus nothing. */
export interface TransferFailure {
  code: string;
  message: string;
  detail: string | null;
  actions: string[];
  stage: SessionStage;
  retryable: boolean;
}

/**
 * Where a transfer has got to.
 *
 * `done` counts from the start of the file rather than from the start of this
 * attempt, so a resumed bar does not jump back to zero.
 */
export type TransferState =
  | { state: "queued" }
  | { state: "running"; done: number; total: number | null }
  | { state: "completed"; bytes: number }
  | ({ state: "failed" } & TransferFailure)
  | { state: "cancelled" };

/** One row of the transfer list. */
export type TransferStatus = {
  transferId: number;
  direction: TransferDirection;
  /** The remote path, raw. What goes back on the wire. */
  remote: string;
  /** The same, escaped. What a row draws. */
  remoteDisplay: string;
  /**
   * The local path as resolved when it was queued, raw — what a future
   * "reveal in folder" would address, and for that reason never drawn.
   */
  local: string;
  /**
   * The same, escaped. A download into a folder takes its file name from the
   * remote path, so this string is server-chosen too.
   */
  localDisplay: string;
  resume: boolean;
  /** What it settled before it began. `null` until it does. */
  start: TransferStart | null;
} & TransferState;

// -------------------------------------------------------------- failure ----

/**
 * A structured failure from the core.
 *
 * Every message names what failed, where, and what to do next — the failure
 * taxonomy in docs/architecture/session-pipeline.md. "Connection failed" is
 * never an acceptable string to show.
 *
 * The text is English, because the core produces it and the core is not the
 * presentation layer. `code` is what makes that survivable: it is stable,
 * documented and never shown, and `locales/<lang>/errors.json` is keyed by it.
 * Render a failure through `FailureNotice`, or through `useFailureText` from
 * `@/i18n` — never by reading `message` or `actions` straight into JSX, which
 * puts English on screen for every reader who chose another language.
 */
export interface IpcFailure {
  code: string;
  message: string;
  detail: string | null;
  /** Suggested next actions, in the order the interface should offer them. */
  actions: string[];
}

/**
 * Whatever a rejected command threw, as a failure.
 *
 * The literal below is the only user-visible English in this file, and it is
 * reached only when the rejection has no shape at all — a panic inside a
 * command, a transport failure below Tauri. It is still translated: `unknown`
 * is a code like any other in `errors.json`, so `useFailureText` renders the
 * catalogue's sentence and this one is the fallback behind it.
 */
export function asFailure(e: unknown): IpcFailure {
  if (typeof e === "object" && e !== null && "code" in e && "message" in e) {
    return e as IpcFailure;
  }
  return {
    code: "unknown",
    message: typeof e === "string" ? e : "Something went wrong.",
    detail: null,
    actions: [],
  };
}

// ------------------------------------------------------------- commands ----

export const ipc = {
  // --- vault lifecycle ---
  listRecentVaults: () => invoke<RecentVault[]>("vault_list_recent"),
  forgetRecentVault: (path: string) => invoke<void>("vault_forget_recent", { path }),
  clearRecentVaults: () => invoke<void>("vault_clear_recents"),
  probeVault: (path: string) => invoke<VaultProbe>("vault_probe", { path }),
  createVault: (req: CreateVaultRequest) => invoke<CreateVaultResult>("vault_create", { req }),
  unlockVault: (path: string, method: UnlockRequest) =>
    invoke<VaultState>("vault_unlock", { path, method }),
  lockVault: () => invoke<void>("vault_lock"),
  vaultState: () => invoke<VaultState>("vault_state"),
  /**
   * Re-derives the below-floor password slots. Returns whether anything
   * changed. The password is needed again because a slot is re-wrapped around
   * the credential, not around the key already in memory.
   */
  upgradeKdf: (method: UnlockRequest) => invoke<boolean>("vault_upgrade_kdf", { method }),

  // --- creation helpers ---
  generatePassphrase: (words: number) => invoke<string>("generate_passphrase", { words }),
  passwordStrength: (password: string) =>
    invoke<PasswordStrength>("password_strength", { password }),
  generateKeyfile: (path: string) => invoke<void>("generate_keyfile", { path }),
  suggestVaultPath: (label: string) => invoke<string>("suggest_vault_path", { label }),

  // --- tree ---
  listNodes: () => invoke<TreeNode[]>("tree_list"),
  search: (query: string) => invoke<SearchHit[]>("tree_search", { query }),
  createNode: (input: CreateNode) => invoke<TreeNode>("node_create", { input }),
  updateNode: (id: string, patch: UpdateNode) => invoke<TreeNode>("node_update", { id, patch }),
  deleteNode: (id: string) => invoke<void>("node_delete", { id }),
  moveNode: (id: string, parentId: string | null, sortOrder: number) =>
    invoke<void>("node_move", { id, parentId, sortOrder }),
  resolveNode: (id: string) => invoke<EffectiveConnection>("node_resolve", { id }),

  // --- protocol schemas ---
  /**
   * Every protocol's settings schema, as the adapters declare them.
   *
   * The shape of each setting — its type, its bounds, the values it offers by
   * name, its default and where that default came from. Fixed for the life of
   * a process, so it is worth caching and never worth invalidating after a
   * tree change.
   */
  protocolSchemas: () => invoke<ProtocolSchema[]>("protocol_schemas"),

  // --- credentials ---
  /**
   * What a candidate private key file is, without any of what is in it. Call
   * this before deciding whether to ask for a passphrase: the file is read
   * because a container cannot be identified from a name, and the bytes are
   * wiped when the command returns. The result is a format, a flag and a size.
   */
  inspectKey: (path: string) => invoke<PrivateKeyInfo>("key_inspect", { path }),

  // --- key slots ---
  vaultSlots: () => invoke<VaultSlots>("vault_slots"),
  /**
   * Adds a second password, or a password plus a key file. Re-wraps the master
   * key under a new credential; the body is not re-encrypted, which is why it
   * is instant on a vault of any size.
   */
  addPasswordSlot: (req: AddPasswordSlot) => invoke<Slot>("vault_add_password_slot", { req }),
  /**
   * Issues another recovery key, returned exactly once. A vault may hold more
   * than one: a sealed envelope in a safe is a legitimate reason to want two.
   */
  addRecoverySlot: (label: string) => invoke<RecoveryKey>("vault_add_recovery_slot", { label }),
  /**
   * Enrols this machine's credential store, so the vault opens without a prompt
   * while the user is logged in.
   */
  addKeychainSlot: (label: string) => invoke<Slot>("vault_add_keychain_slot", { label }),
  /**
   * Revokes a slot. Revocation deletes the slot entry, so a lost hardware key
   * can be revoked without having it to hand. The last slot is refused with
   * `vault.last-slot`: a vault with an empty slot table is a file nobody can
   * ever open again, and there is no escrow key and no support override.
   */
  removeSlot: (index: number) => invoke<void>("vault_remove_slot", { index }),
  /**
   * Re-wraps one slot around a new password. The master key does not change:
   * nothing is re-encrypted, every other slot keeps working, and the recovery
   * key stays valid. The current credential is verified before anything is
   * replaced.
   */
  changeMasterPassword: (req: ChangePassword) =>
    invoke<void>("vault_change_master_password", { req }),
  /**
   * Replaces a recovery slot's key. The old key stops working; the new one is
   * returned exactly once. The master key does not change.
   */
  rotateRecoveryKey: (index: number) =>
    invoke<RecoveryKey>("vault_rotate_recovery_key", { index }),
  /**
   * Re-keys the vault: a new master key, every slot re-wrapped, every secret
   * resealed.
   *
   * What it does **not** do is make a leaked copy unreadable — that file still
   * opens with the old keys, including the rolling backups beside the vault,
   * which this save rotates. Say so on the screen before the user commits.
   */
  rotateMasterKey: (req: RotateMasterKey) =>
    invoke<RotationOutcome>("vault_rotate_master_key", { req }),

  // --- per-vault settings ---
  getVaultSettings: () => invoke<VaultSettings>("vault_settings_get"),
  setVaultSettings: (patch: VaultSettingsPatch) =>
    invoke<VaultSettings>("vault_settings_set", { patch }),

  // --- audit ---
  /** One page of the audit log, newest first. */
  queryAudit: (query: AuditQuery) => invoke<AuditPage>("audit_query", { query }),
  auditFilters: () => invoke<AuditFilters>("audit_filters"),
  /**
   * Writes the filtered log to a file, and records that it was written.
   * Exporting copies entries; it never removes them.
   */
  exportAudit: (req: AuditExport) => invoke<AuditExportResult>("audit_export", { req }),

  // --- import ---
  /**
   * What a file appears to be, before anything is parsed. This is what tells
   * the wizard whether to ask for the document password, and whether the file
   * was protected with the well-known default.
   */
  detectImport: (path: string) => invoke<ImportDetection>("import_detect", { path }),
  /**
   * Parses a file into the tree it would create. `source` overrides detection
   * when the user picks the format themselves; `password` is the document
   * password, which is sent inward and never comes back.
   */
  parseImport: (path: string, password: string | null, source: ImportSource | null) =>
    invoke<ImportPreview>("import_parse", { path, password, source }),
  /**
   * Drops a preview without importing it, wiping the secrets it holds.
   * Cancelling something that is already gone is not a failure — the wizard
   * closing twice must not raise an error at the user.
   */
  cancelImport: (importId: string) => invoke<void>("import_cancel", { importId }),
  /** Writes a previewed import into the vault, in one transaction. */
  commitImport: (req: ImportCommit) => invoke<ImportResult>("import_commit", { req }),

  // --- settings ---
  getSettings: () => invoke<AppSettings>("settings_get"),
  setSettings: (patch: AppSettingsPatch) => invoke<AppSettings>("settings_set", { patch }),
  /**
   * Every keyboard binding, with its conflicts named. The conflicts are
   * computed in the core rather than left for the user to discover: a shortcut
   * that quietly does nothing because the desktop took it first reads as a
   * broken application.
   */
  listShortcuts: () => invoke<Shortcut[]>("shortcuts_list"),

  // --- update check ---
  /**
   * Asks GitHub what has been released, and records that the check ran.
   *
   * This is the only outbound request Remoter makes that is not a session the
   * user opened, and the request says one thing about this machine: which
   * build is asking, in the user-agent. No identifier, no locale, no
   * telemetry. Keep it that way — the Updates screen states this promise to
   * the user in those words.
   *
   * It reports what was published; it does not decide whether an update is
   * available. Compare with {@link pickUpdate} in
   * `features/settings/version.ts`.
   *
   * A rejection is an {@link IpcFailure} whose `code` distinguishes the cases
   * that need different answers: `update.unreachable` (no network),
   * `update.rate-limited` (GitHub is refusing for now),
   * `update.no-releases` (nothing published), `update.unreadable` and
   * `update.failed`. Show them apart — a check that fails vaguely teaches
   * people to stop believing it.
   */
  checkForUpdate: () => invoke<UpdateCheck>("update_check"),

  // --- sessions ---
  /**
   * Opens a session: resolve, authorise, acquire, transport, handshake,
   * authenticate, attach — the nine stages, end to end.
   *
   * Resolves once the far end has authenticated and a shell is open. Build
   * `channel` with {@link sessionChannel} and pass it here; it is live from
   * before the handshake, so a host key question or a 2FA prompt arrives while
   * this promise is still pending. The channel's first message carries the
   * session id, which is what an answer to such a prompt needs.
   *
   * A rejection is an {@link IpcFailure} whose `code` names the stage that
   * failed and whose `actions` are the buttons to offer.
   *
   * To cancel an attempt that is still connecting, call {@link ipc.closeSession}
   * with the id from the channel's first message: the session is registered
   * from the moment it is spawned, so a Cancel button on the connecting tab
   * works before this promise settles.
   */
  openSession: (nodeId: string, channel: Channel<SessionChannelMessage>) =>
    invoke<SessionOpened>("session_open", { nodeId, channel }),
  /**
   * Sends keystrokes, a paste or an IME commit to the remote host.
   *
   * `bytes` is a plain number array rather than a `Uint8Array` because Tauri
   * only takes a binary body when it is the *whole* payload, and this command
   * also needs the session id. Keystrokes are a few bytes; a very large paste
   * pays for the encoding.
   *
   * **Terminal sessions only.** This is `InputEvent::Bytes`, which is the byte
   * stream a PTY wants. The RDP adapter drops a `Bytes` event and the VNC
   * adapter refuses it outright, because a framebuffer protocol's input is keys
   * and a pointer: {@link sendKey} and {@link sendPointer} are the two commands
   * for that, and `features/sessions/keymap.ts` is the translation that feeds
   * them.
   */
  sendInput: (sessionId: number, bytes: Uint8Array) =>
    invoke<void>("session_input", { sessionId, bytes: Array.from(bytes) }),
  /**
   * Sends one key transition to a graphical session.
   *
   * **Both halves travel, because neither can be derived from the other.** RDP
   * carries a PS/2 Set 1 make code and lets the server apply the keyboard
   * layout (MS-RDPBCGR §2.2.8.1.1.3.1.1.1); VNC carries an X11 keysym with the
   * layout already applied by the client (RFC 6143 §7.5.4). The layout exists
   * only in this WebView, so this side produces both and each adapter takes the
   * one it needs.
   *
   * Build the arguments with `keyInputFrom` in `features/sessions/keymap.ts`
   * rather than from a `KeyboardEvent` here: `event.keyCode` is neither a
   * scancode nor a keysym, and a client that treats it as one types correctly
   * on a US keyboard and wrongly on a Turkish, German or AZERTY one.
   *
   * `keysym` is null for a key that produced no character — a bare modifier, a
   * function key, a dead key mid-composition — and that event is still worth
   * sending. `modifiers` is the bit set `remoter_proto::Modifiers` defines, the
   * three lock states included: RDP synchronises latches explicitly, and a
   * session that never says "Caps Lock is on" types in capitals until someone
   * works out why.
   *
   * Subject to the input freeze, and rejected with `session.frozen` while the
   * vault is locked under that policy — exactly as {@link sendInput} is.
   */
  sendKey: (
    sessionId: number,
    key: { scancode: number; keysym: number | null; modifiers: number; pressed: boolean },
  ) =>
    invoke<void>("session_key", {
      sessionId,
      scancode: key.scancode,
      keysym: key.keysym,
      modifiers: key.modifiers,
      pressed: key.pressed,
    }),
  /**
   * Sends one pointer state to a graphical session.
   *
   * A full state rather than a transition: `buttons` is which buttons are down
   * *now*, which is what both protocols put on the wire. Back and forward are
   * in the set; the VNC adapter drops them because RFB has nowhere to put them,
   * and the RDP adapter sends them as `PTRXFLAGS_BUTTON1` and `2`.
   *
   * `x` and `y` are **remote display coordinates**, not canvas ones — the tab's
   * scale and the device pixel ratio already divided out. `remotePoint` in
   * `features/sessions/scaling.ts` is that division, and it belongs on this
   * side because only this side knows what it drew.
   *
   * Both wheel axes are carried, in notches of 120. A horizontal wheel is a
   * different axis, not a different sign.
   *
   * Subject to the input freeze, for the reason a keyboard is: a pointer at an
   * unattended machine can close a window and click Confirm.
   */
  sendPointer: (
    sessionId: number,
    pointer: { x: number; y: number; buttons: number; wheel: number; wheelX: number },
  ) =>
    invoke<void>("session_pointer", {
      sessionId,
      x: pointer.x,
      y: pointer.y,
      buttons: pointer.buttons,
      wheel: pointer.wheel,
      wheelX: pointer.wheelX,
    }),
  /**
   * Tells the far end the tab changed size.
   *
   * **The unit depends on the session's kind, and the parameter names are the
   * terminal's.** For a `terminal` session these are character cells. For a
   * `framebuffer` session they are *pixels*, and this is "smart resize" in
   * `docs/architecture/rendering.md`: the core turns it into MS-RDPEDISP for
   * RDP and `SetDesktopSize` for VNC, which change the remote desktop itself
   * rather than scaling a picture of it. Ask for physical pixels, not logical
   * ones, so text on a HiDPI display is rendered sharp remotely instead of
   * upscaled here.
   *
   * A server may refuse: `capabilities.resizable` says whether the channel that
   * performs it is open, and an adapter that has to refuse raises a warning
   * rather than failing the session. Do not offer a resize control on a session
   * whose capabilities say it cannot be resized.
   *
   * Not subject to the input freeze. A window resized while the vault is locked
   * still has to redraw at the right size.
   */
  resizeSession: (sessionId: number, cols: number, rows: number) =>
    invoke<void>("session_resize", { sessionId, cols, rows }),
  /**
   * Closes a session and waits for it to release everything: sockets closed,
   * buffers dropped, cached secrets zeroized. A session that overruns its grace
   * period is stopped by force and that is reported, not swallowed — a
   * lingering task is a lingering exposure, because the process holds
   * credentials.
   */
  closeSession: (sessionId: number) => invoke<void>("session_close", { sessionId }),
  /** Every open session, oldest first. */
  listSessions: () => invoke<SessionSummary[]>("session_list"),
  /**
   * Answers a suspended host key handshake.
   *
   * `accept` is refused on a `"changed"` prompt and rejected with
   * `session.host-key-changed`: a key that contradicts the trusted one is a
   * possible man-in-the-middle, and the only way past it is `replace` with the
   * tail of the offered fingerprint typed off the screen. Never wire an
   * "accept" button to a changed-key dialog.
   */
  decideHostKey: (sessionId: number, decision: HostKeyDecision) =>
    invoke<void>("host_key_decide", { sessionId, decision }),

  // --- tunnels ---
  /**
   * Opens a port forward on a connection of its own — no shell, no tab.
   *
   * Because it has no tab it cannot ask about an unknown host key: open a
   * session to the node once, accept the key there, and the tunnel will use
   * the decision stored in the vault.
   */
  openTunnel: (nodeId: string, spec: TunnelSpec) =>
    invoke<Tunnel>("tunnel_open", { nodeId, spec }),
  /** Closes a forward and the connection opened for it. */
  closeTunnel: (tunnelId: number) => invoke<void>("tunnel_close", { tunnelId }),
  /** Every running forward, with its live counters. */
  listTunnels: () => invoke<Tunnel[]>("tunnel_list"),

  // --- sftp: browsing ---
  /**
   * Attaches a file pane to a session that has already authenticated.
   *
   * One more channel on the connection the tab is using (RFC 4254 6.5) — no
   * handshake, no host key check, no second authentication. Which is why it
   * takes a session and not a node.
   */
  openPane: (sessionId: number) => invoke<SftpPane>("sftp_open", { sessionId }),
  /**
   * Closes a pane and waits for it to let go.
   *
   * Returns only once the drain task has finished, so "the pane is closed" and
   * "nothing is still writing to disk" are the same moment. Always call it —
   * a pane left open holds a channel and a file handle on the user's link.
   */
  closePane: (paneId: number) => invoke<void>("sftp_close", { paneId }),
  /**
   * Lists a directory. Cancels whatever this pane was listing before.
   *
   * A rejection may name a listing cap (250 000 entries, 32 MiB) rather than a
   * permission problem. Show which limit was hit; an empty pane is a lie.
   */
  listDirectory: (paneId: number, path: string) =>
    invoke<DirectoryEntry[]>("sftp_list", { paneId, path }),
  /** One entry's metadata, following symbolic links. */
  statPath: (paneId: number, path: string) =>
    invoke<DirectoryEntry>("sftp_stat", { paneId, path }),
  /** Resolves a path to the absolute one the server means by it. */
  canonicalizePath: (paneId: number, path: string) =>
    invoke<string>("sftp_canonicalize", { paneId, path }),
  /** Reads where a symbolic link points, without following it. */
  readLink: (paneId: number, path: string) =>
    invoke<string>("sftp_read_link", { paneId, path }),
  /** Creates a directory. */
  makeDirectory: (paneId: number, path: string) =>
    invoke<void>("sftp_mkdir", { paneId, path }),
  /**
   * Renames or moves an entry.
   *
   * `SSH_FXP_RENAME` fails across filesystems on most servers, and the core
   * says so by name rather than reporting a permission problem the user does
   * not have.
   */
  renamePath: (paneId: number, from: string, to: string) =>
    invoke<void>("sftp_rename", { paneId, from, to }),
  /**
   * Removes an entry, or a whole tree.
   *
   * The walk does not follow symbolic links — a link to a directory is
   * unlinked, not descended. It reports what it managed rather than returning
   * nothing, because an interrupted walk leaves the tree half-removed.
   */
  deletePath: (paneId: number, path: string, recursive: boolean) =>
    invoke<SftpDeleteReport>("sftp_delete", { paneId, path, recursive }),
  /** Changes an entry's POSIX mode bits. At most `0o7777`. */
  setPermissions: (paneId: number, path: string, mode: number) =>
    invoke<void>("sftp_set_permissions", { paneId, path, mode }),
  /** Creates a symbolic link at `path` pointing at `target`. */
  createSymlink: (paneId: number, path: string, target: string) =>
    invoke<void>("sftp_symlink", { paneId, path, target }),

  // --- sftp: transfers ---
  /**
   * Queues transfers, returning the new ids in the order given.
   *
   * The batch is resolved before any of it is queued: forty requests with one
   * bad path refuse as a batch rather than starting twenty and then
   * complaining. Nothing here waits for a byte to move.
   */
  enqueueTransfers: (paneId: number, requests: TransferRequest[]) =>
    invoke<number[]>("sftp_enqueue", { paneId, requests }),
  /**
   * Every transfer this pane knows about, in the order they were queued.
   *
   * For the first paint and for reconciliation after a tab switch.
   */
  listTransfers: (paneId: number) => invoke<TransferStatus[]>("sftp_transfers", { paneId }),
  /**
   * Stops one transfer. What has already been written stays on disk, which is
   * what makes a later resume possible.
   */
  cancelTransfer: (paneId: number, transferId: number) =>
    invoke<void>("sftp_transfer_cancel", { paneId, transferId }),
  /** Stops every transfer on this pane. */
  cancelAllTransfers: (paneId: number) => invoke<void>("sftp_transfer_cancel_all", { paneId }),
  /**
   * Queues a fresh transfer from a finished one's request, returning the new id.
   *
   * It does not resurrect the old entry: a terminal state stays terminal, so
   * the history of what happened stays readable.
   */
  retryTransfer: (paneId: number, transferId: number) =>
    invoke<number>("sftp_transfer_retry", { paneId, transferId }),
} as const;
