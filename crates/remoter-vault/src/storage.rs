//! The SQLite database inside the encrypted body.
//!
//! The whole database lives in memory while the vault is unlocked and is
//! serialised and re-encrypted as one unit on every save. That trade-off is
//! argued in `docs/architecture/storage.md`; the short version is that vaults
//! are measured in megabytes, saves are user-initiated, and the alternative —
//! page-level encryption — adds a C crypto dependency and leaks structure
//! through page access patterns.
//!
//! Secret fields are still ciphertext in here. Decrypting the body gets you a
//! database, not a pile of passwords: each secret is sealed under the SEK with
//! associated data binding it to its record, its field name and that record's
//! revision, so at any moment only the handful of secrets actually in use exist
//! as plaintext.

use std::collections::BTreeSet;

use rusqlite::types::Value;
use rusqlite::{Connection, MAIN_DB, OptionalExtension, params, params_from_iter};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::audit::{AuditCategory, AuditQuery, AuditRecord};
use crate::crypto::{self, KEY_LEN, NONCE_LEN};
use crate::error::VaultError;
use crate::secret::{ExposeSecret, Secret};

/// The schema version this build writes and understands.
pub const SCHEMA_VERSION: u32 = 2;

/// AEAD algorithm identifier stored beside each secret, so the field can be
/// re-keyed to a different cipher later without guessing.
const ALG_XCHACHA20POLY1305: i64 = 1;

/// Separator between the parts of a secret field's associated data.
/// ASCII unit separator: it cannot occur in a field name and needs no escaping.
const AAD_SEPARATOR: u8 = 0x1F;

/// Forward-only, numbered, embedded in the binary, applied in one transaction.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/001_initial.sql")),
    (
        2,
        include_str!("../migrations/002_trust_store_null_node.sql"),
    ),
];

/// What happened, for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEvent {
    /// A vault file was created.
    VaultCreated,
    /// A vault was opened.
    VaultUnlocked,
    /// An unlock attempt failed.
    VaultUnlockFailed,
    /// A vault was locked and its keys wiped.
    VaultLocked,
    /// A vault was written to disk.
    VaultSaved,
    /// A schema migration was applied.
    VaultMigrated,
    /// A key slot was added.
    SlotAdded,
    /// A key slot was revoked.
    SlotRemoved,
    /// A recovery key was issued or rotated.
    RecoveryKeyIssued,
    /// A password slot was re-wrapped under a new password or key file.
    PasswordChanged,
    /// The vault master key was replaced: every slot re-wrapped, every secret
    /// re-sealed, the body re-encrypted.
    MasterKeyRotated,
    /// A password slot's Argon2id parameters were raised to the current floor.
    KdfUpgraded,
    /// A node was created.
    NodeCreated,
    /// A node was changed.
    NodeUpdated,
    /// A node was tombstoned.
    NodeDeleted,
    /// A node was reparented or reordered.
    NodeMoved,
    /// A secret field was written.
    SecretStored,
    /// A secret field was deleted.
    SecretRemoved,
    /// A secret was borrowed to open a connection.
    SecretUsed,
    /// A secret was shown to the user on screen.
    SecretRevealed,
    /// A secret was written to an export.
    SecretExported,
    /// A host key or certificate was pinned.
    TrustPinned,
    /// A host key or certificate was refused.
    TrustRejected,
    /// A session was opened.
    SessionStarted,
    /// A session ended.
    SessionEnded,
    /// An application setting changed.
    SettingChanged,
}

impl AuditEvent {
    /// Every event this build writes or recognises.
    ///
    /// Exhaustive by construction: the round-trip test walks it, so an event
    /// added to the enum without being added here fails the suite rather than
    /// quietly dropping out of the audit screen's filters.
    pub const ALL: &'static [Self] = &[
        Self::VaultCreated,
        Self::VaultUnlocked,
        Self::VaultUnlockFailed,
        Self::VaultLocked,
        Self::VaultSaved,
        Self::VaultMigrated,
        Self::SlotAdded,
        Self::SlotRemoved,
        Self::RecoveryKeyIssued,
        Self::PasswordChanged,
        Self::MasterKeyRotated,
        Self::KdfUpgraded,
        Self::NodeCreated,
        Self::NodeUpdated,
        Self::NodeDeleted,
        Self::NodeMoved,
        Self::SecretStored,
        Self::SecretRemoved,
        Self::SecretUsed,
        Self::SecretRevealed,
        Self::SecretExported,
        Self::TrustPinned,
        Self::TrustRejected,
        Self::SessionStarted,
        Self::SessionEnded,
        Self::SettingChanged,
    ];

    /// Which filter chip on the audit screen this event belongs to.
    ///
    /// Never [`AuditCategory::Warning`]: that one is decided by the outcome as
    /// well as by the event, so it cuts across these rather than partitioning
    /// them.
    #[must_use]
    pub const fn category(self) -> AuditCategory {
        match self {
            Self::VaultCreated
            | Self::VaultUnlocked
            | Self::VaultUnlockFailed
            | Self::VaultLocked
            | Self::VaultSaved
            | Self::VaultMigrated
            | Self::SlotAdded
            | Self::SlotRemoved
            | Self::RecoveryKeyIssued
            | Self::PasswordChanged
            | Self::MasterKeyRotated
            | Self::KdfUpgraded
            | Self::SettingChanged => AuditCategory::Vault,

            Self::NodeCreated | Self::NodeUpdated | Self::NodeDeleted | Self::NodeMoved => {
                AuditCategory::Node
            }

            Self::SecretStored
            | Self::SecretRemoved
            | Self::SecretUsed
            | Self::SecretRevealed
            | Self::SecretExported => AuditCategory::Secret,

            Self::TrustPinned | Self::TrustRejected | Self::SessionStarted | Self::SessionEnded => {
                AuditCategory::Connection
            }
        }
    }

    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::VaultCreated => "vault_created",
            Self::VaultUnlocked => "vault_unlocked",
            Self::VaultUnlockFailed => "vault_unlock_failed",
            Self::VaultLocked => "vault_locked",
            Self::VaultSaved => "vault_saved",
            Self::VaultMigrated => "vault_migrated",
            Self::SlotAdded => "slot_added",
            Self::SlotRemoved => "slot_removed",
            Self::RecoveryKeyIssued => "recovery_key_issued",
            Self::PasswordChanged => "password_changed",
            Self::MasterKeyRotated => "master_key_rotated",
            Self::KdfUpgraded => "kdf_upgraded",
            Self::NodeCreated => "node_created",
            Self::NodeUpdated => "node_updated",
            Self::NodeDeleted => "node_deleted",
            Self::NodeMoved => "node_moved",
            Self::SecretStored => "secret_stored",
            Self::SecretRemoved => "secret_removed",
            Self::SecretUsed => "secret_used",
            Self::SecretRevealed => "secret_revealed",
            Self::SecretExported => "secret_exported",
            Self::TrustPinned => "trust_pinned",
            Self::TrustRejected => "trust_rejected",
            Self::SessionStarted => "session_started",
            Self::SessionEnded => "session_ended",
            Self::SettingChanged => "setting_changed",
        }
    }

    /// Reads back a stored spelling. `None` for an event written by a newer
    /// build, which is preserved in the log and simply not classified here.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|e| e.as_str() == text)
    }
}

/// How an audited action ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// It worked.
    Success,
    /// It was attempted and failed.
    Failure,
    /// It was refused by a policy check.
    Denied,
}

impl AuditOutcome {
    /// The stored spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }

    /// Reads back a stored spelling.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "success" => Some(Self::Success),
            "failure" => Some(Self::Failure),
            "denied" => Some(Self::Denied),
            _ => None,
        }
    }
}

/// One audit row as it is read back: the timestamp in milliseconds since the
/// Unix epoch, the event, the outcome, and the plain-text detail.
///
/// A tuple rather than a struct because a struct would have to be nameable by
/// callers, and the crate root's export list is the crate's public surface.
pub(crate) type AuditEntry = (i64, String, String, Option<String>);

/// One row of the `nodes` table, plus the pieces that live beside it.
///
/// This is the crate's internal shape. Mapping it to and from
/// `remoter_core::Node` happens in `vault.rs`, which keeps the SQL in one place
/// and the domain model in another.
#[derive(Debug, Clone)]
pub(crate) struct NodeRow {
    pub(crate) id: Uuid,
    pub(crate) parent_id: Option<Uuid>,
    pub(crate) sort_order: i64,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) icon: Option<String>,
    pub(crate) colour: Option<String>,
    /// CBOR of the kind-specific properties.
    pub(crate) props: Vec<u8>,
    /// CBOR map of user and plugin data, preserved verbatim.
    pub(crate) custom_fields: Vec<u8>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) revision: i64,
    pub(crate) deleted_at: Option<i64>,
    pub(crate) tags: Vec<String>,
    /// The connection's host, for the search index only. Not a column on
    /// `nodes`: it lives inside `props`, and is lifted out here so the index
    /// does not have to decode CBOR.
    pub(crate) search_host: Option<String>,
}

/// One row of `secrets`, as stored.
#[derive(Debug, Clone)]
pub(crate) struct SecretRow {
    pub(crate) node_id: Uuid,
    pub(crate) field: String,
    pub(crate) alg: i64,
    pub(crate) nonce: Vec<u8>,
    pub(crate) ciphertext: Vec<u8>,
    pub(crate) revision: i64,
    #[allow(dead_code, reason = "read back for diagnostics and future sync merge")]
    pub(crate) updated_at: i64,
}

/// The associated data that binds a secret to its record, field and revision.
///
/// `record_uuid ‖ 0x1F ‖ field_name ‖ 0x1F ‖ record_revision`, with the UUID as
/// its 16 raw bytes and the revision as a little-endian `i64`. Both widths are
/// fixed, so the separators are for readability in a hex dump rather than for
/// disambiguation.
pub(crate) fn secret_aad(node: Uuid, field: &str, revision: i64) -> Vec<u8> {
    let field = field.as_bytes();
    let mut aad = Vec::with_capacity(16 + 1 + field.len() + 1 + 8);
    aad.extend_from_slice(node.as_bytes());
    aad.push(AAD_SEPARATOR);
    aad.extend_from_slice(field);
    aad.push(AAD_SEPARATOR);
    aad.extend_from_slice(&revision.to_le_bytes());
    aad
}

/// The in-memory database.
pub(crate) struct Store {
    conn: Connection,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Store(<in-memory sqlite>)")
    }
}

impl Store {
    /// A fresh database with the current schema.
    ///
    /// The schema is built in a throwaway connection and then handed to
    /// [`Store::load`], which is not a detour. `sqlite3_serialize` returns a
    /// pointer into the live pages — no copy, nothing to free — only for a
    /// connection that was populated by `sqlite3_deserialize`; on an ordinary
    /// `:memory:` connection it mallocs a fresh image, and rusqlite frees that
    /// image through `sqlite3_free`, which does not wipe. Every save on such a
    /// connection would therefore leave a full plaintext copy of the connection
    /// inventory in freed heap. Going through `load` once, while the database
    /// holds nothing but an empty schema, means the only image ever freed
    /// unwiped contains no user data.
    pub(crate) fn create_new(now: i64) -> Result<Self, VaultError> {
        let conn = Connection::open_in_memory()?;
        let mut seed = Self { conn };
        seed.apply_pragmas()?;
        seed.migrate(now)?;

        let image = seed.serialize()?;
        drop(seed);
        Self::load(&image, now)
    }

    /// Loads a serialised database image.
    pub(crate) fn load(bytes: &[u8], now: i64) -> Result<Self, VaultError> {
        if bytes.is_empty() {
            return Err(VaultError::NotADatabase);
        }
        let mut conn = Connection::open_in_memory()?;
        conn.deserialize_read_exact(MAIN_DB, &mut &bytes[..], bytes.len(), false)
            .map_err(|_| VaultError::NotADatabase)?;

        // `sqlite3_deserialize` accepts the pointer without inspecting it; the
        // first real query is where a non-database shows up. Ask a cheap one so
        // the failure surfaces here rather than three calls later.
        conn.query_row("SELECT count(*) FROM sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })
        .map_err(|_| VaultError::NotADatabase)?;

        let mut store = Self { conn };
        store.apply_pragmas()?;
        store.migrate(now)?;
        Ok(store)
    }

    fn apply_pragmas(&self) -> Result<(), VaultError> {
        // Referential integrity is off by default in SQLite and the schema
        // leans on it: tombstoned nodes rely on ON DELETE RESTRICT to stop a
        // folder vanishing out from under its children.
        self.conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA trusted_schema = OFF;",
        )?;
        Ok(())
    }

    /// Serialises the database to bytes for encryption.
    ///
    /// The returned buffer is the only plaintext copy this makes, and it is
    /// wiped when it drops. See [`Store::create_new`] for why the connection is
    /// arranged so that SQLite hands back a borrowed view of its own pages here
    /// rather than a freshly allocated image it will later free unwiped.
    pub(crate) fn serialize(&self) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let data = self.conn.serialize(MAIN_DB)?;
        Ok(Zeroizing::new(data.to_vec()))
    }

    /// Whether `sqlite3_serialize` borrows this connection's pages rather than
    /// allocating a copy it will free unwiped. Only the regression test for
    /// [`Store::create_new`] uses it.
    #[cfg(test)]
    pub(crate) fn serialize_borrows_pages(&self) -> Result<bool, VaultError> {
        Ok(matches!(
            self.conn.serialize(MAIN_DB)?,
            rusqlite::serialize::Data::Shared(_)
        ))
    }

    /// The schema version currently in the database, or 0 for an empty one.
    pub(crate) fn schema_version(&self) -> Result<u32, VaultError> {
        let has_table: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if has_table.is_none() {
            return Ok(0);
        }
        let version: Option<i64> = self
            .conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                row.get(0)
            })
            .optional()?
            .flatten();
        let version = version.unwrap_or(0);
        u32::try_from(version).map_err(|_| VaultError::CorruptRow("schema_version.version"))
    }

    /// Applies every migration this build has that the database does not.
    ///
    /// Each one runs in its own transaction, so a failure leaves the database
    /// at the last version that applied cleanly rather than half-migrated.
    pub(crate) fn migrate(&mut self, now: i64) -> Result<(), VaultError> {
        let current = self.schema_version()?;
        if current > SCHEMA_VERSION {
            return Err(VaultError::SchemaTooNew {
                found: current,
                supported: SCHEMA_VERSION,
            });
        }

        for (version, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            let tx = self.conn.transaction()?;
            tx.execute_batch(sql)
                .map_err(|_| VaultError::Migration(*version))?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![*version, now],
            )
            .map_err(|_| VaultError::Migration(*version))?;
            tx.commit().map_err(|_| VaultError::Migration(*version))?;
        }
        Ok(())
    }

    // ------------------------------------------------------------- nodes ---

    /// Inserts a node, its tags and its search index entry.
    pub(crate) fn insert_node(&self, row: &NodeRow) -> Result<(), VaultError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO nodes
               (id, parent_id, sort_order, kind, name, description, icon, colour,
                props, custom_fields, created_at, updated_at, revision, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                row.id,
                row.parent_id,
                row.sort_order,
                row.kind,
                row.name,
                row.description,
                row.icon,
                row.colour,
                row.props,
                row.custom_fields,
                row.created_at,
                row.updated_at,
                row.revision,
                row.deleted_at,
            ],
        )?;
        write_tags(&tx, row)?;
        write_index(&tx, row)?;
        tx.commit()?;
        Ok(())
    }

    /// Replaces a node's mutable columns, tags and index entry.
    ///
    /// Does not touch `revision`: bumping it re-keys every secret on the node,
    /// so it is a separate, deliberate step — see [`Store::bump_revision`].
    pub(crate) fn update_node(&self, row: &NodeRow) -> Result<(), VaultError> {
        let tx = self.conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE nodes SET
                parent_id = ?2, sort_order = ?3, kind = ?4, name = ?5,
                description = ?6, icon = ?7, colour = ?8, props = ?9,
                custom_fields = ?10, updated_at = ?11, deleted_at = ?12
             WHERE id = ?1",
            params![
                row.id,
                row.parent_id,
                row.sort_order,
                row.kind,
                row.name,
                row.description,
                row.icon,
                row.colour,
                row.props,
                row.custom_fields,
                row.updated_at,
                row.deleted_at,
            ],
        )?;
        if changed == 0 {
            return Err(VaultError::NoSuchNode(row.id));
        }
        tx.execute("DELETE FROM tags WHERE node_id = ?1", params![row.id])?;
        write_tags(&tx, row)?;
        write_index(&tx, row)?;
        tx.commit()?;
        Ok(())
    }

    /// Re-seals every secret on a node from one revision to another and moves
    /// the node's `revision` column with them.
    ///
    /// The revision is bound into the associated data of every secret field, so
    /// the two must move together or the secrets stop opening. Doing it in one
    /// transaction is what keeps a failure here from leaving a node whose
    /// secrets no longer decrypt.
    pub(crate) fn set_revision(
        &self,
        sek: &[u8; KEY_LEN],
        node: Uuid,
        from: i64,
        to: i64,
        now: i64,
    ) -> Result<(), VaultError> {
        if from == to {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;

        // Collected before the update loop so the read statement is finalised
        // before the same transaction starts writing to the table it scanned.
        let rows: Vec<SecretRow> = {
            let mut stmt = tx.prepare(
                "SELECT node_id, field, alg, nonce, ciphertext, revision, updated_at
                 FROM secrets WHERE node_id = ?1",
            )?;
            stmt.query_map(params![node], read_secret_row)?
                .collect::<Result<Vec<_>, _>>()?
        };

        for row in rows {
            let plaintext = open_secret(sek, &row, from)?;
            let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
            let ciphertext =
                crypto::seal(sek, &nonce, &plaintext, &secret_aad(node, &row.field, to))?;
            tx.execute(
                "UPDATE secrets SET nonce = ?3, ciphertext = ?4, revision = ?5, updated_at = ?6
                 WHERE node_id = ?1 AND field = ?2",
                params![node, row.field, nonce.to_vec(), ciphertext, to, now],
            )?;
        }

        let changed = tx.execute(
            "UPDATE nodes SET revision = ?2, updated_at = ?3 WHERE id = ?1",
            params![node, to, now],
        )?;
        if changed == 0 {
            return Err(VaultError::NoSuchNode(node));
        }
        tx.commit()?;
        Ok(())
    }

    /// The revision currently recorded for a node.
    pub(crate) fn revision_of(&self, node: Uuid) -> Result<i64, VaultError> {
        self.conn
            .query_row(
                "SELECT revision FROM nodes WHERE id = ?1",
                params![node],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NoSuchNode(node))
    }

    /// Every live node, oldest first — which for UUIDv7 is creation order.
    pub(crate) fn live_nodes(&self) -> Result<Vec<NodeRow>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, parent_id, sort_order, kind, name, description, icon, colour,
                    props, custom_fields, created_at, updated_at, revision, deleted_at
             FROM nodes WHERE deleted_at IS NULL ORDER BY sort_order, id",
        )?;
        let mut rows: Vec<NodeRow> = stmt
            .query_map([], read_node_row)?
            .collect::<Result<Vec<_>, _>>()?;

        for row in &mut rows {
            row.tags = self.tags_of(row.id)?;
        }
        Ok(rows)
    }

    /// One node, live or tombstoned.
    pub(crate) fn node(&self, id: Uuid) -> Result<Option<NodeRow>, VaultError> {
        let row = self
            .conn
            .query_row(
                "SELECT id, parent_id, sort_order, kind, name, description, icon, colour,
                        props, custom_fields, created_at, updated_at, revision, deleted_at
                 FROM nodes WHERE id = ?1",
                params![id],
                read_node_row,
            )
            .optional()?;

        match row {
            Some(mut row) => {
                row.tags = self.tags_of(row.id)?;
                Ok(Some(row))
            }
            None => Ok(None),
        }
    }

    fn tags_of(&self, node: Uuid) -> Result<Vec<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT tag FROM tags WHERE node_id = ?1 ORDER BY tag")?;
        let tags = stmt
            .query_map(params![node], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(tags)
    }

    /// Counts live nodes of one kind, for the interface's summary line.
    pub(crate) fn count_kind(&self, kind: &str) -> Result<usize, VaultError> {
        let count: i64 = self.conn.query_row(
            "SELECT count(*) FROM nodes WHERE kind = ?1 AND deleted_at IS NULL",
            params![kind],
            |row| row.get(0),
        )?;
        usize::try_from(count).map_err(|_| VaultError::CorruptRow("nodes count"))
    }

    /// Full-text search over the non-secret fields, best match first.
    pub(crate) fn search(&self, query: &str, limit: usize) -> Result<Vec<Uuid>, VaultError> {
        let Some(match_expression) = fts_query(query) else {
            return Ok(Vec::new());
        };
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);

        let mut stmt = self.conn.prepare(
            "SELECT node_id FROM nodes_fts WHERE nodes_fts MATCH ?1
             ORDER BY rank LIMIT ?2",
        )?;
        let texts = stmt
            .query_map(params![match_expression, limit], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        texts
            .iter()
            .map(|t| Uuid::parse_str(t).map_err(|_| VaultError::CorruptRow("nodes_fts.node_id")))
            .collect()
    }

    // ----------------------------------------------------------- secrets ---

    /// Seals a secret field under the SEK and stores it.
    pub(crate) fn put_secret(
        &self,
        sek: &[u8; KEY_LEN],
        node: Uuid,
        field: &str,
        value: &Secret<Vec<u8>>,
        now: i64,
    ) -> Result<(), VaultError> {
        let revision: i64 = self
            .conn
            .query_row(
                "SELECT revision FROM nodes WHERE id = ?1",
                params![node],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NoSuchNode(node))?;

        let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
        let ciphertext = crypto::seal(
            sek,
            &nonce,
            value.expose_secret(),
            &secret_aad(node, field, revision),
        )?;

        self.conn.execute(
            "INSERT INTO secrets (node_id, field, alg, nonce, ciphertext, revision, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(node_id, field) DO UPDATE SET
                alg = excluded.alg, nonce = excluded.nonce,
                ciphertext = excluded.ciphertext, revision = excluded.revision,
                updated_at = excluded.updated_at",
            params![
                node,
                field,
                ALG_XCHACHA20POLY1305,
                nonce.to_vec(),
                ciphertext,
                revision,
                now
            ],
        )?;
        Ok(())
    }

    /// Opens one secret field.
    ///
    /// Fails rather than guessing if the stored revision has drifted from the
    /// record's: that combination means either an interrupted write or a
    /// deliberate rollback, and neither should silently produce a password.
    pub(crate) fn get_secret(
        &self,
        sek: &[u8; KEY_LEN],
        node: Uuid,
        field: &str,
    ) -> Result<Secret<Vec<u8>>, VaultError> {
        let node_revision: i64 = self
            .conn
            .query_row(
                "SELECT revision FROM nodes WHERE id = ?1",
                params![node],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(VaultError::NoSuchNode(node))?;

        let row = self
            .conn
            .query_row(
                "SELECT node_id, field, alg, nonce, ciphertext, revision, updated_at
                 FROM secrets WHERE node_id = ?1 AND field = ?2",
                params![node, field],
                read_secret_row,
            )
            .optional()?
            .ok_or_else(|| VaultError::NoSuchSecret {
                node,
                field: field.to_owned(),
            })?;

        if row.revision != node_revision {
            return Err(VaultError::StaleSecret);
        }

        let plaintext = open_secret(sek, &row, node_revision)?;
        Ok(Secret::new(plaintext.to_vec()))
    }

    /// The stored ciphertext for one field, without decrypting it.
    ///
    /// Ciphertext is not secret, and the domain model carries it inline: a
    /// `SecretKind` holds the sealed envelope this crate produced. Handing it
    /// back unopened is how the two representations stay in step without a
    /// second copy of the plaintext existing anywhere.
    pub(crate) fn raw_secret(
        &self,
        node: Uuid,
        field: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let found = self
            .conn
            .query_row(
                "SELECT ciphertext FROM secrets WHERE node_id = ?1 AND field = ?2",
                params![node, field],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(found)
    }

    /// Whether a secret field exists, without decrypting it.
    pub(crate) fn has_secret(&self, node: Uuid, field: &str) -> Result<bool, VaultError> {
        let found: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM secrets WHERE node_id = ?1 AND field = ?2",
                params![node, field],
                |row| row.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The field names a node has secrets for.
    pub(crate) fn secret_fields(&self, node: Uuid) -> Result<Vec<String>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT field FROM secrets WHERE node_id = ?1 ORDER BY field")?;
        let fields = stmt
            .query_map(params![node], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(fields)
    }

    /// Re-seals every stored secret from one field key to another, and reports
    /// how many it moved.
    ///
    /// Part of a master key rotation: the SEK is derived from the VMK, so a new
    /// VMK makes every existing ciphertext unopenable unless it is re-sealed.
    /// One transaction, because a half-re-sealed `secrets` table is a vault
    /// whose credentials have silently become unreadable.
    ///
    /// Only the field key changes. The associated data — record, field name,
    /// revision — is rebuilt identically, so nothing about which ciphertext
    /// belongs where moves.
    pub(crate) fn reseal_secrets(
        &self,
        from: &[u8; KEY_LEN],
        to: &[u8; KEY_LEN],
        now: i64,
    ) -> Result<usize, VaultError> {
        let tx = self.conn.unchecked_transaction()?;

        // Read to completion before writing: the statement scans the table the
        // loop then updates.
        let rows: Vec<SecretRow> = {
            let mut stmt = tx.prepare(
                "SELECT node_id, field, alg, nonce, ciphertext, revision, updated_at
                 FROM secrets",
            )?;
            stmt.query_map([], read_secret_row)?
                .collect::<Result<Vec<_>, _>>()?
        };

        let moved = rows.len();
        for row in rows {
            let plaintext = open_secret(from, &row, row.revision)?;
            let nonce: [u8; NONCE_LEN] = crypto::random_array()?;
            let ciphertext = crypto::seal(
                to,
                &nonce,
                &plaintext,
                &secret_aad(row.node_id, &row.field, row.revision),
            )?;
            tx.execute(
                "UPDATE secrets SET nonce = ?3, ciphertext = ?4, updated_at = ?5
                 WHERE node_id = ?1 AND field = ?2",
                params![row.node_id, row.field, nonce.to_vec(), ciphertext, now],
            )?;
        }

        tx.commit()?;
        Ok(moved)
    }

    /// Removes a secret field.
    pub(crate) fn delete_secret(&self, node: Uuid, field: &str) -> Result<(), VaultError> {
        self.conn.execute(
            "DELETE FROM secrets WHERE node_id = ?1 AND field = ?2",
            params![node, field],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------- audit ---

    /// Appends to the audit log.
    ///
    /// `detail` is CBOR-encoded plain text. It is written by callers inside
    /// this workspace and must never carry a secret; the audit log is exported
    /// wholesale by the compliance features.
    pub(crate) fn audit(
        &self,
        at: i64,
        event: AuditEvent,
        outcome: AuditOutcome,
        node: Option<Uuid>,
        session: Option<Uuid>,
        detail: Option<&str>,
    ) -> Result<(), VaultError> {
        self.audit_row(at, event, outcome, node, session, detail)
            .map(|_| ())
    }

    /// The same, returning the row it wrote so the caller can correct its
    /// outcome later.
    ///
    /// Only the save path needs this: the row describing a save has to be
    /// inside the image the save produces, which means writing it before the
    /// write is known to have worked. See [`Store::set_audit_outcome`].
    pub(crate) fn audit_row(
        &self,
        at: i64,
        event: AuditEvent,
        outcome: AuditOutcome,
        node: Option<Uuid>,
        session: Option<Uuid>,
        detail: Option<&str>,
    ) -> Result<i64, VaultError> {
        let detail = match detail {
            Some(text) => {
                let mut out = Vec::new();
                ciborium::into_writer(&text, &mut out).map_err(|_| VaultError::HeaderEncode)?;
                Some(out)
            }
            None => None,
        };

        self.conn.execute(
            "INSERT INTO audit_log (at, event, node_id, session_id, outcome, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![at, event.as_str(), node, session, outcome.as_str(), detail],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Corrects one audit row's outcome.
    ///
    /// The log must not assert something that did not happen. A row written
    /// optimistically before an operation — because the record has to be part
    /// of what the operation writes — is corrected through here when the
    /// operation fails.
    pub(crate) fn set_audit_outcome(
        &self,
        id: i64,
        outcome: AuditOutcome,
        detail: Option<&str>,
    ) -> Result<(), VaultError> {
        let detail = match detail {
            Some(text) => {
                let mut out = Vec::new();
                ciborium::into_writer(&text, &mut out).map_err(|_| VaultError::HeaderEncode)?;
                Some(out)
            }
            None => None,
        };

        self.conn.execute(
            "UPDATE audit_log SET outcome = ?2, detail = ?3 WHERE id = ?1",
            params![id, outcome.as_str(), detail],
        )?;
        Ok(())
    }

    /// The most recent audit entries, newest first.
    pub(crate) fn audit_recent(&self, limit: usize) -> Result<Vec<AuditEntry>, VaultError> {
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT at, event, outcome, detail FROM audit_log ORDER BY at DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(params![limit], |row| {
                let at: i64 = row.get(0)?;
                let event: String = row.get(1)?;
                let outcome: String = row.get(2)?;
                let detail: Option<Vec<u8>> = row.get(3)?;
                Ok((at, event, outcome, detail))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(rows
            .into_iter()
            .map(|(at, event, outcome, detail)| {
                let text = detail
                    .and_then(|bytes| ciborium::from_reader::<String, _>(bytes.as_slice()).ok());
                (at, event, outcome, text)
            })
            .collect())
    }

    /// The entries a filter selects, newest first.
    pub(crate) fn audit_query(&self, query: &AuditQuery) -> Result<Vec<AuditRecord>, VaultError> {
        let (where_clause, mut values) = audit_filter(query);

        // A limit is always sent, so that `offset` without `limit` — which
        // SQLite rejects — cannot be constructed by a caller who only wanted to
        // skip a page.
        let limit = query
            .limit_value()
            .and_then(|n| i64::try_from(n).ok())
            .unwrap_or(i64::MAX);
        let offset = i64::try_from(query.offset_value()).unwrap_or(i64::MAX);
        values.push(Value::Integer(limit));
        values.push(Value::Integer(offset));

        let sql = format!(
            "SELECT id, at, event, outcome, node_id, session_id, detail
             FROM audit_log
             WHERE {where_clause}
             ORDER BY at DESC, id DESC
             LIMIT ?{limit_index} OFFSET ?{offset_index}",
            limit_index = values.len() - 1,
            offset_index = values.len(),
        );

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt
            .query_map(params_from_iter(values), read_audit_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// How many entries the same filter selects, ignoring its paging.
    pub(crate) fn audit_count(&self, query: &AuditQuery) -> Result<usize, VaultError> {
        let (where_clause, values) = audit_filter(query);
        let sql = format!("SELECT count(*) FROM audit_log WHERE {where_clause}");
        let count: i64 = self
            .conn
            .query_row(&sql, params_from_iter(values), |row| row.get(0))?;
        usize::try_from(count).map_err(|_| VaultError::CorruptRow("audit_log count"))
    }

    // ---------------------------------------------------------- settings ---

    /// Reads one setting.
    pub(crate) fn setting(&self, key: &str) -> Result<Option<Vec<u8>>, VaultError> {
        let value = self
            .conn
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Writes one setting.
    pub(crate) fn set_setting(&self, key: &str, value: &[u8]) -> Result<(), VaultError> {
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ------------------------------------------------------------- trust ---

    /// Records a host key or certificate as trusted.
    #[allow(clippy::too_many_arguments, reason = "mirrors the trust_store columns")]
    pub(crate) fn trust_pin(
        &self,
        host: &str,
        port: u16,
        kind: &str,
        algorithm: &str,
        fingerprint: &[u8],
        raw: &[u8],
        accepted_by: &str,
        now: i64,
    ) -> Result<Uuid, VaultError> {
        let id = Uuid::now_v7();
        self.conn.execute(
            "INSERT INTO trust_store
               (id, scope, node_id, host, port, kind, algorithm, fingerprint, raw,
                first_seen, last_seen, accepted_by)
             VALUES (?1, 'global', NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)
             ON CONFLICT(host, port, kind, algorithm, scope, COALESCE(node_id, X'00'))
             DO UPDATE SET
                fingerprint = excluded.fingerprint,
                raw = excluded.raw,
                last_seen = excluded.last_seen",
            params![
                id,
                host,
                i64::from(port),
                kind,
                algorithm,
                fingerprint,
                raw,
                now,
                accepted_by
            ],
        )?;
        Ok(id)
    }

    /// The fingerprint pinned for a host, if any.
    pub(crate) fn trust_lookup(
        &self,
        host: &str,
        port: u16,
        kind: &str,
        algorithm: &str,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let found = self
            .conn
            .query_row(
                "SELECT fingerprint FROM trust_store
                 WHERE host = ?1 AND port = ?2 AND kind = ?3 AND algorithm = ?4
                   AND scope = 'global' AND node_id IS NULL",
                params![host, i64::from(port), kind, algorithm],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(found)
    }

    // ----------------------------------------------------------- session ---

    /// Records the start of a session.
    pub(crate) fn session_start(
        &self,
        node: Option<Uuid>,
        protocol: &str,
        host: &str,
        username: Option<&str>,
        now: i64,
    ) -> Result<Uuid, VaultError> {
        let id = Uuid::now_v7();
        self.conn.execute(
            "INSERT INTO session_history (id, node_id, protocol, host, username, started_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, node, protocol, host, username, now],
        )?;
        Ok(id)
    }

    /// Records the end of a session and its byte counts.
    pub(crate) fn session_end(
        &self,
        session: Uuid,
        close_reason: &str,
        bytes_in: i64,
        bytes_out: i64,
        now: i64,
    ) -> Result<(), VaultError> {
        self.conn.execute(
            "UPDATE session_history
             SET ended_at = ?2, close_reason = ?3, bytes_in = ?4, bytes_out = ?5
             WHERE id = ?1",
            params![session, now, close_reason, bytes_in, bytes_out],
        )?;
        Ok(())
    }
}

/// Builds the `WHERE` clause an [`AuditQuery`] describes, and the values it
/// binds.
///
/// Every value is bound, including the event names: they are this crate's own
/// constants and could safely be interpolated, but a query builder that
/// interpolates *some* strings is one edit away from interpolating one that
/// came from a filter box.
fn audit_filter(query: &AuditQuery) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();

    let bind = |value: Value, values: &mut Vec<Value>| {
        values.push(value);
        format!("?{}", values.len())
    };

    if let Some(since) = query.since_at() {
        let placeholder = bind(Value::Integer(since), &mut values);
        clauses.push(format!("at >= {placeholder}"));
    }
    if let Some(until) = query.until_at() {
        let placeholder = bind(Value::Integer(until), &mut values);
        clauses.push(format!("at < {placeholder}"));
    }
    if let Some(node) = query.node() {
        let placeholder = bind(Value::Blob(node.as_bytes().to_vec()), &mut values);
        clauses.push(format!("node_id = {placeholder}"));
    }
    if let Some(session) = query.session() {
        let placeholder = bind(Value::Blob(session.as_bytes().to_vec()), &mut values);
        clauses.push(format!("session_id = {placeholder}"));
    }

    if !query.outcomes().is_empty() {
        let placeholders: Vec<String> = query
            .outcomes()
            .iter()
            .map(|o| bind(Value::Text(o.as_str().to_owned()), &mut values))
            .collect();
        clauses.push(format!("outcome IN ({})", placeholders.join(", ")));
    }

    if !query.categories().is_empty() {
        let mut alternatives: Vec<String> = Vec::new();
        for category in query.categories() {
            match category {
                // Defined by outcome as much as by event: anything that did not
                // succeed, plus the three events a review looks for whether or
                // not they succeeded.
                AuditCategory::Warning => {
                    let names: Vec<String> = AuditEvent::ALL
                        .iter()
                        .filter(|e| {
                            AuditCategory::Warning.matches(Some(**e), Some(AuditOutcome::Success))
                        })
                        .map(|e| bind(Value::Text(e.as_str().to_owned()), &mut values))
                        .collect();
                    alternatives.push(format!(
                        "(outcome <> 'success' OR event IN ({}))",
                        names.join(", ")
                    ));
                }
                other => {
                    let names: Vec<String> = AuditEvent::ALL
                        .iter()
                        .filter(|e| e.category() == *other)
                        .map(|e| bind(Value::Text(e.as_str().to_owned()), &mut values))
                        .collect();
                    if names.is_empty() {
                        continue;
                    }
                    alternatives.push(format!("event IN ({})", names.join(", ")));
                }
            }
        }
        if !alternatives.is_empty() {
            clauses.push(format!("({})", alternatives.join(" OR ")));
        }
    }

    if clauses.is_empty() {
        return (String::from("1"), values);
    }
    (clauses.join(" AND "), values)
}

/// One audit row, with its CBOR detail decoded back to text.
fn read_audit_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRecord> {
    let detail: Option<Vec<u8>> = row.get(6)?;
    Ok(AuditRecord {
        id: row.get(0)?,
        at: row.get(1)?,
        event: row.get(2)?,
        outcome: row.get(3)?,
        node: row.get(4)?,
        session: row.get(5)?,
        detail: detail.and_then(|bytes| ciborium::from_reader::<String, _>(bytes.as_slice()).ok()),
    })
}

/// Rewrites a node's tag rows.
fn write_tags(conn: &Connection, row: &NodeRow) -> Result<(), VaultError> {
    let unique: BTreeSet<&String> = row.tags.iter().collect();
    let mut stmt = conn.prepare("INSERT OR IGNORE INTO tags (node_id, tag) VALUES (?1, ?2)")?;
    for tag in unique {
        stmt.execute(params![row.id, tag])?;
    }
    Ok(())
}

/// Rewrites a node's search index entry.
fn write_index(conn: &Connection, row: &NodeRow) -> Result<(), VaultError> {
    // The identifier is stored as text rather than as the 16-byte blob used
    // everywhere else: FTS5's own tables are not the place to rely on how a
    // virtual table round-trips a blob in an UNINDEXED column.
    let id = row.id.to_string();
    conn.execute("DELETE FROM nodes_fts WHERE node_id = ?1", params![id])?;
    if row.deleted_at.is_some() {
        return Ok(());
    }
    conn.execute(
        "INSERT INTO nodes_fts (node_id, name, description, host, tags)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            id,
            row.name,
            row.description,
            row.search_host.clone().unwrap_or_default(),
            row.tags.join(" "),
        ],
    )?;
    Ok(())
}

/// Turns what the user typed into an FTS5 expression.
///
/// Every token is quoted and given a prefix `*`, so the search box can contain
/// quotes, parentheses, `NEAR` or anything else without becoming a syntax error
/// or, worse, a query that means something other than it looks like.
fn fts_query(input: &str) -> Option<String> {
    let tokens: Vec<String> = input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{t}\"*"))
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

fn read_node_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<NodeRow> {
    Ok(NodeRow {
        id: row.get(0)?,
        parent_id: row.get(1)?,
        sort_order: row.get(2)?,
        kind: row.get(3)?,
        name: row.get(4)?,
        description: row.get(5)?,
        icon: row.get(6)?,
        colour: row.get(7)?,
        props: row.get(8)?,
        custom_fields: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
        revision: row.get(12)?,
        deleted_at: row.get(13)?,
        tags: Vec::new(),
        search_host: None,
    })
}

fn read_secret_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretRow> {
    Ok(SecretRow {
        node_id: row.get(0)?,
        field: row.get(1)?,
        alg: row.get(2)?,
        nonce: row.get(3)?,
        ciphertext: row.get(4)?,
        revision: row.get(5)?,
        updated_at: row.get(6)?,
    })
}

/// Opens one stored secret against the revision it should be bound to.
fn open_secret(
    sek: &[u8; KEY_LEN],
    row: &SecretRow,
    revision: i64,
) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    if row.alg != ALG_XCHACHA20POLY1305 {
        return Err(VaultError::CorruptRow("secrets.alg"));
    }
    let nonce: [u8; NONCE_LEN] = row
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| VaultError::CorruptRow("secrets.nonce"))?;
    crypto::open(
        sek,
        &nonce,
        &row.ciphertext,
        &secret_aad(row.node_id, &row.field, revision),
    )
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]
mod tests {
    use super::*;

    fn node(id: Uuid, name: &str) -> NodeRow {
        NodeRow {
            id,
            parent_id: None,
            sort_order: 0,
            kind: "connection".into(),
            name: name.into(),
            description: String::new(),
            icon: None,
            colour: None,
            props: vec![0xa0],
            custom_fields: vec![0xa0],
            created_at: 1,
            updated_at: 1,
            revision: 1,
            deleted_at: None,
            tags: vec!["production".into()],
            search_host: Some(format!("{name}.example.internal")),
        }
    }

    #[test]
    fn serialising_never_allocates_a_plaintext_image_sqlite_will_free_unwiped() {
        // `sqlite3_free` does not wipe. An image it allocated and later frees
        // is a full plaintext copy of the connection inventory left in the
        // heap, once per save. Borrowing the live pages instead means the only
        // copy is the `Zeroizing` buffer `serialize` returns.
        let store = store();
        store.insert_node(&node(Uuid::now_v7(), "web-01")).unwrap();

        assert!(
            store.serialize_borrows_pages().unwrap(),
            "a fresh store must serialise without an owned copy"
        );

        let image = store.serialize().unwrap();
        let loaded = Store::load(&image, 2).unwrap();
        assert!(
            loaded.serialize_borrows_pages().unwrap(),
            "a loaded store must serialise without an owned copy"
        );
        assert_eq!(loaded.count_kind("connection").unwrap(), 1);
    }

    fn store() -> Store {
        Store::create_new(1).unwrap()
    }

    fn sek() -> [u8; KEY_LEN] {
        *crypto::random_key().unwrap()
    }

    #[test]
    fn a_new_store_is_at_the_current_schema_version() {
        let s = store();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn migrations_are_idempotent() {
        let mut s = store();
        s.migrate(2).unwrap();
        assert_eq!(s.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn a_newer_schema_is_refused() {
        let mut s = store();
        s.conn
            .execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, 0)",
                params![i64::from(SCHEMA_VERSION) + 1],
            )
            .unwrap();
        assert!(matches!(s.migrate(1), Err(VaultError::SchemaTooNew { .. })));
    }

    #[test]
    fn nodes_round_trip_with_their_tags() {
        let s = store();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        let back = s.node(id).unwrap().unwrap();
        assert_eq!(back.name, "web-01");
        assert_eq!(back.tags, vec!["production".to_string()]);
        assert_eq!(s.live_nodes().unwrap().len(), 1);
        assert_eq!(s.count_kind("connection").unwrap(), 1);
    }

    #[test]
    fn a_serialised_store_reloads_identically() {
        let s = store();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        let bytes = s.serialize().unwrap();
        let reloaded = Store::load(&bytes, 2).unwrap();
        assert_eq!(reloaded.node(id).unwrap().unwrap().name, "web-01");
    }

    #[test]
    fn a_body_that_is_not_a_database_is_refused() {
        assert!(matches!(
            Store::load(b"absolutely not a database", 1),
            Err(VaultError::NotADatabase)
        ));
        assert!(matches!(Store::load(b"", 1), Err(VaultError::NotADatabase)));
    }

    #[test]
    fn secrets_round_trip() {
        let s = store();
        let sek = sek();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        s.put_secret(&sek, id, "password", &Secret::new(b"hunter2".to_vec()), 5)
            .unwrap();
        assert!(s.has_secret(id, "password").unwrap());
        let got = s.get_secret(&sek, id, "password").unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"hunter2");
        assert_eq!(s.secret_fields(id).unwrap(), vec!["password".to_string()]);

        s.delete_secret(id, "password").unwrap();
        assert!(!s.has_secret(id, "password").unwrap());
    }

    #[test]
    fn a_ciphertext_swapped_between_records_does_not_open() {
        let s = store();
        let sek = sek();
        let a = Uuid::now_v7();
        let b = Uuid::now_v7();
        s.insert_node(&node(a, "web-01")).unwrap();
        s.insert_node(&node(b, "web-02")).unwrap();

        s.put_secret(&sek, a, "password", &Secret::new(b"alpha".to_vec()), 5)
            .unwrap();
        s.put_secret(&sek, b, "password", &Secret::new(b"bravo".to_vec()), 5)
            .unwrap();

        // Move A's ciphertext and nonce onto B's row, exactly as an attacker
        // with write access to the decrypted database would.
        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = s
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM secrets WHERE node_id = ?1",
                params![a],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        s.conn
            .execute(
                "UPDATE secrets SET nonce = ?2, ciphertext = ?3 WHERE node_id = ?1",
                params![b, nonce, ciphertext],
            )
            .unwrap();

        assert!(matches!(
            s.get_secret(&sek, b, "password"),
            Err(VaultError::Aead)
        ));
    }

    #[test]
    fn a_ciphertext_moved_between_fields_does_not_open() {
        let s = store();
        let sek = sek();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        s.put_secret(&sek, id, "password", &Secret::new(b"alpha".to_vec()), 5)
            .unwrap();
        s.put_secret(&sek, id, "private_key", &Secret::new(b"bravo".to_vec()), 5)
            .unwrap();

        let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = s
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM secrets WHERE node_id = ?1 AND field = 'password'",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        s.conn
            .execute(
                "UPDATE secrets SET nonce = ?2, ciphertext = ?3
                 WHERE node_id = ?1 AND field = 'private_key'",
                params![id, nonce, ciphertext],
            )
            .unwrap();

        assert!(matches!(
            s.get_secret(&sek, id, "private_key"),
            Err(VaultError::Aead)
        ));
    }

    #[test]
    fn a_ciphertext_rolled_back_to_an_earlier_revision_does_not_open() {
        let s = store();
        let sek = sek();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        s.put_secret(&sek, id, "password", &Secret::new(b"old".to_vec()), 5)
            .unwrap();
        let (old_nonce, old_ciphertext): (Vec<u8>, Vec<u8>) = s
            .conn
            .query_row(
                "SELECT nonce, ciphertext FROM secrets WHERE node_id = ?1",
                params![id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        // The record moves on; its secrets are re-sealed under the new revision.
        s.set_revision(&sek, id, 1, 2, 6).unwrap();
        assert_eq!(s.revision_of(id).unwrap(), 2);
        s.put_secret(&sek, id, "password", &Secret::new(b"new".to_vec()), 7)
            .unwrap();

        // Put the old ciphertext back, keeping the current revision column so
        // the staleness check cannot be what catches it.
        s.conn
            .execute(
                "UPDATE secrets SET nonce = ?2, ciphertext = ?3 WHERE node_id = ?1",
                params![id, old_nonce, old_ciphertext],
            )
            .unwrap();

        assert!(matches!(
            s.get_secret(&sek, id, "password"),
            Err(VaultError::Aead)
        ));
    }

    #[test]
    fn a_stale_revision_column_is_caught_before_decryption() {
        let s = store();
        let sek = sek();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();
        s.put_secret(&sek, id, "password", &Secret::new(b"x".to_vec()), 5)
            .unwrap();

        s.conn
            .execute(
                "UPDATE nodes SET revision = revision + 1 WHERE id = ?1",
                params![id],
            )
            .unwrap();

        assert!(matches!(
            s.get_secret(&sek, id, "password"),
            Err(VaultError::StaleSecret)
        ));
    }

    #[test]
    fn bumping_a_revision_keeps_secrets_readable() {
        let s = store();
        let sek = sek();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();
        s.put_secret(&sek, id, "password", &Secret::new(b"hunter2".to_vec()), 5)
            .unwrap();

        for revision in 1..4 {
            s.set_revision(&sek, id, revision, revision + 1, 6).unwrap();
            let got = s.get_secret(&sek, id, "password").unwrap();
            assert_eq!(got.expose_secret().as_slice(), b"hunter2");
        }
    }

    #[test]
    fn search_finds_by_name_host_and_tag() {
        let s = store();
        let id = Uuid::now_v7();
        let mut row = node(id, "web-01");
        row.description = "Frontend node in München".into();
        s.insert_node(&row).unwrap();

        for query in ["web", "web-01", "example", "production", "munchen"] {
            let hits = s.search(query, 10).unwrap();
            assert_eq!(hits, vec![id], "query {query:?} found nothing");
        }
        assert!(s.search("nothing-like-this", 10).unwrap().is_empty());
        assert!(s.search("   ", 10).unwrap().is_empty());
    }

    #[test]
    fn search_does_not_choke_on_query_syntax() {
        let s = store();
        s.insert_node(&node(Uuid::now_v7(), "web-01")).unwrap();
        for query in ["\"", "NEAR(", "a AND (", "*", "^web"] {
            assert!(s.search(query, 10).is_ok(), "query {query:?} was an error");
        }
    }

    #[test]
    fn a_tombstoned_node_leaves_the_index() {
        let s = store();
        let id = Uuid::now_v7();
        let mut row = node(id, "web-01");
        s.insert_node(&row).unwrap();

        row.deleted_at = Some(9);
        s.update_node(&row).unwrap();

        assert!(s.search("web", 10).unwrap().is_empty());
        assert!(s.live_nodes().unwrap().is_empty());
        assert!(s.node(id).unwrap().is_some(), "the tombstone must remain");
    }

    #[test]
    fn the_audit_log_round_trips() {
        let s = store();
        s.audit(
            10,
            AuditEvent::VaultUnlocked,
            AuditOutcome::Success,
            None,
            None,
            Some("password slot 0"),
        )
        .unwrap();

        let entries = s.audit_recent(10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1, "vault_unlocked");
        assert_eq!(entries[0].2, "success");
        assert_eq!(entries[0].3.as_deref(), Some("password slot 0"));
        assert_eq!(
            AuditEvent::parse("vault_unlocked"),
            Some(AuditEvent::VaultUnlocked)
        );
        assert_eq!(AuditOutcome::parse("denied"), Some(AuditOutcome::Denied));
        assert_eq!(AuditEvent::parse("from_the_future"), None);
    }

    #[test]
    fn settings_round_trip() {
        let s = store();
        assert!(s.setting("theme").unwrap().is_none());
        s.set_setting("theme", b"dark").unwrap();
        assert_eq!(s.setting("theme").unwrap().as_deref(), Some(&b"dark"[..]));
        s.set_setting("theme", b"light").unwrap();
        assert_eq!(s.setting("theme").unwrap().as_deref(), Some(&b"light"[..]));
    }

    #[test]
    fn the_trust_store_pins_and_looks_up() {
        let s = store();
        s.trust_pin(
            "web-01.example.internal",
            22,
            "ssh_hostkey",
            "ssh-ed25519",
            b"fingerprint",
            b"raw key",
            "user",
            10,
        )
        .unwrap();

        assert_eq!(
            s.trust_lookup("web-01.example.internal", 22, "ssh_hostkey", "ssh-ed25519")
                .unwrap()
                .as_deref(),
            Some(&b"fingerprint"[..])
        );
        assert!(
            s.trust_lookup("other.example.internal", 22, "ssh_hostkey", "ssh-ed25519")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn session_history_records_a_session() {
        let s = store();
        let id = Uuid::now_v7();
        s.insert_node(&node(id, "web-01")).unwrap();

        let session = s
            .session_start(Some(id), "ssh", "web-01.example.internal", Some("root"), 10)
            .unwrap();
        s.session_end(session, "closed by user", 100, 200, 20)
            .unwrap();

        let (ended, bytes_in): (Option<i64>, i64) = s
            .conn
            .query_row(
                "SELECT ended_at, bytes_in FROM session_history WHERE id = ?1",
                params![session],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ended, Some(20));
        assert_eq!(bytes_in, 100);
    }

    #[test]
    fn the_secret_associated_data_has_the_documented_shape() {
        let id = Uuid::from_u128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10);
        let aad = secret_aad(id, "password", 7);

        let mut expected = Vec::new();
        expected.extend_from_slice(id.as_bytes());
        expected.push(0x1F);
        expected.extend_from_slice(b"password");
        expected.push(0x1F);
        expected.extend_from_slice(&7i64.to_le_bytes());
        assert_eq!(aad, expected);
    }
}

#[cfg(test)]
mod trust_pin_upsert_tests {
    use super::*;

    /// The bug this pins down: SQLite treats NULLs as distinct in a UNIQUE
    /// index, so a globally scoped pin (node_id NULL) never collided and
    /// `ON CONFLICT ... DO UPDATE` never ran. Replacing a host key inserted a
    /// second row, `trust_lookup` kept answering with the superseded
    /// fingerprint, and the bridge's cross-check against the cached key then
    /// failed — so the host read as *unknown* and the blocking "this key
    /// changed" warning could never fire for it again.
    #[test]
    fn replacing_a_pinned_key_updates_the_row_rather_than_adding_one() {
        let mut store = Store::create_new(1).expect("a blank store");

        store
            .trust_pin(
                "db-01.internal",
                22,
                "ssh_hostkey",
                "ssh-ed25519",
                b"old",
                b"oldblob",
                "user",
                1,
            )
            .expect("first pin");
        store
            .trust_pin(
                "db-01.internal",
                22,
                "ssh_hostkey",
                "ssh-ed25519",
                b"new",
                b"newblob",
                "user",
                2,
            )
            .expect("second pin");

        let rows: i64 = store
            .conn
            .query_row(
                "SELECT count(*) FROM trust_store WHERE host = ?1 AND algorithm = ?2",
                params!["db-01.internal", "ssh-ed25519"],
                |row| row.get(0),
            )
            .expect("counting");
        assert_eq!(rows, 1, "a replacement must update, not accumulate");

        let found = store
            .trust_lookup("db-01.internal", 22, "ssh_hostkey", "ssh-ed25519")
            .expect("lookup")
            .expect("a pinned key");
        assert_eq!(found, b"new", "the lookup must answer with the current key");
    }

    /// A different host, port or algorithm is a different identity and must
    /// still get its own row — the fix must not collapse everything into one.
    #[test]
    fn distinct_identities_still_get_their_own_rows() {
        let mut store = Store::create_new(1).expect("a blank store");
        store
            .trust_pin("a", 22, "ssh_hostkey", "ssh-ed25519", b"1", b"1", "user", 1)
            .expect("a");
        store
            .trust_pin("b", 22, "ssh_hostkey", "ssh-ed25519", b"2", b"2", "user", 1)
            .expect("b");
        store
            .trust_pin(
                "a",
                2222,
                "ssh_hostkey",
                "ssh-ed25519",
                b"3",
                b"3",
                "user",
                1,
            )
            .expect("port");
        store
            .trust_pin("a", 22, "ssh_hostkey", "ssh-rsa", b"4", b"4", "user", 1)
            .expect("alg");

        let rows: i64 = store
            .conn
            .query_row("SELECT count(*) FROM trust_store", [], |row| row.get(0))
            .expect("counting");
        assert_eq!(rows, 4);
    }
}
