# Storage

The SQLite database inside the encrypted vault body: schema, migrations, and the
decisions that keep future synchronisation possible.

## Why SQLite inside an encrypted container

The body of a `.rvault` file is a complete SQLite database, encrypted as one
unit ([vault-format.md](../security/vault-format.md)).

The alternatives:

| Option | Why not |
|---|---|
| Encrypted JSON/CBOR document | Simple, but the whole document must be parsed and rewritten on every change, and there is no query engine. Fine at 50 connections, unpleasant at 5000 |
| SQLite with page-level encryption (SQLCipher) | Good for large datasets, but adds a C dependency and leaks structural metadata through page access patterns |
| **In-memory SQLite, encrypted as a whole on save** | **Chosen.** No C crypto dependency, no partial-plaintext-on-disk window, full SQL query power, and vaults are small — a 5000-connection vault is a few megabytes |

The trade-off is real and worth stating: the entire database is held in RAM
while unlocked, and every save re-encrypts the whole body. For a connection
manager, where vaults are measured in megabytes and saves are user-initiated,
that is the right side of the trade. If a vault ever grows past a threshold
where this hurts (measured, not guessed), page-level encryption becomes the
migration path — the format's version byte exists for exactly this.

## Schema (v1)

```sql
-- Every mutable row carries: id, updated_at, revision.
-- These exist from day one for causality and rollback detection, even though
-- v1.0 has no synchronisation. Retrofitting identity onto existing data is
-- painful; carrying three columns is not.

CREATE TABLE nodes (
    id            BLOB PRIMARY KEY,        -- UUIDv7, 16 bytes
    parent_id     BLOB REFERENCES nodes(id) ON DELETE RESTRICT,
    sort_order    INTEGER NOT NULL DEFAULT 0,
    kind          TEXT    NOT NULL CHECK (kind IN
                    ('folder','connection','credential','group','separator')),
    name          TEXT    NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    description   TEXT    NOT NULL DEFAULT '',
    icon          TEXT,
    colour        TEXT,
    props         BLOB    NOT NULL,        -- CBOR: kind-specific properties
    custom_fields BLOB    NOT NULL DEFAULT X'A0',  -- CBOR map, user/plugin data
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL,
    revision      INTEGER NOT NULL DEFAULT 1,
    deleted_at    INTEGER                  -- soft delete → tombstone
);

CREATE INDEX idx_nodes_parent ON nodes(parent_id, sort_order)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_nodes_kind   ON nodes(kind) WHERE deleted_at IS NULL;

-- Secret fields live in their own table, separately encrypted with the SEK.
-- Splitting them out means a query over connection metadata never touches
-- ciphertext, and the secret table can be audited on its own.
CREATE TABLE secrets (
    node_id    BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,              -- 'password' | 'private_key' | ...
    alg        INTEGER NOT NULL,           -- AEAD algorithm id
    nonce      BLOB NOT NULL CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL,              -- AAD = node_id ‖ field ‖ revision
    revision   INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (node_id, field)
) WITHOUT ROWID;

CREATE TABLE tags (
    node_id BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    tag     TEXT NOT NULL,
    PRIMARY KEY (node_id, tag)
) WITHOUT ROWID;
CREATE INDEX idx_tags_tag ON tags(tag);

-- SSH host keys and pinned TLS certificates. Inside the vault, not in a
-- plaintext known_hosts, so poisoning the trust store requires the password.
CREATE TABLE trust_store (
    id           BLOB PRIMARY KEY,
    scope        TEXT NOT NULL,            -- 'global' | 'node'
    node_id      BLOB REFERENCES nodes(id) ON DELETE CASCADE,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    kind         TEXT NOT NULL,            -- 'ssh_hostkey' | 'tls_cert'
    algorithm    TEXT NOT NULL,
    fingerprint  BLOB NOT NULL,
    raw          BLOB NOT NULL,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    accepted_by  TEXT                      -- 'user' | 'import'
);
CREATE UNIQUE INDEX idx_trust ON trust_store(host, port, kind, algorithm, scope, node_id);

-- Append-only. No UPDATE, no DELETE except by retention policy.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    at         INTEGER NOT NULL,
    event      TEXT NOT NULL,
    node_id    BLOB,
    session_id BLOB,
    outcome    TEXT NOT NULL,              -- 'success' | 'failure' | 'denied'
    detail     BLOB                        -- CBOR; MUST NOT contain secrets
);
CREATE INDEX idx_audit_at ON audit_log(at DESC);

CREATE TABLE session_history (
    id           BLOB PRIMARY KEY,
    node_id      BLOB REFERENCES nodes(id) ON DELETE SET NULL,
    protocol     TEXT NOT NULL,
    host         TEXT NOT NULL,
    username     TEXT,
    started_at   INTEGER NOT NULL,
    ended_at     INTEGER,
    close_reason TEXT,
    bytes_in     INTEGER NOT NULL DEFAULT 0,
    bytes_out    INTEGER NOT NULL DEFAULT 0,
    recording    TEXT                      -- relative path, if recorded
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE schema_version (
    version    INTEGER NOT NULL,
    applied_at INTEGER NOT NULL
);

-- Full-text search over non-secret fields only.
CREATE VIRTUAL TABLE nodes_fts USING fts5(
    name, description, host, tags,
    content = '',                          -- external content, populated by trigger
    tokenize = 'unicode61 remove_diacritics 2'
);
```

Three schema decisions worth defending:

**Secrets in a separate table.** Listing 5000 connections never reads a single
byte of ciphertext. It also means a reviewer can look at exactly one table to
verify that nothing secret escapes.

**`props` as CBOR, not columns.** Protocol settings differ wildly between SSH
and RDP and cannot be known in advance for plugin protocols. A typed blob
validated against the adapter's schema is honest about that; forty nullable
columns is not. The cost is that you cannot `WHERE props->>'port' = 22` — which
is why the fields that *are* queried (name, host, tags) are real columns and
indexed.

**Soft deletes.** `deleted_at` produces tombstones rather than vanishing rows.
That gives an undo window today and gives synchronisation a way to propagate
deletions tomorrow. Tombstones are purged after a retention period.

**`unicode61 remove_diacritics 2`** in FTS matters for a ten-language product:
searching `sunucu` should find `Sunucu`, and searching `munchen` should find
`München`.

## Migrations

Forward-only, numbered, embedded in the binary, run inside a transaction:

```
crates/remoter-vault/migrations/
  001_initial.sql
  002_add_session_history.sql
  ...
```

Rules:

1. A migration runs in one transaction. Partial application is impossible
2. The vault is backed up before any migration and the backup is retained until
   the next clean save
3. Migrations never touch ciphertext. Re-encryption is a separate, explicit
   operation with its own progress UI
4. Opening a vault whose `schema_version` is **newer** than the binary is
   refused with a clear message: "This vault was created by a newer version of
   Remoter." Guessing at a future schema is how data gets corrupted

## Concurrency

The vault is **single-writer**. All mutations funnel through one task; readers
take consistent snapshots. This is not a limitation to work around — it is what
makes atomic saves and the encrypted-body model coherent.

Two Remoter instances opening the same file is detected with an advisory lock
file (`<vault>.lock`, containing pid and hostname). The second instance opens
read-only and says so, rather than racing and losing writes. A stale lock — the
pid is gone — can be broken by the user after an explicit confirmation.

## Backups

Every save rotates the previous file: `<vault>.bak.1` … `<vault>.bak.N`
(default 3). Backups are complete, encrypted vault files openable with the same
credentials — not diffs, not partial state. A user whose vault fails to decrypt
therefore has a recent, known-good file, which is the difference between an
inconvenience and a catastrophe.

## Sync-readiness

v1.0 ships no synchronisation. These properties exist so that adding it later
does not require a data migration:

| Property | Present in v1.0 | Enables |
|---|---|---|
| UUIDv7 identifiers | ✅ | Merging vaults without id collisions |
| `updated_at` + `revision` per row | ✅ | Last-writer-wins and conflict detection |
| Tombstones instead of hard deletes | ✅ | Propagating deletions |
| Per-field encryption with per-record keys | ✅ | Field-level merge without decrypting everything |
| Blind-index key in the hierarchy | ✅ (unused) | Server-side lookup without server-side decryption |
| Operation log | ❌ | Would enable CRDT-style merge; deferred to the sync design |

The intended shape of synchronisation — when it comes — is end-to-end
encrypted, with the server storing opaque blobs and never holding a key. That
constraint is what shapes the list above.
