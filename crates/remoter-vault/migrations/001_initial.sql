-- Schema v1. See docs/architecture/storage.md, which is normative.
--
-- Every mutable row carries id, updated_at and revision. These exist from day
-- one for causality and rollback detection, even though v1.0 has no
-- synchronisation: retrofitting identity onto existing data is painful and
-- carrying three columns is not.
--
-- Migrations are forward-only and run inside one transaction. Never edit an
-- applied migration; add the next numbered file instead.

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
    deleted_at    INTEGER                  -- soft delete -> tombstone
);

CREATE INDEX idx_nodes_parent ON nodes(parent_id, sort_order)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_nodes_kind   ON nodes(kind) WHERE deleted_at IS NULL;

-- Secret fields live in their own table, separately encrypted with the SEK.
-- Splitting them out means a query over connection metadata never touches
-- ciphertext, and the secret table can be audited on its own.
--
-- The associated data is node_id || 0x1F || field || 0x1F || revision, so a
-- ciphertext cannot be moved between records or fields, and an old one cannot
-- be rolled back over a new one.
CREATE TABLE secrets (
    node_id    BLOB NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    field      TEXT NOT NULL,              -- 'password' | 'private_key' | ...
    alg        INTEGER NOT NULL,           -- AEAD algorithm id; 1 = XChaCha20-Poly1305
    nonce      BLOB NOT NULL CHECK (length(nonce) = 24),
    ciphertext BLOB NOT NULL,
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
--
-- storage.md sketches this as an external-content table populated by triggers.
-- That shape needs an INTEGER rowid to join on, and this schema's primary keys
-- are 16-byte UUIDs, so there is nothing for the trigger to key against. The
-- index therefore carries its own copy of four short, non-secret text fields
-- and is maintained by the same Rust code that writes the node rows, inside the
-- same transaction. `host` comes out of the node's CBOR props, which is why it
-- is not a column on `nodes`.
CREATE VIRTUAL TABLE nodes_fts USING fts5(
    node_id UNINDEXED,
    name,
    description,
    host,
    tags,
    tokenize = 'unicode61 remove_diacritics 2'
);
