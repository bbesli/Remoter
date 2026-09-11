-- The unique index on the trust store never fired for a global pin, so
-- replacing a host key inserted a second row instead of updating the first.
--
-- SQLite treats NULLs as DISTINCT in a UNIQUE index. `node_id` is NULL for a
-- globally scoped pin, so two rows for the same host and algorithm never
-- collided, `ON CONFLICT ... DO UPDATE` never ran, and `trust_lookup` kept
-- answering with the fingerprint that had been superseded.
--
-- The consequence was not a stale row. The bridge cross-checks the pinned
-- fingerprint against a cached copy of the key, and after a replacement those
-- two disagreed — so the lookup refused to answer at all, and the host read as
-- UNKNOWN. Every later connection then showed the calm first-use prompt, and
-- the blocking "this key changed" warning could never fire for that host
-- again. A live test caught it; the unit tests use an in-memory map, which
-- does not have SQLite's NULL semantics.
--
-- The fix is an expression index over COALESCE(node_id, ...), which gives every
-- global pin the same key. Stored values are unchanged.

-- Keep the most recently seen row per identity and drop the superseded ones.
DELETE FROM trust_store
WHERE rowid NOT IN (
    SELECT rowid FROM (
        SELECT rowid,
               ROW_NUMBER() OVER (
                   PARTITION BY host, port, kind, algorithm, scope,
                                COALESCE(node_id, X'00')
                   ORDER BY last_seen DESC, rowid DESC
               ) AS rank
        FROM trust_store
    )
    WHERE rank = 1
);

DROP INDEX IF EXISTS idx_trust;

CREATE UNIQUE INDEX idx_trust
    ON trust_store(host, port, kind, algorithm, scope, COALESCE(node_id, X'00'));
