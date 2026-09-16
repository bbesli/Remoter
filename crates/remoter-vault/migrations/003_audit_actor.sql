-- Who wrote each audit row, and from which machine.
--
-- A vault is shared by copying the file and telling a colleague the password,
-- and until now its audit log could say that a session to a server was opened
-- but not whether the owner opened it or the colleague did. Every row written
-- from here on names the operating-system account and the machine the process
-- was running as.
--
-- This is attribution, not authentication. The names are what the operating
-- system reported to the process, and anybody who can unlock the vault can
-- write any row they like into it. It answers "which of the people who can open
-- this vault did that", which is the question a shared vault raises; it does
-- not answer "prove it".
--
-- The identity is a row of its own rather than four columns on every entry. A
-- vault that has been in use for a year holds tens of thousands of audit rows
-- written by two or three accounts, and the whole body is re-encrypted on every
-- save, so repeating a machine and a user name on each row would grow every save
-- for no information.
--
-- `domain` is NOT NULL with an empty default on purpose. SQLite treats NULLs as
-- distinct in a UNIQUE constraint — the defect migration 002 had to repair in
-- the trust store — so a nullable column here would give every write by a
-- non-domain account a fresh actor row instead of finding the existing one.
CREATE TABLE audit_actor (
    id       INTEGER PRIMARY KEY,
    machine  TEXT NOT NULL,
    os_user  TEXT NOT NULL,
    domain   TEXT NOT NULL DEFAULT '',
    os       TEXT NOT NULL,
    UNIQUE (machine, os_user, domain, os)
);

-- NULL for every row written before this migration, and for any row written by
-- a process that could not determine who it was running as. The interface says
-- "not recorded" for those rather than guessing.
ALTER TABLE audit_log ADD COLUMN actor_id INTEGER REFERENCES audit_actor(id);
CREATE INDEX idx_audit_actor ON audit_log(actor_id);
