# ADR-0005: Local-first storage in a single portable encrypted file

- **Status**: Accepted
- **Date**: 2026-09-10

## Context

Connection managers span a spectrum from single-user local files (KeePass-style)
to full team platforms with a server, RBAC and shared vaults. Where v1.0 sits
determines the scope, the operational burden, and the trust model.

## Options considered

**A · Local-first, single encrypted file.** One `.rvault`, no server, no
account. Simple to reason about, trivial to back up, works offline, zero
infrastructure. Sharing is manual; no per-user access control; no central audit.

**B · Server-synchronised multi-user from day one.** Shared vaults, RBAC,
central audit. This is what enterprises eventually want — and it multiplies the
v1.0 scope, adds a server to operate, adds accounts and sessions and their
entire attack surface, and delays a working product by a long time.

**C · Local-first plus external secret managers.** The vault holds structure;
secrets live in HashiCorp Vault, Bitwarden or 1Password. Elegant for
organisations that already run one, useless for the individual administrator who
does not, and it makes the product depend on third-party availability.

## Decision

**Option A for v1.0, with the data model built so that B and C remain
possible.**

Concretely, from v0.1 the schema carries UUIDv7 identifiers, `updated_at` and
`revision` on every mutable row, tombstones instead of hard deletes, and
per-field encryption with per-record binding. None of that is used by v1.0.
All of it is prohibitively awkward to retrofit onto an existing dataset.
`SecretKind::External` exists in the model from day one so that option C becomes
a plugin rather than a redesign.

## Consequences

**Positive.** A shippable v1.0. No infrastructure, no accounts, no server
breach to worry about. Works offline. The vault is a file — back it up, put it
in Git, carry it on a USB stick. The trust model is small enough to explain in a
paragraph.

**Negative.** No team features in v1.0, which will be the most common feature
request. File-based sharing via cloud storage invites concurrent-edit conflicts;
we detect them with an advisory lock and warn, but cannot merge. No central
audit for organisations that need one.

**Neutral.** The synchronisation design, when it comes, must be end-to-end
encrypted with the server holding only opaque blobs. That constraint is already
what shapes the schema above.

## Revisit if

Team synchronisation becomes the dominant request after v1.0 — at which point it
gets its own design document and ADR, not an incremental bolt-on.
