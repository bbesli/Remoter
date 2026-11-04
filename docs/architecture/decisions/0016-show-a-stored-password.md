# ADR-0016: Show a stored password, behind the vault password and a ten-minute window

- **Status**: Accepted
- **Date**: 2026-11-04
- **Deciders**: bbesli

## Context

Remoter stores the passwords of the servers it connects to, and until this
decision nothing could read one back. The rule behind that was deliberate and is
written in three places — `crates/remoter-ipc/src/lib.rs`, CLAUDE.md §6 and
[key-management.md](../../security/key-management.md#credential-handling-at-runtime):
a secret never crosses the IPC boundary into the WebView; the frontend asks for
an action and the core performs it.

The owner needs the opposite, for an ordinary reason: to read the password of a
server they administer — to type it into a console, a vendor's portal, a
colleague's screen-share. A credential manager that can only *use* a password is
a credential manager the owner keeps a second copy of the password beside, and
that second copy is the thing this application exists to replace.

The specification already anticipated the feature and constrained it.
[threat-model.md](../../security/threat-model.md) T7 says "revealing one requires
an explicit action and is written to the audit log", and the audit catalogue has
had a `secret_revealed` event since the first release, written by
`Purpose::Reveal`, that nothing raised.

What the specification did not settle is what the explicit action is. T7 is the
unattended, unlocked screen. An open vault proves only that someone unlocked it
at some point; a menu item that shows any password to whoever is at the keyboard
would make every unlocked session a list of plaintext passwords.

## Options considered

### Option A — show it on request, audited

A menu item, one call, the password on screen and a row in the log.

Simple, and the log records it. But the log records it *after* the fact, and the
person reading it then is not the person who walked up to the unlocked screen.
This is the T7 failure the threat model names.

### Option B — ask for the vault password every time

The strongest gate, and the same derivation an unlock performs.

Each confirmation is a deliberate second of Argon2id. Reading the passwords of
five servers in a row — the common case, when moving a run of machines between
tools — is five prompts and five seconds of derivation, which is the kind of
friction that pushes the owner back to the second copy this feature is meant to
make unnecessary.

### Option C — ask for the vault password, then trust it for ten minutes

The first password shown asks for the vault password; for ten minutes after, the
next ones are shown without asking. The window is held in the core, not the
interface; it runs from the confirmation and is not extended by use; locking the
vault, by hand or by any trigger, ends it; and a countdown in a corner of the
window says it is open and offers to end it early.

## Decision

Option C, with the exception to the boundary rule kept as narrow as it can be:

- **One command crosses.** `secret_reveal` in `crates/remoter-ipc/src/reveal.rs`
  returns a password and nothing else — never a private key, a passphrase or a
  TOTP seed. Its DTO carries the review note CLAUDE.md §5 asks for: a redacting
  `Debug`, no `Clone`, the value in a wiping buffer until it is serialised.
- **The confirmation is the unlock's own.** The password is checked by
  `Vault::password_check`, which tries the vault's password slots with the same
  Argon2id parameters, offers the remembered key file only to slots created with
  one, and is subject to the unlock screen's backoff after repeated failures. A
  refused confirmation is audited as a failed unlock.
- **The derivation runs with the vault released.** `password_check` copies the
  public half of each password slot and a keyed BLAKE3 commitment to the master
  key — never the master key — so the second of Argon2id runs on the blocking
  pool without holding the lock every other command needs, and without freezing
  the window as a command on the main thread would.
- **Ten minutes, fixed.** `REVEAL_WINDOW` in `reveal.rs`. Monotonic, so moving
  the system clock cannot stretch it; cleared by every path that closes or
  replaces the vault.
- **Every password shown is audited** as `secret_revealed`, through
  `Vault::borrow_secret` with `Purpose::Reveal`, and saved at once.
- **The interface holds it in component state only** — not in TanStack Query's
  cache, not in a store — and drops it when the dialog closes or the shell
  unmounts on a lock.

## Consequences

**Positive** — The owner can read a stored password without keeping a second
copy of it. The feature the threat model already described now exists, under the
constraints it already stated, and the audit event that had no producer has one.

**Negative** — A password now crosses into the WebView, where it lives in a
JavaScript string the engine will not zeroize and in the JSON buffer the IPC
layer serialised it into. Nothing in this application can wipe either; they are
reclaimed when the engine collects them. For ten minutes after a confirmation,
someone at an unlocked, unattended screen can read every stored password without
knowing the vault's — the countdown says so in a corner, and ending it early is
one click, but it is a real widening of T7 for the length of the window.

**Neutral** — The boundary rule's wording changes from "no command returns a
password" to "one command does, and says why", in `lib.rs`, `ipc.ts`, CLAUDE.md
§6 and the security documents. There is no copy-to-clipboard button: the
clipboard is shared with every other application, and the clipboard timeout
[key-management.md](../../security/key-management.md#credential-handling-at-runtime)
describes is not built.

## Revisit if

- The window should be configurable per vault — a stricter vault wanting none, a
  laptop owner wanting less.
- A copy button is added: it needs the clipboard timeout first.
- Process isolation ([ADR-0007](0007-process-isolation.md)) moves secrets out of
  the interface's process, at which point a reveal has to be redesigned rather
  than carried across.
