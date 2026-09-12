# Key Management

Lifecycle of the keys and unlock methods described in
[vault-format.md](vault-format.md), from the user's point of view.

> **What ships.** Creation, unlock, lock, rotation and revocation are built, for
> three of the four slot kinds: master password, password plus key file,
> recovery key, and the OS keychain. ⏳ **The hardware-key (FIDO2) slot is not
> implemented** — `kek_for` answers `UnlockError::Fido2Unsupported` for it,
> `Vault::open` refuses it before touching the file, and adding one is refused
> too. Every sentence below about a hardware key is design, not behaviour, and is
> marked. ⏳ Two of the five auto-lock triggers also cannot be observed from this
> build; see *Auto-lock*.

## Creating a vault

The creation wizard is four steps. It is deliberately not skippable — the
recovery key screen in particular is where most real-world data loss is
prevented.

**1 · Name and location.** Where the `.rvault` file lives. Remoter warns, once,
if the chosen directory is inside a cloud-sync folder: it works, but concurrent
edits from two machines will conflict, and the sync provider keeps historical
copies of the ciphertext.

**2 · Master password.** A live entropy estimate (zxcvbn-style) with a minimum
threshold, not a "must contain a symbol" rule — arbitrary composition rules
produce predictable passwords. A "generate a passphrase" button offers a
six-word Diceware-style phrase. Confirmation field, and an optional reveal
toggle.

**3 · Key file (optional).** Any file the user picks becomes a second factor.
The dialog states clearly: *this file is now required to open the vault; if you
lose it, only your recovery key will work.* Remoter can also generate a random
key file. It never modifies the file it is given, and it warns if the file is
stored in the same directory as the vault, which defeats the purpose.

**4 · Recovery key.** Generated, displayed once, and gated behind a
transcription check — the user must re-type one specified group before
continuing. Buttons: copy, download as text, print. The warning text is in
[vault-format.md](vault-format.md#recovery-slot) and must not be softened by
translators; the i18n review checklist flags that string specifically.

After creation, the vault is unlocked and the user is offered — not
automatically given — the optional slots: "remember on this device" (the OS
keychain), and ⏳ a hardware key, once that slot kind exists.

## Unlocking

The unlock screen lists the slots this vault actually has, by label. A vault
with only a password slot shows one option; a vault with a hardware key offers
the touch prompt first, because it is faster.

```
┌────────────────────────────────────────────┐
│  Production vault                          │
│  ~/vaults/production.rvault                │
│                                            │
│  ○ Master password        [············]   │
│    Key file: prod.pem            [Browse]  │
│  ○ Security key           Touch your key…  │
│  ○ Recovery key           [Use recovery…]  │
│                                            │
│                      [Cancel]   [Unlock]   │
└────────────────────────────────────────────┘
```

Failure messages never reveal which factor was wrong. "That did not unlock the
vault" covers a wrong password, a wrong key file, or both — an attacker who
learns that the *password* was right but the key file was missing has learned
something valuable.

The one case where Remoter is specific: if the header MAC verifies but the body
does not decrypt, the file is corrupt rather than the credentials wrong, and the
user is told so and pointed at the rolling backups. That distinction only
becomes visible *after* a slot has been successfully unwrapped, so it leaks
nothing to someone who cannot already open the vault.

### Refusals on an open vault are specific, and must be

Re-wrapping a slot — changing a password, upgrading a slot's Argon2id cost,
rotating the master key — verifies the offered credential against the slot it
names before replacing anything, and every one of those operations runs on a
vault that is already open. The rule above therefore does not apply to them: the
caller has already proved they hold a credential, so the refusal says what it
knows.

Three things it must distinguish, because they are three different problems and
"that does not open key slot 0" is actionable for none of them:

- **The key file could not be read.** A key file contributes
  `BLAKE3(file_bytes)`, so reading it is a step that fails on its own — a
  removable drive that dropped, a synchronised file whose local copy is no
  longer materialised, a path that has become a directory, a file past the
  64 MiB cap. This is reported as a key file failure. It is *not* a wrong
  credential, and reporting it as one tells an owner their password is wrong
  when it never was.
- **The credential is for another slot.** An unlock tries every slot of the
  method's kind; a re-wrap verifies the one it was given. On a vault holding
  more than one password, "the credential that has this vault open" and "the
  credential for this slot" are different claims. The vault knows which slot the
  session was opened through, and says so.
- **The credential is simply wrong** — including a key file at the right path
  whose contents are not the enrolled ones. A vault that is already open is no
  evidence about a key file: its master key was unwrapped earlier in the
  session, and the file is not read again until a re-wrap asks for it.

What stays absolute is the check itself. A slot is re-wrapped only when the
offered credential unwraps *that* slot to the master key the session is holding;
a rewrap without that check destroys the only copy of the master key the slot
held, and the owner finds out at the next unlock.

## Auto-lock

Locking is real: it zeroizes the VMK, the CEK, the SEK and every cached
plaintext secret, then drops the in-memory database. Reopening requires a full
unlock.

| Trigger | Default | |
|---|---|---|
| Idle timeout | 15 minutes | ✅ |
| Manual (`Ctrl/Cmd+L`) | — | ✅ |
| System suspend or hibernate | Lock | ◐ — see below |
| OS screen lock / session lock | Lock | ⏳ not observable |
| Application minimised | Off | ⏳ not observable |
| User switch (Windows) | Lock | ⏳ not observable |

**Suspend is seen on the way back, not on the way out.** logind's
`PrepareForSleep` would give advance notice and needs a D-Bus client this build
does not carry. What is free is the return: `Instant` is `CLOCK_MONOTONIC` and
does not advance while the machine is suspended, while `SystemTime` does, so a
thread sampling both and finding the wall clock far ahead has just watched the
machine wake. **The keys were therefore in memory for the whole sleep, and inside
the hibernation image if it hibernated.** The interface says exactly that; it is
not a caveat a user should have to discover. Linux only.

**The screen lock and minimise are not seen at all.** The freedesktop screensaver
and login1 signals are D-Bus, every other platform has its own API, and Tauri
2.11's `WindowEvent` has no minimise variant — the polled `is_minimized()`
underneath it is fed by GTK's `ICONIFIED` state, which a Wayland compositor never
sends. A switch that worked on X11 and silently did nothing on Wayland would be
the same defect in a smaller box, so both are reported to the interface as
`"unobserved"`, and the Vault settings screen disables them and says why.

Active sessions are, by default, **kept alive** across a lock — an
administrator watching a long-running deployment does not want their SSH session
killed because they went for coffee. A per-vault setting can change this to
"freeze input" or "disconnect all", and the choice is recorded in the audit log
when it is changed.

**Idle is Remoter's own traffic, not the desktop's.** It is not OS-level input
idle time — reading that per platform is work this build has not done, and the
interface says so rather than claiming otherwise. What touches the clock is vault
activity *and* session input and output, which is what matters: idle was once
measured from the last vault-touching IPC call, so working inside a terminal was
not activity at all and the vault locked out from under a user who was typing. A
session being watched but not typed into does not count as idle while it is
producing output.

## Rotating and revoking

| Operation | What changes | Re-encrypts the body? | |
|---|---|---|---|
| Change master password | Slot 0 re-wrapped with a new KEK | No | ✅ |
| Change or remove key file | Slot 0 re-wrapped | No | ✅ |
| Add a second password slot | New slot appended | No | ✅ |
| Issue or rotate a recovery key | Recovery slot added or replaced; the old key becomes useless | No | ✅ |
| Disable "remember on this device" | Slot deleted, keychain token erased | No | ✅ |
| **Rotate the Vault Master Key** | New VMK; every slot re-wrapped; body re-encrypted | **Yes** | ✅ |
| Enrol a hardware key | New slot appended | No | ⏳ |
| Revoke a hardware key | Slot deleted | No | ⏳ — though revocation only deletes the entry, so it needs no device |

Rotating the master key is the expensive one, and it is the correct response to "I think a copy of
this file leaked while a key was compromised". Remoter offers it explicitly in
that language rather than hiding it under "advanced" — and says on the screen
what it does **not** do: a leaked copy of the file still opens with the old keys,
including the rolling backups beside it, which the rotating save also rotates.

**A vault must always retain at least one usable slot.** The UI refuses to
delete the last one, and refuses to delete the recovery slot without an explicit
"I understand this removes my last resort" confirmation.

## Credential handling at runtime

A credential's plaintext exists for as short a time as possible.

```rust
// Illustrative. The borrow is scoped; the plaintext is zeroed on drop.
let secret = vault.borrow_secret(cred_id, Purpose::SshPassword)?;
session.authenticate(secret.expose()).await?;
// `secret` dropped here → buffer zeroized
```

Rules enforced in review:

- Secrets are never cached beyond the operation that needs them, unless the user
  has enabled reconnect-without-prompt for that connection — in which case the
  cache is bounded, per-session, and cleared on lock
- Secrets never cross the IPC boundary into the WebView. The frontend asks for
  *an action*; the Rust core performs it
- Secrets never appear in `argv`, environment variables or temporary files. When
  an external helper needs one, it arrives over a pipe
- "Reveal password" is an explicit, audited action, and the revealed value is
  cleared from the clipboard after a configurable timeout (default 30 s)

## SSH agent integration

Remoter can both consume and provide agent services.

**Consuming.** For connections configured to use an agent, Remoter talks to the
platform agent — `SSH_AUTH_SOCK`, Pageant, or the Windows OpenSSH agent — and
the private key never enters Remoter's memory at all. This is the *most* secure
option for SSH and the UI says so.

**Providing.** Remoter can expose keys stored in its own vault to child
processes over an agent socket, with per-key confirmation prompts. This lets
`git`, `rsync` and `scp` launched from a Remoter terminal use vault keys without
those keys ever touching disk. Off by default; each key is opt-in.

Agent forwarding to remote hosts is **off by default** and carries an inline
warning, because a compromised remote host with a forwarded agent can
impersonate the user to every host that key opens.

## Key material in memory

- All key buffers are `Zeroizing<[u8; 32]>` — cleared on drop, with compiler
  fences so the clearing is not optimised away
- `mlock` (Unix) / `VirtualLock` (Windows) on key pages, best-effort: if the
  platform refuses, Remoter logs a warning at startup rather than failing
- Core dumps disabled; `PR_SET_DUMPABLE` cleared on Linux
- At startup on Linux, Remoter checks `ptrace_scope` and warns if the system
  permits arbitrary same-user attach

None of this defeats malware running as the user (see
[threat-model.md](threat-model.md#t9)); all of it shrinks the window.

## What we cannot do for you

There is no escrow key, no support override and no vendor backdoor. If both the
master password and every recovery key are lost, the vault is
cryptographically inaccessible. This is stated at creation time, repeated in the
documentation, and will be repeated by maintainers in every issue that asks. A
recovery channel that works for a forgetful user works equally well for an
attacker who can impersonate one.

**Practical advice we give users instead:**

- Store the recovery key offline — printed, in a safe, or in a *different*
  password manager
- ⏳ Enrol two hardware keys if you use one at all — once hardware keys exist
- Keep the rolling backups; they cost almost nothing
- Export a plaintext archive before a risky operation only if you can protect it
  properly, and delete it afterwards. Remoter warns loudly on plaintext export
  and writes it to the audit log
