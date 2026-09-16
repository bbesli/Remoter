# Session Recording and Audit

Two related but distinct capabilities: recording *what happened inside* a
session, and logging *that a session happened at all*.

> **What ships: the audit log, and none of the recording.** The log, its viewer
> and its JSON/CSV export are built and cover most of the event table below.
> **Nothing in this document's *Terminal recording*, *Graphical recording*,
> *Storage* and *Policy* sections exists** — there is no `remoter-record` crate,
> no writer, no player, no encrypted recordings directory and no recording
> indicator. The `RecordingPolicy` field is in the data model and inherits
> correctly through the tree; nothing reads it. Three protocol adapters report
> `recordable: true`, which is a statement that the session *could* be replayed
> and is consumed by no one.

## Audit log — ✅ shipped

An append-only log inside the encrypted vault. Every entry records what
occurred, when, against which node, with what outcome, and — ✅ since schema 3 —
**which operating-system account on which computer wrote it**. It never contains
secrets — `tests/audit_query.rs` runs a full lifecycle and searches the rendered
rows for the credentials it used.

### Who wrote an entry — ✅ shipped

A vault is shared by copying the file and telling a colleague the password, and
from then on the log has to be able to say which of the people who can open it
did what. Each row carries the account and the computer the writing process ran
as, read once at startup the way each operating system states it:

| Platform | Computer | Account |
|---|---|---|
| Windows | `COMPUTERNAME` | `USERNAME`, with `USERDOMAIN` shown as `DOMAIN\user` when it is a real domain — an Active Directory NetBIOS name or `AzureAD` — and dropped when it only repeats the computer name, as it does for a local account |
| macOS | `scutil --get ComputerName`, the name the Sharing pane shows | `id -un`, the process's real user ID resolved through Directory Services |
| Linux and other Unixes | `/proc/sys/kernel/hostname`, then `/etc/hostname` | `id -un`, which follows NSS, so LDAP and SSSD accounts resolve |

Commands run by absolute path; environment variables are the fallback outside
Windows, where they are the platform's own mechanism. The detection is in
`crates/remoter-ipc/src/actor.rs`, and every platform's branch is tested on every
platform by substituting its sources.

The identity is stored once, in an `audit_actor` table, and each row carries its
number — a year of entries written by three people costs three names, not tens
of thousands. The audit screen shows it in a **Who** column, filters by it, and
both exports carry `machine`, `account` and `os` as the last three columns so a
script written against an older export still finds every earlier column where it
was.

**Attribution, not authentication.** These are the names each computer's
operating system reported to the process, and anybody who can unlock the vault
can write any row they like. The column tells apart the people who can open the
file; it does not prove who they are, and the screen's column header says so.
Rows written before schema 3 — or by a process that could not tell who it ran
as — show **Not recorded**, never a blank that would read as *nobody*.

**Logged events**

| Category | Events | |
|---|---|---|
| Vault | Created, unlocked, failed unlock, locked, saved, migrated, slot added/removed, recovery key issued, password changed, master key rotated, KDF upgraded | ✅ |
| Connections | Created, updated, deleted, moved | ✅ |
| Sessions | Started, ended | ✅ |
| Security | Host key or certificate pinned; host key or certificate refused | ✅ |
| Credentials | Stored, removed, used, revealed, exported | ✅ |
| Settings | Changed | ✅ |
| Sessions, detail | Duration and close reason, in the `session_history` table beside the log | ◐ — `bytes_in` and `bytes_out` are written as zero, because nothing counts them |
| Security, detail | Legacy algorithm enabled, agent forwarding enabled | ⏳ |
| Transfers | File uploaded, downloaded — with both paths, the size, and the session it moved over; a failed transfer is a warning | ✅ |
| Transfers, remote changes | File deleted, renamed on the remote host | ⏳ |
| Data | Imported (source and counts, beside the row per node created), exported (format, count and destination — for the connection tree and for this log alike), filed under *Connection records*, and every export under *Warnings* as well | ✅ — plaintext secret export, which would carry its own flag, does not exist |
| Plugins | Installed, loaded, capability granted, terminated | ⏳ — there is no plugin host |

`AuditEvent::ALL` is walked by a round-trip test, so an event added to the enum
without being added to the audit screen's filters fails the suite rather than
quietly dropping out of the interface.

**Deliberately not logged**: passwords, key material, terminal content,
framebuffer content, and file *contents*. The log records that a file moved, not
what was in it.

The log is queryable and filterable in the UI — filtering and counting happen in
SQL rather than by loading the whole log — and exportable to JSON or CSV, with
the export itself recorded. ⏳ There is no retention policy: the log keeps
everything, and there is no setting to bound it by time or size.

### What the log's integrity actually guarantees

Stated precisely, because the honest guarantee is narrower than the one a
feature list would imply:

> The audit log cannot be read or modified by anyone who cannot open the vault.
> It is **not** tamper-evident against someone who can: a person with your
> master password can edit the log, and Remoter cannot detect it.

The log lives inside the vault body, which is encrypted and authenticated as one
unit. That already stops anyone without the key from touching a byte of it — so
a hash chain would add nothing there. And a hash chain keyed under a key the
attacker holds is no obstacle to someone who *does* have the key: they can edit
entries and recompute every link. It would defend against nobody.

Remoter therefore ships **no hash chain** in v1.0, and says what is true instead
of claiming tamper evidence it does not provide. The reasoning in full, and the
forward-secure construction that *would* work, are in
[ADR-0012](../architecture/decisions/0012-audit-log-integrity.md).

That construction — an evolving log key, with each key destroyed after use, so
that compromising the vault today cannot forge yesterday's entries — is
specified and ready. It gets built when the log acquires a second reader: team
synchronisation (v2), or a user with a concrete compliance requirement. In a
single-user local tool the vault holder *is* the auditor, and a mechanism whose
entire purpose is to constrain the vault holder has no one to protect.

**For compliance users who need it before then**: an opt-in **external audit
sink** writes entries to syslog or an append-only file outside the vault, sealed
with the forward-secure scheme. It is off by default and warns clearly, because
an external log is a copy of your connection inventory living outside the
vault's protection. That trade is the user's to make knowingly.

## Terminal recording — ⏳ not built

None of this section exists. It is the design, kept because it is the design.

SSH and other terminal sessions are recorded in
[asciicast v2](https://docs.asciinema.org/manual/asciicast/v2/), the format
asciinema uses.

It is the right choice for several reasons: it is newline-delimited JSON, so it
is written incrementally and a crash costs at most the last line rather than the
whole recording; it is plain text, so recordings are greppable and diffable; it
is tiny compared to video; and an ecosystem of players already exists.

```
{"version":2,"width":120,"height":32,"timestamp":1757462400,
 "title":"web-01.eu.acme.internal","env":{"TERM":"xterm-256color"}}
[0.248135,"o","Last login: Wed Sep 10 09:14:22 2026 from 10.0.0.4\r\n"]
[0.512890,"o","deploy@web-01:~$ "]
[2.104772,"i","systemctl status nginx\r"]
[2.106001,"o","systemctl status nginx\r\n"]
```

Remoter records both output (`"o"`) and input (`"i"`), which plain asciinema
does not. Input capture is what makes a recording useful for auditing rather
than only for demonstrations — and it is also why it could capture a password
typed at a `sudo` prompt.

**Password redaction.** The recorder watches for terminal echo being disabled,
which is what happens at a password prompt, and suppresses input capture until
echo returns. This catches `sudo`, `su`, `ssh` and most well-behaved programs.
It is a mitigation, not a guarantee: a program that reads a password with echo
on will have it recorded. The UI says exactly that where recording is enabled,
because a user who believes redaction is complete will behave accordingly.

**Playback** is built in: play, pause, seek, variable speed, and full-text
search across the recording. Recordings export as `.cast` for asciinema, or
render to SVG or GIF.

## Graphical recording — ⏳ not built

RDP and VNC sessions record the dirty-rectangle stream with timestamps, in a
container holding the same updates the renderer received.

This is far smaller than video for typical administrative work — a terminal
window on a static desktop changes very little — and it can be transcoded to MP4
or WebM on demand for sharing.

Configurable: frame rate cap, JPEG quality, and a maximum session size after
which recording stops with a warning rather than filling the disk.

## Storage — ⏳ not built

No recordings directory is created. The `session_history` table below *does*
exist and is written on every session start and end — it is the index waiting
for something to index, and its `recording` column has never been set.

Recordings live **outside** the vault, in a configurable directory, because they
grow large and a vault is designed to be small and rewritten atomically.

They are encrypted individually with a key derived from the Vault Master Key, so
they are readable only while the vault is unlocked. The index — which recording
belongs to which session — lives in the vault's `session_history` table.

```
~/.local/share/remoter/recordings/
  <vault-id>/
    2026/09/10/
      <session-uuid>.cast.enc          terminal
      <session-uuid>.rfr.enc           framebuffer
      <session-uuid>.meta.json.enc     index entry
```

Retention is configurable by age, by total size, or unlimited. Deletion is
logged. There is no automatic upload anywhere.

## Policy — ⏳ not built

`RecordingPolicy` exists in `remoter-core` with these four values and inherits
through the tree exactly as described. Nothing reads it, so all four behave
identically: no recording, and no notice.

Recording policy is inheritable through the folder tree, so an organisation sets
it once:

| Policy | Behaviour |
|---|---|
| `Never` | No recording |
| `Ask` | Prompt at session start |
| `Always` | Record, with a notice before the session opens |
| `Required` | Record; refuse to connect if recording cannot start |

`Required` exists for compliance contexts where an unrecorded session is worse
than no session.

**Consent and disclosure.** The user is always told before a session is
recorded, never after. A recording indicator is visible in the tab for the
session's entire duration. There is no hidden recording mode and there will not
be one — a tool that can silently record its user is a tool that can be used
against them.

Where a session is recorded, the *remote* party is not automatically informed.
Users recording sessions on systems they do not own should be aware that local
law may require disclosure; the documentation says so, and that is as far as an
application can reasonably go.
