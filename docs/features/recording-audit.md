# Session Recording and Audit

Two related but distinct capabilities: recording *what happened inside* a
session, and logging *that a session happened at all*.

## Audit log

An append-only log inside the encrypted vault. Every entry records what
occurred, when, against which node, and with what outcome. It never contains
secrets — enforced at the type level, not by convention.

**Logged events**

| Category | Events |
|---|---|
| Vault | Created, unlocked (with which slot kind), locked, failed unlock, slot added/removed, master key rotated |
| Connections | Created, modified, deleted, moved, credential changed |
| Sessions | Started, ended (with reason), failed, duration, bytes transferred |
| Security | Host key accepted, host key **changed**, certificate pinned, legacy algorithm enabled, agent forwarding enabled |
| Credentials | Used (with purpose and target), revealed, copied to clipboard, exported |
| Transfers | File uploaded, downloaded, deleted, renamed — with paths and sizes |
| Plugins | Installed, loaded (id, version, hash), capability granted, terminated |
| Data | Imported, exported (with a flag for plaintext exports) |

**Deliberately not logged**: passwords, key material, terminal content,
framebuffer content, and file *contents*. The log records that a file moved, not
what was in it.

The log is queryable and filterable in the UI, exportable to JSON or CSV, and
subject to a retention policy (default: keep everything; configurable to a time
window, with the change itself logged).

`OPEN:` The log is append-only by application convention, not cryptographically.
A hash chain — each entry committing to its predecessor — would make tampering
detectable by anyone holding the vault, at a small storage cost. Worth doing
before v1.0 if any user needs the log as compliance evidence; tracked as an
issue.

## Terminal recording

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

## Graphical recording

RDP and VNC sessions record the dirty-rectangle stream with timestamps, in a
container holding the same updates the renderer received.

This is far smaller than video for typical administrative work — a terminal
window on a static desktop changes very little — and it can be transcoded to MP4
or WebM on demand for sharing.

Configurable: frame rate cap, JPEG quality, and a maximum session size after
which recording stops with a warning rather than filling the disk.

## Storage

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

## Policy

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
