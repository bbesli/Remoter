# SFTP Command Surface

What `remoter-ipc` must expose so that a dual-pane file manager can be built on
the SFTP engine that already exists.

This document specifies. `crates/remoter-ipc/src/sftp.rs` implements it; where
the implementation went beyond what is written here, [Where the
implementation differs](#where-the-implementation-differs) says so and why.

## Where this sits

`crates/remoter-proto-ssh/src/sftp.rs` is finished and tested: `SftpBrowser`
does the browsing and the transfers, `TransferQueue` holds the work, and
`run_queue` drains it. The commands, the DTOs and the interface above that line
now exist too, and a user reaches them by two routes — both of them a *session*,
because a pane is a channel on one:

```
apps/desktop/ui  ──▶  remoter-ipc  ──▶  remoter-proto-ssh::sftp
   exists              exists              exists
```

- An `sftp` connection opened from the tree runs the ordinary pipeline and gets
  a session whose `capabilities.kind` is `file_transfer`. Its tab draws the file
  manager instead of a terminal
  (`apps/desktop/ui/src/features/files/FileSessionHost.tsx`).
- A session that is already connected and whose adapter reports
  `capabilities.file_transfer` — SSH — gets a pane docked under its terminal,
  from the Files control in the tab strip. Every docked pane stays mounted while
  its session runs, including while another tab is in front: unmounting it would
  close the pane, and closing the pane stops the drain task mid-transfer.

The layering rule of CLAUDE.md §3 applies unchanged: `remoter-ipc` is a seam. It
maps DTOs, checks permissions and forwards. If a decision is being written in it
— what a resume is safe on, what a listing cap is, how a path is joined — that
decision belongs one layer down, and `sftp.rs` has already made most of them.

## The session it runs on

An SFTP browser is **not** a second connection to the same host. `SftpBrowser::open`
takes an `Arc<SshConnection>` and opens a subsystem channel on it (RFC 4254
§6.5), so a file pane on a host the user already has a shell on costs one
channel, not one handshake, one host-key check and one authentication.

Two consequences the command surface has to encode:

1. **A file pane is attached to a session, not to a node.** The command takes a
   `SessionId` where one exists. Opening a file manager on a node with no open
   session runs the full pipeline of `session-pipeline.md` first and registers a
   session of kind `FileTransfer`, so it appears in the session list, counts
   against the session cap, and is closed by the same supervisor as everything
   else. There is no second lifetime to get wrong.
2. **Closing the shell must not silently kill the file pane, and vice versa.**
   Both hold an `Arc<SshConnection>`; the connection ends when the last share is
   dropped and the supervisor cancels the session.

## Naming and shape

Commands are `sftp_*`, following `session_*` and `tunnel_*`. Every one returns
`Result<T, IpcError>`, and every `IpcError` names what failed, where, and what
to do next — `session-pipeline.md`'s failure taxonomy applies to a file manager
exactly as it applies to a connection. "Transfer failed" is not an acceptable
outcome.

Paths crossing this boundary are remote paths in SFTP form: `/`-separated
whatever the server runs on, as `join_path` already assumes. Local paths are
whatever the platform uses and are only ever produced by a file picker or by
`local_name_for`, never by concatenating a server-supplied string.

## Browsing

| Command | Takes | Returns |
|---|---|---|
| `sftp_open` | `session_id` | `SftpPaneDto` — pane id, the server's idea of the home directory |
| `sftp_close` | `pane_id` | `()` |
| `sftp_list` | `pane_id`, `path` | `Vec<DirectoryEntryDto>` |
| `sftp_stat` | `pane_id`, `path` | `DirectoryEntryDto` |
| `sftp_canonicalize` | `pane_id`, `path` | `ResolvedPathDto` |
| `sftp_read_link` | `pane_id`, `path` | `ResolvedPathDto` |
| `sftp_mkdir` | `pane_id`, `path` | `()` |
| `sftp_rename` | `pane_id`, `from`, `to` | `()` |
| `sftp_delete` | `pane_id`, `path`, `recursive` | `SftpDeleteReportDto` |
| `sftp_set_permissions` | `pane_id`, `path`, `mode` | `()` |
| `sftp_symlink` | `pane_id`, `path`, `target` | `()` |

`ResolvedPathDto` carries `path` and `displayPath`, like every other DTO here.
Both of these commands take a path from the user and get a path back from the
*server*, and the server's answer is text it chose — a symbolic link may point
at `/srv/annex\u{202E}txt.exe`, and a canonicalised path travels through
whatever the server's own links resolve to. They returned a bare `String` until
that was noticed, which made them the one place a whole remote path reached the
interface with no escaped twin.

`DirectoryEntryDto` is `DirectoryEntry` with camelCase field names: `name`,
`path`, `kind` (`"file" | "directory" | "symlink" | "other"`), `size`,
`permissions`, `modified`. **Every string in it is server-supplied and
untrusted.** The frontend renders it as text, never as markup, and never uses
`dangerouslySetInnerHTML` (CLAUDE.md §6). A file called
`<img src=x onerror=...>` is a legal file name.

Four things this layer must get right, none of which is optional:

**A listing is cancellable.** `SftpBrowser::list` already takes a
`CancellationToken`, because `readdir` runs until the server says it is done and
a server can decline to. The pane holds a token per in-flight listing and
cancels it when the user navigates away. Without that, clicking through six
directories leaves six listings accumulating in memory against six caps.

**The caps are the server's problem made visible, not hidden.**
`MAX_DIRECTORY_ENTRIES` (250 000) and `MAX_DIRECTORY_BYTES` (32 MiB) come back
as a `ProtocolError::ProtocolViolation` naming the limit. The command maps it to
an `IpcError` that says which limit was hit — a user whose build directory has
400 000 files needs to be told that, not shown an empty pane.

**Deleting a directory is not one call.** `SftpBrowser` has `remove_file` and
`remove_directory`, and SFTP's `SSH_FXP_RMDIR` fails on a non-empty directory.
Recursive delete is therefore a walk, and a walk that is interrupted leaves the
tree half-removed. So: `recursive` is explicit, the walk is cancellable, and
`SftpDeleteReportDto` reports what was removed and what was not rather than a
bare `Ok`. A file manager that says "done" after deleting nine of twelve files
has lied.

**Rename is not move-across-filesystems.** `SSH_FXP_RENAME` fails across
devices on most servers. The error must say so and offer copy-then-delete as the
next action, rather than reporting a permission problem the user does not have.

## The transfer queue

The queue already exists. What the command surface adds is a way to put work
into it, watch it, and stop it.

| Command | Takes | Returns |
|---|---|---|
| `sftp_preflight` | `pane_id`, `Vec<TransferRequestDto>` | `Vec<TransferPreflightDto>` |
| `sftp_enqueue` | `pane_id`, `Vec<TransferRequestDto>` | `EnqueueReportDto` |
| `sftp_transfers` | `pane_id` | `Vec<TransferStatusDto>` |
| `sftp_transfer_cancel` | `pane_id`, `transfer_id` | `()` |
| `sftp_transfer_cancel_all` | `pane_id` | `()` |
| `sftp_transfer_retry` | `pane_id`, `transfer_id` | `TransferId` |

`TransferRequestDto` is `direction` (`"upload" | "download"`), `remote`,
`local`, `resume`. `TransferStatusDto` is the id, the request, and a state:
`"queued"`, `"running"` with `done` and optional `total`, `"completed"` with
`bytes`, `"failed"` with a `SessionFailureDto`, or `"cancelled"`.

`sftp_transfer_retry` enqueues a **new** transfer from a finished one's request
and returns the new id. It does not resurrect the old entry: a terminal state
stays terminal, so the history of what happened stays readable.

### Nothing is queued before the question is asked

`sftp_preflight` answers, for each request in a batch and without queueing any
of it, the question a destructive action has to ask first: **is something
already there, and what is it?** A transfer truncates its destination — an
upload always, and a download whose resume offset is zero — and there is no
trash on either side.

`TransferPreflightDto` is `index`, `direction`, `destinationDisplay`, `exists`,
`size`, `modified`, `directory`, `sourceIsFolder` and an optional `problem`.
Three of those encode answers that must never be collapsed into one another:

* `exists: false` with no `problem` — nothing is there.
* `exists: false` **with** a `problem` — nobody could look. A local destination
  that could not be read is `sftp.local-destination-unreadable`, which is
  deliberately not fatal: the transfer is still offered, and the interface says
  which destinations it can claim nothing about. Drawing this as the first case
  is how a file manager quietly replaces a file it said was absent.
* `directory: true` — a transfer cannot replace a folder, so such a request is
  dropped from the batch rather than queued to fail.

The command is read-only by construction: it creates nothing, not even the
directory a folder transfer would need. That is what lets the confirmation
happen *before* the work rather than after it.

It is a check and not a lock. A file created in the gap between the preflight
and the enqueue is still overwritten; SFTP offers no atomic alternative across
the operations a transfer needs, and the case this closes is the one that
happens — the file that was already there when the button was pressed.

### An enqueue reports, because a folder can come back short

`sftp_enqueue` is asynchronous and returns `EnqueueReportDto`:
`transferIds`, `foldersExpanded`, `directoriesCreated`, `skipped` and
`limitReached`. A list of ids answered "how many" and nothing else, which
stopped being enough the moment a folder became transferable — one request now
expands into one transfer per file beneath it, and the walk that does it can
refuse an entry and stop at its own limit. A caller holding only ids would
report a partial result as a success.

### Progress must not be polled

`sftp_transfers` exists for the initial render and for reconciliation. It is not
how a progress bar is driven. A transfer reports progress every
`PROGRESS_INTERVAL_BYTES` (512 KiB) — chosen because a per-chunk event on a fast
link is thousands of events a second, all of which the interface would have to
render — and those already leave through the session's `EventSink` as
`SessionEvent::Progress`. The pane subscribes once, exactly as a terminal
subscribes to its output.

`ProgressUpdate` carries `operation`, `done`, `total` and `detail`. `operation`
is a stable catalogue key. `detail` is the file being transferred and is
therefore a **server-supplied path**: it is rendered as text, and it is the one
field in the struct that an attacker chooses.

### Cancellation must reach a transfer that is moving

This is the requirement most easily got wrong, and `run_queue` already
implements it: the session's token is *raced* against the transfer, not checked
between files. A 40 GB download that keeps writing after the user closed the tab
is a leaked task holding a socket and a file handle, which CLAUDE.md §5 calls a
correctness bug rather than an untidiness.

The command layer must not weaken that. `sftp_close` cancels the pane's token
and waits for the drain task to finish before returning, so that "the pane is
closed" and "nothing is still writing to disk" are the same moment.

### Resume, and why it is conservative

`resume_offset` is already written and already refuses more often than a user
might expect. It resumes only when the destination is **strictly shorter** than
a source whose size is known. Anything else — a destination at least as long as
the source, or a source of unknown size — starts over.

The reason is asymmetric cost: appending to the wrong file corrupts it silently,
and re-copying a file costs time. The command surface must not offer a setting
that overrides this, and the interface must not present resume as a guarantee.
Where a resume was requested and declined, say so — "starting over: the local
file is not shorter than the remote one" is a sentence a user can act on.

There is no checksum verification, and that is a real gap rather than an
oversight. A resumed transfer trusts that the first *n* bytes on disk are the
first *n* bytes of the remote file. SFTP has no standard checksum request in the
version `russh-sftp` speaks; some servers offer `check-file@openssh.com` as an
extension. Until that is implemented, resume is an optimisation the user opts
into, off by default.

## Two panes, and what crosses between them

The local pane is not SFTP at all — it is the local filesystem, and it needs its
own small surface (`fs_list`, `fs_mkdir`, `fs_rename`, `fs_delete`) or a
platform file picker. It is listed here only so that its absence from the SFTP
commands is a decision rather than a gap.

The rule that matters is the one `local_name_for` already enforces: **a remote
name never chooses a local path.** Only the last component of a server-supplied
path is kept, and anything that still looks like a traversal is refused. A file
manager that writes where the server told it to is a file manager that can be
told to overwrite `~/.ssh/authorized_keys`. Every download destination goes
through that function; none is built by joining strings.

A drag from remote to local is `sftp_enqueue` with `direction: "download"` and a
local path from the picker. A drag the other way is the same with `"upload"`.

Dragging a *directory* is a walk on the source side that expands into one
`TransferRequest` per file, with the directories created first — and the walk
is bounded and cancellable for the same reason a listing is. It is implemented:
`SftpBrowser::plan_download_tree` and `plan_upload_tree`, bounded at
`MAX_TREE_TRANSFERS` (10 000 files) and `MAX_TREE_DEPTH` (64 levels), and
cancelled by the pane's token. It follows the same four rules the recursive
delete does — child paths composed from the entry's name and never from the
`path` the server put in the listing, every name held to `is_safe_local_name`
before it becomes part of a local path, symbolic links unlinked in the walk
rather than followed, and nothing dropped without being reported.

The one asymmetry is deliberate: the **root** of a transfer follows a symbolic
link, because the user pointed at that entry and a link to a directory is a
directory to them, while every link the walk itself finds is the server's
choice and is skipped. That is the rule `cp -r link/` has.

## What this does not cover

- **Clipboard file transfer.** `ClipboardPolicy::files` is off by default so a
  compromised host cannot drop files into the local clipboard. That is a
  separate decision from an explicit drag, and turning one on does not turn the
  other on.
- **Editing a remote file in place.** Download, watch, re-upload is a feature
  with its own conflict-resolution questions, and it is not on the current
  milestone.
- **`scp`.** OpenSSH 9 made `scp` use the SFTP protocol underneath. There is
  nothing to add.
- **A second SFTP session for parallelism.** `TransferQueue::concurrency` runs
  several transfers on one session, which is what helps on a high-latency link.
  A second session is a second authentication, and the gain does not pay for it.

## Where the implementation differs

Written down rather than discovered in review. Everything here is an addition
to what is above, not a contradiction of it.

**A file pane is opened by `session_open` on an `sftp` connection.** The gate in
`session.rs` accepts `ssh` and `sftp` and refuses everything else by name. An
`sftp` session runs the identical pipeline — the same chain, the same host key
check, the same credential — and then holds the connection open instead of
opening a shell (`remoter_proto_ssh::sftp::run_sftp_session`). It registers with
`SessionKind::FileTransfer`, so it is in the session list, counts against the
cap, and is closed by the same supervisor. `sftp_open` then attaches a pane to
it, exactly as it attaches one to a session that has a shell.

**`TransferRequestDto` names a local *folder* as well as a local file.**
`localDirectory` is downloads only, and where it is used the file name comes
from `local_name_for` rather than from anything the server said. The alternative
— having the interface join a server-supplied name onto a folder — is the one
thing this document is most emphatic must not happen, and a field is a cheaper
guarantee than a convention.

**`DirectoryEntryDto` carries two forms of every server-supplied string.**
`name`/`path` are raw and are what go back on the wire; `displayName`/
`displayPath`, `user` and `group` are escaped, and a `risks` object says which
of `control`, `bidi`, `invisible` and `separator` was found. A name is never
hidden for having one — a file called `report\u{202E}fdp.exe` exists and the
user may want it — but the row says so, and the escaped form is never used to
address anything. `mode` is the `drwxr-xr-x` rendering, produced once here so
that every pane shows the set-user-id and sticky bits the same way.

**`TransferStatusDto` is flat, and carries what the transfer decided and when.**
`transferId`, `direction`, `remote`, `remoteDisplay`, `local`, `localDisplay`,
`resume`, `state`, a `start` block holding `resumeRequested`, `resumeFrom`,
`total`, `resumeDeclined` and a `note`, and four timestamps in milliseconds
since the Unix epoch: `queuedAtMs`, `startedAtMs`, `finishedAtMs` and
`progressAtMs`.

The timestamps are what let a row say how fast, how long and how much longer. A
byte count and a percentage answer "how much", and the question somebody
watching a transfer has is "how long"; without a clock on the DTO the interface
had nothing to compute one from but its own successive readings, which is a
timer and a piece of derived state where a subtraction would do. `progressAtMs`
is separate from `startedAtMs` because it is the only thing that tells a stalled
transfer from a slow one — a rate averaged over a transfer's whole life cannot. The note is the sentence this document asks for —
"starting over: the local file is not shorter than the remote one" — and it is
absent when there was simply nothing to continue, because a notice that fires on
every first attempt is a notice people learn to ignore.

**A listing is cancelled by the next one.** Each pane holds one listing token;
`sftp_list` cancels the previous listing before it starts its own, and
`sftp_close` cancels whatever is outstanding. That is what "the pane cancels a
listing when the user navigates away" means when navigating away is itself a
command.

**A non-recursive delete on a non-empty directory has its own message.**
`sftp.directory-not-empty`, rather than the generic failure a server reports,
which reads as a permission problem the user does not have.

**Two bounds on the recursive walk**, alongside the listing caps: 250 000
entries touched and 64 levels deep. A removal that has passed either has met
something nobody meant to point it at.

**Progress detail is escaped at the session layer.** `ProgressUpdate::detail` is
a remote path, and it is escaped in `forward_events` before it reaches the tab —
the only place that knows the field is remote.

**The local pane is still absent.** `fs_list` and friends are not implemented,
as [Two panes](#two-panes-and-what-crosses-between-them) already allows: the
local side is a file picker's business or its own small surface, and it is not
part of the SFTP command surface. What the interface has instead is the
platform picker, the folder it last downloaded into (`settings.fileDownloadFolder`,
which travels with the machine rather than with the vault), and the platform's
own downloads folder as the suggestion before anyone has chosen one.

**`sftp_symlink` has no caller.** The core implements and tests it; nothing in
this build creates a symbolic link, so the frontend deliberately does not wrap
it. A wrapper with no caller reads as a capability and is not one — which is
what the other four unreachable commands on this surface turned out to be.
`sftp_stat`, `sftp_read_link` and `sftp_set_permissions` now have a screen (the
properties dialog), and `sftp_canonicalize` is what makes a relative path typed
into the path box resolve.
