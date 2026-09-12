# Connection Management

Organising, finding and operating on connections. The model behind this is in
[data-model.md](../architecture/data-model.md); this document is about what the
user does with it.

> **What ships.** The tree, inheritance with provenance, search and the command
> palette, tags and favourites, the generated connection editor, and the
> keyboard model. ⏳ **Not built:** multi-select and everything that depends on
> it (bulk edit, bulk connect), cut/copy/paste, undo, quick connect, "test
> connection", the inheritance diff before a move, session groups and broadcast
> typing, tab detach and split view. Each is marked in place below.

## The tree

A hierarchical tree of folders, connections, credentials and groups, with
drag-and-drop reordering. ⏳ Multi-select is not implemented, and neither is
`Ctrl/Cmd+click` or `Shift+click` selection, cut/copy/paste, duplicate, or undo
for structural changes — a move that went to the wrong folder is undone by
dragging it back.

⏳ Connections do **not** show status in the tree. A row knows nothing about the
session store, so the tree is an inventory rather than a session overview — the
live status dot is on the tab, not on the row that opened it.

Folders are not merely cosmetic. A folder carries settings and credentials that
everything beneath it inherits, which is what makes the tree worth maintaining
rather than just a list with indentation.

### Dragging a row

A row that holds things and a row that does not divide their height
differently, because they answer different questions:

- A **folder or group** splits in three. The outer quarters mean "between these
  two rows" and the middle half means "inside this one". A group takes the
  middle band and refuses it, naming the difference — it wears the folder glyph
  and holds nothing, so a gesture aimed at its inside has to be answered rather
  than quietly turned into something else.
- Everything else splits in **two**: the top half is above it, the bottom half
  below it. There is no inside a connection, so there is no band that means
  one. Giving connections a middle band was the reason reordering read as
  broken: the natural aim — at the row you want to sit next to — landed in a
  band whose only possible answer was a refusal about containment.

While the pointer is down it carries a chip naming the entry, and the chip
carries the reason when the target under it will not take the drop. A refusal
is explained *below* the tree, so the rows do not move under the pointer
between one attempt and the next.

Resting on a closed folder opens it after a moment; dragging toward the top or
bottom edge of the sidebar scrolls it; `Escape` abandons the drag. The pointer
is captured once the press becomes a drag, and the target is found by
hit-testing the point rather than by reading the event's target — see
[ADR-0014](../architecture/decisions/0014-drag-and-drop-on-windows.md) for why
that distinction is the difference between a drag that works and one that works
only on the machine it was written on.

`Ctrl/Cmd` with an arrow key does the same four moves without a pointer, and is
the accessible equivalent: Up and Down reorder among siblings, Left moves the
entry out of its folder, Right moves it into the folder directly above it.

## Property inheritance in the UI

Every inherited field shows where its value came from, with a one-click
override:

```
  Username    ┌────────────────────────────────────┐
              │ svc-deploy                         │   ⓘ from 📁 Datacentre EU-West
              └────────────────────────────────────┘   [Override here]

  Port        ┌────────────────────────────────────┐
              │ 2222                               │   ● set on this connection
              └────────────────────────────────────┘   [Revert to inherited (22)]
```

Provenance display is not decoration. Inheritance without it produces the single
most common confusion in tools that have this feature: a connection that logs in
as the wrong user for reasons the user cannot see. Any inherited value must be
traceable to its source in one glance.

Moving a node re-resolves inheritance for its entire subtree. ⏳ Remoter does
**not** yet show a diff of what will change before applying the move — the code
that would compute it does not exist, and the tree says so in a comment rather
than pretending otherwise. A drag-and-drop that silently changes which
credentials fifty servers use is exactly the kind of surprise that costs a tool
its users' trust, so this is the gap in this screen that matters most.

## Search

`Ctrl/Cmd+K` opens the command palette; typing filters connections immediately.

- Fuzzy matching across name, hostname, username, description and tags
- Prefix filters: `tag:production`, `proto:rdp`, `host:10.0.`, `user:root`.
  ⏳ `folder:` is not among them
- ⏳ Results are **not** ranked by recency or frequency — nothing records when a
  node was last used
- `Enter` connects; `Ctrl/Cmd+Enter` opens the editor instead
- Diacritic-insensitive and case-insensitive across all supported languages —
  and case folding happens in the right language, which is not always the
  reader's. A name or a tag folds in the reader's language; a hostname,
  username, protocol name or shortcut folds invariantly, because under Turkish
  rules `VDI-GW` folds to `vdı-gw` and a Turkish reader searching `vdi` would
  otherwise find nothing an English colleague finds with the same keystrokes

Search never touches secret fields. It cannot: they are encrypted, and searching
them would require decrypting the whole vault into an index.

## Tags, favourites, recents

Tags are free-form and cross-cut the tree: a `needs-patching` tag can span four
folders. ⏳ They are not colour-codable.

Favourites pin to the top of the sidebar, as a section above the tree proper. A
favourite is a *projection of the `favourite` tag* rather than a flag of its
own, which is why a favourite row cannot be dropped onto — it is not a place in
the tree. ⏳ There are no per-vault connection recents; the only recents list is
of recently opened **vault files**, on the picker, and that one can be cleared.

## Bulk operations — ⏳ not built

There is no multi-select, so none of this exists: no connect-all, no shared-property
edit, no bulk move, tag, credential change, export or delete.

Multi-select would support: connect all, edit a shared property across the
selection, move, tag, change credential, export, and delete. Bulk edit shows
exactly which fields will change on how many nodes, and asks for confirmation.
Every bulk operation is a single undo step.

## Groups — ⏳ not built

`NodeKind::Group` exists in `remoter-core` with its `broadcast` flag, and the
tree stores one. Nothing opens one, no layout is applied, and broadcast typing
has no implementation — so the safeguards below guard nothing yet.

A group opens several connections at once into a chosen layout — tabs, split
horizontally or vertically, or a grid. Useful for a cluster: open all six web
servers in a 2×3 grid and watch them together.

**Broadcast typing** sends keystrokes to every terminal in the group. It is
genuinely useful and genuinely dangerous, so:

- Off by default, enabled per session, never persisted as a default
- A persistent, unmissable banner across the top of the window while active
- Disabled entirely for sessions in a folder tagged `production` unless
  explicitly permitted in that folder's settings
- Every broadcast session is recorded in the audit log

## Sessions and tabs

- Tabs are reorderable and closable. ⏳ Detaching into their own window is not
  built
- ⏳ Split view is not built
- Tab colours inherit from the connection's colour, so production is red at a
  glance
- `Ctrl/Cmd+W` closes, and closing asks first when the session has work in
  flight — a transfer running, or a framebuffer tab a click would otherwise
  disconnect silently
- A session panel lists what is open, alongside the tunnels the vault is holding
  ⏳ Uptime, latency and transferred bytes are not shown
- ⏳ Reconnect and duplicate are not in the tab context menu

## Quick connect — ⏳ not built

There is no address bar. A connection has to exist in the tree before it can be
opened, which is the opposite of the "connect first, organise afterwards" order
below. The syntax is the design:

```
ssh://root@10.0.0.5:2222
rdp://CONTOSO\admin@ctso-dc01
vnc://192.168.1.50:5901
sftp://deploy@files.example.com
```

Quick connections appear in Recents and can be promoted into the tree with one
click, which is how most connections should get created — connect first,
organise afterwards.

## Editing

The connection editor is a form generated from the protocol adapter's settings
schema, so a plugin protocol gets exactly the same editing experience as SSH.

- Changes are validated live against the schema
- ⏳ There is no "test connection" button
- Every field shows its inheritance state
- The editor also states, per protocol, what *this build's* adapter cannot do —
  RDP's absent clipboard and redirection channels, VNC's fixed size — rather
  than omitting those settings and letting the absence read as an oversight
- ⏳ There is no gateway field, so a jump chain cannot be configured here
- Cancel discards; there is no autosave, because a half-edited connection that
  silently persists is worse than one that is lost

## Keyboard

| Action | Shortcut | |
|---|---|---|
| Command palette / search | `Ctrl/Cmd+K` | ✅ |
| Shortcut cheat sheet | `?` | ✅ |
| New connection | `Ctrl/Cmd+N` | ✅ |
| New folder | `Ctrl/Cmd+Shift+N` | ✅ |
| Connect selected | `Enter` | ✅ tree-local |
| Edit selected | `F2` | ✅ tree-local |
| Close tab | `Ctrl/Cmd+W` | ✅ |
| Next tab | `Ctrl/Cmd+Tab` | ✅ |
| Previous tab | `Ctrl/Cmd+Shift+Tab` | ⏳ |
| Jump to tab *n* | `Alt+1`…`Alt+9` | ✅ |
| Lock vault | `Ctrl/Cmd+L` | ✅ |
| Toggle sidebar | `Ctrl/Cmd+B` | ✅ |
| Full screen session | `F11` | ✅ |

The shortcut map is user-editable, and the settings screen reports three kinds
of problem rather than accepting a binding that will not work: a **duplicate**
of another binding, a **desktop** conflict where the window manager takes the
key first (`Ctrl+Tab` on GNOME, which Remoter yields rather than fights), and
**terminal-reserved**.

That last one is how the "steal `Ctrl+C` from the remote host" problem is
actually solved — not with a prefix key. A shortcut whose scope is *universal*
cannot be bound to `Ctrl+C`, `Ctrl+D` or `Alt+F` at all: those belong to the
remote host, a focused terminal has to receive them, and the binding is refused
with that sentence. ⏳ A configurable prefix key does not exist.
