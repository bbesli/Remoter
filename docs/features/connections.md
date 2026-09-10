# Connection Management

Organising, finding and operating on connections. The model behind this is in
[data-model.md](../architecture/data-model.md); this document is about what the
user does with it.

## The tree

A hierarchical tree of folders, connections, credentials and groups, with
drag-and-drop reordering and multi-select. Standard expectations apply:
`Ctrl/Cmd+click` and `Shift+click` selection, cut/copy/paste, duplicate, and
undo for every structural change.

Connections show status in the tree — connected, connecting, disconnected,
failed — so the tree doubles as a session overview.

Folders are not merely cosmetic. A folder carries settings and credentials that
everything beneath it inherits, which is what makes the tree worth maintaining
rather than just a list with indentation.

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

Moving a node re-resolves inheritance for its entire subtree. Remoter shows a
diff of what will change *before* applying the move. A drag-and-drop that
silently changes which credentials fifty servers use is exactly the kind of
surprise that costs a tool its users' trust.

## Search

`Ctrl/Cmd+K` opens the command palette; typing filters connections immediately.

- Fuzzy matching across name, hostname, username, description and tags
- Prefix filters: `tag:production`, `proto:rdp`, `host:10.0.`, `user:root`,
  `folder:EU-West`
- Results ranked by recency and frequency of use, so the servers you actually
  touch surface first
- `Enter` connects; `Ctrl/Cmd+Enter` opens the editor instead
- Diacritic-insensitive and case-insensitive across all supported languages —
  searching `munchen` finds `München`, `sunucu` finds `Sunucu`

Search never touches secret fields. It cannot: they are encrypted, and searching
them would require decrypting the whole vault into an index.

## Tags, favourites, recents

Tags are free-form, colour-codable, and shown as chips. They cross-cut the tree:
a `needs-patching` tag can span four folders.

Favourites pin to the top of the sidebar. Recents are per-vault, ordered by last
connection, and can be cleared — a list of recently accessed production servers
is itself sensitive.

## Bulk operations

Multi-select supports: connect all, edit a shared property across the selection,
move, tag, change credential, export, and delete. Bulk edit shows exactly which
fields will change on how many nodes, and asks for confirmation. Every bulk
operation is a single undo step.

## Groups

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

- Tabs are reorderable, closable, and detachable into their own window
- Split view: two or four sessions side by side in one window
- Tab colours inherit from the connection's colour, so production is red at a
  glance
- Middle-click closes; `Ctrl/Cmd+W` closes with a confirmation for sessions with
  unsaved work (an SFTP transfer in progress, for instance)
- A session list panel shows everything open with uptime, protocol, latency and
  transferred bytes
- Reconnect and duplicate are available from the tab context menu

## Quick connect

An address bar for one-off connections that do not belong in the tree:

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
- A "test connection" button verifies reachability and authentication without
  opening a session
- Every field shows its inheritance state
- Cancel discards; there is no autosave, because a half-edited connection that
  silently persists is worse than one that is lost

## Keyboard

| Action | Shortcut |
|---|---|
| Command palette / search | `Ctrl/Cmd+K` |
| New connection | `Ctrl/Cmd+N` |
| New folder | `Ctrl/Cmd+Shift+N` |
| Connect selected | `Enter` |
| Edit selected | `F2` |
| Close tab | `Ctrl/Cmd+W` |
| Next / previous tab | `Ctrl/Cmd+Tab` / `Ctrl/Cmd+Shift+Tab` |
| Jump to tab *n* | `Alt+1`…`Alt+9` |
| Lock vault | `Ctrl/Cmd+L` |
| Toggle sidebar | `Ctrl/Cmd+B` |
| Full screen session | `F11` |

Every action is reachable from the keyboard, and the shortcut map is
user-editable. Terminal sessions capture most keys, so application shortcuts in
a focused terminal use a prefix key (configurable, `Ctrl+Alt` by default) to
avoid stealing `Ctrl+C` from the remote host.
