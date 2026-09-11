# Information Architecture

Screens, navigation and the keyboard model.

## Window layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Remoter — Acme Production           [🔒 unlocked]   ⚙  ?   ─ □ ✕        │  title bar
├────────────────┬─────────────────────────────────────────────────────────┤
│ 🔍 Search…     │  web-01 ×  │  db-01 ×  │  ctso-dc01 ×  │  +            │  tabs
│                ├─────────────────────────────────────────────────────────┤
│ ⭐ Favourites  │                                                          │
│   web-01       │                                                          │
│   jump.acme.io │                                                          │
│                │                                                          │
│ 📁 Datacentre  │              active session content                       │
│  └📁 Web tier  │              (terminal / framebuffer / file grid)         │
│    🖥 web-01 ●  │                                                          │
│    🖥 web-02   │                                                          │
│  └📁 DB tier   │                                                          │
│    🖥 db-01  ● │                                                          │
│  🔑 svc-deploy │                                                          │
│                │                                                          │
│ 📁 Customers   ├─────────────────────────────────────────────────────────┤
│                │  ⬤ Connected · 10.0.4.12 · 14 ms · ↓2.1 MB ↑340 KB      │  status
├────────────────┴─────────────────────────────────────────────────────────┤
│  3 sessions · 2 tunnels · vault locks in 12:04                            │  footer
└──────────────────────────────────────────────────────────────────────────┘
```

The sidebar collapses to icons or hides entirely. The inspector — connection
properties, inheritance provenance, session statistics — opens on the right as a
third column or as an overlay on narrow windows.

The session area draws whichever of the three kinds of content the session
itself reports — terminal, framebuffer, file grid — never a guess from the
protocol name, so a plugin protocol is treated exactly as a built-in one. The
file grid reaches it two ways, and both of them are a session rather than a
screen of their own:

- an `sftp` connection opened from the tree fills its whole tab with it;
- a session that is already connected and carries files — SSH — docks a pane
  under its terminal from the tab strip's Files control. That pane is one more
  channel on the connection the tab already authenticated (RFC 4254 §6.5), not
  a second sign-in, which is why the control is offered per session and not as
  a destination in the title bar.

A docked pane belongs to its tab and keeps running while another tab is in
front: it holds a transfer queue, and a tab switch must not cancel a copy.

Between the tab strip and the session content sit the rows of chrome that belong
to the session — the warning count, a refused keystroke, and for a graphical
session its own toolbar: Ctrl+Alt+Del, Alt+Tab and the scale controls. They are
rows, not overlays, and that is a rule rather than a preference: **a remote
desktop uses all four of its edges and all four of its corners**, so nothing of
ours is drawn on top of one. `docs/ui/design-system.md` gives the reasoning and
the three blocking questions that are allowed to cover a session.

## Screens

| Screen | Purpose |
|---|---|
| **Vault picker** | Shown at launch. Recent vaults, open from file, create new |
| **Unlock** | Slot selection and credential entry |
| **Main window** | The layout above — the application's home |
| **Connection editor** | Modal or inspector; form generated from the protocol's settings schema |
| **Vault settings** | Key slots, auto-lock, recording policy, backups |
| **Application settings** | Theme, language, shortcuts, plugins, updates |
| **Import wizard** | The seven-step flow in [import-export.md](../features/import-export.md) |
| **Audit log viewer** | Filterable, searchable, exportable |
| **Recording player** | Playback with seek, speed, and search |
| **Session panel** | Everything open, with uptime, latency, throughput |
| **Tunnel panel** | Active and persistent forwards |

## Navigation model

Three ways to reach a connection, because different users work differently:

1. **The tree** — browsing, for people who know where things live
2. **Search (`Ctrl/Cmd+K`)** — typing, for people who know the name
3. **Recents and favourites** — for the twenty machines that account for most
   sessions

All three are always available. None is privileged.

## Keyboard model

The full shortcut table is in
[connections.md](../features/connections.md#keyboard). The design constraint
that shapes it:

**A focused terminal must receive almost every keystroke.** `Ctrl+C`, `Ctrl+D`,
`Ctrl+W`, `Alt+F` all belong to the remote host. Application shortcuts inside a
focused session therefore use a configurable prefix (`Ctrl+Alt` by default),
and the small set of universal shortcuts — lock the vault, the command palette
— are chosen not to collide with common terminal bindings.

Every action is keyboard-reachable, every shortcut is user-editable, and the
current bindings are visible in a searchable cheat sheet (`?`).

## States that must be designed, not defaulted

The states that get skipped in most applications and then feel broken:

| State | Requirement |
|---|---|
| **Empty vault** | Not a blank screen. Offer: create a connection, import from another tool, open a different vault |
| **Connecting** | Show which stage — resolving, connecting, authenticating, negotiating — and which hop. A spinner alone tells the user nothing |
| **Connection failed** | The specific error from the taxonomy in [session-pipeline.md](../architecture/session-pipeline.md#failure-taxonomy), plus the next action |
| **Reconnecting** | Countdown, attempt number, and a cancel button |
| **Vault locked while sessions run** | Sessions continue by default; the tab shows a locked badge and input is queued or frozen per policy |
| **Long operation** | Progress with an estimate, and a cancel that actually cancels |
| **Offline** | Distinguish "no network" from "this host is down" — they need different responses |
| **First launch** | A short setup: create or open a vault, choose a language, offer an import |

## Accessibility

Targets, not aspirations — they are checked in CI:

- **WCAG 2.2 AA** contrast across all themes, including the high-contrast theme
- Full keyboard operation with a visible focus indicator on every interactive
  element
- Correct ARIA roles for the tree, tab list, and dialogs; live regions for
  session state changes
- Screen reader support verified against NVDA (Windows), VoiceOver (macOS) and
  Orca (Linux)
- Respect `prefers-reduced-motion` and `prefers-contrast`
- No information conveyed by colour alone — a red tab also carries a label
- Text scales to 200 % without loss of function
- Terminal content is exposed to screen readers via xterm.js's accessibility
  buffer

The terminal is the hard case: a screen reader user needs the terminal's
content, not a canvas. xterm.js maintains a parallel accessible buffer for
exactly this, and it must stay enabled even though it costs a little
performance.
