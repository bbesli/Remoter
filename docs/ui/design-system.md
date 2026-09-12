# Design System

Tokens, theming and component conventions. The goal is a product that looks
deliberate rather than assembled, and that a contributor can extend without
guessing.

> **What ships.** The tokens, the four themes, the CSS-modules approach, the
> component conventions and the accessibility rules are what the frontend
> actually does. Where a component row below describes something unbuilt — a
> detachable tab, a session-history table — it is marked in place.

## Principles

1. **Density with air.** Administrators work with hundreds of connections and
   many open sessions. The interface must be compact without being cramped —
   closer to a code editor than a consumer application.
2. **The session is the content.** Chrome recedes. When a session is open, the
   maximum possible pixels belong to it.
3. **Status is always visible.** Connected, connecting, failed, locked,
   recording — never hidden behind a hover or a menu.
4. **Dangerous actions look dangerous.** Production connections, broadcast
   typing, plaintext export and legacy cryptography carry visual weight
   proportional to their risk.
5. **Nothing is colour-only.** Every state that colour communicates also has a
   shape, an icon or a label.
6. **Nothing of ours is drawn over a remote desktop.** A remote desktop uses all
   four of its edges and all four of its corners: Windows puts a taskbar along
   one edge and a maximised window's minimise, maximise and close buttons in a
   corner, macOS has a menu bar and a dock, a Linux desktop can put a panel
   anywhere. There is no safe place to float our own chrome over someone else's
   screen, so no place is used. See **Chrome around a session** below.

## Tokens

All values are CSS custom properties in
`apps/desktop/ui/src/styles/tokens.css`. Components reference tokens, never
literals — this is what makes theming a data change rather than a code change.

```css
:root {
  /* Spacing — 4 px base */
  --space-1: 0.25rem;  --space-2: 0.5rem;   --space-3: 0.75rem;
  --space-4: 1rem;     --space-6: 1.5rem;   --space-8: 2rem;

  /* Type — system stack first, so the app looks native on each platform */
  --font-ui:   system-ui, -apple-system, "Segoe UI", Roboto, "Noto Sans", sans-serif;
  --font-mono: "JetBrains Mono", "Cascadia Code", "SF Mono", Consolas, monospace;
  --text-xs: 0.75rem;  --text-sm: 0.8125rem;  --text-base: 0.875rem;
  --text-lg: 1rem;     --text-xl: 1.25rem;

  /* Radius, elevation */
  --radius-sm: 4px; --radius-md: 6px; --radius-lg: 10px;
  --shadow-1: 0 1px 2px rgb(0 0 0 / 0.06);
  --shadow-2: 0 4px 12px rgb(0 0 0 / 0.10);

  /* Semantic colour — never a raw hex in a component */
  --bg-canvas: …;   --bg-surface: …;  --bg-elevated: …;  --bg-inset: …;
  --fg-default: …;  --fg-muted: …;    --fg-subtle: …;    --fg-on-accent: …;
  --border-default: …; --border-strong: …; --border-focus: …;
  --accent: …;      --accent-hover: …;
  --success: …;     --warning: …;     --danger: …;       --info: …;

  /* Session state */
  --state-connected: var(--success);
  --state-connecting: var(--warning);
  --state-failed: var(--danger);
  --state-locked: var(--fg-muted);
  --state-recording: var(--danger);
}
```

The base UI text size is 14 px rather than 16 px. This is a deliberate density
choice for a professional tool, and it is why text scaling to 200 % is an
accessibility requirement rather than an optional extra.

## Themes

Four built in: **Light**, **Dark**, **High contrast light**, **High contrast
dark**. The default follows the OS.

A theme is a token override file. Community themes are declarative data with no
code, which is why they need no sandbox
([plugin-system.md](../architecture/plugin-system.md)).

Terminal themes are **separate** from application themes — a user may want a
light interface and a dark terminal, and picking a terminal palette ignores the
interface theme entirely. Both ship with a set of well-known palettes; the
terminal's individual colours can then be overridden one at a time in
Settings → Terminal, and each override is stored on its own so that changing
palette moves everything that was left alone.

A terminal palette is **not** a file the user can bring or take away. This
paragraph used to say terminal themes "accept user files"; importing or
exporting a palette is not built, and nothing in the interface offers it. The
choice is one of the built-in palettes plus the user's own overrides, and that
is all it is until an import is written and this line is amended with it.

A terminal palette is also **not** a token override file. The built-in
palettes, the user's overrides and the contrast arithmetic are data in
`apps/desktop/ui/src/lib/terminalPalette.ts`; `features/sessions/terminals.ts`
resolves them and writes the result onto the document element as `--term-bg`,
`--term-fg`, `--term-red` and the rest. The token *names* are unchanged and
still mean what they always did, so CSS that sits flush against a terminal
reads them exactly as before — what moved is the values. It had to: a CSS
custom property has no per-user value, so a colour picker has nothing to write
into a stylesheet and a hex field has nothing to read back out of one
(`features/sessions/terminalTokens.css` records the move).

## Styling: CSS Modules, not Tailwind

The original draft of this document specified Tailwind. Implementation changed
that, and the reasoning belongs here rather than in a commit message.

Remoter's interface is not a page of composed utilities. It is a fixed
application chrome — a 38 px title bar, a 268 px sidebar, a 36 px tab strip —
whose every dimension is a design token, wrapped around a session area that
must give away as few pixels as possible. Expressed in Tailwind, almost every
class would be an arbitrary value: `h-[var(--titlebar-h)]`,
`bg-[var(--bg-surface)]`, `text-[13px]`. That is Tailwind being fought rather
than used, and it puts a second naming layer between a design token and the
rule that consumes it.

So: **plain CSS Modules**, one `.module.css` beside each component, referencing
the tokens directly. Vite handles the scoping with no additional dependency and
no build configuration. The rule that matters is unchanged and is enforced in
review — *components reference tokens, never literals*.

## Components

The document named **Radix UI** as the primitive for anything needing real
accessibility semantics. Implementation did not use it, and a reviewer caught
the gap: three overlays declared `aria-modal="true"` — telling a screen reader
the background was inert — while Tab still walked straight into it.

The fix was a shared focus trap of about thirty lines
(`features/connections/focusTrap.ts`), used by the command palette, the
connection editor and the delete confirmation. Adding Radix for one behaviour
mid-milestone would have been more churn than the behaviour is worth, and the
trap is small enough to read in one sitting.

So the rule is now: **`aria-modal` is a promise, and whatever makes the promise
must keep it.** Focus enters on open, Tab is trapped, Escape cancels, focus
returns on close, and the handlers underneath are suppressed. A surface that
declares `aria-modal` without all five is a defect, whether the mechanism is
Radix or our own. If a future component needs menus, comboboxes or anything
with real roving-focus semantics, adopt Radix then — as its own change, with
the existing overlays migrated, not as an assumption.

Simple controls stay plain elements; wrapping a button in a dependency buys
nothing.

| Component | Notes |
|---|---|
| Tree | Virtualised; keyboard navigable; drag-and-drop with a clear drop indicator |
| Tabs | Reorderable, colour-inherited from the connection, with a live status dot that is never colour alone. ⏳ Not detachable |
| Command palette | Fuzzy search over connections and actions |
| Form fields | Every inheritable field shows provenance and an override control |
| Data table | For the audit log; sortable, paginated. ⏳ No session-history view |
| Dialogs | Focus-trapped, escape-dismissible, with a clear primary action |
| Toasts | Non-blocking; never used for anything the user must act on |
| Progress | Determinate wherever a total is known; always cancellable |
| Framebuffer surface | The canvas an RDP or VNC session is seen on, with its toolbar in a row above it — never over it |
| Warning strip | Everything a session warned about, as a count in the session's chrome that opens the list above the session |
| File manager | Two panes and a transfer queue, attached to a session rather than to a node |

### The warning strip

A session raises warnings that are facts about the connection the user is
looking at — a VNC server that negotiated no authentication at all, an RDP
session running without Network Level Authentication, a clear-text RFB session
to a routable address, a server that refused the channel smart resize needs.
Three rules decide how they are drawn, and each one exists because the
alternative is a warning nobody reads.

**They are always visible, and never over the session.** A warning in a panel
the user has to go and find has not been shown — so a count sits permanently in
the session's chrome, above the picture, terminal and graphical alike, and an
SSH banner and a VNC security type land in the same place. It opens the list in
the same strip, which pushes the session down rather than covering it. The strip
used to be an overlay at the bottom inline start of the session area; that is
the Start button on a remote Windows desktop, and principle 6 is what replaced
it.

**A `danger` warning cannot be collapsed.** The set folds to a single line once
it has been read — a bell that rang and a clipboard that was transcoded are not
worth a permanent panel — but "this session is not authenticated" does not fold.

**An unrecognised warning is shown as itself, not suppressed.** An adapter that
raises something nobody has written copy for should look unfinished rather than
silent, so the key is drawn where the sentence would be.

The strip no longer redefines the ground tokens. It is chrome beside the session
rather than a callout on the dark terminal ground, so it takes the window's own
theme. Anything that *is* drawn on that ground — the connect panel, the host key
question, the ended notice — still redefines them, because the ground is dark in
every theme and a callout inheriting the light theme's near-black text would be
unreadable on it. That is the one sanctioned reason to redefine a semantic
colour token locally rather than reach for a literal.

### Chrome around a session

Principle 6 in practice. Everything the application has to say about a session
is a row in the flow, with a height of its own, between the tab strip and the
picture:

- the **session chrome strip** — the warning count and its list, and the notice
  that a keystroke was refused — drawn only when it has something in it, so a
  quiet terminal grows no empty row;
- the **framebuffer toolbar** — the Ctrl+Alt+Del and Alt+Tab buttons, which
  exist because the local machine takes those chords first, the scale controls,
  the view-only badge, and one line of keyboard orientation that retires itself
  after the first click;
- the **notices** a graphical session raises in a sentence rather than on a chip
  — waiting for a first frame, a dropped frame, an unreadable one.

The desktop size is **not** among them: the status bar under the session already
carries it, and one fact belongs in one place.

Three exceptions may cover a session, and all three are blocking questions about
it rather than chrome: the connect panel, the host key dialog and the prompt, and
the ended-session notice. None is present while a session is simply running.

`features/sessions/layout.test.tsx` asserts the rule against the computed
layout — no element inside the session area is `absolute`, `fixed` or `sticky`
except the session host itself — so a control floated back over the picture
fails `npm run test` rather than reaching a user. That is a Vitest run, which
CI does on all three platforms; it is not part of `npm run build`.

### The file manager

Two panes — local and remote — with a transfer queue beneath them. It is
attached to a **session**, not to a node: opening one adds a channel to a
connection a tab already holds rather than making a second handshake, host key
check and authentication, so the pane and the shell are the same trust
decision. The queue lives beside the session rather than in the interface, so a
transfer survives a tab switch and shows real progress rather than a spinner.

Every row is server-supplied text and is drawn as the escaped twin the DTO
carries, never the raw field — see
[../architecture/rendering.md](../architecture/rendering.md#remote-text-and-where-it-is-allowed-to-render).
A name whose escaping changed it is flagged on its row, because a file called
`invoice\u{202E}gpj.exe` and one called `invoice.jpg` must not look alike.

## Iconography

One icon set throughout (Lucide, or an equivalent open set), 16 px in dense
contexts and 20 px elsewhere. Protocol icons are distinct at a glance —
SSH, RDP, VNC and SFTP must be distinguishable in a tree at 16 px, which is a
real constraint on how detailed they can be.

Directional icons mirror under RTL; object icons do not.

## Motion

Fast and purposeful. Transitions are 120–200 ms; anything slower feels sluggish
in a tool used all day. Motion is used to show relationship — where a panel came
from, what a tab detached into — never for decoration.

`prefers-reduced-motion` disables all non-essential animation.

## Writing

Interface copy is part of the design:

- **Plain and specific.** "Could not reach `db-01` through `bastion-2`" beats
  "Connection error"
- **Second person, active voice.** "Choose a credential", not "A credential must
  be chosen"
- **No jargon without a definition** on first use in that context
- **Warnings state the consequence**, not the mechanism: "your vault cannot be
  opened", not "key derivation will fail"
- **No apologies, no exclamation marks.** An error message is information, not
  an emotion
- Every string is translatable, and security-critical strings are flagged so
  translators know not to soften them
