# Design System

Tokens, theming and component conventions. The goal is a product that looks
deliberate rather than assembled, and that a contributor can extend without
guessing.

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
| Tabs | Reorderable, detachable, colour-inherited from the connection |
| Command palette | Fuzzy search over connections and actions |
| Form fields | Every inheritable field shows provenance and an override control |
| Data table | For the audit log and session history; sortable, virtualised |
| Dialogs | Focus-trapped, escape-dismissible, with a clear primary action |
| Toasts | Non-blocking; never used for anything the user must act on |
| Progress | Determinate wherever a total is known; always cancellable |
| Framebuffer surface | The canvas an RDP or VNC session is seen on, with the scaling controls over it and the desktop size under it |
| Warning strip | Everything a session warned about, over the session |
| File manager | Two panes and a transfer queue, attached to a session rather than to a node |

### The warning strip

A session raises warnings that are facts about the connection the user is
looking at — a VNC server that negotiated no authentication at all, an RDP
session running without Network Level Authentication, a clear-text RFB session
to a routable address, a server that refused the channel smart resize needs.
Three rules decide how they are drawn, and each one exists because the
alternative is a warning nobody reads.

**They sit over the session, not beside it.** A warning in a panel the user has
to open has not been shown. The strip is an overlay at the inline start of the
session area, terminal and graphical alike, so an SSH banner and a VNC security
type land in the same place.

**A `danger` warning cannot be collapsed.** The set folds to a single line once
it has been read — a bell that rang and a clipboard that was transcoded are not
worth a permanent panel — but "this session is not authenticated" does not fold.

**An unrecognised warning is shown as itself, not suppressed.** An adapter that
raises something nobody has written copy for should look unfinished rather than
silent, so the key is drawn where the sentence would be.

The strip redefines the ground tokens for itself. The session area is dark in
every theme, and a callout that inherited the light theme's near-black text
would be unreadable on it — this is the one sanctioned reason to redefine a
semantic colour token locally rather than reach for a literal.

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
