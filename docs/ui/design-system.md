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
light interface and a dark terminal. Both ship with a set of well-known palettes
and both accept user files.

## Components

Built on **Radix UI** primitives for correct accessibility semantics, styled
with Tailwind against the tokens above. Radix handles focus management, escape
handling, portalling and ARIA — the parts that are tedious to get right and
embarrassing to get wrong.

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
