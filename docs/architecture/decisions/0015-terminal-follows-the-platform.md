# ADR-0015: The terminal behaves like the platform's own terminal

- **Status**: Accepted
- **Date**: 2026-09-16
- **Deciders**: bbesli

## Context

An SSH session is an xterm.js instance inside a WebView, and it inherited the
WebView's defaults. On the owner's Linux desktop a right click on a live session
opened WebKitGTK's text-field menu — Cut, Copy, Paste, Delete, Select All,
*Insert Emoji*, *Insert Unicode Control Character* — over the shell. The owner's
own words for the result: it felt as though the session had connected to a
browser rather than to a terminal.

That menu was the most visible symptom of a wider gap. Nothing in the
application handled the clipboard at all:

- **Windows** — Ctrl+V sent a literal `^V` (0x16) to the remote shell, because
  xterm.js encodes every Ctrl+letter as a control character and nothing asked it
  not to. There was no way to paste with the keyboard.
- **Linux** — a selection never reached the X11 PRIMARY selection, and the middle
  button did not paste, which is how people on those desktops move text between
  terminals all day.
- **Everywhere** — the cursor, the font and the word boundaries of a double click
  were the same on all three, and matched none of them. The terminal was set in
  the interface's editor font.

Outside the terminal the WebView's browser habits were also live: F5 and Ctrl+R
reloaded the interface and dropped every open session with it, Ctrl+P opened a
print dialog, a right click on a label offered browser actions, the middle button
on Windows started a page auto-scroll, and an icon could be dragged out of the
window as an image.

## Options considered

### Option A — the WebView's own clipboard API

`navigator.clipboard.readText()` and `writeText()` from the frontend.

No new dependency. But each engine treats reading differently: WKWebView on
macOS shows a system "Paste" confirmation bubble on every read, which is
precisely the non-native behaviour being removed; WebKitGTK's permission
handling has changed between versions; and none of them can reach the PRIMARY
selection at all, so Linux select-to-copy and middle-click paste cannot be built
on it.

### Option B — the Tauri clipboard plugin

`tauri-plugin-clipboard-manager`, which is `arboard` behind a permission layer.

Maintained and conventional, but it exposes the ordinary clipboard only, so the
Linux half of the problem stays unsolved, and it adds a capability file and a
plugin to reach something one Rust function can.

### Option C — `arboard`, directly, behind two IPC commands

`clipboard_read_text(selection)` and `clipboard_write_text(selection, text)` in
`crates/remoter-ipc/src/clipboard.rs`, where `selection` is `clipboard` or
`primary`.

Reaches PRIMARY on Linux; behaves identically on every engine because no engine
is involved; pure Rust. One new direct dependency.

## Decision

**Option C**, and a per-platform behaviour table the terminal follows, taken from
the terminal people on each platform actually use — Windows Terminal, Terminal.app,
GNOME Terminal and Konsole. The rules are pure and live in
`apps/desktop/ui/src/features/sessions/terminalInput.ts`, so each platform's rules
are tested on every platform:

| | Windows | macOS | Linux |
|---|---|---|---|
| Copy | Ctrl+C *with a selection*, Ctrl+Shift+C, Ctrl+Insert | Cmd+C | Ctrl+Shift+C, and every selection becomes PRIMARY |
| Paste | Ctrl+V, Ctrl+Shift+V, Shift+Insert | Cmd+V | Ctrl+Shift+V; middle button and Shift+Insert paste PRIMARY |
| Ctrl+C with nothing selected | the interrupt | the interrupt | the interrupt |
| Right button | copy a selection, or paste | the terminal's menu | the terminal's menu |
| Cursor | blinking bar | steady block | blinking block |
| Default face | Cascadia Mono, Consolas | SF Mono, Menlo | the desktop's `monospace` |
| Also | Ctrl +/−/0 zoom | Cmd+A, Cmd+K clear, Cmd+F find, Cmd +/−/0 zoom | Ctrl+Shift+A, Ctrl +/−/0 zoom |

When the program on the far end has asked for mouse reports, the buttons belong
to it and Shift takes them back, as in every native terminal. A paste goes
through xterm's `paste()`, so bracketed-paste mode is honoured and a multi-line
paste into a shell that asked for it is not run line by line as it arrives.

Outside the terminal, `apps/desktop/ui/src/app/nativeFeel.ts` stops the WebView's
reload, print, view-source, caret-browsing and page-zoom keys, its context menu
outside text fields, middle-button auto-scroll and image dragging — in production
builds only, because reload and the inspector are how the interface is developed.
A text field keeps its platform editing menu, and AltGr (Ctrl+Alt on Windows) is
never treated as a shortcut.

## Consequences

**Positive** — the clipboard works the same way on the three engines, and the
way each platform's users expect. The Linux PRIMARY selection works. Reloading
the interface by accident, and losing every session with it, is no longer one
key away.

**Negative** — a new dependency, `arboard`, bringing `x11rb` on Linux and the
BSL-1.0 `clipboard-win` and `error-code` on Windows (recorded in `deny.toml`).
Clipboard text crosses the IPC boundary; it is the user's own clipboard, taken at
their request, and it is never logged, but it is a new kind of data on that
boundary. Wayland is served through XWayland rather than natively:
`arboard`'s `wayland-data-control` feature is off because GNOME's compositor does
not implement the protocol it relies on, so a Wayland session with no XWayland
at all has no clipboard in the terminal. The platform is read from the user
agent, and a WebView that misreported its operating system would get another
platform's keys.

**Neutral** — a terminal no longer uses the interface's monospace stack by
default, so a user who had been relying on that face sees their platform's
terminal font until they choose one in Settings, where the preview now shows the
same face the terminal uses.

## Revisit if

- GNOME ships a clipboard protocol `arboard` can use natively, or a supported
  desktop drops XWayland — turn `wayland-data-control` on.
- A platform's own terminal changes its defaults (Windows Terminal changing what
  the right button does is the likeliest).
- Users ask for the multi-line paste warning Windows Terminal shows. It was left
  out: bracketed paste already stops a shell that supports it from running a
  pasted block line by line.
