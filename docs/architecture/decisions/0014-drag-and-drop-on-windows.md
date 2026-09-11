# ADR-0014: Pointer-event dragging, and Tauri's drag-drop handler turned off

- **Status**: Accepted
- **Date**: 2026-09-11
- **Deciders**: bbesli

## Context

Dragging a connection onto a folder did nothing on Windows. It worked on
Linux, which is where it was written and where every test of it ran.

The cause is not in this codebase. Tauri's window option `dragDropEnabled`
defaults to **true**, and on Windows that makes `wry` call `RevokeDragDrop()`
on every WebView2 child window and register a drop target of its own — one
that understands only `CF_HDROP`, the clipboard format an operating-system
file drop uses. An in-page HTML5 drag carries no `CF_HDROP`, so that target
returns `DROPEFFECT_NONE` and never forwards the event. Because the webview's
own drop target was revoked first, the page receives `dragstart` and then
nothing at all: no `dragover`, no `drop`, no cursor.

Tauri's own documentation says so in one line, which is easy to miss:
"Disabling it is required to use HTML5 drag and drop on the frontend on
Windows."

WebKitGTK does not revoke the webview's drag destination, which is why the
defect was invisible to every Linux test and to the whole test suite — jsdom
cannot observe a WebView2 drop target either.

## Options considered

### A. Turn `dragDropEnabled` off and keep HTML5 drag and drop

One line of configuration. Keeps the platform's own gesture, its cursors and
its accessibility affordances. The cost is that the operating system's file
drop stops reaching the Rust side as a Tauri event — though with the handler
gone the webview's own handling returns, so `dataTransfer.files` works through
the ordinary web API instead.

### B. Stop using HTML5 drag and drop where we control the gesture

Pointer events are not routed through the drop target at all, so a gesture
built on them behaves the same on every platform and cannot be broken again by
a webview's file-drop plumbing. The cost is that the browser's drag image,
cursors and keyboard semantics have to be provided rather than inherited.

### C. Both

## Decision

**Both.**

The connection tree's drag is a pointer-event gesture (option B). It is the
surface a user drags most, it moves data that never comes from outside the
window, and it must not depend on a webview flag that a future contributor
could reasonably turn back on.

`dragDropEnabled` is nevertheless **false** (option A), because the SFTP file
manager does use HTML5 drag between its panes, and turning this off is what
makes that work on Windows at all. It also restores the ordinary web behaviour
for a file dragged in from the desktop, which `LocalPane` already handles.

## Consequences

- A row in the connection tree is **not** `draggable`, deliberately. Putting
  the attribute back would produce a gesture that works on Linux and silently
  does nothing on Windows — the exact defect this records.
- The operating system's file drop is no longer delivered as a Tauri event. If
  it is ever wanted on the Rust side, it needs a handler there **and** a
  frontend listener; it cannot coexist with in-page HTML5 drag on Windows.
- No automated test can catch a regression here. jsdom has neither `DragEvent`
  nor a WebView2. The tests assert the two things that are observable — that
  the gesture produces the right move, and that no tree row carries
  `draggable` — and this document carries the rest.
