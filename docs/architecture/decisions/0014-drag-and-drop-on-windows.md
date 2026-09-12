# ADR-0014: Pointer-event dragging, and Tauri's drag-drop handler turned off

- **Status**: Accepted
- **Date**: 2026-09-11, amended 2026-09-12
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
- No automated test can catch a regression in the *flag*. jsdom has neither
  `DragEvent` nor a WebView2. The tests assert the two things that are
  observable — that the gesture produces the right move, and that no tree row
  carries `draggable` — and this document carries the rest.

## Amendment, 2026-09-12: the pointer gesture had two defects of its own

The gesture above was reported as still not working, and both halves of the
report were right. Neither is about Windows; both were reachable in an ordinary
Chromium, which is how they were finally found — by driving the real component
in a real browser rather than by dispatching events at the elements a test had
in mind.

**The drop target was read from the event's target.** Each row answered
`pointermove` for itself and told the tree which of its bands the pointer was
in. That works exactly as long as the platform delivers each move to the
element under the pointer, and stops the moment anything takes the pointer:
with the pointer captured — which is the only way to keep receiving moves once
the pointer leaves the window, and which some platforms do implicitly — every
move names one element for the whole gesture, so the tree would see the source
row for the entire drag and refuse everything. The tree now takes the capture
itself, for the length of the gesture, and finds the target with
`document.elementFromPoint`, which answers "what is under the pointer"
regardless of where the event was delivered. Rows publish `data-drop-id`;
finding one is the hit test's job and not the row's. **The capture is taken on
the row the press landed on** — see the amendment below, which corrects what
this paragraph said when it was written.

**Every row was split into three bands, including rows that hold nothing.** The
middle half of a row meant "inside this one", which for a connection can only
ever be refused — so half of the target area of every reorder answered "only a
folder can hold other entries", and aiming at the row you want to sit beside
was the way to hit it. A row that presents itself as a container keeps three
bands; everything else is halved into above and below. A *group* keeps its
middle band and refuses it, because it wears the folder glyph and a gesture
aimed at its inside deserves an answer rather than a silent reinterpretation.

The lesson for the tests is the one this repository keeps relearning. The
original suite passed because it dispatched `pointermove` directly at the row
it meant, which skips the two decisions the browser makes and the component was
wrong about: which element gets the event, and which element is under the
point. The suite now installs an `elementFromPoint` over the same pretend
layout it already installs `getBoundingClientRect` over, drives a pointer
across the rows in the steps a mouse takes, and runs each case twice — once
delivered to the row under the pointer and once delivered to the scroller, as a
captured pointer would. That second variant is the regression test for the
first defect, and it fails against the code this amendment replaces.

## Amendment, 2026-09-12 (later): what is actually there

The amendment above was written from the change it was describing rather than
from the code that shipped, and it got one fact wrong. Three more defects were
found around the gesture at the same time. All four were established by driving
the real `ConnectionTree` in a real Chromium with real mouse input — the
harness now lives in `apps/desktop/ui/src/features/connections/harness/`, and
`drive.mjs` at the top of it says how to run it. Every number below came out of
that.

### The capture is on the row, not on the scroller

`capture()` calls `setPointerCapture` on the row the press landed on. Measured
mid-drag, the row reports `hasPointerCapture` and the scroller does not, and
every `pointermove` in the gesture is delivered to that one row whatever the
pointer is over.

The element the capture sits on is very nearly irrelevant, which is the point
of hit-testing rather than reading the target. The same drag was run three
ways — capture on the row, capture forced onto the scroller, and
`setPointerCapture` stubbed out entirely — and in all three the entry landed
inside the folder the pointer was over. What differs is only where the moves
are delivered: to the source row, to the scroller, or, with no capture at all,
to whatever happens to be under the pointer, which over a folder row is its
chevron `<button>` and the `<svg>` inside it. A gesture that read its target
from the event would therefore behave differently on each of the three, and two
of them are things a platform decides for you.

One thing does turn on it, and it is why the row is the right element. A press
that crosses the drag threshold and comes back down on the row it started on is
a click as far as the person making it is concerned. The click that ends such a
gesture goes to the capturing element: with the capture on the row, the row is
selected; with the capture moved to the scroller, the same gesture selects
nothing. Measured both ways.

The claim in `capture()` that this is also what makes the click *after a drag*
belong to its source row is not true and has been removed — a drag released
over a different row selects nothing, with the capture on the row or on the
scroller alike.

### A separator was a hole in the drop surface

`NodeRow` returned early for `kind: "separator"` before the `data-drop-id`
spread, so `closest('[data-drop-id]')` walked past a separator to the scroller
and read the drop as the background. Dropping an entry on the line between two
folders moved it to the end of the top level, with no indicator, no refusal and
an announcement naming a place the pointer had never been.

A separator is a gap somebody drew between two entries, and a gap is a
position. It now publishes `data-drop-id` like any other row and splits into
two bands like any other row that holds nothing, so a drop on it lands where
the line is. It carries no `data-container`: there is no inside of a gap. It is
still not a drag source, because it has no name and "Moved “” above “x”" is
not a sentence worth being able to produce.

Because a separator has no name, the announcement names the nearest named
neighbour on the side the entry came to rest — `anchorFor` in
`ConnectionTree.tsx` — and the folder it landed in when a separator is all
there is. The alternative was a sentence with a hole in it, which for a screen
reader is the only description of the move there is.

### A click with a wobble in it announced a refused drop

The drag threshold was four pixels, which is what a Windows drag uses
(`SM_CXDRAG`). At four pixels an ordinary click on a row, with the small
sideways travel a trackpad produces, became a drag that ended on the row it
started on — and that is refused, "an entry cannot be dropped onto itself", so
the tree raised its whole warning callout about an operation nobody had
attempted. Reproduced at four pixels, six and twelve.

Both halves of the gesture were wrong, so both were changed. The threshold is
eight pixels: a row is twenty-eight pixels tall and the nearest band anyone can
deliberately aim at is half a row away, so nothing intentional lives between
four and eight. And a drag that ends on the row it began on now moves nothing
and says nothing — it is a cancellation, announced as one, because putting an
entry back where it was is not a failure. After the change, three, four and six
pixel wobbles do nothing at all, and eight and twelve leave the row selected
and the live region saying the move was cancelled.

### One reorder cost a call per sibling

`movesFor` respaced the entire sibling list whenever the two neighbours at the
insertion point had no integer between them — and `node_create` and every
importer hand out consecutive integers, so on a tree nobody has reordered that
is every insertion. Each `node_move` is a whole vault write: read, decrypt,
apply, re-encrypt, `fsync`, rename.

Measured against a top level of thirty-three entries: one drag cost **32**
calls and one Ctrl+Up cost **32**. Against four hundred, the size this project
keeps citing as the reason import matters, a drag from one end to the middle
cost **402**.

Only the siblings between the insertion point and the nearest slack have to
move, and the ends of a list are themselves slack — nothing lives above the
last entry or below the first, and `sort_order` is an `i64`. `movesFor` now
searches outward in both directions and takes the cheaper side. The same three
gestures now cost **3**, **2** and **200**.

The last of those is the honest limit of a frontend-only fix: a node carried
from the end of a four-hundred-entry list to the middle of it, with no gaps
anywhere, genuinely needs two hundred single-node moves. It is also
self-healing — the region it respaces comes out spaced by sixteen, so the same
drag a second time costs **1** — but the real answer is a `node_move` that
takes a batch and writes the vault once. That command does not exist in
`remoter-ipc`; until it does, this is the floor.

What was given up was written up here as "two siblings can now briefly share an
order… the list is self-consistent either way", and that was wrong. The
amendment below is what it actually cost and what was done about it.

### What the suite can and cannot hold

The unit suite covers all four in jsdom, which is worth having and is not
proof: it has no layout, no `elementFromPoint` and no pointer capture, and each
of those is stood in for. Everything in this amendment was found by driving the
real component in a real browser, and the two facts that could only be
established there — where the capture sits, and what a click does after one —
are the two the previous amendment got wrong from reading.

## Amendment, 2026-09-12 (later still): what the cheap respace cost

The paragraph above conceded a "brief" shared sort order and called the list
self-consistent either way. Driven in a real Chromium with one `node_move`
refused, it is neither brief nor self-consistent.

### A run of `node_move` calls is not one operation

Ctrl+Up on `srv-010` of a freshly imported top level is two calls: `srv-009`
to 12, then `srv-010` to 11. Twelve is the order `srv-010` is still sitting on
— `movesFor` found its slack in the slot the moved entry has not vacated yet,
which is exactly why the gesture is two calls and not thirty-two. Refuse the
second call and the first one stands: **`srv-009` and `srv-010` both hold 12,
in the vault, until somebody moves one of them again.**

That is not a tie a reader can see and shrug at. The sidebar breaks it with
`compareInLocale(a.name, b.name, locale)` — *the reader's* language — and
`storage.rs` breaks it with `ORDER BY sort_order, id`. So the same vault draws
in one order in the tree and another in the core, two people with different
interface languages can see the pair in different orders, and it survives a
restart with nothing on screen to say it happened.

### Why not a numbering scheme that survives a partial run

It was the first thing tried, and it does not exist at this price. On a list
with no gaps, excluding the moved entry's own slot from the respace makes the
outward search take in one more sibling for each integer it gains, so it never
catches up: it runs to the end of the list, which is the thirty-two calls the
search was written to avoid. The general case is smaller than that and just as
final — two adjacent entries with no integer between them cannot be exchanged
by two single-node writes in any order, because there is no third value to
hold one of them in the meantime. A scheme that tolerates a partial run has to
buy a free integer first, which is an extra vault write on the common path and
leaves the entry visibly parked somewhere it was never dragged to when the run
stops there anyway.

### What is there instead: the run is walked back

Every step now carries where its node came from, and a run that stops walks
back along the way it came — the undo of each applied step, in reverse. The
states it retreats through are the states the vault has already been in, so it
invents nothing; the first undo that fails stops the walk, because pressing on
would mix two of them. Measured in the harness, which takes `?failAt=2` to
refuse the second `node_move` of a run and `?failAt=2,3` to refuse the first
undo as well: with the second call refused, the calls are `srv-009` to 12,
`srv-010` to 11 (refused), `srv-009` back to 11 — and no two siblings share an
order.

A tie that does get left behind is not permanent, which is what the sentence
about it is allowed to promise: moving either entry again finds the gap the
half-run opened and costs one call. Driven, and it does.

When the walk back itself fails — a second write failing during the recovery
from the first — the tie is kept, and **the tree says so**, in the failure
notice and in the live region. It is the one outcome here where the tree on
screen and the tree in the vault are two different trees, and the only thing
worse than it is not being told.

None of this is atomicity, and it is not dressed up as it. The fix is a
`node_move` that takes the whole run and writes the vault once: `read_tree`,
every `move_node`, one `vault.apply` and one `save`, so a refusal anywhere
saves nothing. That command is not in `remoter-ipc` — `commands.rs` has
`node_move` and nothing plural — and the frontend cannot invent it.

### Two hundred writes, and an interface that said "Moving…"

The two-hundred-call reorder is still two hundred calls. What changed is that
the sidebar stops pretending it is instant: while a run is longer than one
call it draws a `progressbar` — `aria-valuenow` over `aria-valuemax`, with the
count in the label — beside the spinner. Driven against the four-hundred-entry
tree, the bar showed all 201 values from 0 to 200 and then went away. The live
region deliberately does *not* carry the count: it is polite, and two hundred
changes would be two hundred interruptions, so it says a move is in progress
and then says how it ended. Counting costs about 2.8 ms a call in a
four-hundred-row tree (200 writes took 803 ms without the counter and 1.37 s
with it, against a fake core that does no work) — worth it beside a real vault
write, and gone entirely once the batch command makes the whole run one call.

### A separator can be dragged

It was a drop target and not a drag source, and the reason given here was that
it has no name, so its move would be announced as `Moved “” above “x”`. That
is a reason to write four sentences, not a reason to nail a line to the tree:
it is a node like any other, its whole meaning is where it sits, and the
keyboard could move it all along — producing exactly the sentence the drag was
withheld to avoid. `move.movedSeparatorAbove`, `…Below`, `…Into` and
`…ToTop` are what it needed. The chip under the pointer carries a drawn line,
because a chip with an empty label reads as a gesture that did not start.

The keyboard path had the other half of the same hole: it built its
announcement from `without[at - 1]` with no name check, so Ctrl+Up onto a
separator said `Moved “db-01” above “”` — the defect the drag path had been
fixed for, in the half of the feature the fix did not touch. Both paths go
through one `announceMove` now, which is `anchorFor` and `describeMove`
together and is the only place either is called from.
