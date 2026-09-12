# Rendering

> **What ships.** Both paths carry real pixels today: the terminal through
> xterm.js with the WebGL renderer, the frame-interval coalescing and the live
> palette, and the framebuffer through the `WebViewPresenter` described in
> *The WebView presenter, as built*, with the input, scaling and remote-text
> rules as written. ⏳ **`remoter-bench-framepath` does not exist**, so the
> acceptance bar was never measured and the presenter decision gate never ran;
> ⏳ the `NativePresenter` does not exist either, which is why every platform
> gets the WebView one — by absence, not by measurement. ⏳ **Recording does not
> exist anywhere**: the asciicast recorder in the first diagram and the
> *Recording* section at the end describe a crate that was never written. The
> one gap inside what does ship is marked in place — `SessionWarning::Banner`
> still crosses IPC without an escaped twin.

How remote pixels and remote text reach the screen. This is the hardest
engineering problem in the project and the one most likely to force a design
change, so it is documented with its risks in the open.

## Two very different workloads

| | Terminal (SSH, serial, local shell) | Framebuffer (RDP, VNC) |
|---|---|---|
| Payload | UTF-8 byte stream with escape sequences | Dirty rectangles of pixels |
| Volume | Kilobytes per second, bursts to megabytes | 5–50 MB/s uncompressed at 1080p30 |
| Latency budget | ~30 ms keystroke echo | ~50 ms input-to-photon |
| Renderer | xterm.js with the WebGL addon | `<canvas>` — 2D `putImageData` or WebGL2 texture |

The terminal case is solved. The framebuffer case is the risk.

## Terminal rendering

```
russh channel ──▶ SessionEvent::Data(Bytes) ──▶ IPC ──▶ xterm.js.write()
                        │                                     │
                        └──▶ asciicast recorder               └──▶ WebGL renderer
```

- **xterm.js** with `@xterm/addon-webgl`. It is the mature choice: GPU-accelerated
  glyph rendering, correct wide-character and combining-mark handling, working
  IME, and a large test suite. The 2026 alternatives — WASM VT parsers with
  Canvas 2D, Ghostty-derived cores — are either less mature or have broken IME,
  which is unacceptable for a tool shipping in ten languages
- Output is **coalesced at the frame interval**, not written per-chunk. A
  fast-scrolling terminal produces thousands of small writes per second;
  batching them into one write per frame is the difference between a responsive
  and an unusable terminal
- Local echo is not simulated. Keystrokes go to the remote host and appear when
  it echoes them, which is what users expect from a terminal
- Search, selection, hyperlink detection and copy-on-select come from xterm.js
  addons

Terminal themes are separate from the application theme: a user may want a light
UI and a dark terminal, and any palette other than "follow the interface theme"
ignores the interface theme entirely.

The terminal's palette is data, not a token file: the built-in palettes and the
user's per-colour overrides live in `apps/desktop/ui/src/lib/terminalPalette.ts`,
and `terminals.ts` resolves them, publishes the result as the `--term-*` custom
properties on the document element, and pushes it straight into every open
`Terminal` — a palette change reaches sessions that are already open without a
reconnect. The token names are still the CSS-side interface; only the values
moved. The palette is not shareable as a file either: importing or exporting
one is not built, and `docs/ui/design-system.md` says the same.

## Framebuffer rendering

### The problem

Tauri's IPC is message-passing, deliberately: shared memory between the Rust
core and the WebView is neither supported nor planned, and that is a security
property, not an oversight. But it means every pixel that reaches the screen
must cross a message boundary.

The naive approach — serialise a frame to base64 JSON and `emit` it — collapses
immediately. At 1080p, one raw frame is ~8 MB; base64 makes it ~11 MB; JSON
parsing that at 30 fps is not achievable.

### The approach we will take

Three techniques, applied together:

**1 · Dirty rectangles only.** RDP and RFB both transmit incremental updates
already. A typical interactive desktop changes 2–5 % of its pixels per frame.
Sending only changed regions cuts the volume by more than an order of magnitude
before anything else is optimised. The core coalesces updates that arrive faster
than the display refresh.

Rectangles are **not** merged in the general case, and the reason is copy-rect:
a copy-rect *reads* the surface the presenter holds, so dropping an earlier
rectangle that a later copy-rect copies from corrupts the display. Doing it
safely means tracking the surface in Rust, which is a second full copy of every
session's framebuffer. `remoter_proto::framebuffer::FrameCoalescer` therefore
applies only the supersession that is unconditionally sound — a full-surface
repaint of real pixels makes everything queued before it unobservable, so the
batch is cleared and marked a keyframe. Finer merging belongs to the encoder,
which knows what it emitted.

**2 · Raw byte payloads, never JSON.** Tauri v2's IPC rewrite supports raw
payloads specifically to avoid JSON serialisation of binary data. Frame updates
are returned as `tauri::ipc::Response` byte slices with a compact binary header.
The format is defined and implemented in
`crates/remoter-proto/src/framebuffer.rs`; that module is the normative
description and this is its summary. Little-endian throughout, because every
platform Remoter builds for is little-endian and a `DataView` takes the
endianness as an argument anyway:

```
┌──────────────────────────────────────────────────────────────────────┐
│ u64 session │ u32 seq │ u8 message │ u8 flags │ u16 n                 │  16 B
├──────────────────────────────────────────────────────────────────────┤
│ n × rect { u16 x, u16 y, u16 w, u16 h,                                │  14 B
│            u8 encoding, u8 pixel_format, u32 byte_length }            │  each
├──────────────────────────────────────────────────────────────────────┤
│ payloads, concatenated, in descriptor order                           │
└──────────────────────────────────────────────────────────────────────┘

message  0 framebuffer, 1 cursor shape
flags    bit 0 = keyframe: this update depends on nothing before it
```

Two fields differ from the sketch this document first carried, and both were
changed deliberately rather than drifted into:

- **The session identifier is 64 bits.** `SessionId` is a `u64` counter, and
  truncating it into a 32-bit header is how two tabs quietly become one.
- **The encoding byte moved into the rectangle descriptor.** The encoding table
  below says the encoder chooses *per rectangle*, which a single message-level
  byte cannot express. The descriptor also carries the pixel format, so a
  message can mix a JPEG region with raw ones — which is exactly what a desktop
  showing a video in a window produces.

A **cursor** message is one rectangle whose `x`/`y` are the hot spot rather than
a position on the desktop, and whose payload is the cursor image; a width and
height of zero hide the pointer. It is a separate message rather than pixels
drawn into the framebuffer because the pointer moves far more often than it
changes shape, and a presenter that owns the shape can follow the local pointer
at the display's refresh rate instead of the network's.

The frontend parses this with a `DataView` — no allocation per rectangle — and
uploads each rect to the presenter described below.

**3 · A custom URI scheme for the bulk path.** Tauri's
`register_asynchronous_uri_scheme_protocol` lets the WebView fetch bytes over
its own HTTP-like path, bypassing the command IPC entirely. This is the standard
technique for streaming media into a WebView and is the fallback if the command
path proves too slow under load.

### Encodings

| Encoding | When | Cost |
|---|---|---|
| Raw RGBA | Small rects, or already-decoded RemoteFX output | Zero CPU, highest bytes |
| RLE | Large flat regions — window fills, solid backgrounds | Cheap, very effective on desktops |
| JPEG | Photographic content, video regions | CPU on encode, lossy, big win on volume |
| Copy-rect | Scrolling and window moves | Almost free; a rectangle reference, no pixels |

The encoder chooses per rectangle based on size and entropy, and adapts to
measured frontend decode time. If the WebView cannot keep up, the encoder shifts
towards lossy encodings before it starts dropping frames.

**4 · A byte budget, so degradation is graceful.** The encoder targets a
configurable per-second byte budget, default **12 MB/s**, tied to the
connection's bandwidth profile. Within the budget it escalates towards lossy
encodings rather than dropping frames. Under load the image softens; it does not
stutter. For remote administration a slightly soft frame on time beats a sharp
one late, and this inverts the failure mode from "unresponsive" to "less
crisp".

### Measuring this before building on it

Settled by [ADR-0010](decisions/0010-framebuffer-transport.md). The short
version:

**A harness comes first.** ⏳ **It was not.** `remoter-bench-framepath` does not
exist, RDP and VNC were built before it, and so the presenter decision gate below
was never run — every platform uses the WebView presenter by default rather than
by measurement. The design is unchanged and the harness is still the right next
step; what follows describes what should have happened and did not.

`remoter-bench-framepath` is built in **v0.1**,
before any RDP work, and replays synthetic and captured dirty-rectangle streams
through the real transport and presenter. It needs no protocol implementation,
which is precisely why it can run this early.

**Acceptance bar**, at 1080p and 1440p on all three platforms:

| Metric | Threshold |
|---|---|
| p95 input-to-photon latency | ≤ 80 ms |
| Sustained frame rate, interactive workload | ≥ 30 fps |
| Sustained frame rate, video workload | ≥ 24 fps |
| Frame queue depth over a 10-minute run | Bounded, no growth |
| Hardware acceleration | Confirmed in use, not merely available |

That last row is not pedantry. WebKitGTK can create a WebGL2 context backed by a
software rasteriser, so a context that initialises successfully proves nothing.
The harness checks the renderer string, which is two lines of code and prevents
a benchmark that measures the wrong thing.

**This is not hypothetical.** The first Linux launch of the application, on
Wayland with an NVIDIA GPU, did not render at all: WebKitGTK imports its frames
through DMA-BUF, that import fails on the proprietary driver, and it surfaces as
a fatal Wayland protocol error before the window appears. `remoter-desktop`
now disables that path at startup under Wayland — accelerated compositing is
retained; only the buffer's route to the compositor changes.

Two consequences for the measurement. The harness must run with
`REMOTER_KEEP_DMABUF=1` as well as without it, because the two configurations
are different rendering paths with different costs. And the acceptance bar has
to be met on the path users will actually get, which on NVIDIA + Wayland is the
one without DMA-BUF.

### The presenter is an interface, and it is per-platform — ◐ one of two exists

The WebView presenter is built and is documented below as built. ⏳ The
`NativePresenter` is not: there is no `wgpu` dependency and no child surface.
Because the gate that would choose between them never ran, the choice was made by
absence.

```
FrameEncoder ──▶ binary frame format ──▶ ┌ WebViewPresenter  (IPC → canvas/WebGL2)
                                          └ NativePresenter   (wgpu → child surface)
```

The `NativePresenter` renders the framebuffer with `wgpu` into a child surface
beneath a transparent WebView carrying the UI chrome. It costs WebView
conveniences inside the session area and more per-platform window code.

The important consequence: **the choice does not have to be the same on every
platform.** WebView2 and WKWebView may clear the bar while WebKitGTK does not.
Shipping the WebView presenter on Windows and macOS and the native presenter on
Linux is a legitimate outcome, not a failure — and because only the presenter
differs, nothing above it changes.

**Decision gate: end of v0.2**, when the harness has numbers from real
hardware.

### The WebView presenter, as built

The `WebViewPresenter` half of that diagram exists. It is
`apps/desktop/ui/src/features/sessions/presenter.ts`, and three of its choices
are worth recording here because they are not obvious and they are not
provisional.

**Canvas 2D, not WebGL2 — and copy-rect is the reason.** The table above says a
copy-rect is "almost free", which is only true of a presenter that can read its
own surface. A 2D context can: `drawImage(canvas, sx, sy, …)` is specified to
read a snapshot of the source, so a self-copy of overlapping regions is well
defined. A WebGL2 presenter cannot sample the texture it is writing, so the same
operation needs a second texture and a blit pass — which is a full-surface copy
per scroll, on the encoding that exists to avoid copying anything. Raw and RLE
rectangles go through `putImageData`; JPEG rectangles through
`createImageBitmap`. This is the WebView presenter and says nothing about the
native one, which is `wgpu` and has no such constraint.

**The surface outlives the component.** The canvas is created by
`features/sessions/surfaces.ts` at the moment the core names the session's kind,
not by the React component that shows it — the component borrows the element and
gives it back. Two reasons, and either alone is sufficient. The canvas holds the
only copy of the remote screen that exists anywhere (`framebuffer.rs`: "the
presenter owns the surface; the core streams deltas at it"), so a re-mount would
clear the backing store and every delta after it would land on a blank screen
with no way to ask for a repaint. And frames arrive on a channel that is
subscribed before `session_open` is called, so the presenter has to exist before
any component could have mounted.

**Order survives an await.** A JPEG rectangle decodes asynchronously, and a
rectangle applied out of order corrupts everything a later copy-rect reads. So
messages queue, each message decodes all of its images *before* any of its
rectangles are applied, and the apply pass is synchronous.

The presenter also watches `seq`. A gap means the encoder dropped a frame under
load and the surface is therefore stale — which the tab says on screen rather
than showing pixels it knows to be wrong, until a keyframe restores it.

## Input

Input travels the other way and has a much smaller budget: correctness matters
more than throughput.

- Keyboard events are captured at the tab level with `preventDefault` on
  everything the session should receive, so `Ctrl+W` closes a remote window
  rather than a local tab
- **The way back to Remoter's own shortcuts is the terminal prefix**, and
  deliberately the same one: a focused remote screen holds the keyboard exactly
  as a focused terminal does, so `Ctrl+Alt` (or whatever the prefix has been
  rebound to) reaches an application binding, and a universal binding — the
  palette, locking the vault — still answers to its plain form so that locking
  is never more than one chord away. A chord with no Ctrl, Alt or Meta is never
  taken from the remote host: it is a character someone is typing, and `?` is
  bound to the cheat sheet. The rule is stated on the surface itself while it
  has focus, because a user who cannot find the way out reads the application
  as hung
- **Alt+Tab and Ctrl+Alt+Delete are buttons, not keystrokes.** The window
  manager takes the first and the operating system takes the second before any
  application sees them, so there is nothing for the tab to capture. The
  surface sends them explicitly instead, as the key transitions `chordFor` in
  `features/sessions/keymap.ts` builds — down in order, up in reverse, because
  a Control released before the key it modified produces a bare keypress at the
  far end
- **Every key the surface pressed is released when it loses focus**, and when
  the window does. Otherwise Alt+Tab leaves Alt held at the remote host for the
  rest of the session and every later keystroke arrives as an Alt chord
- **Input is sent in order.** Each `session_key` and `session_pointer` call is
  chained onto the one before it: two `invoke` calls in flight at once are two
  promises with no ordering between them, and a keyboard that can deliver "ab"
  as "ba" is not a keyboard
- **A view-only session attaches no input handler at all.** Not "sends and is
  refused" — the surface takes no keyboard focus, mounts no pointer handler,
  and says on screen that nothing it does reaches the far end
- **The two framebuffer protocols want different things from one keypress, and
  neither can be derived from the other in Rust.** RDP carries a PS/2 Set 1
  scancode and lets the *server* apply the layout (MS-RDPBCGR
  §2.2.8.1.1.3.1.1.1). RFB carries an X11 keysym, layout already applied by the
  client (RFC 6143 §7.5.4). The browser has both — `KeyboardEvent.code` is the
  physical key and maps to a scancode, `KeyboardEvent.key` is the character the
  layout produced and maps to a keysym — and it is the only place the layout is
  known. So `InputEvent::Key` carries both, and each adapter takes the one it
  needs. `KeyboardEvent.keyCode` is neither, despite its name: it is deprecated,
  it varies by browser and layout, and an adapter that treats it as a scancode
  types correctly on a US keyboard and wrongly everywhere else. This is where
  keyboard-layout bugs live; the mapping tables are tested against a matrix of
  layouts including Turkish Q/F, German, French AZERTY and Arabic. The frontend
  half of that translation is
  `apps/desktop/ui/src/features/sessions/keymap.ts` — `code` → PS/2 Set 1 make
  code with the `E0` prefix carried as bit 8, `key` → X11 keysym — and the Rust
  half, which fills in the keysyms for keys that produce no character, is
  `crates/remoter-proto-vnc/src/keymap.rs`. Neither table guesses: a key the
  browser reports and the table does not name produces nothing, because pressing
  whichever key happens to sit at an invented code is worse than pressing none
- AltGr is read from `getModifierState("AltGraph")`, never inferred from
  `altKey`. On a Turkish, German or French layout the right-hand Alt selects a
  third level of the layout, and sent as plain Alt it arrives at the remote host
  as a window-manager chord the user never pressed. Windows reports AltGr as
  Ctrl+Alt because that is how it is implemented there, so those two bits are
  cleared when AltGraph is set
- Lock states are carried explicitly rather than inferred, because RDP
  synchronises them with a Client Synchronize Event
  (MS-RDPBCGR §2.2.8.1.1.3.1.1.5). A session that never sends one types in the
  wrong case until the user notices and presses Caps Lock twice
- IME composition is passed through for terminal sessions, where xterm.js
  commits the composed text and it travels as `InputEvent::Bytes`. **On a
  framebuffer session it does not yet travel at all**: a key event is dropped
  while `isComposing` is set — forwarding the raw keys as well would type
  everything twice — and there is no variant of `InputEvent` that can carry the
  composed text, because `Key` requires a scancode and composed text has none.
  A user on a Japanese, Chinese or Korean input method therefore has to use the
  remote host's own input method. Closing this needs a vocabulary change in
  `remoter-proto`, not a change in the interface
- Mouse events carry coordinates in **remote** pixels, with the tab's scale and
  the device pixel ratio already divided out. That division belongs in the
  frontend because only the frontend knows what it drew —
  `features/sessions/scaling.ts`, `remotePoint` — and the result is clamped to
  the desktop and to `u16`, which is what both protocols carry, so a pointer
  dragged past the edge reports the edge rather than a coordinate that wraps to
  the opposite side of the screen
- Wheel movement carries **both axes**, in notches of 120 to match RDP's
  `rotationUnits`. A tilt wheel and a trackpad's horizontal swipe are a
  different axis, not a different sign, and dropping `deltaX` is why horizontal
  scrolling does nothing in most remote desktop clients. The vertical axis is
  negated — the DOM calls positive "towards the user" and RDP calls it "away" —
  and `deltaMode` is normalised to pixels first, so one notch is one notch
  whatever the device claims to measure in
- Multi-monitor RDP: each monitor is a separate framebuffer stream; the layout
  is negotiated at connect time

## Scaling and DPI

Four modes, implemented in `features/sessions/scaling.ts` as pure arithmetic so
that the geometry is testable without a canvas.

| Mode | Behaviour | What it needs |
|---|---|---|
| Smart resize | Ask the remote host to resize its desktop to the tab (RDP dynamic resolution over MS-RDPEDISP, VNC `SetDesktopSize`) | A granted resize capability. ⏳ **VNC cannot**: `SetDesktopSize` and ExtendedDesktopSize are community extensions outside RFC 6143 and `vnc-rs` 0.5 does not implement them, so VNC reports `resizable: false`. RDP's answer depends on a channel the server opens, and there is no event that revises a tab's capabilities mid-session |
| Fit to window | Scale the remote framebuffer to the tab, preserving aspect ratio. Never *enlarges*: a desktop smaller than the tab is centred at 1:1 | nothing |
| 1:1 | Native resolution with scrollbars | nothing |
| Zoom | An **integer** magnification — 2x, 3x, 4x and nothing between | nothing |

Scaling is done by the compositor, not by the presenter: the canvas backing
store is always exactly the remote desktop's size and every rectangle lands at
1:1, while the element's CSS size carries the scale. That keeps the per-frame
cost proportional to the dirty area rather than to the window.

**Zoom is integer-only, and that is a correctness choice rather than a
simplification.** A remote desktop is a grid of pixels carrying text that was
already rasterised and hinted for that grid. Resampling it by a non-integer
factor mixes each glyph's stem across two output pixels and 8pt text becomes a
grey smear. An integer factor with nearest-neighbour sampling replicates whole
pixels, so a stem stays a stem — which is what `image-rendering: pixelated`
asks the compositor for whenever one remote pixel covers at least one *device*
pixel. Zooming out is what Fit is for, and there the smooth default is right:
a downscale without interpolation aliases.

HiDPI is handled by requesting a framebuffer at the physical pixel size, not the
logical one, so text on a 4K display is sharp rather than upscaled.

### Smart resize is the default only where the server granted it

"Smart resize" is the best experience where supported, and it is the default for
a session that can do it — Fit is the fallback, because a remote desktop is
nearly always larger than the tab and at 1:1 the first thing a user sees of a
1920×1080 desktop in a 1200px tab is its top-left corner.

**"Where supported" has to mean what the server granted, not what the adapter
offers.** `Capabilities.resizable` as it reaches the interface today is the
adapter's static offer: it is fixed before the connection sequence runs and says
"this adapter implements dynamic resize", not "this server opened the channel".
A Windows host that never opened the Display Control Virtual Channel arrives as
`resizable: true` all the same, and a Smart control drawn from that is a control
that does nothing — on by default.

The gap is bridged in two places and only the second one is permanent:

- **In the RDP adapter**, `granted_capabilities()` and `display_control_open()`
  are the real answer, known once the capability exchange has run.
- **In the interface**, `features/sessions/manager.ts` treats the adapter's
  `rdp.display_control_unavailable` warning as a capability *revision*: it
  withdraws `resizable` from the tab's record, which takes the Smart control off
  the screen and stops the resize requests, and moves a tab still sitting in
  Smart to Fit. The warning itself stays on screen, because the user still has
  to be told why the control they were reaching for is not there.

The second is a stand-in for a capability-revision event on the session channel.
Capabilities are read once, when the tab opens, and this one is not knowable
then; until an event carries the revision, a warning is the only thing that
crosses IPC at the moment the truth is learned.

### On a server that cannot resize, the empty tab is explained, not filled

Withdrawing Smart is correct and it is not sufficient. What the user is then
looking at is Fit doing exactly what it is specified to do — `min(1, vw/dw,
vh/dh)` on both axes — which on a 16:9 desktop in a wider tab leaves a band down
each side, with every control that could have removed it now gone from the row.
The reading that follows is "Fit does not fit", and the warning that would
correct it is a line in the session's notices behind a count, several inches
from the place the question is asked.

So the interface **says why, beside the scale controls**: a chip in the
graphical session's own toolbar, drawn only while there is actually a band and
only while nothing in the tab can change the remote size. Its tooltip names the
one thing that does remove the band — a remote desktop at the tab's proportions
— and says that stretching the picture is deliberately not offered.

**There is no stretch-to-fill mode and there will not be one.** Ignoring the
aspect ratio resamples rasterised remote text along one axis only, which is the
grey-smear failure the integer-zoom rule above exists to avoid, in its worst
form. Every serious client behaves this way; the honest fix for a band is a
matching resolution, and the honest interface is one that says so.

## Remote text, and where it is allowed to render

Pixels are not the only thing the far end draws with. A login banner, a
message of the day, a keyboard-interactive challenge, a directory listing, a
hostname in an error — all of it is text chosen by a machine this application
does not control, and the banner in particular is shown *before* the session has
authenticated.

Three defences, applied in this order, and they are not substitutes for one
another:

1. **It renders as text.** React escapes text children, ICU MessageFormat
   substitutes arguments as data rather than re-parsing them, and
   `dangerouslySetInnerHTML` is an ESLint error in every file that can hold JSX
   — a guard a disable comment can still silence, which
   [coding-standards.md](../development/coding-standards.md#untrusted-content)
   spells out. This is settled and needs no per-surface thought.
2. **It is escaped in Rust, and the escaped twin is what is drawn.** Control
   characters, bidirectional overrides and zero-width characters become a
   visible `\u{XXXX}`. The raw string still crosses IPC — it is what goes back
   on the wire to address a file — but nothing renders it. The function is
   `remoter_proto_ssh::sftp::escape_untrusted`, and every SFTP name, path, user
   and group, plus a progress event's detail, goes through it.
3. **It is bidi-isolated at the point of display.** Escaping bounds what the
   text can contain; isolation bounds what its *direction* can reach.
   `i18n/bidi.ts` wraps a value interpolated into a sentence, and a multi-line
   block — a banner — is drawn `dir="ltr"` with one `<bdi>` per line, so a line
   of Hebrew renders right-to-left as the server meant while no line can reorder
   the line above it or the interface copy around the block.

**`SessionWarning::Banner { text }` is the one DTO that still crosses without
step 2.** It has no escaped twin, so today the banner gets steps 1 and 3 only,
which bounds where a directional character takes effect without neutralising
one. The fix is the same shape as every other: a `text_display` beside `text`,
computed with `escape_untrusted` in `remoter-ipc`'s `warning_wire`, and rendered
in its place. The escaping is deliberately not duplicated in TypeScript — a
second table drifts from the first, and would double-escape the moment the twin
lands.

## Recording — ⏳ not built

Recording would tap the pipeline before rendering, so that what is recorded is
what arrived, independent of how it was displayed. Nothing does this today —
there is no recorder and no `remoter-record` crate, and the branch in the
terminal diagram above is part of the same plan:

- **Terminal**: the raw byte stream with timestamps → asciicast v2
- **Framebuffer**: dirty rectangles with timestamps → a container that can be
  replayed or transcoded to video

See [../features/recording-audit.md](../features/recording-audit.md).
