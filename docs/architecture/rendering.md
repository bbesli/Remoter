# Rendering

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
before anything else is optimised. The core merges overlapping rectangles and
coalesces updates that arrive faster than the display refresh.

**2 · Raw byte payloads, never JSON.** Tauri v2's IPC rewrite supports raw
payloads specifically to avoid JSON serialisation of binary data. Frame updates
are returned as `tauri::ipc::Response` byte slices with a compact binary header:

```
┌────────────────────────────────────────────────────────────┐
│ u32 session_id │ u32 seq │ u8 encoding │ u8 flags │ u16 n   │
├────────────────────────────────────────────────────────────┤
│ n × rect { u16 x, u16 y, u16 w, u16 h, u32 byte_length }    │
├────────────────────────────────────────────────────────────┤
│ pixel payload, concatenated, encoding as declared           │
└────────────────────────────────────────────────────────────┘
```

The frontend parses this with a `DataView` — no allocation per rectangle — and
uploads each rect with `texSubImage2D` (WebGL2) or `putImageData` (2D fallback).

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

**A harness comes first.** `remoter-bench-framepath` is built in **v0.1**,
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

### The presenter is an interface, and it is per-platform

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

## Input

Input travels the other way and has a much smaller budget: correctness matters
more than throughput.

- Keyboard events are captured at the tab level with `preventDefault` on
  everything the session should receive, so `Ctrl+W` closes a remote window
  rather than a local tab
- Scancode-level translation for RDP, which expects scancodes rather than
  characters. This is where keyboard-layout bugs live; the layout mapping tables
  are tested against a matrix of layouts including Turkish Q/F, German, French
  AZERTY and Arabic
- IME composition is passed through for terminal sessions and handled natively
  for framebuffer sessions
- Mouse events carry sub-pixel-accurate coordinates scaled by the current zoom
  and the device pixel ratio
- Multi-monitor RDP: each monitor is a separate framebuffer stream; the layout
  is negotiated at connect time

## Scaling and DPI

| Mode | Behaviour |
|---|---|
| Fit to window | Scale the remote framebuffer to the tab, preserving aspect ratio |
| 1:1 | Native resolution with scrollbars |
| Smart resize | Ask the remote host to resize its desktop to the tab (RDP dynamic resolution, VNC `SetDesktopSize`) |
| Zoom | User-controlled scale factor, independent of the above |

"Smart resize" is the best experience where supported and is the default for
RDP. HiDPI is handled by requesting a framebuffer at the physical pixel size,
not the logical one, so text on a 4K display is sharp rather than upscaled.

## Recording

Recording taps the pipeline before rendering, so what is recorded is what
arrived, independent of how it was displayed:

- **Terminal**: the raw byte stream with timestamps → asciicast v2
- **Framebuffer**: dirty rectangles with timestamps → a container that can be
  replayed or transcoded to video

See [../features/recording-audit.md](../features/recording-audit.md).
