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
UI and a dark terminal. Both are token-based and shareable as files.

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

### If this is not fast enough

`OPEN:` **This is the project's principal technical risk.** The mitigation is to
find out early rather than late.

A spike in milestone v0.3 will measure, on all three platforms, at 1080p and
1440p:

- End-to-end latency, input event to rendered frame
- Sustained frame rate under a video-playback workload
- CPU cost, split between encode, IPC and decode
- Memory behaviour over a one-hour session

If the WebView path cannot hold ~30 fps at 1080p with acceptable latency, the
fallback is a **native surface overlay**: render the framebuffer with `wgpu`
into a child window positioned beneath a transparent WebView that carries the UI
chrome. This is a known technique, it is how high-performance Tauri applications
handle video, and it costs us WebView conveniences inside the session area
(no CSS effects over the pixels, more per-platform window code). It does not
change any other layer of the architecture, which is why the decision can be
deferred until there is data.

`OPEN:` Linux specifically needs early measurement. WebKitGTK's compositing path
can silently fall back to software rasterisation, and Tauri's own documentation
flags this. The spike must verify hardware acceleration is actually in use,
rather than trusting that WebGL2 context creation succeeded.

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
