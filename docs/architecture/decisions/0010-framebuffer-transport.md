# ADR-0010: Budgeted adaptive encoding over WebView IPC, with a per-platform presenter

- **Status**: Accepted
- **Date**: 2026-09-10
- **Resolves the open question in**: [rendering.md](../rendering.md)
- **Implementation**: ◐ The WebView presenter and the budgeted adaptive encoder are built. ⏳ `remoter-bench-framepath` was never written, the native `wgpu` presenter does not exist, and the per-platform decision gate below was therefore never run — the WebView presenter ships everywhere by default rather than by measurement.

## Context

Getting remote pixels from the Rust core into the WebView is the project's
principal technical risk ([ADR-0001](0001-technology-stack.md)). Tauri's IPC is
message-passing by design; shared memory is neither supported nor planned, and
that is a security property we benefit from elsewhere.

The arithmetic, at 1080p:

| | Bytes per frame | At 30 fps |
|---|---|---|
| Full raw RGBA | 8.3 MB | 249 MB/s |
| 5 % dirty, raw | 415 KB | 12.4 MB/s |
| Full frame, JPEG q75 | ~200 KB | 6 MB/s |

The naive approach — a full raw frame, base64-encoded into JSON — is hopeless.
But the two realistic workloads sit either side of a manageable number:
interactive desktop use produces small dirty regions, and the pathological case
(video, full-screen scrolling) is exactly the content lossy encoding compresses
well. There is no workload that is simultaneously full-frame *and*
incompressible.

The original plan was to build RDP first and discover in v0.3 whether the
transport could carry it. That sequencing is backwards: it puts the largest
protocol implementation in front of the measurement that determines whether the
architecture works.

## Decision

### 1 · A byte budget, not best-effort

The encoder targets a **configurable per-second byte budget**, default
**12 MB/s**, tied to the connection's bandwidth profile. Within the budget it
chooses per rectangle between copy-rect, RLE, raw and JPEG, escalating to lossy
encoding as the budget tightens rather than dropping frames.

This is how VNC's Tight encoding and Guacamole both behave, and it inverts the
failure mode: under load the image degrades gracefully instead of the session
becoming unresponsive. For a remote administration tool, a slightly soft frame
delivered on time is strictly better than a sharp one delivered late.

### 2 · Measure before building, not after

A standalone harness, `remoter-bench-framepath`, is built in **v0.1** — before
any RDP work. It replays synthetic and captured dirty-rectangle streams through
the real transport and presenter, and reports latency, throughput and frame
queue depth. It needs no protocol implementation at all.

**Acceptance bar**, measured at 1080p and 1440p on all three platforms:

| Metric | Threshold |
|---|---|
| p95 input-to-photon latency | ≤ 80 ms |
| Sustained frame rate, interactive workload | ≥ 30 fps |
| Sustained frame rate, video workload | ≥ 24 fps |
| Frame queue depth over a 10-minute run | Bounded, no growth |
| Hardware acceleration | Confirmed in use, not merely available |

The last row exists because WebKitGTK can create a WebGL2 context backed by a
software rasteriser. A context that initialises successfully proves nothing, and
verifying the renderer string is a two-line check that prevents a
misleading benchmark.

### 3 · The presenter is an interface, and it is per-platform

The frame encoder produces the same binary format regardless of destination.
Only the transport and the presenter differ:

```
FrameEncoder ──▶ binary frame format ──▶ ┌ WebViewPresenter   (IPC → canvas/WebGL2)
                                          └ NativePresenter    (wgpu → child surface)
```

Two consequences follow, and the second is the one that matters:

- Switching presenters is localised. It is not a rewrite of the session layer,
  the protocol adapters, or anything above them.
- **The choice does not have to be the same on every platform.** WebView2 and
  WKWebView may well clear the bar while WebKitGTK does not. Shipping the
  WebView presenter on Windows and macOS and the native presenter on Linux is a
  legitimate outcome, not a failure.

### 4 · The decision gate is the end of v0.2

By then the harness has real numbers on real hardware. Per platform:

- **Passes** → WebView presenter, and the native presenter is not built
- **Fails** → native presenter for that platform, scheduled into v0.3 alongside
  the RDP work rather than discovered during it

## Consequences

**Positive.** The largest risk in the project is measured in the first
milestone, with a week of work, instead of surfacing halfway through the RDP
implementation. The budget model gives predictable behaviour under load. The
per-platform presenter means one weak WebView cannot dictate the architecture
everywhere.

**Negative.** Two presenter implementations may need maintaining, with
platform-specific window and compositing code in the native one. The budget
model means the image is sometimes lossy where a faster path would have been
lossless. Building the harness costs time before anything user-visible exists.

**Neutral.** The binary frame format is now a fixed internal interface, which is
mild extra ceremony and makes the recording format fall out of it for free.

## Revisit if

The harness shows a platform failing by a wide margin — which would mean
reconsidering the presentation layer rather than the presenter — or if Tauri
gains a shared-buffer path, which would remove the constraint entirely.
