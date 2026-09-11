/**
 * The framebuffer surfaces, deliberately outside React — for the same reasons
 * `terminals.ts` is.
 *
 * A session's canvas holds the only copy of the remote screen that exists
 * anywhere: `crates/remoter-proto/src/framebuffer.rs` says so in as many words
 * — "the presenter owns the surface; the core streams deltas at it", and
 * keeping a second copy in Rust would double the memory of every session. A
 * copy-rect reads pixels only this canvas has. So React must not be able to
 * unmount it: a re-mount would clear the backing store and every delta after
 * it would be applied to a blank screen, with no way to ask for a repaint.
 *
 * The other reason is timing. Frames arrive on the session channel, which
 * `manager.ts` wires up before `session_open` is called. The presenter has to
 * exist by then; a component that has not mounted yet cannot own it.
 *
 * So the canvas and its presenter are created here, the component borrows the
 * element, and `disposeSurface` is the one thing that destroys them.
 */

import { FramebufferPresenter, canvasTarget, type PresenterStatus } from "./presenter";

/** What the shell reads off a surface between renders. */
export interface SurfaceMetrics {
  bytesIn: number;
  frames: number;
  width: number;
  height: number;
}

export interface SurfaceCallbacks {
  /** Counters, at most once a second. */
  onMetrics: (metrics: SurfaceMetrics) => void;
}

/**
 * How often live counters reach React.
 *
 * The same reasoning as `terminals.ts`: the counters change on every frame and
 * the status bar does not need to. A framebuffer session makes this sharper —
 * 30 frames a second is 30 renders of the whole shell for a number nobody is
 * reading to that precision.
 */
const METRICS_FLUSH_MS = 1000;

interface Entry {
  /** The element the presenter draws into. Owned here, borrowed by React. */
  canvas: HTMLCanvasElement;
  presenter: FramebufferPresenter | null;
  /**
   * Why there is no presenter, when there is none.
   *
   * A WebView with no 2D context is not a hypothetical — it is what jsdom does,
   * and what a WebView that has exhausted its contexts does. The tab says so
   * rather than showing an empty rectangle for ever.
   */
  unavailable: boolean;
  listeners: Set<() => void>;
  flushTimer: number | null;
  callbacks: SurfaceCallbacks;
}

const registry = new Map<string, Entry>();

/** The status of a surface that could not be created. */
const NO_SURFACE: PresenterStatus = {
  width: 0,
  height: 0,
  frames: 0,
  bytes: 0,
  stale: false,
  decodeError: null,
  cursor: null,
};

/** Whether this tab has a framebuffer surface. */
export function hasSurface(tabId: string): boolean {
  return registry.has(tabId);
}

/**
 * The canvas itself, for the one thing the component owns: how large it is
 * drawn. The backing store is always the remote desktop's size; the element's
 * CSS size is the scale. See `scaling.ts`.
 */
export function surfaceElement(tabId: string): HTMLCanvasElement | null {
  return registry.get(tabId)?.canvas ?? null;
}

/**
 * Creates the surface for a tab, or returns the one it already has.
 *
 * Called the moment the core reports a session whose `capabilities.kind` is
 * `framebuffer`, which is before any frame can arrive: the adapters emit
 * `Ready` before their first `FrameMessage`, and the channel delivers in order.
 */
export function ensureSurface(tabId: string, callbacks: SurfaceCallbacks): void {
  const existing = registry.get(tabId);
  if (existing !== undefined) {
    existing.callbacks = callbacks;
    return;
  }

  const canvas = document.createElement("canvas");
  canvas.className = "remoter-framebuffer-surface";
  /*
   * The remote screen is not interface copy, and it is never mirrored.
   *
   * The same rule `terminals.ts` pins on its host element, for the same reason:
   * the remote host addresses pixels from its own left edge, and a canvas that
   * inherited `dir="rtl"` from `<html>` under an Arabic interface would place
   * every rectangle against the wrong edge. Pinned on the element rather than
   * in a stylesheet because this element is created outside React and has to
   * carry its direction into whatever container attaches it.
   */
  canvas.dir = "ltr";

  const target = canvasTarget(canvas);
  const entry: Entry = {
    canvas,
    presenter: null,
    unavailable: target === null,
    listeners: new Set(),
    flushTimer: null,
    callbacks,
  };

  if (target !== null) {
    entry.presenter = new FramebufferPresenter({
      target,
      onChange: () => {
        for (const listener of entry.listeners) listener();
      },
    });
  }

  registry.set(tabId, entry);
}

/**
 * Lends the canvas to a container, and takes it back on unmount.
 *
 * Mirrors `attachTerminal`: the element outlives the component, so appending
 * and removing it is all React is trusted with.
 */
export function attachSurface(tabId: string, container: HTMLElement): (() => void) | undefined {
  const entry = registry.get(tabId);
  if (entry === undefined) return undefined;
  container.appendChild(entry.canvas);
  return () => {
    if (entry.canvas.parentElement === container) container.removeChild(entry.canvas);
  };
}

/** Takes one encoded frame message off the session channel. */
export function writeFrame(tabId: string, bytes: Uint8Array): void {
  const entry = registry.get(tabId);
  if (entry === undefined) return;
  entry.presenter?.accept(bytes);
  scheduleFlush(entry);
}

/** The remote display changed size, as the core reported it. */
export function resizeSurface(tabId: string, width: number, height: number): void {
  registry.get(tabId)?.presenter?.setDesktopSize(width, height);
}

/** What the surface's chrome reads. Safe on a tab that has no surface. */
export function surfaceStatus(tabId: string): PresenterStatus {
  return registry.get(tabId)?.presenter?.status() ?? NO_SURFACE;
}

/** Whether a surface exists but has no 2D context to draw on. */
export function surfaceUnavailable(tabId: string): boolean {
  return registry.get(tabId)?.unavailable ?? false;
}

/**
 * Subscribes to structural changes: size, staleness, cursor shape, a decode
 * failure. Not to frames — those are counted and flushed on a timer.
 */
export function subscribeSurface(tabId: string, listener: () => void): () => void {
  const entry = registry.get(tabId);
  if (entry === undefined) return () => undefined;
  entry.listeners.add(listener);
  return () => {
    entry.listeners.delete(listener);
  };
}

function scheduleFlush(entry: Entry): void {
  if (entry.flushTimer !== null) return;
  entry.flushTimer = window.setTimeout(() => {
    entry.flushTimer = null;
    const status = entry.presenter?.status() ?? NO_SURFACE;
    entry.callbacks.onMetrics({
      bytesIn: status.bytes,
      frames: status.frames,
      width: status.width,
      height: status.height,
    });
  }, METRICS_FLUSH_MS);
}

/**
 * Destroys a surface and everything it holds.
 *
 * The pixels go with it, and that is the point: a framebuffer is a picture of
 * someone's screen, and a closed tab must not leave one in memory for the next
 * thing that reads a stale canvas.
 */
export function disposeSurface(tabId: string): void {
  const entry = registry.get(tabId);
  if (entry === undefined) return;
  if (entry.flushTimer !== null) window.clearTimeout(entry.flushTimer);
  entry.presenter?.dispose();
  entry.listeners.clear();
  entry.canvas.remove();
  // Zero-sizing releases the backing store; a canvas held by a stray reference
  // would otherwise keep megabytes of the remote screen alive.
  entry.canvas.width = 0;
  entry.canvas.height = 0;
  registry.delete(tabId);
}
