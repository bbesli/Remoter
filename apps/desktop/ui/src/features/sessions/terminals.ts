/**
 * The terminals themselves, deliberately outside React.
 *
 * An xterm.js instance owns a subtree of the DOM and a WebGL context. React
 * owning that subtree means a re-render can move or replace nodes underneath
 * the renderer, and re-mounting a component would throw away the scrollback of
 * a live session. So each session gets a host `<div>` created here, and the
 * component's only job is to append that div and take it away again — the
 * terminal survives every tab switch, every layout change and every re-render
 * of the shell above it.
 *
 * Two rules from docs/architecture/rendering.md are load-bearing here:
 *
 * - **Output is written straight through.** `remoter-proto`'s sink already
 *   coalesces at the frame interval and `remoter-ipc` forwards one message per
 *   frame. Re-batching here would add a frame of latency to every keystroke
 *   echo in exchange for nothing.
 * - **The renderer is checked, not assumed.** See renderer.ts.
 */

import { openUrl } from "@tauri-apps/plugin-opener";
import { Terminal, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { WebglAddon } from "@xterm/addon-webgl";

import { ipc, type TerminalAppearance } from "@/lib/ipc";
import {
  DEFAULT_TERMINAL_APPEARANCE,
  MAX_TERMINAL_FONT_SIZE,
  MIN_TERMINAL_FONT_SIZE,
  TERMINAL_TOKEN_NAMES,
  resolveTerminalColors,
  type InterfaceTheme,
  type TerminalColors,
} from "@/lib/terminalPalette";

import { chooseRenderer, type RendererReport } from "./renderer";

import "@xterm/xterm/css/xterm.css";
import "./terminalTokens.css";

/**
 * How often live counters reach React.
 *
 * The counters change on every frame; the status bar does not need to. One
 * second is the granularity the numbers are read at anyway, and it keeps a
 * scrolling terminal from re-rendering the shell 60 times a second.
 */
const METRICS_FLUSH_MS = 1000;

/**
 * The longest gap still counted as an echo.
 *
 * Beyond this the output almost certainly belongs to something the user did
 * not type — a log line, a `watch`, a background job — and attributing it to
 * the last keystroke would report a latency nobody experienced.
 */
const ECHO_WINDOW_MS = 2000;

/** How much scrollback a session keeps. Bounded: it is decrypted-adjacent memory. */
const SCROLLBACK = 5000;

/** What the shell reads off a terminal between renders. */
export interface TerminalMetrics {
  bytesIn: number;
  bytesOut: number;
  cols: number;
  rows: number;
  /** Milliseconds between the last keystroke and the next output frame. */
  echoMs: number | null;
}

export interface TerminalCallbacks {
  /** User input, already encoded. Send it to the core unchanged. */
  onInput: (bytes: Uint8Array) => void;
  /** The terminal settled on a new size; tell the far end. */
  onResize: (cols: number, rows: number) => void;
  /** Counters, at most once a second. */
  onMetrics: (metrics: TerminalMetrics) => void;
}

interface Entry {
  term: Terminal;
  fit: FitAddon;
  search: SearchAddon;
  /** The element xterm draws into. Owned here, borrowed by the component. */
  host: HTMLDivElement;
  renderer: RendererReport;
  /**
   * The WebGL addon, while one is loaded.
   *
   * Held because a palette change has to reach it. xterm caches every glyph it
   * has drawn in a GPU texture atlas keyed by colour; assigning `options.theme`
   * updates the background — which is painted separately — but leaves already
   * cached glyphs in their old colours, so a re-themed terminal keeps drawing
   * the previous palette's text until the atlas is dropped.
   */
  webgl: WebglAddon | null;
  opened: boolean;
  observer: ResizeObserver | null;
  metrics: TerminalMetrics;
  lastInputAt: number | null;
  flushTimer: number | null;
  callbacks: TerminalCallbacks;
}

const registry = new Map<string, Entry>();

const encoder = new TextEncoder();

/** Reads a CSS custom property, or empty when the document has none. */
function token(name: string): string {
  if (typeof getComputedStyle !== "function") return "";
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

// ------------------------------------------------------------ appearance ----

/*
 * The terminal's appearance lives here, not in React.
 *
 * Two reasons. The registry below already holds every live `Terminal`, so this
 * is the only module that can push a new palette into a running session
 * without a reconnect — which is the whole point: changing a colour while you
 * are reading a log must recolour the log, not ask you to log in again. And
 * terminals are created by `manager.ts` before any component mounts, so the
 * appearance has to be reachable from outside a hook.
 *
 * The values themselves are in `lib/terminalPalette.ts`, which is pure. This
 * module owns *when* they are applied; that module owns *what* they are.
 */

let appearance: TerminalAppearance = DEFAULT_TERMINAL_APPEARANCE;

/**
 * The interface theme in effect, read off the element `App.tsx` stamps it on.
 *
 * Read from the DOM rather than from the store because this module is outside
 * React and a session can be opened before any component that subscribes to
 * the store has rendered. The attribute is always the resolved theme —
 * "system" has already been turned into light or dark by the time it is set.
 */
function interfaceTheme(): InterfaceTheme {
  const stamped = typeof document === "undefined" ? "" : (document.documentElement.dataset["theme"] ?? "");
  if (stamped === "light" || stamped === "hc-light" || stamped === "hc-dark") return stamped;
  return "dark";
}

/** The colours the current appearance resolves to right now. */
function currentColors(): TerminalColors {
  return resolveTerminalColors(appearance, interfaceTheme());
}

/** The palette as xterm wants it. */
function terminalTheme(colors: TerminalColors): ITheme {
  return {
    background: colors.background,
    foreground: colors.foreground,
    cursor: colors.cursor,
    cursorAccent: colors.cursorAccent,
    selectionBackground: colors.selection,
    black: colors.black,
    red: colors.red,
    green: colors.green,
    yellow: colors.yellow,
    blue: colors.blue,
    magenta: colors.magenta,
    cyan: colors.cyan,
    white: colors.white,
    brightBlack: colors.brightBlack,
    brightRed: colors.brightRed,
    brightGreen: colors.brightGreen,
    brightYellow: colors.brightYellow,
    brightBlue: colors.brightBlue,
    brightMagenta: colors.brightMagenta,
    brightCyan: colors.brightCyan,
    brightWhite: colors.brightWhite,
  };
}

/**
 * The font the terminal is set in.
 *
 * An empty family means "the one the interface uses", which is the default and
 * is why the setting can be left alone by anyone who does not care.
 *
 * A chosen family is put *in front of* the interface's stack rather than
 * replacing it. Nothing here can tell whether the name matches a font on this
 * machine — the platform decides that, silently — so the stack behind it is
 * what turns a typo into "you still have a monospace terminal" instead of
 * "your terminal is now set in the browser's default serif". The settings
 * screen says so in as many words.
 */
function terminalFontFamily(): string {
  const stack = token("--font-mono");
  const chosen = appearance.fontFamily.trim();
  if (chosen === "") return stack;
  return stack === "" ? chosen : `${chosen}, ${stack}`;
}

function terminalFontSize(): number {
  const size = Math.round(appearance.fontSize);
  if (!Number.isFinite(size)) return DEFAULT_TERMINAL_APPEARANCE.fontSize;
  return Math.min(Math.max(size, MIN_TERMINAL_FONT_SIZE), MAX_TERMINAL_FONT_SIZE);
}

/**
 * Publishes the palette as `--term-*` on the document element.
 *
 * xterm takes colours as strings, so it does not need these — but the settings
 * preview, and any future CSS that wants to sit flush against a terminal, do.
 * Writing them here keeps `terminalTokens.css` free of a second copy of the
 * numbers, which is what the old arrangement could not manage once the values
 * became per-user.
 */
function publishTokens(colors: TerminalColors): void {
  if (typeof document === "undefined") return;
  const root = document.documentElement;
  for (const [key, name] of Object.entries(TERMINAL_TOKEN_NAMES)) {
    const value = colors[key as keyof TerminalColors];
    if (value !== undefined) root.style.setProperty(name, value);
  }
}

/**
 * Applies an appearance to every open session, immediately.
 *
 * `terminals.ts` holds the live `Terminal` instances, so a colour change is a
 * property assignment and a repaint — there is nothing to reconnect. A font
 * change also moves the cell size, so the fit is redone: without it the far
 * end would keep sending output sized for the old geometry.
 */
export function applyTerminalAppearance(next: TerminalAppearance): void {
  appearance = next;
  const colors = currentColors();
  publishTokens(colors);

  const theme = terminalTheme(colors);
  const fontFamily = terminalFontFamily();
  const fontSize = terminalFontSize();

  for (const entry of registry.values()) {
    entry.term.options.theme = theme;
    if (fontFamily !== "") entry.term.options.fontFamily = fontFamily;
    entry.term.options.fontSize = fontSize;
    // The new palette reaches the background immediately and the text only
    // after the cached glyphs are dropped. Without this a re-themed terminal
    // shows the new background behind the old palette's foreground, which is
    // the one combination nobody chose and the one most likely to be
    // unreadable.
    try {
      entry.webgl?.clearTextureAtlas();
    } catch {
      // A context that died between the null check and the call. The addon's
      // own loss handler puts the terminal back on the DOM renderer, which
      // reads the theme directly and needs no atlas.
    }
    try {
      entry.fit.fit();
    } catch {
      // A tab that is switched away from has no layout to fit to. It refits
      // when it is attached again.
    }
  }
}

/**
 * Reads the stored appearance once, at start-up.
 *
 * The settings screen is not the only way into a session — most sessions are
 * opened without it ever being visited — so the terminal cannot wait for that
 * screen to hand it a palette. Failure is silent and leaves the default in
 * place: outside Tauri there is no core to ask, and a broken settings file is
 * already reported by the settings screen itself. What must not happen is a
 * session area that refuses to open because a colour could not be read.
 */
async function primeTerminalAppearance(): Promise<void> {
  try {
    const settings = await ipc.getSettings();
    applyTerminalAppearance(settings.terminal);
  } catch {
    applyTerminalAppearance(DEFAULT_TERMINAL_APPEARANCE);
  }
}

void primeTerminalAppearance();

/*
 * "Follow the interface theme" has to keep following it. The attribute is set
 * by `App.tsx` whenever the theme changes, including when the OS flips at
 * sunset, and the high-contrast pair carries a different terminal palette — so
 * an observer, not a one-time read.
 */
if (typeof MutationObserver === "function" && typeof document !== "undefined") {
  new MutationObserver(() => {
    if (appearance.palette === "auto") applyTerminalAppearance(appearance);
  }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
}

function scheduleFlush(entry: Entry): void {
  if (entry.flushTimer !== null) return;
  entry.flushTimer = window.setTimeout(() => {
    entry.flushTimer = null;
    entry.callbacks.onMetrics({ ...entry.metrics });
  }, METRICS_FLUSH_MS);
}

/**
 * Creates the terminal for a tab, or returns the one it already has.
 *
 * Called before the component mounts, because output can arrive before the
 * session area has painted — `session_open` returns after authentication, and
 * the shell's first banner is often already in flight by then.
 */
export function ensureTerminal(tabId: string, callbacks: TerminalCallbacks): Entry {
  const existing = registry.get(tabId);
  if (existing !== undefined) {
    existing.callbacks = callbacks;
    return existing;
  }

  const renderer = chooseRenderer();

  // The stored appearance, as it stands at this moment. If the read at
  // start-up has not landed yet this is the default, and `applyTerminalAppearance`
  // pushes the real one into this instance the moment it does.
  const fontFamily = terminalFontFamily();

  const term = new Terminal({
    // The renderer decision is made here, once, from the probe — see
    // renderer.ts for why a context that initialises proves nothing.
    allowProposedApi: true,
    convertEol: false,
    cursorBlink: true,
    // The user's terminal font, defaulting to the interface's mono stack so
    // the terminal and the fingerprints beside it are set in the same face.
    // Empty falls through to xterm's own default.
    ...(fontFamily === "" ? {} : { fontFamily }),
    fontSize: terminalFontSize(),
    scrollback: SCROLLBACK,
    // The remote host echoes; nothing here simulates it, so what is on screen
    // is what the server accepted (rendering.md).
    theme: terminalTheme(currentColors()),
  });

  const fit = new FitAddon();
  const search = new SearchAddon();
  term.loadAddon(fit);
  term.loadAddon(search);
  // Links are opened by the platform, never navigated to inside the WebView:
  // a MOTD is remote content and must not be able to steer this window.
  term.loadAddon(
    new WebLinksAddon((event, uri) => {
      event.preventDefault();
      void openExternal(uri);
    }),
  );

  const host = document.createElement("div");
  host.className = "remoter-terminal-host";

  const entry: Entry = {
    term,
    fit,
    search,
    host,
    renderer,
    webgl: null,
    opened: false,
    observer: null,
    metrics: { bytesIn: 0, bytesOut: 0, cols: term.cols, rows: term.rows, echoMs: null },
    lastInputAt: null,
    flushTimer: null,
    callbacks,
  };

  term.onData((data) => {
    const bytes = encoder.encode(data);
    entry.lastInputAt = performance.now();
    entry.metrics.bytesOut += bytes.byteLength;
    scheduleFlush(entry);
    entry.callbacks.onInput(bytes);
  });

  // `onBinary` carries bytes xterm could not express as UTF-8 text — a mouse
  // report under some encodings. Each code unit is one byte by contract.
  term.onBinary((data) => {
    const bytes = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i += 1) bytes[i] = data.charCodeAt(i) & 0xff;
    entry.metrics.bytesOut += bytes.byteLength;
    scheduleFlush(entry);
    entry.callbacks.onInput(bytes);
  });

  term.onResize(({ cols, rows }) => {
    entry.metrics.cols = cols;
    entry.metrics.rows = rows;
    scheduleFlush(entry);
    entry.callbacks.onResize(cols, rows);
  });

  registry.set(tabId, entry);
  return entry;
}

/** Opens a URI with the platform's handler rather than inside the WebView. */
async function openExternal(uri: string): Promise<void> {
  try {
    await openUrl(uri);
  } catch {
    // Outside Tauri — a test, a browser preview — there is nothing to open
    // with, and failing silently beats navigating this window away from the
    // application.
  }
}

/**
 * Attaches the terminal's host element to a container and starts fitting it.
 *
 * Returns a detach function. Detaching leaves the terminal alive: it is how a
 * tab is switched away from, and a switched-away session keeps running.
 */
export function attachTerminal(tabId: string, container: HTMLElement): () => void {
  const entry = registry.get(tabId);
  if (entry === undefined) return () => undefined;

  container.appendChild(entry.host);
  if (!entry.opened) {
    entry.term.open(entry.host);
    entry.opened = true;
    if (entry.renderer.kind === "webgl") {
      try {
        const webgl = new WebglAddon();
        // A lost context is not fatal — the GPU can be reset by the driver, or
        // by another application taking it. Dropping the addon puts the
        // terminal back on the DOM renderer rather than leaving a dead canvas.
        webgl.onContextLoss(() => {
          webgl.dispose();
          // Nothing to clear once it is gone, and calling into a disposed
          // addon throws.
          entry.webgl = null;
        });
        entry.term.loadAddon(webgl);
        entry.webgl = webgl;
      } catch {
        entry.renderer = {
          kind: "dom",
          renderer: entry.renderer.renderer,
          reason: "the WebGL renderer refused to start",
        };
      }
    }
  }

  // Fit on every container resize: the addon computes cell size from the
  // element, so it needs the element to have one first.
  const refit = () => {
    try {
      entry.fit.fit();
    } catch {
      // A container with no layout yet — mid-transition, or hidden — has no
      // dimensions to fit to. The next observation will have.
    }
  };
  refit();

  const observer = new ResizeObserver(refit);
  observer.observe(container);
  entry.observer = observer;

  return () => {
    observer.disconnect();
    entry.observer = null;
    entry.host.remove();
  };
}

/**
 * Writes one coalesced frame to the terminal.
 *
 * Straight through, unbuffered: the core already batched this at the frame
 * interval, and a second buffer here would only add latency.
 */
export function writeToTerminal(tabId: string, bytes: Uint8Array): void {
  const entry = registry.get(tabId);
  if (entry === undefined) return;

  entry.metrics.bytesIn += bytes.byteLength;
  if (entry.lastInputAt !== null) {
    const elapsed = performance.now() - entry.lastInputAt;
    entry.lastInputAt = null;
    if (elapsed <= ECHO_WINDOW_MS) entry.metrics.echoMs = Math.round(elapsed);
  }
  scheduleFlush(entry);
  entry.term.write(bytes);
}

/** Writes interface text — a close notice, a reconnect line — as the terminal's own. */
export function writeNotice(tabId: string, text: string): void {
  registry.get(tabId)?.term.writeln(text);
}

/** The renderer this tab's terminal ended up with, for the session panel. */
export function rendererFor(tabId: string): RendererReport | null {
  return registry.get(tabId)?.renderer ?? null;
}

/** The current size, for a resize sent as soon as the session is ready. */
export function sizeOf(tabId: string): { cols: number; rows: number } | null {
  const entry = registry.get(tabId);
  return entry === undefined ? null : { cols: entry.term.cols, rows: entry.term.rows };
}

/** Puts the keyboard back in the terminal after a dialog or a tab switch. */
export function focusTerminal(tabId: string): void {
  registry.get(tabId)?.term.focus();
}

/**
 * Finds text in the scrollback. Returns whether anything matched.
 *
 * The search runs over the buffer the terminal already holds — it does not ask
 * the remote host for anything, which is why it works on a session that has
 * since closed.
 */
export function searchTerminal(tabId: string, needle: string, back = false): boolean {
  const entry = registry.get(tabId);
  if (entry === undefined || needle === "") return false;
  return back ? entry.search.findPrevious(needle) : entry.search.findNext(needle);
}

/** Clears the search highlight when the find bar goes away. */
export function clearSearch(tabId: string): void {
  registry.get(tabId)?.search.clearDecorations();
}

/**
 * Destroys a terminal and everything it holds.
 *
 * Called when a tab closes, never when it is merely switched away from. The
 * scrollback holds whatever the remote host printed, so it is dropped with the
 * tab rather than kept for a tab that might come back.
 */
export function disposeTerminal(tabId: string): void {
  const entry = registry.get(tabId);
  if (entry === undefined) return;
  if (entry.flushTimer !== null) window.clearTimeout(entry.flushTimer);
  entry.observer?.disconnect();
  entry.host.remove();
  entry.term.dispose();
  registry.delete(tabId);
}

/** Whether this tab still has a terminal. */
export function hasTerminal(tabId: string): boolean {
  return registry.has(tabId);
}

/**
 * Whether the keyboard is currently inside a terminal.
 *
 * `docs/ui/information-architecture.md` gives a focused terminal the keyboard
 * and puts the application's own shortcuts behind a `Ctrl+Alt` prefix, because
 * `Ctrl+K` is "kill to end of line" to every shell ever written and an
 * application that swallowed it would be one people stop using for real work.
 * This is how a global handler tells which world it is in.
 *
 * `.xterm` is xterm.js's own root class, and the textarea that actually holds
 * focus is inside it.
 */
export function isTerminalFocused(): boolean {
  const active = document.activeElement;
  return active instanceof Element && active.closest(".xterm") !== null;
}
