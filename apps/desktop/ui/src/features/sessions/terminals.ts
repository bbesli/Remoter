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

import { asFailure, ipc, type ClipboardSelection, type IpcFailure, type TerminalAppearance } from "@/lib/ipc";
import { currentPlatform } from "@/lib/platform";
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
import { behaviourFor, keyAction, type TerminalAction } from "./terminalInput";

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

/**
 * This platform's terminal conventions — clipboard keys, what the right and
 * middle buttons do, the cursor, the default face. Decided once: the platform
 * does not change while the application runs. See terminalInput.ts.
 */
const platform = currentPlatform();
const behaviour = behaviourFor(platform);

/**
 * How long after a paste this code performed a paste event from the WebView is
 * treated as the same paste arriving twice.
 *
 * WebKitGTK pastes the PRIMARY selection into a focused text field on a middle
 * click by itself, and xterm's hidden textarea is one. This code pastes on that
 * click too, through the core, so that it works on every engine; whichever of
 * the two the engine lets through second is the duplicate.
 */
const NATIVE_PASTE_GUARD_MS = 750;

/** How far one zoom step moves the font, in pixels. */
const ZOOM_STEP = 1;

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

/**
 * Something a terminal needs the interface around it to draw: its menu, or a
 * clipboard that could not be reached. Terminals live outside React (see the
 * header), so they announce these rather than render them.
 */
export type TerminalEvent =
  | { kind: "menu"; tabId: string; x: number; y: number; hasSelection: boolean }
  | { kind: "clipboardFailed"; tabId: string; failure: IpcFailure };

const listeners = new Set<(event: TerminalEvent) => void>();

/** Hears every terminal's menus and clipboard failures. Returns an unsubscribe. */
export function subscribeTerminalEvents(listener: (event: TerminalEvent) => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function emit(event: TerminalEvent): void {
  for (const listener of listeners) listener(event);
}

/**
 * Reports a clipboard that could not be reached from a graphical tab.
 *
 * Through the terminals' channel because it is the same sentence in the same
 * place: `SessionSurface` already draws a clipboard failure over whichever tab
 * it came from, and a second notice for the same fact would be two ways of
 * saying one thing.
 */
export function reportClipboardFailure(tabId: string, failure: IpcFailure): void {
  emit({ kind: "clipboardFailed", tabId, failure });
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
  /** Font size steps from the configured size, as Ctrl/Cmd +/- leave it. Not stored. */
  zoom: number;
  /** Until when a paste event from the WebView is a duplicate. See {@link NATIVE_PASTE_GUARD_MS}. */
  nativePasteGuardUntil: number;
  /** The pending PRIMARY-selection write, debounced while a drag is still selecting. */
  primaryTimer: number | null;
}

const registry = new Map<string, Entry>();

const encoder = new TextEncoder();

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
  // The platform's own terminal face, not the interface's monospace stack: a
  // terminal set in the editor font of the application around it is one of the
  // things that made it read as a web page. A face the user chose goes first,
  // with the platform's behind it for any glyph it lacks.
  const chosen = appearance.fontFamily.trim();
  if (chosen === "") return behaviour.fontFamily;
  return `${chosen}, ${behaviour.fontFamily}`;
}

/** The face a terminal is set in when the user has not chosen one. For the settings preview. */
export function defaultTerminalFontFamily(): string {
  return behaviour.fontFamily;
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
    entry.term.options.fontSize = zoomed(fontSize, entry.zoom);
    // A safety net, kept deliberately.
    //
    // The WebGL addon does handle a colour change on its own — it subscribes
    // to the theme service and rebuilds its glyph atlas — and a measurement of
    // the pixels actually painted, taken in a real browser, confirmed that the
    // background, the foreground and all sixteen ANSI entries follow a palette
    // change without any help from here.
    //
    // This stays anyway, because it costs one repaint on a deliberate user
    // action and it does not depend on a renderer we do not control behaving
    // the same way on every GPU and driver. What it must not do is claim to be
    // the thing that makes palettes work: it is not, and a comment saying so
    // would send the next reader to the wrong place.
    //
    // Failures are reported rather than swallowed — an earlier version caught
    // and discarded them, which hid the addon refusing the call as effectively
    // as not making it.
    if (entry.webgl !== null) {
      try {
        entry.webgl.clearTextureAtlas();
      } catch (error) {
        // Not fatal: the DOM renderer reads the theme directly and needs no
        // atlas, so the refresh below still repaints correctly.
        console.error("the terminal's glyph cache refused to clear", error);
      }
    }
    try {
      entry.term.refresh(0, Math.max(0, entry.term.rows - 1));
    } catch (error) {
      console.error("the terminal refused to repaint after a palette change", error);
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
    cursorBlink: behaviour.cursorBlink,
    cursorStyle: behaviour.cursorStyle,
    wordSeparator: behaviour.wordSeparator,
    // The right button is handled below, per platform. xterm's own habit of
    // selecting the word under it would turn Windows' "right-click pastes"
    // into "right-click copies the word you happened to be pointing at".
    rightClickSelectsWord: false,
    // Terminal.app: Option+click selects even while a program has the mouse.
    macOptionClickForcesSelection: true,
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
  /*
   * The character grid is left-to-right by specification, whatever language the
   * chrome around it is in.
   *
   * A terminal is not interface copy: the remote host counts columns from the
   * left, addresses the cursor from the left and draws its own box art on that
   * assumption. `\r` means "column zero", and column zero is on the left of the
   * screen for every server this application will ever talk to. So the grid's
   * direction is not the user's to choose, and it is not ours either —
   * docs/features/i18n.md puts it plainly: terminal content is never mirrored.
   *
   * Without this the div inherits `dir` from `<html>`, and under `ar` xterm
   * lays every row out right-aligned. Pinned on the element rather than in a
   * stylesheet because this div is created here, outside React and outside any
   * CSS module (see the header) — the attribute travels with it into whatever
   * container attaches it, including one that has not been written yet.
   */
  host.dir = "ltr";

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
    zoom: 0,
    nativePasteGuardUntil: 0,
    primaryTimer: null,
  };

  // The clipboard and zoom keys, before xterm turns them into bytes for the
  // far end. Returning false tells xterm the key is not input. Asked for every
  // event of a chord, not only the keydown, so a release cannot slip through
  // as a stray character after the press did something else.
  term.attachCustomKeyEventHandler((event) => {
    const action = keyAction(
      platform,
      {
        type: "keydown",
        key: event.key,
        code: event.code,
        ctrlKey: event.ctrlKey,
        shiftKey: event.shiftKey,
        altKey: event.altKey,
        metaKey: event.metaKey,
      },
      term.hasSelection(),
    );
    if (action === null) return true;
    if (event.type === "keydown") {
      event.preventDefault();
      void runTerminalAction(tabId, action);
    }
    return false;
  });

  if (behaviour.selectionIsPrimary) {
    // Whatever is selected is the PRIMARY selection, as it is in every X11
    // terminal. Debounced: a drag changes the selection on every mouse move,
    // and only where it comes to rest is worth a round trip.
    term.onSelectionChange(() => {
      if (entry.primaryTimer !== null) window.clearTimeout(entry.primaryTimer);
      entry.primaryTimer = window.setTimeout(() => {
        entry.primaryTimer = null;
        const text = term.getSelection();
        if (text === "") return;
        ipc.writeClipboardText("primary", text).catch((error: unknown) => {
          emit({ kind: "clipboardFailed", tabId, failure: asFailure(error) });
        });
      }, 150);
    });
  }

  installMouse(tabId, entry);

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
        // A code, not a sentence: `describeRenderer` turns it into the one
        // the user reads, in their language.
        entry.renderer = {
          kind: "dom",
          renderer: entry.renderer.renderer,
          reason: "addonRefused",
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
  if (entry.primaryTimer !== null) window.clearTimeout(entry.primaryTimer);
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

// ------------------------------------------------------ clipboard and mouse ----

function zoomed(size: number, zoom: number): number {
  return Math.min(Math.max(size + zoom * ZOOM_STEP, MIN_TERMINAL_FONT_SIZE), MAX_TERMINAL_FONT_SIZE);
}

/** Whether the program on the far end has asked for mouse reports. */
function farEndHasMouse(entry: Entry): boolean {
  return entry.term.modes.mouseTrackingMode !== "none";
}

/**
 * The buttons, per platform. Listeners go on the host in the capture phase, so
 * they see a click before xterm's own handlers inside it do.
 */
function installMouse(tabId: string, entry: Entry): void {
  const { host } = entry;

  host.addEventListener(
    "contextmenu",
    (event) => {
      // The WebView's own menu never: it is a browser's text-field menu.
      event.preventDefault();
      // The far end asked for the mouse, and xterm has already reported the
      // press to it. Shift takes the button back, as in every native terminal.
      if (farEndHasMouse(entry) && !event.shiftKey) return;

      if (behaviour.rightClick === "copyOrPaste" && !event.shiftKey) {
        if (entry.term.hasSelection()) void runTerminalAction(tabId, "copy");
        else void runTerminalAction(tabId, "paste");
        return;
      }
      emit({
        kind: "menu",
        tabId,
        x: event.clientX,
        y: event.clientY,
        hasSelection: entry.term.hasSelection(),
      });
    },
    true,
  );

  if (behaviour.middleClickPastes) {
    const isOurMiddleClick = (event: MouseEvent) =>
      event.button === 1 && !(farEndHasMouse(entry) && !event.shiftKey);

    host.addEventListener(
      "mousedown",
      (event) => {
        if (!isOurMiddleClick(event)) return;
        event.preventDefault();
        entry.term.focus();
        void pasteInto(tabId, entry, "primary");
      },
      true,
    );
    for (const type of ["mouseup", "auxclick"] as const) {
      host.addEventListener(
        type,
        (event) => {
          if (isOurMiddleClick(event)) event.preventDefault();
        },
        true,
      );
    }
  }

  // A paste the WebView performs on its own, arriving just after one this code
  // performed. See NATIVE_PASTE_GUARD_MS.
  host.addEventListener(
    "paste",
    (event) => {
      if (performance.now() < entry.nativePasteGuardUntil) {
        event.preventDefault();
        event.stopImmediatePropagation();
      }
    },
    true,
  );
}

/**
 * Performs a terminal action: from a key, from a click, or from the menu.
 *
 * Exported for the menu, which is drawn by React and calls back in here.
 */
export async function runTerminalAction(tabId: string, action: TerminalAction): Promise<void> {
  const entry = registry.get(tabId);
  if (entry === undefined) return;

  switch (action) {
    case "copy":
      await copySelection(tabId, entry);
      return;
    case "paste":
      await pasteInto(tabId, entry, "clipboard");
      return;
    case "pastePrimary":
      await pasteInto(tabId, entry, "primary");
      return;
    case "selectAll":
      entry.term.selectAll();
      return;
    case "clearScrollback":
      entry.term.clear();
      return;
    case "zoomIn":
    case "zoomOut":
    case "zoomReset": {
      entry.zoom = action === "zoomReset" ? 0 : entry.zoom + (action === "zoomIn" ? 1 : -1);
      const size = zoomed(terminalFontSize(), entry.zoom);
      // Keep the step count honest at the bounds, so zooming back out after
      // hitting the ceiling takes one press and not ten.
      entry.zoom = Math.round((size - terminalFontSize()) / ZOOM_STEP);
      entry.term.options.fontSize = size;
      try {
        entry.fit.fit();
      } catch {
        // Not attached yet; the next attach fits it.
      }
      return;
    }
  }
}

async function copySelection(tabId: string, entry: Entry): Promise<void> {
  const text = entry.term.getSelection();
  if (text === "") return;
  try {
    await ipc.writeClipboardText("clipboard", text);
  } catch (error) {
    emit({ kind: "clipboardFailed", tabId, failure: asFailure(error) });
    return;
  }
  // Windows Terminal lets go of the selection once it is copied — the cue that
  // the copy happened. Terminal.app and GNOME keep it.
  if (behaviour.rightClick === "copyOrPaste") entry.term.clearSelection();
}

async function pasteInto(tabId: string, entry: Entry, selection: ClipboardSelection): Promise<void> {
  entry.nativePasteGuardUntil = performance.now() + NATIVE_PASTE_GUARD_MS;
  let text: string | null;
  try {
    text = await ipc.readClipboardText(selection);
  } catch (error) {
    emit({ kind: "clipboardFailed", tabId, failure: asFailure(error) });
    return;
  }
  if (text === null) return;
  // `paste`, not `input`: it honours bracketed-paste mode, so a shell that
  // asked for it receives the text as one paste rather than as keystrokes that
  // run each line as it lands, and it turns line endings into the carriage
  // returns a terminal sends for Enter.
  entry.term.paste(text);
  entry.term.focus();
}
