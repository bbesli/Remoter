/**
 * How a terminal behaves under the mouse and the clipboard keys, per platform.
 *
 * A terminal embedded in a WebView inherits the WebView's defaults unless told
 * otherwise, and those defaults are a browser's: a right click opens WebKit's
 * text-field menu — Cut, Paste, *Insert Emoji*, *Insert Unicode Control
 * Character* — Ctrl+V on Windows sends a literal `^V` to the remote shell, and
 * nothing a person selects ever reaches the X11 selection. Each of those is
 * small; together they are why a session here felt like a web page rather than
 * a terminal.
 *
 * So each platform gets what its own terminal does, taken from the terminal
 * people there actually use:
 *
 * - **Windows** — Windows Terminal and conhost. Ctrl+C copies *when there is a
 *   selection* and is an interrupt when there is not; Ctrl+V pastes; the right
 *   button copies a selection or, with nothing selected, pastes. Ctrl+Shift+C/V
 *   and the old Ctrl+Insert / Shift+Insert pair work too. A bar cursor.
 * - **macOS** — Terminal.app. Cmd+C, Cmd+V, Cmd+A, Cmd+K to clear the
 *   scrollback; Ctrl+C is always an interrupt, because Cmd is never sent to the
 *   remote end. The right button opens a menu. Option+click selects even while
 *   a program has the mouse. A steady block cursor.
 * - **Linux** — GNOME Terminal and Konsole, which agree. Ctrl+Shift+C/V;
 *   whatever is selected becomes the PRIMARY selection and the middle button
 *   pastes it, and so does Shift+Insert; the right button opens a menu. A
 *   blinking block cursor.
 *
 * Everywhere: when the program on the far end has asked for mouse reports —
 * `vim` with `mouse=a`, `htop`, `mc` — the buttons belong to that program, and
 * holding Shift takes them back. That is what every one of those terminals does,
 * and a paste or a menu stealing a click `mc` was waiting for is a bug.
 *
 * This module decides; `terminals.ts` does. Keeping the decision pure is what
 * lets `terminalInput.test.ts` check Windows' rules on a Linux machine.
 */

import type { Platform } from "@/lib/platform";

/** Something a key or a click asks the terminal to do instead of typing. */
export type TerminalAction =
  | "copy"
  | "paste"
  | "pastePrimary"
  | "selectAll"
  | "clearScrollback"
  | "zoomIn"
  | "zoomOut"
  | "zoomReset";

/** What the right button does, when the far end has not claimed the mouse. */
export type RightClick = "menu" | "copyOrPaste";

export interface TerminalBehaviour {
  cursorStyle: "block" | "bar";
  cursorBlink: boolean;
  rightClick: RightClick;
  /** Whether selecting writes the X11 PRIMARY selection. */
  selectionIsPrimary: boolean;
  /** Whether the middle button pastes the PRIMARY selection. */
  middleClickPastes: boolean;
  /**
   * Characters that end a word for a double-click selection.
   *
   * GNOME and Konsole keep `-./:@_~=?&%` inside a word, so a path, an address
   * or a URL is selected whole — the thing someone double-clicks to copy.
   * Windows Terminal splits on them, and its users expect that.
   */
  wordSeparator: string;
  /** The font a terminal on this platform is set in when the user chose none. */
  fontFamily: string;
}

const UNIX_WORD_SEPARATOR = " ()[]{}',\"`<>|;";
const WINDOWS_WORD_SEPARATOR = " /\\()\"'-.,:;<>~!@#$%^&*|+=[]{}?";

export function behaviourFor(platform: Platform): TerminalBehaviour {
  switch (platform) {
    case "windows":
      return {
        cursorStyle: "bar",
        cursorBlink: true,
        rightClick: "copyOrPaste",
        selectionIsPrimary: false,
        middleClickPastes: false,
        wordSeparator: WINDOWS_WORD_SEPARATOR,
        // Cascadia Mono ships with Windows Terminal and is its default;
        // Consolas is on every Windows since Vista.
        fontFamily: '"Cascadia Mono", "Cascadia Code", Consolas, "Courier New", monospace',
      };
    case "macos":
      return {
        cursorStyle: "block",
        cursorBlink: false,
        rightClick: "menu",
        selectionIsPrimary: false,
        middleClickPastes: false,
        wordSeparator: UNIX_WORD_SEPARATOR,
        // Terminal.app's default face, then the one it used before SF Mono.
        fontFamily: '"SF Mono", SFMono-Regular, Menlo, Monaco, monospace',
      };
    case "linux":
      return {
        cursorStyle: "block",
        cursorBlink: true,
        rightClick: "menu",
        selectionIsPrimary: true,
        middleClickPastes: true,
        wordSeparator: UNIX_WORD_SEPARATOR,
        // The generic family first: fontconfig resolves `monospace` to the
        // face the desktop is configured with, which is exactly what GNOME
        // Terminal and Konsole use by default. Naming a specific font ahead of
        // it would override the user's own system setting.
        fontFamily: 'monospace, "DejaVu Sans Mono", "Noto Sans Mono", "Liberation Mono"',
      };
  }
}

/** The parts of a `KeyboardEvent` a decision needs, so tests can build one. */
export interface KeyChord {
  type: string;
  key: string;
  code: string;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
  metaKey: boolean;
}

/**
 * What a key press means to the terminal itself, or `null` when it is input
 * for the far end.
 *
 * Letters are read from `key`, not `code`: a shortcut follows the letter
 * printed on the key, which is what the native terminals do and what a person
 * on a Turkish F or a French AZERTY keyboard presses.
 */
export function keyAction(
  platform: Platform,
  chord: KeyChord,
  hasSelection: boolean,
): TerminalAction | null {
  if (chord.type !== "keydown") return null;
  const key = chord.key.toLowerCase();
  const { ctrlKey: ctrl, shiftKey: shift, altKey: alt, metaKey: meta } = chord;

  const zoom = zoomAction(chord);

  if (platform === "macos") {
    if (!meta || ctrl || alt) return null;
    if (zoom !== null) return zoom;
    if (shift) return null;
    switch (key) {
      case "c":
        return "copy";
      case "v":
        return "paste";
      case "a":
        return "selectAll";
      case "k":
        return "clearScrollback";
      default:
        return null;
    }
  }

  if (meta || alt) return null;

  // Shift+Insert and Ctrl+Insert predate every other clipboard key. Linux
  // terminals paste the PRIMARY selection on Shift+Insert, as xterm always has.
  if (chord.code === "Insert" || key === "insert") {
    if (shift && !ctrl) return platform === "linux" ? "pastePrimary" : "paste";
    if (ctrl && !shift) return platform === "windows" ? "copy" : null;
    return null;
  }

  if (!ctrl) return null;
  if (zoom !== null) return zoom;

  if (shift) {
    switch (key) {
      case "c":
        return "copy";
      case "v":
        return "paste";
      case "a":
        return platform === "linux" ? "selectAll" : null;
      default:
        return null;
    }
  }

  if (platform === "windows") {
    // The Windows Terminal rule: Ctrl+C copies only when there is something
    // to copy, and is otherwise the interrupt it has always been.
    if (key === "c" && hasSelection) return "copy";
    if (key === "v") return "paste";
  }
  return null;
}

/**
 * Ctrl (Cmd on macOS) with `=`/`+`, `-` or `0`: the font size, as every native
 * terminal binds it. Read from `code` as well as `key`, because the character
 * on the `=` key differs by layout and the numeric keypad has its own.
 */
function zoomAction(chord: KeyChord): TerminalAction | null {
  if (chord.key === "+" || chord.key === "=" || chord.code === "Equal" || chord.code === "NumpadAdd") {
    return "zoomIn";
  }
  if (chord.key === "-" || chord.code === "Minus" || chord.code === "NumpadSubtract") {
    return "zoomOut";
  }
  if (chord.key === "0" || chord.code === "Digit0" || chord.code === "Numpad0") {
    return "zoomReset";
  }
  return null;
}

/**
 * The keys shown beside an item in the terminal's menu, as that platform's own
 * menus write them. Key names are never translated (docs/features/i18n.md).
 */
export function menuShortcut(
  platform: Platform,
  action: "copy" | "paste" | "selectAll" | "clearScrollback" | "find",
): string | null {
  switch (platform) {
    case "macos":
      return { copy: "⌘C", paste: "⌘V", selectAll: "⌘A", clearScrollback: "⌘K", find: "⌘F" }[action];
    case "linux":
      return {
        copy: "Ctrl+Shift+C",
        paste: "Ctrl+Shift+V",
        selectAll: "Ctrl+Shift+A",
        clearScrollback: null,
        find: "Ctrl+Shift+F",
      }[action];
    case "windows":
      return {
        copy: "Ctrl+C",
        paste: "Ctrl+V",
        selectAll: null,
        clearScrollback: null,
        find: "Ctrl+Shift+F",
      }[action];
  }
}
