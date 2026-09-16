/**
 * Switches off the parts of the WebView that make a desktop application behave
 * like a web page.
 *
 * Every engine this ships in is a browser underneath, and each brings a
 * browser's habits along unless told otherwise: F5 and Ctrl+R reload the whole
 * interface — dropping every open session with it — Ctrl+P opens a print
 * dialog for the window, a right click on a label offers "Reload" or "Inspect
 * Element" or "Insert Emoji", the middle button on Windows starts a page
 * auto-scroll, and an icon can be dragged out of the window as an image. None
 * of those has a place in a connection manager, and a person who meets one no
 * longer trusts that the rest is native.
 *
 * What is left alone, deliberately:
 *
 * - **Text fields.** An input keeps the platform's own editing menu — Cut,
 *   Copy, Paste — because that menu is native there and people use it.
 * - **Anything that handled the event first.** A component with its own menu
 *   or its own shortcut still gets the event; this only stops the WebView's
 *   default.
 * - **The terminal's keys.** xterm has already turned Ctrl+R into a reverse
 *   search for the shell by the time this sees it; stopping the WebView's
 *   reload does not stop that.
 * - **Development builds.** Reload and the inspector are how the interface is
 *   worked on, so this installs only in a production build.
 */

/** Reload, print, view source, caret browsing, downloads, the page's own find and zoom. */
function isBrowserShortcut(event: KeyboardEvent): boolean {
  const key = event.key.toLowerCase();
  const command = event.ctrlKey || event.metaKey;

  if (key === "f5" || key === "f7" || key === "browserrefresh") return true;
  if (key === "browserback" || key === "browserforward") return true;
  if (!command) return false;
  // AltGr arrives as Ctrl+Alt on Windows, and it is how half the world types
  // `@`, `{` and `\\`. No browser shortcut uses Alt, so a chord with it is left
  // entirely alone.
  if (event.altKey) return false;
  // Ctrl/Cmd + R, Shift+R, P, U, J, S, G, F and the zoom keys. Every one of
  // these is a WebView action with nothing behind it in this application; the
  // application's own shortcuts are registered elsewhere and still run.
  if (["r", "p", "u", "j", "s", "g"].includes(key)) return true;
  if (key === "f" && !event.shiftKey) return !insideTerminal(event.target);
  if (["+", "=", "-", "0"].includes(key)) return !insideTerminal(event.target);
  return false;
}

function insideTerminal(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest(".xterm") !== null;
}

/** A field whose own editing menu is native and worth keeping. */
function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof Element) || insideTerminal(target)) return false;
  if (target.closest("input, textarea, [contenteditable=''], [contenteditable='true']") !== null) {
    return true;
  }
  return false;
}

export function installNativeFeel(target: Window = window): () => void {
  const onKeyDown = (event: KeyboardEvent) => {
    if (isBrowserShortcut(event)) event.preventDefault();
  };

  const onContextMenu = (event: MouseEvent) => {
    if (!isEditable(event.target)) event.preventDefault();
  };

  // Windows' middle-button auto-scroll and Linux's paste-into-anything are both
  // started by the press; the terminal handles its own middle button before
  // this sees it.
  const onMouseDown = (event: MouseEvent) => {
    if (event.button === 1 && !isEditable(event.target) && !insideTerminal(event.target)) {
      event.preventDefault();
    }
  };

  // An icon or a logo dragged out of the window as an image. Anything that
  // opts in with `draggable="true"` — a file in the transfer panes — still can.
  const onDragStart = (event: DragEvent) => {
    const origin = event.target;
    if (origin instanceof Element && origin.closest("[draggable='true']") !== null) return;
    event.preventDefault();
  };

  target.addEventListener("keydown", onKeyDown, true);
  target.addEventListener("contextmenu", onContextMenu, true);
  target.addEventListener("mousedown", onMouseDown, true);
  target.addEventListener("dragstart", onDragStart, true);
  return () => {
    target.removeEventListener("keydown", onKeyDown, true);
    target.removeEventListener("contextmenu", onContextMenu, true);
    target.removeEventListener("mousedown", onMouseDown, true);
    target.removeEventListener("dragstart", onDragStart, true);
  };
}
