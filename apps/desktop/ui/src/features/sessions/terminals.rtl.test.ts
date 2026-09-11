/**
 * The terminal grid does not mirror.
 *
 * The chrome around a session mirrors under Arabic, and should. The grid must
 * not: the remote host counts columns from the left, returns the cursor to
 * column zero on `\r`, and draws its box art on that assumption. A right-
 * aligned, row-reversed shell prompt is not a localised terminal, it is a
 * broken one — and the user cannot tell which, because the text inside it is
 * still the text the server sent.
 *
 * Two mechanisms hold it, in two files, and this file tests both: the `dir`
 * attribute terminals.ts pins on the host div it creates outside React, and the
 * `direction` declaration on the container in SessionSurface.module.css. They
 * are redundant on purpose, so each is asserted on its own.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { attachTerminal, disposeTerminal, ensureTerminal } from "./terminals";
import s from "./SessionSurface.module.css";

const TAB = "tab-rtl";

beforeAll(() => {
  // jsdom has neither, and xterm's `open()` and `attachTerminal()` need them.
  // Both are stubs rather than fakes: nothing here asserts on a media query or
  // on a resize, only on the direction the elements end up laid out in.
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: () => ({
      matches: false,
      media: "",
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }),
  });
  Object.defineProperty(globalThis, "ResizeObserver", {
    writable: true,
    value: class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    },
  });
});

beforeEach(() => {
  // The whole application under Arabic: one attribute on `<html>`, which is
  // all `applyDocumentLanguage()` writes and all the layout reads.
  document.documentElement.setAttribute("dir", "rtl");
});

afterEach(() => {
  disposeTerminal(TAB);
  document.documentElement.removeAttribute("dir");
  document.body.replaceChildren();
});

function callbacks() {
  return { onInput: () => undefined, onResize: () => undefined, onMetrics: () => undefined };
}

describe("a terminal inside a right-to-left interface", () => {
  it("lays the host element out left-to-right, not the document's way", () => {
    const entry = ensureTerminal(TAB, callbacks());

    // Attached under an RTL ancestor rather than to `<body>` directly, because
    // inheritance is the failure mode: the host carried no direction of its
    // own and took the document's.
    const rtlAncestor = document.createElement("div");
    rtlAncestor.setAttribute("dir", "rtl");
    document.body.appendChild(rtlAncestor);
    rtlAncestor.appendChild(entry.host);

    expect(getComputedStyle(rtlAncestor).direction).toBe("rtl");
    expect(getComputedStyle(entry.host).direction).toBe("ltr");
  });

  it("keeps the host left-to-right once xterm has opened into it", () => {
    const entry = ensureTerminal(TAB, callbacks());

    const container = document.createElement("div");
    container.className = s.terminal ?? "";
    document.body.appendChild(container);
    attachTerminal(TAB, container);

    expect(getComputedStyle(entry.host).direction).toBe("ltr");
    // xterm builds its own subtree inside the host. It inherits from the host,
    // so this is the row layer the renderer actually positions cells in.
    const viewport = entry.host.querySelector(".xterm-screen");
    expect(viewport).not.toBeNull();
    if (viewport !== null) expect(getComputedStyle(viewport).direction).toBe("ltr");
  });

  it("pins the direction on the session container as well as on the host", () => {
    // The stylesheet half of the pair, asserted without a terminal at all: a
    // container that inherited RTL would hand it to anything appended into it
    // later, including a future addon's element that carries no `dir`.
    const container = document.createElement("div");
    container.className = s.terminal ?? "";
    document.body.appendChild(container);

    expect(getComputedStyle(document.documentElement).direction).toBe("rtl");
    expect(getComputedStyle(container).direction).toBe("ltr");
  });
});
