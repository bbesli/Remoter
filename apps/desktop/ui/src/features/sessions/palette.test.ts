/**
 * Does choosing a palette actually reach the terminal object?
 *
 * Written because the owner reported, twice, that a palette change moved the
 * background and left the text in the previous palette's colours. The data
 * path reads correctly in source at every step — the palettes differ in their
 * ANSI entries, `resolveTerminalColors` returns them, `terminalTheme` copies
 * all sixteen into the theme, and `applyTerminalAppearance` assigns it to
 * every registered terminal — so this asserts against a REAL `Terminal`
 * rather than a mock, to find out which half of that is wrong.
 */

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { applyTerminalAppearance, disposeTerminal, ensureTerminal } from "./terminals";
import { paletteById } from "@/lib/terminalPalette";

const TAB = "tab-palette";

beforeAll(() => {
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

afterEach(() => {
  disposeTerminal(TAB);
  document.body.replaceChildren();
});

function callbacks() {
  return { onInput: () => undefined, onResize: () => undefined, onMetrics: () => undefined };
}

describe("choosing a palette", () => {
  it("puts the palette's own ANSI colours on the terminal, not just its background", () => {
    const entry = ensureTerminal(TAB, callbacks());

    applyTerminalAppearance({ palette: "gruvbox-dark", overrides: {}, fontFamily: "", fontSize: 13 });
    const gruvbox = paletteById("gruvbox-dark");
    expect(gruvbox).toBeDefined();
    expect(entry.term.options.theme?.background).toBe(gruvbox?.colors.background);
    expect(entry.term.options.theme?.red).toBe(gruvbox?.colors.red);

    applyTerminalAppearance({ palette: "nord", overrides: {}, fontFamily: "", fontSize: 13 });
    const nord = paletteById("nord");
    expect(nord).toBeDefined();
    // The reported symptom, stated as an assertion: the background moves and
    // the text colour does not.
    expect(entry.term.options.theme?.background).toBe(nord?.colors.background);
    expect(entry.term.options.theme?.red).toBe(nord?.colors.red);
    expect(entry.term.options.theme?.brightGreen).toBe(nord?.colors.brightGreen);
  });

  it("damages every row, so the cached glyphs are drawn again in the new colours", () => {
    const entry = ensureTerminal(TAB, callbacks());
    const refresh = vi.spyOn(entry.term, "refresh");

    applyTerminalAppearance({ palette: "solarized-dark", overrides: {}, fontFamily: "", fontSize: 13 });

    // The assertion the reported defect needs: assigning the theme repaints
    // the background on its own, and leaves already-drawn text in the old
    // palette until something marks its rows dirty. Without this call the
    // interface shows one palette's background behind another's foreground.
    expect(refresh).toHaveBeenCalledWith(0, entry.term.rows - 1);
  });
});
