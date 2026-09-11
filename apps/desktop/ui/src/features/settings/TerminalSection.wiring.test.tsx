/**
 * Does choosing a palette on the settings screen reach a live terminal?
 *
 * TerminalSection.test.tsx mocks `@/features/sessions/terminals`, so it proves
 * the section CALLS the applier and nothing about what the applier then does
 * to a real `Terminal`. The owner reports that a palette change moves the
 * background and leaves the text — and the background is a CSS custom
 * property (`--term-bg`, SessionSurface.module.css:44) written by
 * `publishTokens`, which runs first. So a change that never reached the
 * terminal at all would look exactly like the reported defect.
 *
 * This test wires the two together with nothing mocked between them.
 */

import { render } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import type { AppSettings, TerminalAppearance } from "@/lib/ipc";
import { paletteById } from "@/lib/terminalPalette";
import { disposeTerminal, ensureTerminal } from "@/features/sessions/terminals";
import { TerminalSection } from "./TerminalSection";

const TAB = "tab-wiring";

beforeAll(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
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

const BASE: TerminalAppearance = {
  palette: "remoter-dark",
  overrides: {},
  fontFamily: "",
  fontSize: 13,
};

function settingsWith(terminal: TerminalAppearance): AppSettings {
  return {
    theme: "dark",
    locale: "en",
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    sidebarWidth: 280,
    inspectorOpen: true,
    updateCheckEnabled: false,
    updateChannel: "stable",
    updateLastCheckedAt: null,
    terminalPrefix: "ctrl+alt",
    shortcuts: {},
    terminal,
  };
}

describe("the settings screen and a live terminal", () => {
  it("puts the chosen palette's text colours on a session that is already open", async () => {
    const entry = ensureTerminal(TAB, {
      onInput: () => undefined,
      onResize: () => undefined,
      onMetrics: () => undefined,
    });

    render(
      <TerminalSection
        settings={settingsWith(BASE)}
        onSave={vi.fn()}
        saving={false}
        failure={null}
        onRetrySave={() => undefined}
      />,
    );

    const radios = Array.from(
      document.querySelectorAll<HTMLInputElement>('input[type="radio"]'),
    );
    const gruvbox = radios.find((r) => r.value === "gruvbox-dark");
    expect(gruvbox, "the gruvbox radio should exist").toBeDefined();

    await userEvent.click(gruvbox as HTMLInputElement);

    const expected = paletteById("gruvbox-dark");
    expect(expected).toBeDefined();

    // The background is the half that already works — it is a CSS token.
    expect(document.documentElement.style.getPropertyValue("--term-bg")).toBe(
      expected?.colors.background,
    );

    // The half the owner reports as broken.
    expect(entry.term.options.theme?.red).toBe(expected?.colors.red);
    expect(entry.term.options.theme?.foreground).toBe(expected?.colors.foreground);
  });
});
