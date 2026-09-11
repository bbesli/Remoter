/**
 * The line this section ends on.
 *
 * It used to say terminal themes "are not configurable in this version", which
 * stopped being true the moment the Terminal tab shipped with eight palettes,
 * per-colour editing and a contrast check. A settings screen that denies a
 * feature the next tab along provides sends the user looking for something
 * they already have — so the note is checked here, and so is the half of it
 * that is easy to get wrong: the terminal palette ships as "follow the
 * interface theme", so the two are not simply independent.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

// jsdom has no media queries. The section reads one, through `useSystemTheme`,
// to say what "follow the system" currently resolves to.
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

import type { AppSettings } from "@/lib/ipc";

import { AppearanceSection } from "./AppearanceSection";

const settings: AppSettings = {
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
  fileDownloadFolder: null,
  terminalPrefix: "ctrl+alt",
  shortcuts: {},
  terminal: { palette: "auto", overrides: {}, fontFamily: "", fontSize: 13 },
};

function renderSection(): HTMLElement {
  const { container } = render(
    <AppearanceSection
      settings={settings}
      onSave={vi.fn()}
      savingField={null}
      failure={null}
      onRetrySave={() => undefined}
    />,
  );
  return container;
}

describe("AppearanceSection", () => {
  it("points at the Terminal tab instead of denying the feature exists", () => {
    const container = renderSection();
    const text = container.textContent ?? "";

    expect(screen.getByText(/Terminal tab/)).toBeInTheDocument();
    expect(text).not.toMatch(/not configurable/i);
  });

  it("says the terminal palette follows this theme until one is chosen there", () => {
    const container = renderSection();
    const text = container.textContent ?? "";

    // The default is `palette: "auto"`, so "they are separate" on its own
    // would be the next false sentence on this screen.
    expect(text).toMatch(/follows the theme you pick here/);
  });
});
