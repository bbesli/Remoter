/**
 * The promises this section makes on screen, checked against what it does.
 *
 * Three of them, and each has been a bug in this project before in some other
 * form: a control that says it resets something must actually reset it, a
 * warning about contrast must appear for a palette that fails and not for one
 * that passes, and "changes reach sessions that are already open" must mean a
 * push into the live terminals rather than a note in a settings file.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// The real module owns xterm instances and a WebGL probe. What matters here is
// only that the section pushes into it, so it is replaced by a spy.
const applyTerminalAppearance = vi.fn();
vi.mock("@/features/sessions/terminals", () => ({
  applyTerminalAppearance: (...args: unknown[]) => applyTerminalAppearance(...args),
}));

// jsdom has no media queries. The section reads one, through `useSystemTheme`,
// to know what "follow the interface theme" currently resolves to.
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

import type { AppSettings, IpcFailure, TerminalAppearance } from "@/lib/ipc";
import { paletteById } from "@/lib/terminalPalette";
import { TerminalSection } from "./TerminalSection";

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

const BASE: TerminalAppearance = {
  palette: "remoter-dark",
  overrides: {},
  fontFamily: "",
  fontSize: 13,
};

function renderSection(terminal: TerminalAppearance = BASE) {
  const onSave = vi.fn();
  applyTerminalAppearance.mockClear();
  render(
    <TerminalSection
      settings={settingsWith(terminal)}
      onSave={onSave}
      saving={false}
      failure={null}
      onRetrySave={() => undefined}
    />,
  );
  return { onSave };
}

/** The hex field for one colour, by its visible name. */
function hexField(name: string): HTMLInputElement {
  const field = screen.getByLabelText(`${name}, hex value`);
  expect(field).toBeInstanceOf(HTMLInputElement);
  return field as HTMLInputElement;
}

describe("editing a colour", () => {
  it("pushes the change into open sessions before anything is stored", async () => {
    const user = userEvent.setup();
    renderSection();

    const field = hexField("1 Red");
    await user.clear(field);
    await user.type(field, "#00ff00");

    // The last push is what the terminals ended up with.
    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.overrides["red"]).toBe("#00ff00");
  });

  it("shows a half-typed value without taking it as a colour", async () => {
    const user = userEvent.setup();
    renderSection();

    const field = hexField("1 Red");
    await user.clear(field);
    // `#00f` and `#00ff` are both colours — the short forms with and without
    // alpha — so both are taken. `#00fff` is five digits and is nothing.
    await user.type(field, "#00fff");

    expect(field.value).toBe("#00fff");
    expect(field).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByRole("alert")).toHaveTextContent("That is not a colour");

    // The terminal keeps the last value that was a colour rather than being
    // blanked while someone is mid-keystroke.
    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.overrides["red"]).toBe("#0000ff");
  });

  it("resets one colour back to the palette's own", async () => {
    const user = userEvent.setup();
    const remoterDark = paletteById("remoter-dark");
    expect(remoterDark).toBeDefined();
    renderSection({ ...BASE, overrides: { red: "#00ff00" } });

    await user.click(
      screen.getByRole("button", { name: "Reset 1 Red to the palette's own colour" }),
    );

    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.overrides["red"]).toBeUndefined();
    expect(hexField("1 Red").value).toBe(remoterDark?.colors.red);
  });

  it("offers a whole-set reset only when something is actually overridden", async () => {
    const user = userEvent.setup();
    const { unmount } = render(
      <TerminalSection
        settings={settingsWith(BASE)}
        onSave={vi.fn()}
        saving={false}
        failure={null}
        onRetrySave={() => undefined}
      />,
    );
    expect(screen.getByRole("button", { name: "Reset every colour" })).toBeDisabled();
    unmount();

    renderSection({ ...BASE, overrides: { red: "#00ff00", blue: "#ff0000" } });
    const resetAll = screen.getByRole("button", { name: "Reset every colour" });
    expect(resetAll).toBeEnabled();
    await user.click(resetAll);

    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.overrides).toEqual({});
  });
});

describe("the contrast warning", () => {
  it("names the colour and its ratio when one will be hard to read", () => {
    // Red on a dark blue background: the pairing the whole check exists for.
    renderSection({
      ...BASE,
      overrides: { background: "#001a4d", red: "#c00000" },
    });

    const list = screen.getByRole("list");
    const red = within(list)
      .getAllByRole("listitem")
      .find((item) => item.textContent?.includes("1 Red"));
    expect(red).toBeDefined();
    expect(red?.textContent).toMatch(/\d\.\d:1/);
    expect(red?.textContent).toContain("Unreadable");
  });

  it("does not block the choice it warns about", async () => {
    const user = userEvent.setup();
    renderSection();

    const field = hexField("1 Red");
    await user.clear(field);
    await user.type(field, "#131418");

    // A colour that is all but invisible on the background is still applied:
    // it is the user's terminal.
    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.overrides["red"]).toBe("#131418");
  });

  it("says so plainly when nothing falls short", () => {
    // High contrast is white on black; only colour 0 falls short, and that one
    // is the background's own colour in every palette ever published.
    renderSection({ ...BASE, palette: "high-contrast", overrides: { black: "#ffffff" } });
    expect(screen.getByText(/Every colour clears 4.5:1/)).toBeInTheDocument();
  });
});

describe("the palette list", () => {
  it("names who made each palette rather than presenting them as ours", () => {
    renderSection();
    expect(
      screen.getByRole("radio", { name: /Solarized Dark — Ethan Schoonover, MIT/ }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("radio", { name: /Nord — Arctic Ice Studio and Sven Greb, MIT/ }),
    ).toBeInTheDocument();
  });

  it("keeps overrides when the palette underneath them changes", async () => {
    const user = userEvent.setup();
    renderSection({ ...BASE, overrides: { red: "#00ff00" } });

    await user.click(screen.getByRole("radio", { name: /^Gruvbox Dark/ }));

    const gruvbox = paletteById("gruvbox-dark");
    const pushed = applyTerminalAppearance.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
    expect(pushed?.palette).toBe("gruvbox-dark");
    expect(pushed?.overrides["red"]).toBe("#00ff00");
    // Everything that was left alone moves with the palette.
    expect(hexField("Background").value).toBe(gruvbox?.colors.background);
  });

  it("says what following the interface theme currently resolves to", () => {
    renderSection({ ...BASE, palette: "auto" });
    expect(screen.getByText(/Right now that is Remoter Dark\./)).toBeInTheDocument();
  });
});

/**
 * What the editor shows against what the core stored.
 *
 * The draft used to be seeded once, so the two could drift apart with nothing
 * to bring them back: a refused write left the rejected value in the fields,
 * and the next edit sent it again.
 */
describe("reconciling with what the core stored", () => {
  const REFUSED: IpcFailure = {
    code: "settings.write-failed",
    message: "The settings file could not be written.",
    detail: null,
    actions: [],
  };

  /** Renders with the two props the screen above changes after a write. */
  function renderControlled(terminal: TerminalAppearance = BASE) {
    const onSave = vi.fn();
    applyTerminalAppearance.mockClear();
    const view = render(
      <TerminalSection
        settings={settingsWith(terminal)}
        onSave={onSave}
        saving={false}
        failure={null}
        onRetrySave={() => undefined}
      />,
    );
    return {
      onSave,
      /** What the screen above does when `settings_set` comes back an error. */
      refuse(failure: IpcFailure) {
        view.rerender(
          <TerminalSection
            settings={settingsWith(terminal)}
            onSave={onSave}
            saving={false}
            failure={failure}
            onRetrySave={() => undefined}
          />,
        );
      },
      /** What it does when the core answers with the value it actually kept. */
      stored(next: TerminalAppearance) {
        view.rerender(
          <TerminalSection
            settings={settingsWith(next)}
            onSave={onSave}
            saving={false}
            failure={null}
            onRetrySave={() => undefined}
          />,
        );
      },
    };
  }

  it("puts the stored colour back when the write is refused", async () => {
    const user = userEvent.setup();
    const remoterDark = paletteById("remoter-dark");
    expect(remoterDark).toBeDefined();
    const { onSave, refuse } = renderControlled();

    const field = hexField("1 Red");
    await user.clear(field);
    await user.type(field, "#00ff00");
    await waitFor(() => expect(onSave).toHaveBeenCalled());
    expect(hexField("1 Red").value).toBe("#00ff00");

    refuse(REFUSED);

    await waitFor(() => expect(hexField("1 Red").value).toBe(remoterDark?.colors.red));
  });

  it("does not send the refused colour again with the next edit", async () => {
    const user = userEvent.setup();
    const { onSave, refuse } = renderControlled();

    const red = hexField("1 Red");
    await user.clear(red);
    await user.type(red, "#00ff00");
    await waitFor(() => expect(onSave).toHaveBeenCalled());

    refuse(REFUSED);
    await waitFor(() => expect(hexField("1 Red").value).not.toBe("#00ff00"));

    const green = hexField("2 Green");
    await user.clear(green);
    await user.type(green, "#00cc00");

    await waitFor(() => {
      const sent = onSave.mock.calls.at(-1)?.[0] as TerminalAppearance | undefined;
      expect(sent?.overrides["green"]).toBe("#00cc00");
      // The value the core refused is gone, rather than riding along with an
      // edit the user did make.
      expect(sent?.overrides["red"]).toBeUndefined();
    });
  });

  it("takes the appearance the core kept when it is not the one that was sent", async () => {
    const user = userEvent.setup();
    const { onSave, stored } = renderControlled();

    await user.click(screen.getByRole("radio", { name: /^Nord/ }));
    await waitFor(() => expect(onSave).toHaveBeenCalled());

    // The core stored something else — a clamp, a migration, another window.
    stored({ ...BASE, palette: "gruvbox-dark" });

    await waitFor(() =>
      expect(screen.getByRole("radio", { name: /^Gruvbox Dark/ })).toBeChecked(),
    );
  });
});
