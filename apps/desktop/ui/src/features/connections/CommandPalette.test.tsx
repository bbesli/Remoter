/**
 * The palette's action list.
 *
 * The three vault screens are reachable from the title bar and from here, and
 * "from here" means the query filters down to them. The filter is the part
 * worth pinning: it runs over the action labels in the interface rather than
 * in the core, so a renamed action silently stops being findable and nothing
 * else notices.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { i18n } from "@/i18n";
import { useApp } from "@/stores/app";

import { CommandPalette } from "./CommandPalette";
import { useConnectionEditor } from "./ConnectionEditor";

// Hoisted with the `vi.mock` call below, which runs before the imports above.
const { ipcMock } = vi.hoisted(() => ({
  ipcMock: { search: vi.fn(), listNodes: vi.fn(), lockVault: vi.fn() },
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

function renderPalette() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  useApp.setState({ paletteOpen: true });
  return render(
    <QueryClientProvider client={client}>
      <CommandPalette />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  ipcMock.search.mockResolvedValue([]);
  ipcMock.listNodes.mockResolvedValue([]);
  // Reset before the render, not after: the previous test's sheet is still
  // mounted while the teardown hooks run, and closing it there is a state
  // update outside `act`.
  useApp.setState({ openModals: new Set<string>() });
  useConnectionEditor.setState({ target: null });
  // jsdom implements no layout, so it has no `scrollIntoView`. The palette
  // keeps the active row in view with it on every move of the selection.
  Element.prototype.scrollIntoView = vi.fn();
});

describe("the palette's actions", () => {
  it("offers every screen the title bar offers", async () => {
    renderPalette();

    for (const label of ["Import connections", "Audit log", "Vault settings", "Settings"]) {
      expect(await screen.findByRole("option", { name: new RegExp(label) })).toBeInTheDocument();
    }
  });

  it("narrows the list to what was typed", async () => {
    const user = userEvent.setup();
    renderPalette();

    await user.type(await screen.findByLabelText("Search connections"), "audit");

    expect(await screen.findByRole("option", { name: /Audit log/ })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /Vault settings/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /New connection/ })).not.toBeInTheDocument();
  });

  it("sends the user to the screen the action names", async () => {
    const user = userEvent.setup();
    renderPalette();

    await user.click(await screen.findByRole("option", { name: /Audit log/ }));

    expect(useApp.getState().screen).toEqual({ name: "audit" });
    // The palette closes behind the navigation; leaving it open would put a
    // focus trap over a screen the user just asked for.
    expect(useApp.getState().paletteOpen).toBe(false);
  });
});

/**
 * The same filter, run by a reader whose alphabet English does not cover.
 *
 * The palette filters *translated* labels, which is what makes the fold a
 * localisation question rather than an ASCII one: the words being searched are
 * in the reader's language, so the casing rules applied to them have to be
 * that language's too.
 */
describe("the palette's actions, in Turkish", () => {
  afterEach(async () => {
    await act(async () => {
      await i18n().changeLanguage("en");
    });
  });

  async function switchToTurkish() {
    await act(async () => {
      await i18n().changeLanguage("tr");
      await i18n().loadNamespaces(["connections", "common"]);
    });
  }

  it("finds an action typed in Turkish capitals", async () => {
    // "Kasayı kilitle". Turkish capitalises ı as I, so a reader typing the
    // label in capitals produces KASAYI — which English rules fold to
    // "kasayi", a word that appears in no label.
    const user = userEvent.setup();
    await switchToTurkish();
    renderPalette();

    await user.type(await screen.findByRole("textbox"), "KASAYI");

    expect(
      await screen.findByRole("option", { name: /Kasayı kilitle/ }),
    ).toBeInTheDocument();
  });

  it("finds one whose capital I carries a dot", async () => {
    // "Bağlantıları içe aktar". English rules lowercase İ to an i with a
    // separate combining dot, which matches nothing.
    const user = userEvent.setup();
    await switchToTurkish();
    renderPalette();

    await user.type(await screen.findByRole("textbox"), "İÇE");

    expect(
      await screen.findByRole("option", { name: /Bağlantıları içe aktar/ }),
    ).toBeInTheDocument();
  });

  it("still narrows rather than matching everything", async () => {
    const user = userEvent.setup();
    await switchToTurkish();
    renderPalette();

    await user.type(await screen.findByRole("textbox"), "KASAYI");

    expect(screen.queryByRole("option", { name: /Denetim günlüğü/ })).not.toBeInTheDocument();
  });

  it("still reads a prefix filter as a question about connections", async () => {
    // `tag:` and its siblings are ASCII the core defines, not words in the
    // reader's language, so they are recognised through the invariant fold and
    // the action list steps aside whatever the interface is set to.
    const user = userEvent.setup();
    await switchToTurkish();
    renderPalette();

    await user.type(await screen.findByRole("textbox"), "TAG:prod");

    expect(screen.queryByRole("option", { name: /Ayarlar/ })).not.toBeInTheDocument();
  });
});
