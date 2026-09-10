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
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

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
