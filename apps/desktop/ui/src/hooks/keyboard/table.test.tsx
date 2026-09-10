/**
 * The settings table, checked against the registry it is drawn from.
 *
 * This test lives beside the registry rather than beside the component because
 * what it asserts is a property of the registry: the table cannot list an
 * action the application does not carry, and cannot offer an editor for a
 * binding the core will not store. Those are the two ways the old hand-written
 * table lied.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ShortcutsSection } from "@/features/settings/ShortcutsSection";

import { SHORTCUT_ACTIONS, findAction } from "./actions";
import { acceleratorLabel } from "./accelerator";

const { ipcMock } = vi.hoisted(() => ({
  ipcMock: { getSettings: vi.fn(), setSettings: vi.fn() },
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

function settings(overrides: Record<string, string> = {}) {
  return {
    theme: "system",
    locale: "en",
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    sidebarWidth: 268,
    inspectorOpen: false,
    updateCheckEnabled: false,
    updateChannel: "stable",
    updateLastCheckedAt: null,
    terminalPrefix: "ctrl+alt",
    shortcuts: overrides,
  };
}

function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ShortcutsSection />
    </QueryClientProvider>,
  );
}

/** The row whose action column names this action. */
function rowFor(title: string): HTMLElement {
  const cell = screen.getByRole("rowheader", { name: new RegExp(`^${title}`) });
  const row = cell.closest("tr");
  if (row === null) throw new Error(`no row for ${title}`);
  return row;
}

beforeEach(() => {
  vi.clearAllMocks();
  ipcMock.getSettings.mockResolvedValue(settings());
  ipcMock.setSettings.mockImplementation((patch: { shortcuts?: Record<string, string | null> }) =>
    Promise.resolve(
      settings(
        Object.fromEntries(
          Object.entries(patch.shortcuts ?? {}).filter(
            (pair): pair is [string, string] => pair[1] !== null,
          ),
        ),
      ),
    ),
  );
});

describe("every row resolves to a registered action", () => {
  it("draws one row per action and no row without one", async () => {
    mount();
    await screen.findByRole("rowheader", { name: /Command palette/ });

    // One header row plus one row per action, and nothing else.
    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(SHORTCUT_ACTIONS.length + 1);

    for (const row of rows.slice(1)) {
      const heading = within(row).getByRole("rowheader").textContent ?? "";
      const action = SHORTCUT_ACTIONS.find((one) => heading.startsWith(one.title));
      expect(action, `row "${heading}" names no registered action`).toBeDefined();
      expect(findAction(action?.id ?? "")).toBeDefined();
    }
  });

  it("shows the keys the registry resolved, including an override", async () => {
    ipcMock.getSettings.mockResolvedValue(settings({ "tab.close": "ctrl+j" }));
    mount();

    const row = await waitFor(() => rowFor("Close tab"));
    expect(within(row).getByText("Ctrl")).toBeInTheDocument();
    expect(within(row).getByText("J")).toBeInTheDocument();
  });
});

describe("a row never claims more than the build has", () => {
  it("says so when nothing is bound to an action", async () => {
    mount();
    const row = await waitFor(() => rowFor("Shortcut cheat sheet"));

    expect(within(row).getByText(/no cheat-sheet overlay/i)).toBeInTheDocument();
    expect(within(row).getByRole("cell", { name: "Nowhere" })).toBeInTheDocument();
  });

  it("offers no editor where the core cannot store a change", async () => {
    mount();
    await screen.findByRole("rowheader", { name: /Command palette/ });

    for (const action of SHORTCUT_ACTIONS.filter((one) => !one.editable)) {
      const row = rowFor(action.title);
      expect(within(row).queryByRole("button")).toBeNull();
      expect(
        within(row).getByText(action.unrebindableReason ?? ""),
        `${action.title} does not say why it cannot be changed`,
      ).toBeInTheDocument();
    }
  });

  it("names the desktop conflict on the row that has it", async () => {
    mount();
    const row = await waitFor(() => rowFor("Next tab"));
    expect(within(row).getByText(/window switcher/i)).toBeInTheDocument();
  });
});

describe("editing a binding", () => {
  it("rebinds on the keys that are pressed, and stores them", async () => {
    const user = userEvent.setup();
    mount();

    const row = await waitFor(() => rowFor("Close tab"));
    await user.click(within(row).getByRole("button", { name: /Change the shortcut for Close tab/ }));

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "j", ctrlKey: true, code: "KeyJ", cancelable: true }),
      );
    });

    await waitFor(() => {
      expect(ipcMock.setSettings).toHaveBeenCalledWith({ shortcuts: { "tab.close": "ctrl+j" } });
    });
  });

  it("refuses a combination another action holds, and names that action", async () => {
    const user = userEvent.setup();
    mount();

    const row = await waitFor(() => rowFor("Close tab"));
    await user.click(within(row).getByRole("button", { name: /Change the shortcut for Close tab/ }));

    act(() => {
      // Ctrl+K is the command palette's.
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "k", ctrlKey: true, code: "KeyK", cancelable: true }),
      );
    });

    const alert = await within(rowFor("Close tab")).findByRole("alert");
    expect(alert).toHaveTextContent(/Command palette and search/);
    expect(alert).toHaveTextContent(acceleratorLabel("ctrl+k"));
    expect(ipcMock.setSettings).not.toHaveBeenCalled();
  });

  it("refuses a key the remote host owns, for a binding that reaches into a session", async () => {
    const user = userEvent.setup();
    mount();

    const row = await waitFor(() => rowFor("Lock vault"));
    await user.click(within(row).getByRole("button", { name: /Change the shortcut for Lock vault/ }));

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "c", ctrlKey: true, code: "KeyC", cancelable: true }),
      );
    });

    const alert = await within(rowFor("Lock vault")).findByRole("alert");
    expect(alert).toHaveTextContent(/belongs to the remote host/i);
    expect(ipcMock.setSettings).not.toHaveBeenCalled();
  });

  it("cancels on Escape without changing anything", async () => {
    const user = userEvent.setup();
    mount();

    const row = await waitFor(() => rowFor("Close tab"));
    await user.click(within(row).getByRole("button", { name: /Change the shortcut for Close tab/ }));

    act(() => {
      window.dispatchEvent(
        new KeyboardEvent("keydown", { key: "Escape", cancelable: true }),
      );
    });

    await waitFor(() => {
      expect(
        within(rowFor("Close tab")).getByRole("button", { name: /Change the shortcut/ }),
      ).toBeInTheDocument();
    });
    expect(ipcMock.setSettings).not.toHaveBeenCalled();
  });

  it("restores every shipped default in one call, and only the ids the core stores", async () => {
    const user = userEvent.setup();
    ipcMock.getSettings.mockResolvedValue(settings({ "tab.close": "ctrl+j" }));
    mount();

    await waitFor(() => rowFor("Close tab"));
    await user.click(screen.getByRole("button", { name: "Reset every shortcut" }));

    await waitFor(() => expect(ipcMock.setSettings).toHaveBeenCalledTimes(1));
    const call = ipcMock.setSettings.mock.calls[0]?.[0] as { shortcuts: Record<string, null> };
    const editable = SHORTCUT_ACTIONS.filter((one) => one.editable).map((one) => one.id);
    expect(Object.keys(call.shortcuts).sort()).toEqual([...editable].sort());
    expect(Object.values(call.shortcuts).every((value) => value === null)).toBe(true);
  });
});

describe("the terminal prefix", () => {
  it("is a control, and saves what is chosen", async () => {
    const user = userEvent.setup();
    mount();

    const chosen = await screen.findByRole("radio", { name: "Ctrl + Shift" });
    await user.click(chosen);

    await waitFor(() => {
      expect(ipcMock.setSettings).toHaveBeenCalledWith({ terminalPrefix: "ctrl+shift" });
    });
  });
});
