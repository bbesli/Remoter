/**
 * The keyboard map's filter, and the sentence it shows when a save is refused.
 *
 * Both were wrong in the same direction and for the same reason: the screen
 * assumed English. The filter folded case with English rules over text a
 * translator wrote, and the row rendered the core's English `message` under a
 * translated heading.
 *
 * They are tested together because the fix pulls in opposite directions on one
 * screen: the *prose* on a row must fold in the reader's language, and the
 * *key cap* beside it must not — a cap says Ctrl in every language, and
 * folding it as Turkish turns the I on it into a letter no keyboard has.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { i18n } from "@/i18n";
import type { AppSettings } from "@/lib/ipc";

import { ShortcutsSection } from "./ShortcutsSection";

const { ipcMock } = vi.hoisted(() => ({
  ipcMock: { getSettings: vi.fn(), setSettings: vi.fn() },
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

/**
 * The Turkish words the assertions expect, read off the shipped catalogues.
 *
 * The bundler resolves the paths, so moving `locales/` is a build failure here
 * rather than a test that quietly stops reading anything. Pasting the words in
 * instead would let this file keep passing against wording no screen shows.
 */
function shipped<T>(pattern: Record<string, unknown>): T {
  return Object.values(pattern)[0] as T;
}

const TR_COMMON = shipped<{ shortcut: Record<string, { title: string }> }>(
  import.meta.glob("../../../../../../locales/tr/common.json", {
    eager: true,
    import: "default",
  }),
);

const TR_ERRORS = shipped<{ validation: { "name-empty": { message: string } } }>(
  import.meta.glob("../../../../../../locales/tr/errors.json", {
    eager: true,
    import: "default",
  }),
);

/** "Kasayı kilitle" — capitalised in Turkish it becomes KASAYI, not KASAYI's
 *  English fold "kasayi". */
const LOCK_TITLE = TR_COMMON?.shortcut.vaultLock?.title ?? "";
const REFUSAL_TR = TR_ERRORS?.validation["name-empty"]?.message ?? "";

function settings(over: Partial<AppSettings> = {}): AppSettings {
  return {
    theme: "dark",
    locale: "tr",
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
    terminal: null as unknown as AppSettings["terminal"],
    fileDownloadFolder: null,
    ...over,
  };
}

function renderSection() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ShortcutsSection />
    </QueryClientProvider>,
  );
}

async function switchToTurkish() {
  await act(async () => {
    await i18n().changeLanguage("tr");
    // Namespaces load on demand; awaiting them is what makes "still English" a
    // failure rather than a race.
    await i18n().loadNamespaces(["settings", "common", "errors"]);
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  ipcMock.getSettings.mockResolvedValue(settings());
});

afterEach(async () => {
  await act(async () => {
    await i18n().changeLanguage("en");
  });
});

describe("the shortcut filter, in Turkish", () => {
  it("finds a row by its title typed in capitals", async () => {
    // "Kasayı kilitle" capitalises to KASAYI, which English rules fold to
    // "kasayi" — a word in no row on this screen.
    const user = userEvent.setup();
    await switchToTurkish();
    renderSection();
    await screen.findByRole("row", { name: new RegExp(LOCK_TITLE) });

    await user.type(screen.getByRole("textbox"), "KASAYI");

    expect(screen.getByRole("row", { name: new RegExp(LOCK_TITLE) })).toBeInTheDocument();
  });

  it("still narrows rather than matching every row", async () => {
    const user = userEvent.setup();
    await switchToTurkish();
    renderSection();
    await screen.findByRole("row", { name: new RegExp(LOCK_TITLE) });

    const before = screen.getAllByRole("row").length;
    await user.type(screen.getByRole("textbox"), "KASAYI");
    expect(screen.getAllByRole("row").length).toBeLessThan(before);
  });

  it("still finds a row by the letter printed on its key", async () => {
    // A key cap is not language. Folded as Turkish, the I on this cap becomes
    // a dotless ı and the reader's "i" stops matching the key they are
    // looking at.
    const user = userEvent.setup();
    ipcMock.getSettings.mockResolvedValue(settings({ shortcuts: { "vault.lock": "ctrl+i" } }));
    await switchToTurkish();
    renderSection();
    await screen.findByRole("row", { name: new RegExp(LOCK_TITLE) });

    await user.type(screen.getByRole("textbox"), "ctrl i");

    expect(screen.getByRole("row", { name: new RegExp(LOCK_TITLE) })).toBeInTheDocument();
  });
});

describe("a refused save, on the row that asked for it", () => {
  it("says why in Turkish", async () => {
    const user = userEvent.setup();
    ipcMock.setSettings.mockRejectedValue({
      code: "validation.name-empty",
      message: "A name is required.",
      detail: null,
      actions: ["Type a name"],
    });
    await switchToTurkish();
    renderSection();

    // Rebind anything: the row's own failure is what is under test, not which
    // row it lands on.
    const row = await screen.findByRole("row", { name: new RegExp(LOCK_TITLE) });
    await user.click(within(row).getAllByRole("button")[0] as HTMLElement);
    await user.keyboard("{Control>}j{/Control}");

    expect(await screen.findByText(new RegExp(REFUSAL_TR))).toBeInTheDocument();
    expect(screen.queryByText(/A name is required/)).not.toBeInTheDocument();
  });
});
