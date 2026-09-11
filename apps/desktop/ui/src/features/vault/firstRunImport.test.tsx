/**
 * The first-run import door, end to end through the screens it crosses.
 *
 * This is the route the owner of thirty-seven mRemoteNG connections took on
 * their first Windows run, and it did not exist: both doors on the launch
 * screen called the same handler, so "bring across what I have" ran the
 * create-vault wizard and stopped there. The wizard itself was reachable — from
 * the empty-vault card, the title bar and the palette — which is why the vault
 * eventually held the connections, and why nothing in the code looked broken.
 *
 * So what is asserted here is the join, not the wizard: that the import door
 * and the empty door are different actions, that the intent survives the two
 * screens in between, that it is spent once, and that abandoning creation
 * abandons it too.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { CreateVaultResult, RecentVault } from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      listRecentVaults: vi.fn(),
      clearRecentVaults: vi.fn(),
      forgetRecentVault: vi.fn(),
      suggestVaultPath: vi.fn(),
      passwordStrength: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import { CreateVaultWizard } from "./CreateVaultWizard";
import { useImportIntent } from "./importIntent";
import { RecoveryKeyScreen } from "./RecoveryKeyScreen";
import { VaultPicker } from "./VaultPicker";

const mocked = ipc as unknown as {
  listRecentVaults: ReturnType<typeof vi.fn>;
  suggestVaultPath: ReturnType<typeof vi.fn>;
  passwordStrength: ReturnType<typeof vi.fn>;
};

function draw(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

/** Which group of the recovery key the transcription check asks for. */
const CONFIRM_GROUP = 2;

/** What `vault_create` hands back. Fourteen groups, one of them to retype. */
function created(): CreateVaultResult {
  return {
    path: "/home/ada/acme.rvault",
    recoveryKeyGroups: Array.from({ length: 14 }, (_, i) => `G${String(i).padStart(3, "0")}`),
    confirmGroupIndex: CONFIRM_GROUP,
    kdf: null,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  // No remembered vaults: the picker shows the two first-run doors.
  mocked.listRecentVaults.mockResolvedValue([] as RecentVault[]);
  mocked.suggestVaultPath.mockResolvedValue("/home/ada");
  mocked.passwordStrength.mockResolvedValue({ bits: 0, verdict: "weak", warning: null });
  useImportIntent.setState({ wanted: false });
  useApp.setState({ screen: { name: "picker" }, previousScreen: null });
});

describe("the launch screen's import door", () => {
  it("says the vault comes first and the import wizard second", async () => {
    draw(<VaultPicker />);
    const door = await screen.findByRole("button", { name: /Bring across what I have/ });
    // The copy this replaced promised the wizard "in a later version" — which
    // is how a working feature came to be advertised as absent.
    expect(door.textContent).toContain("import wizard");
    expect(door.textContent).not.toContain("later version");
  });

  it("is a different action from starting empty", async () => {
    const user = userEvent.setup();
    draw(<VaultPicker />);

    await user.click(await screen.findByRole("button", { name: /Bring across what I have/ }));
    expect(useApp.getState().screen.name).toBe("create");
    expect(useImportIntent.getState().wanted).toBe(true);

    useApp.setState({ screen: { name: "picker" }, previousScreen: null });
    useImportIntent.setState({ wanted: false });
    draw(<VaultPicker />);
    await user.click((await screen.findAllByRole("button", { name: /Start empty/ }))[0]!);
    expect(useApp.getState().screen.name).toBe("create");
    expect(useImportIntent.getState().wanted).toBe(false);
  });
});

describe("the create-vault wizard in between", () => {
  it("says the import is still coming", async () => {
    useImportIntent.setState({ wanted: true });
    draw(<CreateVaultWizard />);
    expect(await screen.findByText("Your import is next")).toBeInTheDocument();
  });

  it("says nothing about importing when the user chose to start empty", () => {
    draw(<CreateVaultWizard />);
    expect(screen.queryByText("Your import is next")).toBeNull();
  });

  it("drops the intent when creation is abandoned", async () => {
    const user = userEvent.setup();
    useImportIntent.setState({ wanted: true });
    useApp.setState({ screen: { name: "create" }, previousScreen: { name: "picker" } });
    draw(<CreateVaultWizard />);

    await user.click(screen.getByRole("button", { name: "Back" }));

    expect(useApp.getState().screen.name).toBe("picker");
    // Otherwise some later, unrelated vault creation would end in the importer.
    expect(useImportIntent.getState().wanted).toBe(false);
  });
});

describe("the end of vault creation", () => {
  /** The recovery screen refuses to move on until the key has been retyped. */
  async function confirmTheKey(user: ReturnType<typeof userEvent.setup>) {
    const field = screen.getByRole("textbox", { name: /Type group/i });
    await user.type(field, created().recoveryKeyGroups[CONFIRM_GROUP]!);
  }

  it("opens the importer when the user came in through the import door", async () => {
    const user = userEvent.setup();
    useImportIntent.setState({ wanted: true });
    useApp.setState({ screen: { name: "recovery", result: created() }, previousScreen: null });
    draw(<RecoveryKeyScreen result={created()} />);

    const next = screen.getByRole("button", { name: /start the import/i });
    await confirmTheKey(user);
    await user.click(next);

    expect(useApp.getState().screen.name).toBe("import");
    // The wizard leaves through goBack(), so the main window has to be the
    // screen underneath it — never this one, which must not be returned to.
    expect(useApp.getState().previousScreen?.name).toBe("main");
    // Spent once: a second vault created in the same session is not an import.
    expect(useImportIntent.getState().wanted).toBe(false);
  });

  it("opens the vault as before when they did not", async () => {
    const user = userEvent.setup();
    useApp.setState({ screen: { name: "recovery", result: created() }, previousScreen: null });
    draw(<RecoveryKeyScreen result={created()} />);

    expect(screen.queryByRole("button", { name: /start the import/i })).toBeNull();
    await confirmTheKey(user);
    await user.click(screen.getByRole("button", { name: /open the vault/i }));
    expect(useApp.getState().screen.name).toBe("main");
  });
});
