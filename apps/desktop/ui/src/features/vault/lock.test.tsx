/**
 * What the application does when the vault locks under it.
 *
 * This renders the whole application — the real `App`, the real query client
 * from `app/queryClient.ts`, the real screens — and drives it the way the core
 * drives it: the commands start rejecting with `vault.auto-locked`, which is
 * exactly what `crates/remoter-ipc` returns once the idle timeout has fired.
 * Only the IPC boundary is mocked.
 *
 * That is deliberate, and it is the whole reason this file exists rather than
 * a unit test of `enterLockedState`. The defect it pins survived two rounds of
 * fixing: the lock was handled, the query cache was cleared on the lock
 * *button*, `vault_state` was polled — and the tree stayed on screen anyway
 * after an idle lock, because the one path nobody rendered end to end was the
 * one the user walked. A test that asserted `clearVaultScopedQueries` had been
 * called would have been green throughout. So these assert what is in the
 * document.
 */

import { QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { IpcFailure, Slot, TreeNode, VaultProbe, VaultState } from "@/lib/ipc";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      vaultState: vi.fn(),
      listNodes: vi.fn(),
      resolveNode: vi.fn(),
      search: vi.fn(),
      listTunnels: vi.fn(),
      lockVault: vi.fn(),
      unlockVault: vi.fn(),
      probeVault: vi.fn(),
      protocolSchemas: vi.fn(),
      getSettings: vi.fn(),
      listRecentVaults: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";
import { App } from "@/app/App";
import { createQueryClient } from "@/app/queryClient";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useSessions } from "@/features/sessions";
import { withoutBidi } from "@/test/bidi";

const vaultState = vi.mocked(ipc.vaultState);
const listNodes = vi.mocked(ipc.listNodes);
const resolveNode = vi.mocked(ipc.resolveNode);
const listTunnels = vi.mocked(ipc.listTunnels);
const unlockVault = vi.mocked(ipc.unlockVault);
const probeVault = vi.mocked(ipc.probeVault);
const getSettings = vi.mocked(ipc.getSettings);

/*
 * `App` resolves the "system" theme through `matchMedia`, which jsdom does not
 * implement. Stubbed here rather than in the shared setup file: this is the
 * only suite that renders the application shell from the top.
 */
vi.stubGlobal("matchMedia", (query: string) => ({
  matches: false,
  media: query,
  onchange: null,
  addEventListener: () => undefined,
  removeEventListener: () => undefined,
  addListener: () => undefined,
  removeListener: () => undefined,
  dispatchEvent: () => false,
}));

const VAULT_PATH = "/vaults/work.rvault";

const UNLOCKED: VaultState = {
  unlocked: true,
  path: VAULT_PATH,
  label: "Work",
  connectionCount: 3,
  credentialCount: 2,
  locksInSeconds: 900,
  kdfUpgradeAvailable: false,
};

/** What `vault_state` reports once the idle timeout has fired. */
const LOCKED: VaultState = {
  unlocked: false,
  path: VAULT_PATH,
  label: "Work",
  connectionCount: 0,
  credentialCount: 0,
  // Null here does NOT mean auto-lock is off. It means there is no vault open
  // to count down for — the distinction the footer used to collapse.
  locksInSeconds: null,
  kdfUpgradeAvailable: false,
};

/** The rejection `list_nodes` gives once the core has dropped its keys. */
const AUTO_LOCKED: IpcFailure = {
  code: "vault.auto-locked",
  message: "The vault locked itself after the idle period you set. Unlock it to carry on.",
  detail: null,
  actions: ["Unlock the vault", "Change the timeout in settings"],
};

function node(over: Partial<TreeNode> & Pick<TreeNode, "id" | "name">): TreeNode {
  return {
    parentId: null,
    sortOrder: 0,
    kind: "connection",
    description: "",
    tags: [],
    colour: null,
    protocol: "ssh",
    host: null,
    port: null,
    username: null,
    secretKind: null,
    keyFormat: null,
    hasPassphrase: false,
    agentCommentFilter: null,
    credentialId: null,
    attachedCredentialId: null,
    attachedTo: null,
    credentialChange: null,
    ...over,
  } as TreeNode;
}

/** The estate from the screenshot: a folder, and machines with addresses. */
const FOLDER = node({ id: "f1", name: "Devoplus_AWS", kind: "folder", protocol: null });
const WEB = node({ id: "n1", name: "FixCloud-web-01", parentId: "f1", host: "10.0.4.12", port: 22 });
const DB = node({ id: "n2", name: "Musteriler-db-01", parentId: "f1", host: "10.0.4.19", port: 22 });
const TREE = [FOLDER, WEB, DB];

const PASSWORD_SLOT: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_757_000_000,
  lastUsed: null,
  requiresKeyfile: false,
  kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
};

const PROBE: VaultProbe = {
  path: VAULT_PATH,
  label: "Work",
  formatVersion: 1,
  createdAt: 1_757_000_000,
  modifiedAt: 1_757_400_000,
  sizeBytes: 8192,
  slots: [PASSWORD_SLOT],
  backups: [],
  syncWarning: null,
  syncProvider: null,
  rememberedKeyfile: null,
};

let client = createQueryClient();

function wrap(children: ReactNode) {
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
  client = createQueryClient();

  vaultState.mockResolvedValue(UNLOCKED);
  listNodes.mockResolvedValue(TREE);
  resolveNode.mockRejectedValue(new Error("not asked for in these tests"));
  listTunnels.mockResolvedValue([]);
  probeVault.mockResolvedValue(PROBE);
  getSettings.mockRejectedValue(new Error("settings are not part of these tests"));
  unlockVault.mockResolvedValue(UNLOCKED);

  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useApp.setState({
    screen: { name: "main" },
    previousScreen: null,
    selectedNodeId: null,
    sidebarOpen: true,
    inspectorOpen: false,
    // Open, so the machines inside it are actually drawn — which is the state
    // the screenshot was taken in and the state the defect is about.
    expanded: new Set(["f1"]),
  });
});

/**
 * Two connected tabs, opened through the store's own API.
 *
 * Not a hand-written record: a partial one is a fixture that agrees with
 * whatever the test needs and with nothing the application does. Their names
 * differ from the tree's so that a query for a tree row cannot be satisfied by
 * a tab label.
 */
function openTwoSessions() {
  act(() => {
    const sessions = useSessions.getState();
    sessions.open({
      tabId: "t1",
      nodeId: "n1",
      name: "Local",
      colour: null,
      protocol: "ssh",
      target: "10.0.4.12:22",
    });
    sessions.open({
      tabId: "t2",
      nodeId: "n2",
      name: "Cloud",
      colour: null,
      protocol: "ssh",
      target: "10.0.4.19:22",
    });
    sessions.patch("t1", { phase: "running", sessionId: 1 });
    sessions.patch("t2", { phase: "running", sessionId: 2 });
  });
}

/** The whole estate, as it is drawn before anything locks. */
async function renderUnlockedShell() {
  render(wrap(<App />));
  expect(await screen.findByText("Devoplus_AWS")).toBeInTheDocument();
  await screen.findByText("FixCloud-web-01");
  await screen.findByText("Musteriler-db-01");
}

/**
 * The core locks the vault and starts refusing.
 *
 * `refetchQueries` stands in for the moment the tree next reads — a poll, an
 * invalidation after any edit, a remount. What is being tested is what the
 * application does with the rejection, not what provoked it.
 */
async function coreLocksTheVault() {
  vaultState.mockResolvedValue(LOCKED);
  listNodes.mockRejectedValue(AUTO_LOCKED);
  resolveNode.mockRejectedValue(AUTO_LOCKED);
  await act(async () => {
    await client.refetchQueries({ queryKey: qk.nodes() });
  });
}

describe("when the vault locks itself", () => {
  it("takes the estate off the screen", async () => {
    await renderUnlockedShell();
    await coreLocksTheVault();

    // The point of the lock. Not "shows a warning above the tree" — the names
    // and the addresses are not in the document at all.
    await waitFor(() => {
      expect(screen.queryByText("FixCloud-web-01")).toBeNull();
    });
    expect(screen.queryByText("Musteriler-db-01")).toBeNull();
    expect(screen.queryByText("Devoplus_AWS")).toBeNull();
    expect(document.body.textContent).not.toContain("10.0.4.12");
    expect(document.body.textContent).not.toContain("10.0.4.19");

    // And not merely hidden: the cache the tree was drawing from is gone, so
    // nothing can put it back without asking an unlocked vault for it.
    expect(client.getQueryData(qk.nodes())).toBeUndefined();
  });

  it("asks for the password instead of reporting a failed read", async () => {
    await renderUnlockedShell();
    await coreLocksTheVault();

    // The unlock screen — the same one that opens a vault at start-up.
    expect(await screen.findByText("This vault is locked")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlock" })).toBeInTheDocument();
    expect(screen.getByLabelText("Master password")).toBeInTheDocument();

    // The vault is known, so it is named rather than asked for again. Its
    // label is the user's own text and arrives through a bidi isolate.
    expect(screen.getByText("Work", { normalizer: withoutBidi })).toBeInTheDocument();
  });

  it("offers no control that cannot do what it says", async () => {
    await renderUnlockedShell();
    await coreLocksTheVault();
    await screen.findByText("This vault is locked");

    // "Try again" used to retry the read that cannot succeed while the vault
    // is locked. There is no such button now, because there is no such card.
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
    // Neither of the two cards the screenshot showed: the one over the session
    // area, and the copy of it in the sidebar.
    expect(screen.queryByText("The connection tree could not be read.")).toBeNull();
    expect(screen.queryByText("The tree could not be read")).toBeNull();
    expect(document.body.textContent).not.toContain(
      "The vault locked itself after the idle period you set.",
    );
  });

  it("says what became of the sessions that were open", async () => {
    openTwoSessions();
    await renderUnlockedShell();
    await coreLocksTheVault();
    await screen.findByText("This vault is locked");

    // Both survived the lock, so that is what it says — and it says it before
    // the password is typed, not after.
    expect(
      screen.getByText("2 sessions are still connected, and will still be there after you unlock."),
    ).toBeInTheDocument();
  });

  it("says so when the lock policy disconnected them", async () => {
    openTwoSessions();
    await renderUnlockedShell();
    await coreLocksTheVault();
    await screen.findByText("This vault is locked");

    // The core's close events land a moment after the lock does. The sentence
    // follows them rather than the snapshot taken when the lock was noticed.
    act(() => {
      useSessions.getState().patch("t1", { phase: "closed" });
      useSessions.getState().patch("t2", { phase: "closed" });
    });

    expect(
      await screen.findByText(
        "2 sessions were closed when the vault locked. Unlocking does not reopen them.",
      ),
    ).toBeInTheDocument();
  });
});

describe("unlocking again", () => {
  it("brings the estate back", async () => {
    await renderUnlockedShell();
    await coreLocksTheVault();
    await screen.findByText("This vault is locked");

    // The core opens again, and the tree reads.
    vaultState.mockResolvedValue(UNLOCKED);
    listNodes.mockResolvedValue(TREE);

    await userEvent.type(screen.getByLabelText("Master password"), "correct horse");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));

    expect(await screen.findByText("FixCloud-web-01")).toBeInTheDocument();
    expect(screen.getByText("Musteriler-db-01")).toBeInTheDocument();
    expect(screen.getByText("Devoplus_AWS")).toBeInTheDocument();
  });

  it("says so when the password is wrong, and stays where it is", async () => {
    await renderUnlockedShell();
    await coreLocksTheVault();
    await screen.findByText("This vault is locked");

    unlockVault.mockRejectedValue({
      code: "vault.unlock-failed",
      message: "That did not unlock the vault.",
      detail: null,
      actions: [],
    } satisfies IpcFailure);

    await userEvent.type(screen.getByLabelText("Master password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Unlock" }));

    expect(await screen.findByText("That did not unlock the vault.")).toBeInTheDocument();
    // Still on the unlock screen, and the estate is still not on it.
    expect(screen.getByRole("button", { name: "Unlock" })).toBeInTheDocument();
    expect(screen.queryByText("FixCloud-web-01")).toBeNull();
  });
});

