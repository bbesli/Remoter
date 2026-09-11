/**
 * That the window actually mounts a file pane, and only when one was asked for.
 *
 * This is the test the file manager did not have. Every piece of it was written
 * and tested — the listing, the queue, the dialogs, the path rules — and none of
 * it reached a user, because no component imported it and no screen rendered
 * it. A unit test of the pane would have stayed green throughout. So this one
 * renders the main window itself and looks for the file manager inside it.
 *
 * The other half of the route — an `sftp` connection's own tab — is pinned in
 * `features/files/FileSessionHost.rtl.test.tsx`.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Capabilities, DirectoryEntry, SessionOpened, SftpPane, VaultState } from "@/lib/ipc";
import { withoutBidi } from "@/test/bidi";

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
      probeVault: vi.fn(),
      openPane: vi.fn(),
      closePane: vi.fn(),
      listDirectory: vi.fn(),
      listTransfers: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";
import { useSessions } from "@/features/sessions";
import { useApp } from "@/stores/app";

import { MainWindow } from "./MainWindow";

const vaultState = vi.mocked(ipc.vaultState);
const listNodes = vi.mocked(ipc.listNodes);
const listTunnels = vi.mocked(ipc.listTunnels);
const openPane = vi.mocked(ipc.openPane);
const closePane = vi.mocked(ipc.closePane);
const listDirectory = vi.mocked(ipc.listDirectory);
const listTransfers = vi.mocked(ipc.listTransfers);

const SSH: Capabilities = {
  kind: "terminal",
  resizable: true,
  clipboard: "text",
  fileTransfer: true,
  audio: false,
  printing: false,
  multiMonitor: false,
  recordable: true,
};

const OPENED: SessionOpened = {
  sessionId: 42,
  nodeId: "n1",
  name: "web-01",
  protocol: "ssh",
  target: "10.0.4.12:22",
  username: "deploy",
  authMethod: "publickey",
  via: [],
  capabilities: SSH,
  startedAtMs: 1_757_500_000_000,
  recording: "never",
};

const PANE: SftpPane = { paneId: 3, sessionId: 42, home: "/home/deploy", homeDisplay: "/home/deploy" };

const LOG: DirectoryEntry = {
  name: "deploy.log",
  path: "/home/deploy/deploy.log",
  displayName: "deploy.log",
  displayPath: "/home/deploy/deploy.log",
  kind: "file",
  size: 2048,
  permissions: null,
  mode: null,
  uid: null,
  user: null,
  gid: null,
  group: null,
  modified: null,
  risks: { control: false, bidi: false, invisible: false, separator: false },
};

const UNLOCKED: VaultState = {
  unlocked: true,
  path: "/vaults/work.rvault",
  label: "Work",
  connectionCount: 1,
  credentialCount: 0,
  locksInSeconds: null,
  kdfUpgradeAvailable: false,
};

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/** A connected SSH tab, in front, exactly as the session manager would leave it. */
const TAB = "tab-1";
function seedSession() {
  act(() => {
    useSessions.getState().open({
      tabId: TAB,
      nodeId: "n1",
      name: "web-01",
      colour: null,
      protocol: "ssh",
      target: "10.0.4.12:22",
    });
    useSessions.getState().patch(TAB, { phase: "running", sessionId: 42, opened: OPENED });
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  vaultState.mockResolvedValue(UNLOCKED);
  listNodes.mockResolvedValue([]);
  listTunnels.mockResolvedValue([]);
  openPane.mockResolvedValue(PANE);
  closePane.mockResolvedValue(undefined);
  listDirectory.mockResolvedValue([LOG]);
  listTransfers.mockResolvedValue([]);
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useApp.setState({ filePaneTabs: new Set<string>() });
});

describe("the file pane docked under a session", () => {
  it("is not there until it is asked for", async () => {
    seedSession();
    render(wrap(<MainWindow />));

    await waitFor(() => {
      expect(vaultState).toHaveBeenCalled();
    });
    // No pane, and — just as important — no channel opened on the user's
    // connection for a screen nobody asked to see.
    expect(openPane).not.toHaveBeenCalled();
    expect(screen.queryByText("Transfers")).toBeNull();
  });

  it("browses the connection the shell is already using", async () => {
    seedSession();
    act(() => {
      // What the tab strip's Files control does.
      useApp.getState().toggleFilePane(TAB);
    });
    render(wrap(<MainWindow />));

    // On the session that tab already authenticated — one more channel, not a
    // second sign-in. `a_file_pane_browses_on_the_connection_the_shell_is_already_using`
    // in `crates/remoter-ipc/src/live_tests.rs` is the core's half of this.
    await waitFor(() => {
      expect(openPane).toHaveBeenCalledWith(42);
    });
    expect(await screen.findByText("deploy.log", { normalizer: withoutBidi })).toBeInTheDocument();
    expect(screen.getByText("Transfers")).toBeInTheDocument();
  });
});
