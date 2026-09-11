/**
 * What happens between pressing a transfer button and seeing the transfer.
 *
 * Four defects were reported against this path, and each of them was invisible
 * from the outside in the same way: the command was sent, the core did the
 * work, and the screen did not change. So every test here asserts what the
 * **screen** ends up saying, or what the core was actually asked to move —
 * never that a function was called. A test that mocked the thing it is testing
 * would have passed over every one of these.
 *
 *   1. Nothing invalidated the transfer list after an enqueue, and the poll
 *      that would have caught it is switched off whenever nothing is live —
 *      which is precisely the state a pane is in when the first transfer is
 *      queued. A transfer the user had just started never appeared at all.
 *   2. Neither direction asked before overwriting, and `sftp_preflight` was
 *      exposed and called by nothing.
 *   3. A drop ignored the dragged payload and re-ran the bulk action.
 *   4. The remote listing was never invalidated when a transfer finished, so a
 *      file you had just uploaded was not in the folder on screen.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { withoutBidi } from "@/test/bidi";
import type {
  AppSettings,
  DirectoryEntry,
  EnqueueReport,
  SftpPane,
  TransferPreflight,
  TransferRequest,
  TransferStatus,
} from "@/lib/ipc";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      openPane: vi.fn(),
      closePane: vi.fn(),
      listDirectory: vi.fn(),
      listTransfers: vi.fn(),
      preflightTransfers: vi.fn(),
      enqueueTransfers: vi.fn(),
      cancelAllTransfers: vi.fn(),
      getSettings: vi.fn(),
      setSettings: vi.fn(),
    },
  };
});

// The local pane's default destination comes from the platform. Stubbed so the
// pane has a folder without anyone opening a picker — which is the point of the
// change that added it.
vi.mock("@tauri-apps/api/path", () => ({
  downloadDir: () => Promise.resolve("/home/ada/Downloads"),
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));

import { ipc } from "@/lib/ipc";

import { FilePane } from "./FilePane";

const openPane = vi.mocked(ipc.openPane);
const listDirectory = vi.mocked(ipc.listDirectory);
const listTransfers = vi.mocked(ipc.listTransfers);
const preflight = vi.mocked(ipc.preflightTransfers);
const enqueue = vi.mocked(ipc.enqueueTransfers);
const getSettings = vi.mocked(ipc.getSettings);

const PANE: SftpPane = { paneId: 3, sessionId: 42, home: "/srv", homeDisplay: "/srv" };

function file(name: string): DirectoryEntry {
  return {
    name,
    path: `/srv/${name}`,
    displayName: name,
    displayPath: `/srv/${name}`,
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
}

function queued(id: number, remote: string): TransferStatus {
  return {
    transferId: id,
    direction: "download",
    remote,
    remoteDisplay: remote,
    local: `/home/ada/Downloads/${remote.split("/").pop() ?? ""}`,
    localDisplay: `/home/ada/Downloads/${remote.split("/").pop() ?? ""}`,
    resume: false,
    start: null,
    state: "queued",
    queuedAtMs: 1_000,
    startedAtMs: null,
    finishedAtMs: null,
    progressAtMs: null,
  };
}

function absent(index: number, destination: string): TransferPreflight {
  return {
    index,
    direction: "download",
    destinationDisplay: destination,
    exists: false,
    size: null,
    modified: null,
    directory: false,
    sourceIsFolder: false,
    problem: null,
  };
}

function report(ids: number[]): EnqueueReport {
  return {
    transferIds: ids,
    foldersExpanded: 0,
    directoriesCreated: 0,
    skipped: [],
    limitReached: false,
  };
}

const SETTINGS: AppSettings = {
  theme: "system",
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
  terminal: { palette: "auto", overrides: {}, fontFamily: "", fontSize: 13 },
  fileDownloadFolder: "/home/ada/Downloads",
};

function wrap(children: ReactNode) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
  openPane.mockResolvedValue(PANE);
  vi.mocked(ipc.closePane).mockResolvedValue(undefined);
  listDirectory.mockResolvedValue([file("build.tar.gz"), file("deploy.log")]);
  listTransfers.mockResolvedValue([]);
  preflight.mockResolvedValue([]);
  enqueue.mockResolvedValue(report([]));
  getSettings.mockResolvedValue(SETTINGS);
});

/** Renders the pane and waits for the listing to arrive. */
async function openPaneOnScreen() {
  render(wrap(<FilePane sessionId={42} name="web-01" />));
  expect(await screen.findByText("build.tar.gz", { normalizer: withoutBidi })).toBeInTheDocument();
}

/** Chooses one row by its checkbox. */
async function choose(name: string) {
  await userEvent.click(screen.getByRole("checkbox", { name }));
}

describe("a transfer the user has just started", () => {
  it("appears in the queue, even though nothing was live to keep the poll running", async () => {
    // The defect: the transfer list is re-read on a poll, and the poll is off
    // whenever nothing is live — which is the state of a pane whose first
    // transfer has just been queued. Without an invalidation after the enqueue
    // the row never arrived, and the user had no evidence anything had
    // happened at all.
    preflight.mockResolvedValue([absent(0, "/home/ada/Downloads/build.tar.gz")]);
    enqueue.mockResolvedValue(report([7]));
    listTransfers.mockResolvedValueOnce([]).mockResolvedValue([queued(7, "/srv/build.tar.gz")]);

    await openPaneOnScreen();
    expect(screen.getByText("Nothing has been transferred on this pane yet.")).toBeInTheDocument();

    await choose("build.tar.gz");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));

    // The assertion is the row on screen, not that a query was invalidated.
    const queue = screen.getByLabelText("Transfers");
    expect(await within(queue).findByText("build.tar.gz", { normalizer: withoutBidi })).toBeInTheDocument();
  });
});

describe("a transfer that would land on something", () => {
  it("asks first, and queues nothing until it is answered", async () => {
    preflight.mockResolvedValue([
      {
        ...absent(0, "/home/ada/Downloads/build.tar.gz"),
        exists: true,
        size: 4096,
        modified: 1_773_187_200,
      },
    ]);
    enqueue.mockResolvedValue(report([7]));

    await openPaneOnScreen();
    await choose("build.tar.gz");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));

    // The dialog names what is lost before it is lost.
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    expect(screen.getByText("These will be replaced:")).toBeInTheDocument();
    expect(
      screen.getByText(
        "What is at these paths now is written over. There is no trash on either side, and this cannot be undone.",
      ),
    ).toBeInTheDocument();
    expect(enqueue).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: /Replace the file on this computer/ }));
    await waitFor(() => {
      expect(enqueue).toHaveBeenCalledTimes(1);
    });
  });

  it("does not ask when there is nothing there to warn about", async () => {
    // A confirmation with no content is a confirmation people click through,
    // which is how the one that matters stops being read.
    preflight.mockResolvedValue([absent(0, "/home/ada/Downloads/build.tar.gz")]);
    enqueue.mockResolvedValue(report([7]));

    await openPaneOnScreen();
    await choose("build.tar.gz");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));

    await waitFor(() => {
      expect(enqueue).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("reports a folder walk that came back short as short", async () => {
    preflight.mockResolvedValue([absent(0, "/home/ada/Downloads/build.tar.gz")]);
    enqueue.mockResolvedValue({
      transferIds: [7],
      foldersExpanded: 1,
      directoriesCreated: 2,
      skipped: [{ path: "/srv/logs/link", code: "session.unsupported", message: "not supported" }],
      limitReached: false,
    });

    await openPaneOnScreen();
    await choose("build.tar.gz");
    await userEvent.click(screen.getByRole("button", { name: "Download" }));

    // A queue showing only the healthy rows is exactly how a short copy goes
    // unnoticed until somebody needs the file that is missing.
    expect(await screen.findByText("Not everything was queued")).toBeInTheDocument();
    expect(screen.getByText("1 entry was not queued:")).toBeInTheDocument();
    expect(screen.getByText(/\/srv\/logs\/link/, { normalizer: withoutBidi })).toBeInTheDocument();
  });
});

describe("a drop onto the local pane", () => {
  it("downloads the row that was dragged, not the whole selection", async () => {
    // The defect: the drop ignored `dataTransfer` and re-ran the bulk action,
    // so dropping one row fetched everything that happened to be chosen.
    preflight.mockResolvedValue([absent(0, "/home/ada/Downloads/deploy.log")]);
    enqueue.mockResolvedValue(report([7]));

    await openPaneOnScreen();
    // Two rows chosen; one row dragged.
    await choose("build.tar.gz");
    await choose("deploy.log");

    const local = screen.getByLabelText("This computer");
    const payload = JSON.stringify(["/srv/deploy.log"]);
    const dataTransfer = {
      types: ["application/x-remoter-remote-paths"],
      getData: (type: string) => (type === "application/x-remoter-remote-paths" ? payload : ""),
      files: [] as File[],
    };
    const { fireEvent } = await import("@testing-library/react");
    fireEvent.dragOver(local, { dataTransfer });
    fireEvent.drop(local, { dataTransfer });

    await waitFor(() => {
      expect(preflight).toHaveBeenCalled();
    });
    // What the core was actually asked to move: one file, the dragged one.
    const requests = preflight.mock.calls[0]?.[1] as TransferRequest[];
    expect(requests).toHaveLength(1);
    expect(requests[0]?.remote).toBe("/srv/deploy.log");
  });
});

describe("a transfer that finishes", () => {
  it("makes the folder on screen be read again", async () => {
    // A different file, so the queue row and the listing row do not share a
    // name — this test reads the *listing*, and an ambiguous query would not.
    listDirectory.mockResolvedValue([file("deploy.log")]);
    // The defect: the listing was never invalidated when a transfer completed,
    // so a file you had just uploaded was not in the folder in front of you.
    // The assertion is that the directory is read a second time — the effect —
    // rather than that an invalidation function was called.
    listTransfers
      .mockResolvedValueOnce([{ ...queued(7, "/srv/build.tar.gz"), state: "running", done: 1, total: 2 }])
      .mockResolvedValue([{ ...queued(7, "/srv/build.tar.gz"), state: "completed", bytes: 2 }]);

    render(wrap(<FilePane sessionId={42} name="web-01" />));
    expect(await screen.findByText("deploy.log", { normalizer: withoutBidi })).toBeInTheDocument();
    const readsBefore = listDirectory.mock.calls.length;

    await waitFor(
      () => {
        expect(listDirectory.mock.calls.length).toBeGreaterThan(readsBefore);
      },
      { timeout: 4_000 },
    );
  });
});
