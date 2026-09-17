/**
 * The strip that shows what the remote desktop copied, and saves it.
 *
 * What matters is that nothing moves until the user picks a folder, that the
 * folder they picked is the one the core is given, and that a running save can
 * be stopped and an ended one says how it ended.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { ClipboardFilesBar } from "./ClipboardFilesBar";
import { useSessions, type ClipboardFilesState, type SessionRecord } from "./store";

const { ipcMock, dialogOpen } = vi.hoisted(() => ({
  ipcMock: {
    saveClipboardFiles: vi.fn((_sessionId: number, _directory: string) => Promise.resolve()),
    cancelClipboardSave: vi.fn((_sessionId: number) => Promise.resolve()),
  },
  dialogOpen: vi.fn(),
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => dialogOpen(...args) as unknown,
}));

function record(clipboardFiles: ClipboardFilesState): SessionRecord {
  return {
    tabId: "t1",
    nodeId: "n1",
    name: "ctso-dc01",
    colour: null,
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    sessionId: 7,
    phase: "running",
    opened: null,
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    promptBusy: false,
    promptError: null,
    inputError: null,
    warnings: [],
    clipboardFiles,
    metrics: { bytesIn: 0, bytesOut: 0, cols: 0, rows: 0, echoMs: null },
    renderer: null,
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
  };
}

function show(files: ClipboardFilesState) {
  const tab = record(files);
  useSessions.setState({ order: ["t1"], byId: { t1: tab }, activeTabId: "t1" });
  return render(<ClipboardFilesBar record={tab} />);
}

const OFFER: ClipboardFilesState = {
  offer: {
    files: [
      { path: "Reports", size: null, directory: true },
      { path: "Reports/q1.xlsx", size: 1024, directory: false },
      { path: "notes.txt", size: 12, directory: false },
    ],
    totalEntries: 3,
    totalBytes: 1036,
  },
  transfer: null,
};

beforeEach(() => {
  dialogOpen.mockReset();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("files the remote desktop copied", () => {
  it("says what was copied by its top-level names and moves nothing yet", () => {
    show(OFFER);
    expect(screen.getByText(/3 items copied on the remote desktop/)).toBeInTheDocument();
    expect(screen.getByText(/Reports.*notes\.txt/)).toBeInTheDocument();
    expect(screen.queryByText(/q1\.xlsx/)).toBeNull();
    expect(ipcMock.saveClipboardFiles).not.toHaveBeenCalled();
  });

  it("saves into the folder the user picked, and only once one is picked", async () => {
    const user = userEvent.setup();
    show(OFFER);

    dialogOpen.mockResolvedValueOnce(null);
    await user.click(screen.getByRole("button", { name: /save to folder/i }));
    expect(ipcMock.saveClipboardFiles).not.toHaveBeenCalled();

    dialogOpen.mockResolvedValueOnce("/home/ada/Downloads");
    await user.click(screen.getByRole("button", { name: /save to folder/i }));
    expect(dialogOpen).toHaveBeenLastCalledWith(expect.objectContaining({ directory: true }));
    expect(ipcMock.saveClipboardFiles).toHaveBeenCalledWith(7, "/home/ada/Downloads");
  });

  it("says why a save could not start, in the core's words", async () => {
    const user = userEvent.setup();
    ipcMock.saveClipboardFiles.mockRejectedValueOnce({
      code: "clipboard.save-folder-missing",
      message: "That folder does not exist, so nothing was saved.",
      detail: null,
      actions: [],
    });
    dialogOpen.mockResolvedValueOnce("/gone");
    show(OFFER);
    await user.click(screen.getByRole("button", { name: /save to folder/i }));
    expect(await screen.findByText("The files could not be saved")).toBeInTheDocument();
  });

  it("shows a running save and stops it on request", async () => {
    const user = userEvent.setup();
    show({
      offer: OFFER.offer,
      transfer: { kind: "saving", doneBytes: 512, totalBytes: 1036, doneFiles: 1, totalFiles: 2 },
    });
    expect(screen.getByText(/Saving 1 of 2 files/)).toBeInTheDocument();
    // The offer's own row is not drawn over a save of it.
    expect(screen.queryByRole("button", { name: /save to folder/i })).toBeNull();
    await user.click(screen.getByRole("button", { name: /cancel/i }));
    expect(ipcMock.cancelClipboardSave).toHaveBeenCalledWith(7);
  });

  it("says where a finished save went, and a failed one why", async () => {
    const user = userEvent.setup();
    show({
      offer: null,
      transfer: { kind: "finished", directory: "/home/ada/Downloads", files: 2, bytes: 1036 },
    });
    expect(screen.getByText(/Saved 2 files to/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /dismiss/i }));
    expect(useSessions.getState().byId.t1?.clipboardFiles.transfer).toBeNull();
    cleanup();

    show({ offer: null, transfer: { kind: "failed", reason: "rdp.clipboard_save_write_failed" } });
    expect(screen.getByRole("alert")).toHaveTextContent(/could not be written into that folder/);
    cleanup();

    // A reason the interface has no sentence for is still a sentence.
    show({ offer: null, transfer: { kind: "failed", reason: "rdp.something_new" } });
    expect(screen.getByRole("alert")).toHaveTextContent(/The save did not finish/);
  });
});
