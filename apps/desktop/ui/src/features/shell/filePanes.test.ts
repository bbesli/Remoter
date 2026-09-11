/**
 * Which session may have a file pane docked under it.
 *
 * The rule exists because two places read it — the tab strip's control and the
 * window that mounts the dock — and a control enabled over a session the window
 * then refuses to mount is the same defect as a dock with no control that
 * opened it. These pin the four refusals, each of which has a sentence of its
 * own in the catalogue, and the one case that goes through.
 *
 * The records are built through the store rather than as object literals, so a
 * field added to `SessionRecord` does not have to be mirrored here.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { useSessions, type SessionRecord } from "@/features/sessions";
import type { Capabilities, SessionOpened } from "@/lib/ipc";

import { canDockFilePane, filePaneBlocker } from "./filePanes";

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

/** VNC: a picture of a screen, and no channel that carries a file. */
const VNC: Capabilities = { ...SSH, kind: "framebuffer", clipboard: "text", fileTransfer: false };

/** An `sftp` connection's own session — the whole tab is the file manager. */
const SFTP: Capabilities = { ...SSH, kind: "file_transfer", resizable: false, clipboard: "none" };

function opened(sessionId: number, capabilities: Capabilities): SessionOpened {
  return {
    sessionId,
    nodeId: "n1",
    name: "web-01",
    protocol: capabilities.kind === "file_transfer" ? "sftp" : "ssh",
    target: "10.0.4.12:22",
    username: "deploy",
    authMethod: "publickey",
    via: [],
    capabilities,
    startedAtMs: 1_757_500_000_000,
    recording: "never",
  };
}

let tabs = 0;

/** A tab in whatever state the test needs, as the store would hold it. */
function record(patch: Partial<SessionRecord>): SessionRecord {
  tabs += 1;
  const tabId = `tab-${String(tabs)}`;
  const store = useSessions.getState();
  store.open({
    tabId,
    nodeId: "n1",
    name: "web-01",
    colour: null,
    protocol: "ssh",
    target: "10.0.4.12:22",
  });
  store.patch(tabId, patch);
  const made = useSessions.getState().byId[tabId];
  if (made === undefined) throw new Error("the store did not keep the tab");
  return made;
}

beforeEach(() => {
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("where a file pane may be docked", () => {
  it("refuses when no tab is in front", () => {
    expect(filePaneBlocker(undefined)).toBe("noSession");
    expect(canDockFilePane(undefined)).toBe(false);
  });

  it("refuses a tab that is still connecting", () => {
    // The capabilities are not known yet — `opened` is null until `ready` — so
    // there is nothing to open a channel on even though the tab exists.
    expect(filePaneBlocker(record({ phase: "connecting" }))).toBe("notRunning");
  });

  it("refuses a session that has ended", () => {
    expect(
      filePaneBlocker(
        record({ phase: "closed", sessionId: null, opened: opened(4, SSH), closeReason: "disconnected" }),
      ),
    ).toBe("notRunning");
  });

  it("refuses a protocol whose adapter reports no file channel", () => {
    expect(
      filePaneBlocker(record({ phase: "running", sessionId: 7, opened: opened(7, VNC) })),
    ).toBe("noFileChannel");
  });

  it("refuses a session that is already a file session", () => {
    // Nothing to dock it under: that tab is the file manager.
    expect(
      filePaneBlocker(record({ phase: "running", sessionId: 9, opened: opened(9, SFTP) })),
    ).toBe("isFileSession");
  });

  it("allows a running SSH session", () => {
    const running = record({ phase: "running", sessionId: 3, opened: opened(3, SSH) });
    expect(filePaneBlocker(running)).toBeNull();
    expect(canDockFilePane(running)).toBe(true);
  });

  it("reads the adapter's report rather than the protocol name", () => {
    // A plugin protocol that says it carries files is treated as SSH is. The
    // name is never consulted, which is what keeps this rule from becoming a
    // list of protocol strings.
    const plugin = record({
      phase: "running",
      sessionId: 5,
      protocol: "acme-shell",
      opened: { ...opened(5, { ...SSH, fileTransfer: true }), protocol: "acme-shell" },
    });
    expect(filePaneBlocker(plugin)).toBeNull();
  });
});
