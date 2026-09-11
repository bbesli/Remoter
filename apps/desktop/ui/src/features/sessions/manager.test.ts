/**
 * What a tab does when the server takes a capability back.
 *
 * `capabilities.resizable`, as it reaches the frontend today, is the RDP
 * adapter's *static offer*: the set of things the adapter can do, fixed before
 * the connection sequence runs. It is not what the server granted. So Smart
 * resize was drawn on every RDP session and chosen as its default, including on
 * hosts that never opened the Display Control channel and could never honour
 * it — a control that did nothing, on by default.
 *
 * The one thing this build can observe about the real answer is the warning the
 * adapter raises when it finds the channel missing. These tests pin what that
 * warning has to do: withdraw the capability, take the control down with it,
 * move a tab sitting in Smart to the fallback, and stop the requests — whether
 * the warning arrives before `ready` or after it, because the adapter raises it
 * during the capability exchange and the two orders are both real.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { SessionMessage, SessionOpened, TreeNode } from "@/lib/ipc";

const ipcMock = vi.hoisted(() => ({
  openSession: vi.fn(),
  resolveNode: vi.fn(),
  resizeSession: vi.fn(),
  closeSession: vi.fn(),
  sendInput: vi.fn(),
}));

/** Handlers of the channel the manager builds, captured as it builds them. */
const captured = vi.hoisted(() => ({
  onMessage: null as ((message: SessionMessage) => void) | null,
}));

vi.mock("@/lib/ipc", async () => {
  const actual = await vi.importActual<typeof import("@/lib/ipc")>("@/lib/ipc");
  return {
    ...actual,
    ipc: ipcMock,
    sessionChannel: (handlers: { onMessage: (message: SessionMessage) => void }) => {
      captured.onMessage = handlers.onMessage;
      return {};
    },
  };
});

// The terminal and the canvas are registries of live objects with no place in a
// test of what the store decides. Each is replaced wholesale rather than
// partially, so a call this test did not anticipate fails loudly.
vi.mock("./terminals", () => ({
  disposeTerminal: vi.fn(),
  ensureTerminal: vi.fn(),
  focusTerminal: vi.fn(),
  rendererFor: vi.fn(() => null),
  sizeOf: vi.fn(() => null),
  writeNotice: vi.fn(),
  writeToTerminal: vi.fn(),
}));

vi.mock("./surfaces", () => ({
  disposeSurface: vi.fn(),
  ensureSurface: vi.fn(),
  hasSurface: vi.fn(() => true),
  resizeSurface: vi.fn(),
  writeFrame: vi.fn(),
}));

const { openSession, requestDesktopSize } = await import("./manager");
const { useSessions } = await import("./store");

function node(): TreeNode {
  return {
    id: "n1",
    parentId: null,
    kind: "connection",
    name: "ctso-dc01",
    protocol: "rdp",
    host: "ctso-dc01.internal",
    port: 3389,
    username: null,
    colour: null,
    icon: null,
    tags: [],
    sortOrder: 0,
    attachedCredentialId: null,
    hasOwnCredential: false,
    description: null,
    updatedAtMs: 0,
  } as unknown as TreeNode;
}

/** A `ready` for a session the adapter offers as resizable. */
function ready(): SessionMessage {
  const opened: SessionOpened = {
    sessionId: 7,
    nodeId: "n1",
    name: "ctso-dc01",
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    username: "svc-deploy",
    authMethod: "password",
    via: [],
    capabilities: {
      kind: "framebuffer",
      // The lie this whole file is about: the adapter can resize, so it says
      // so, before any server has agreed to.
      resizable: true,
      clipboard: "none",
      fileTransfer: false,
      audio: false,
      printing: false,
      multiMonitor: false,
      recordable: true,
    },
    startedAtMs: Date.now(),
    recording: "never",
  };
  return { event: "ready", ...opened };
}

const refusal: SessionMessage = {
  event: "warning",
  kind: "other",
  detail: "rdp.display_control_unavailable",
};

function push(message: SessionMessage): void {
  captured.onMessage?.(message);
}

/** Opens a tab and hands back its id, with the channel wired. */
function open(): string {
  return openSession(node());
}

beforeEach(() => {
  captured.onMessage = null;
  ipcMock.openSession.mockReturnValue(new Promise(() => undefined));
  // `readViewOnly` runs for every graphical tab and is not what is under test;
  // a rejection leaves the flag unknown, which is the documented behaviour.
  ipcMock.resolveNode.mockRejectedValue(new Error("not under test"));
  ipcMock.resizeSession.mockResolvedValue(undefined);
  ipcMock.closeSession.mockResolvedValue(undefined);
});

afterEach(() => {
  for (const tabId of [...useSessions.getState().order]) useSessions.getState().remove(tabId);
  vi.clearAllMocks();
});

describe("a graphical tab's resize capability", () => {
  it("starts in Smart, because that is what the session claims it can do", () => {
    const tabId = open();
    push(ready());

    const record = useSessions.getState().byId[tabId];
    expect(record?.scale.mode).toBe("smart");
    expect(record?.opened?.capabilities.resizable).toBe(true);
  });

  it("withdraws the capability when the server says the channel is not open", () => {
    const tabId = open();
    push(ready());
    push(refusal);

    const record = useSessions.getState().byId[tabId];
    // The control is drawn from this flag, so withdrawing it is what takes the
    // button off the screen — the interface must not keep offering a resize the
    // server has already refused.
    expect(record?.opened?.capabilities.resizable).toBe(false);
    // And the tab cannot be left in a mode whose only control is now gone.
    expect(record?.scale.mode).toBe("fit");
  });

  it("sends no resize once the capability is withdrawn", () => {
    const tabId = open();
    push(ready());
    push(refusal);
    ipcMock.resizeSession.mockClear();

    requestDesktopSize(tabId, { width: 1600, height: 900 }, 1);
    expect(ipcMock.resizeSession).not.toHaveBeenCalled();
  });

  it("never offers Smart when the refusal arrived before ready", () => {
    // The adapter learns the channel is missing during the capability exchange,
    // which finishes before `ready`. A tab that defaulted to Smart on the way
    // past would draw the control for exactly as long as it took the user to
    // look at it.
    const tabId = open();
    push(refusal);
    push(ready());

    const record = useSessions.getState().byId[tabId];
    expect(record?.opened?.capabilities.resizable).toBe(false);
    expect(record?.scale.mode).toBe("fit");
  });

  it("leaves a mode the user chose for themselves alone", () => {
    const tabId = open();
    push(ready());
    useSessions.getState().setScale(tabId, { mode: "zoom", zoom: 3 });
    push(refusal);

    const record = useSessions.getState().byId[tabId];
    expect(record?.opened?.capabilities.resizable).toBe(false);
    // Only a tab still sitting in Smart is moved. Dragging someone out of a 3x
    // zoom because a different control went away would be its own surprise.
    expect(record?.scale).toEqual({ mode: "zoom", zoom: 3 });
  });

  it("keeps the warning on screen as well as acting on it", () => {
    // The revision must not consume the sentence: the user still has to be told
    // why the control they were about to use is not there.
    const tabId = open();
    push(ready());
    push(refusal);

    expect(useSessions.getState().byId[tabId]?.warnings).toEqual([
      { kind: "other", detail: "rdp.display_control_unavailable", at: expect.any(Number) },
    ]);
  });

  it("does not touch a session that never offered a resize", () => {
    const tabId = open();
    push(ready());
    useSessions.getState().setScale(tabId, { mode: "actual", zoom: 2 });
    push({ event: "warning", kind: "other", detail: "vnc.bell" });

    const record = useSessions.getState().byId[tabId];
    expect(record?.opened?.capabilities.resizable).toBe(true);
    expect(record?.scale.mode).toBe("actual");
  });
});
