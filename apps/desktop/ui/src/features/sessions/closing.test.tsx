/**
 * Closing a live session asks first — and these tests are about the *effect*,
 * not about which function was called.
 *
 * The defect being fixed is that one click on a tab's `x` disconnected a
 * session with no question, and the `x` sits a few pixels from the tab the user
 * meant to switch to. A disconnect is not undoable and it interrupts work on
 * the far machine, so the only assertions worth writing are these two:
 *
 * - declining the question leaves the session **connected** — `session_close`
 *   never reaches the core and the tab is still in the strip;
 * - accepting it **closes** the session — `session_close` reaches the core with
 *   that session's id and the tab is gone.
 *
 * Asserting that `requestCloseTab` was called would pass against a dialog whose
 * Cancel button disconnected, which is the failure mode that matters.
 *
 * Every route is exercised, because a confirmation only one of them respects is
 * worse than none: it teaches the user that closing is guarded and then it is
 * not. The routes are the tab's `x`, a middle click, the `tab.close` shortcut,
 * the sessions panel's Disconnect, and the window's close control — the last
 * being the one that must ask once for all of them rather than once per tab.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";

const ipcMock = vi.hoisted(() => ({
  closeSession: vi.fn(),
  listTunnels: vi.fn(),
  openTunnel: vi.fn(),
  closeTunnel: vi.fn(),
}));

vi.mock("@/lib/ipc", async () => {
  const actual = await vi.importActual<typeof import("@/lib/ipc")>("@/lib/ipc");
  return { ...actual, ipc: ipcMock };
});

// Registries of live objects — an xterm instance and a canvas. Neither is what
// a confirmation decides, and both would need a DOM they cannot have here.
vi.mock("./terminals", () => ({
  disposeTerminal: vi.fn(),
  focusTerminal: vi.fn(),
  hasTerminal: () => false,
  attachTerminal: vi.fn(),
}));
vi.mock("./surfaces", () => ({
  disposeSurface: vi.fn(),
}));

import { handlerFor, type ShortcutEvent } from "@/hooks/keyboard";
import { resetLiveTransfers } from "@/features/files";

import { DisconnectDialog } from "./DisconnectDialog";
import { SessionPanels } from "./SessionPanels";
import { SessionTabs } from "./SessionTabs";
import { requestCloseWindow, useClosing } from "./closing";
import { newTabId, useSessions, type SessionRecord } from "./store";

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/** A tab with a session the core has registered and reported running. */
function seedLive(name: string, sessionId: number, target: string | null = "10.0.0.4:3389"): string {
  const tabId = newTabId();
  act(() => {
    useSessions.getState().open({
      tabId,
      nodeId: `node-${name}`,
      name,
      colour: null,
      protocol: "rdp",
      target,
    });
    useSessions.getState().patch(tabId, { phase: "running", sessionId, target });
  });
  return tabId;
}

/** A tab whose session already ended. A photograph: nothing left to lose. */
function seedEnded(name: string, overrides: Partial<SessionRecord> = {}): string {
  const tabId = newTabId();
  act(() => {
    useSessions.getState().open({
      tabId,
      nodeId: `node-${name}`,
      name,
      colour: null,
      protocol: "rdp",
      target: "10.0.0.9:3389",
    });
    useSessions.getState().patch(tabId, {
      phase: "failed",
      sessionId: null,
      closeReason: "failed",
      ...overrides,
    });
  });
  return tabId;
}

/**
 * A control by its accessible name, with the bidi isolates taken out.
 *
 * `isolate()` wraps every piece of vault data in U+2066/U+2069 so a
 * right-to-left connection name cannot reorder the label around it. They are
 * invisible and they are in the accessible name, so a plain string match
 * against a label that contains one never hits.
 */
function control(name: RegExp): HTMLElement {
  return screen.getByRole("button", {
    name: (accessible) => name.test(accessible.replace(/[\u2066-\u2069]/g, "")),
  });
}

/** The question, if it is on screen. */
function dialog(): HTMLElement | null {
  return screen.queryByRole("alertdialog");
}

function openTabIds(): string[] {
  return [...useSessions.getState().order];
}

beforeEach(() => {
  ipcMock.closeSession.mockResolvedValue(undefined);
  ipcMock.listTunnels.mockResolvedValue([]);
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useClosing.setState({ pending: null, busy: false });
  resetLiveTransfers();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useClosing.setState({ pending: null, busy: false });
  resetLiveTransfers();
});

describe("the tab's close control", () => {
  it("does not disconnect on the click — it asks", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    fireEvent.click(control(/close ctso-dc01/i));

    // The whole defect, in one assertion: the click reached the core before.
    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
    expect(dialog()).not.toBeNull();
    // And it says which machine, because "are you sure?" is not information.
    expect(screen.getByRole("alertdialog")).toHaveTextContent("ctso-dc01");
    expect(screen.getByRole("alertdialog")).toHaveTextContent("10.0.0.4:3389");
  });

  it("leaves the session connected when the question is declined", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    fireEvent.click(control(/close ctso-dc01/i));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /stay connected/i }));
    });

    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
    expect(useSessions.getState().byId[tabId]?.phase).toBe("running");
    expect(dialog()).toBeNull();
  });

  it("closes the session when the question is accepted", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    fireEvent.click(control(/close ctso-dc01/i));
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /^disconnect$/i }));
    });

    expect(ipcMock.closeSession).toHaveBeenCalledWith(7);
    expect(openTabIds()).toEqual([]);
    expect(useSessions.getState().byId[tabId]).toBeUndefined();
    expect(dialog()).toBeNull();
  });

  it("keeps the session when Escape dismisses the question", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    fireEvent.click(control(/close ctso-dc01/i));
    await act(async () => {
      fireEvent.keyDown(window, { key: "Escape" });
    });

    // Escape is the safe direction on purpose: a dialog whose dismissal
    // disconnected would be worse than the control it guards.
    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
  });

  it("asks for the last tab exactly as it does for one of many", () => {
    seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    expect(openTabIds()).toHaveLength(1);
    fireEvent.click(control(/close ctso-dc01/i));
    expect(dialog()).not.toBeNull();
    expect(ipcMock.closeSession).not.toHaveBeenCalled();
  });
});

describe("the other ways out of a session", () => {
  it("asks on a middle click, which is the easiest one to do by accident", () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    // A real `auxclick` with the middle button on it: Testing Library has no
    // helper for this one, and the handler is gated on `button === 1`.
    fireEvent(
      control(/ctso-dc01 — connected/i),
      new MouseEvent("auxclick", { bubbles: true, cancelable: true, button: 1 }),
    );

    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
    expect(dialog()).not.toBeNull();
  });

  it("asks on the close shortcut", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    const close = handlerFor("tabs", "tab.close");
    expect(close).not.toBeNull();
    const event: ShortcutEvent = { actionId: "tab.close", accelerator: "ctrl+w", seriesIndex: 0 };
    act(() => close?.(event));

    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
    expect(dialog()).not.toBeNull();

    // And it still closes when the answer is yes, through the same dialog.
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /^disconnect$/i }));
    });
    expect(ipcMock.closeSession).toHaveBeenCalledWith(7);
    expect(openTabIds()).toEqual([]);
  });

  it("asks from the sessions panel's Disconnect", async () => {
    const tabId = seedLive("ctso-dc01", 7);
    const onClose = vi.fn();
    render(
      wrap(
        <>
          <SessionPanels onClose={onClose} />
          <DisconnectDialog />
        </>,
      ),
    );

    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /^disconnect$/i }));
    });

    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([tabId]);
    // The panel stands down rather than leaving two focus traps on screen.
    expect(onClose).toHaveBeenCalled();
  });
});

describe("a tab with nothing left to lose", () => {
  it("goes without a question when its session already failed", () => {
    const tabId = seedEnded("ctso-dc01");
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );

    fireEvent.click(control(/close ctso-dc01/i));

    // Confirming the dismissal of a photograph is the noise that teaches a
    // user to confirm without reading.
    expect(dialog()).toBeNull();
    expect(openTabIds()).toEqual([]);
    expect(useSessions.getState().byId[tabId]).toBeUndefined();
    // Nothing was asked of the core either: there is no session to close.
    expect(ipcMock.closeSession).not.toHaveBeenCalled();
  });
});

describe("closing the window", () => {
  it("asks once and says how many, rather than once per tab", () => {
    seedLive("ctso-dc01", 7);
    seedLive("ctso-file01", 8);
    seedLive("ctso-app02", 9);
    seedEnded("ctso-old");
    const proceed = vi.fn();
    render(wrap(<DisconnectDialog />));

    act(() => {
      requestCloseWindow(proceed);
    });

    expect(screen.getAllByRole("alertdialog")).toHaveLength(1);
    const question = screen.getByRole("alertdialog");
    // Three, not four: the ended tab goes with the window and is not something
    // the user is being asked to weigh.
    expect(question).toHaveTextContent("3 sessions");
    for (const name of ["ctso-dc01", "ctso-file01", "ctso-app02"]) {
      expect(question).toHaveTextContent(name);
    }
    expect(proceed).not.toHaveBeenCalled();
  });

  it("leaves every session connected, and the window open, when declined", async () => {
    const first = seedLive("ctso-dc01", 7);
    const second = seedLive("ctso-file01", 8);
    const proceed = vi.fn();
    render(wrap(<DisconnectDialog />));

    act(() => {
      requestCloseWindow(proceed);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /stay connected/i }));
    });

    expect(ipcMock.closeSession).not.toHaveBeenCalled();
    expect(proceed).not.toHaveBeenCalled();
    expect(openTabIds()).toEqual([first, second]);
  });

  it("closes every session before the window, when accepted", async () => {
    seedLive("ctso-dc01", 7);
    seedLive("ctso-file01", 8);
    const ended = seedEnded("ctso-old");
    const order: string[] = [];
    ipcMock.closeSession.mockImplementation(() => {
      order.push("session");
      return Promise.resolve();
    });
    const proceed = vi.fn(() => {
      order.push("window");
    });
    render(wrap(<DisconnectDialog />));

    act(() => {
      requestCloseWindow(proceed);
    });
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: /disconnect and close/i }));
    });

    expect(ipcMock.closeSession).toHaveBeenCalledWith(7);
    expect(ipcMock.closeSession).toHaveBeenCalledWith(8);
    // The window goes last: `session_close` returns once the sockets are shut
    // and the cached secrets are zeroized, and a window that vanished first
    // would not have waited for it.
    expect(order).toEqual(["session", "session", "window"]);
    // The ended tab went too, without having been part of the question.
    expect(useSessions.getState().byId[ended]).toBeUndefined();
    expect(openTabIds()).toEqual([]);
  });

  it("closes straight through when nothing is connected", () => {
    seedEnded("ctso-old");
    const proceed = vi.fn();
    render(wrap(<DisconnectDialog />));

    act(() => {
      requestCloseWindow(proceed);
    });

    // The ordinary case, and it must not grow a dialog.
    expect(dialog()).toBeNull();
    expect(proceed).toHaveBeenCalledTimes(1);
  });
});

describe("what the question says is at stake", () => {
  it("names a file transfer the disconnect would cancel", async () => {
    const tabId = seedLive("ctso-file01", 8);
    const { reportLiveTransfers } = await import("@/features/files/liveTransfers");
    reportLiveTransfers(8, 2);

    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );
    fireEvent.click(control(/close ctso-file01/i));

    const question = screen.getByRole("alertdialog");
    expect(question).toHaveTextContent(/2 file transfers/i);
    expect(question).toHaveTextContent(/cancelled/i);
    expect(openTabIds()).toEqual([tabId]);
  });

  it("says nothing about transfers when there are none", () => {
    seedLive("ctso-dc01", 7);
    render(
      wrap(
        <>
          <SessionTabs />
          <DisconnectDialog />
        </>,
      ),
    );
    fireEvent.click(control(/close ctso-dc01/i));

    expect(screen.getByRole("alertdialog")).not.toHaveTextContent(/file transfer/i);
  });
});
