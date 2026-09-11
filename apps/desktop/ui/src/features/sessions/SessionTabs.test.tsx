/**
 * What the tab strip claims of the keyboard.
 *
 * The registry's contract is that a `null` handler leaves the keystroke alone
 * and a handler that exists consumes it. Every binding here is conditional on
 * there being something to do, and "Jump to tab 1–9" was the one that was not:
 * it registered a function whether or not a session was open, so Alt+1 in a
 * window with no tabs was swallowed by an action that then did nothing.
 */

import { describe, expect, it, vi, beforeEach } from "vitest";
import { act, render } from "@testing-library/react";

// The strip is what is under test; closing and reconnecting reach the core,
// and focusing reaches an xterm instance. Neither belongs in this test.
vi.mock("./manager", () => ({
  closeTab: vi.fn(),
  reconnect: vi.fn(),
}));
vi.mock("./terminals", () => ({
  focusTerminal: vi.fn(),
}));

import { handlerFor, type ShortcutEvent } from "@/hooks/keyboard";

import { SessionTabs } from "./SessionTabs";
import { newTabId, useSessions } from "./store";

function seed(name: string): string {
  const tabId = newTabId();
  act(() => {
    useSessions.getState().open({
      tabId,
      nodeId: `node-${name}`,
      name,
      colour: null,
      protocol: "ssh",
      target: "127.0.0.1:22",
    });
  });
  return tabId;
}

/** The jump handler as the one window listener would find it. */
function jumpHandler() {
  return handlerFor("tabs", "tab.jump");
}

beforeEach(() => {
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("jump to tab 1-9", () => {
  it("registers no handler while no session is open", () => {
    render(<SessionTabs />);

    // Not a handler that does nothing: no handler at all, so the dispatcher
    // never calls preventDefault and Alt+1 reaches whatever else wants it.
    expect(jumpHandler()).toBeNull();
  });

  it("registers one as soon as there is a tab to jump to", () => {
    render(<SessionTabs />);
    const first = seed("web-01");
    const second = seed("db-01");

    const jump = jumpHandler();
    expect(jump).not.toBeNull();

    const event: ShortcutEvent = { actionId: "tab.jump", accelerator: "alt+1", seriesIndex: 0 };
    act(() => jump?.(event));
    expect(useSessions.getState().activeTabId).toBe(first);

    act(() => jump?.({ ...event, accelerator: "alt+2", seriesIndex: 1 }));
    expect(useSessions.getState().activeTabId).toBe(second);
  });

  it("gives the handler up again when the last tab closes", () => {
    render(<SessionTabs />);
    const only = seed("web-01");
    expect(jumpHandler()).not.toBeNull();

    act(() => {
      useSessions.getState().remove(only);
    });

    expect(jumpHandler()).toBeNull();
  });
});
