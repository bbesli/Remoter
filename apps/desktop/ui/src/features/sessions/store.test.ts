/**
 * The tab is the interface's own object, and these are the properties the rest
 * of the feature relies on.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { newTabId, useSessions } from "./store";

function seed(name: string): string {
  const tabId = newTabId();
  useSessions.getState().open({
    tabId,
    nodeId: `node-${name}`,
    name,
    colour: null,
    protocol: "ssh",
    target: "127.0.0.1:2222",
  });
  return tabId;
}

beforeEach(() => {
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("opening a tab", () => {
  it("gives it an id of its own before the core has one", () => {
    const tabId = seed("web-01");
    const record = useSessions.getState().byId[tabId];

    // Null, and that is the point: the tab exists to be cancelled before the
    // core has named the session.
    expect(record?.sessionId).toBeNull();
    expect(record?.phase).toBe("preparing");
  });

  it("gives two sessions on the same connection two tabs", () => {
    seed("web-01");
    seed("web-01");
    expect(useSessions.getState().order).toHaveLength(2);
  });

  it("brings the new tab to the front", () => {
    seed("web-01");
    const second = seed("db-01");
    expect(useSessions.getState().activeTabId).toBe(second);
  });
});

describe("closing a tab", () => {
  it("moves focus to a neighbour rather than to nothing", () => {
    const first = seed("web-01");
    const second = seed("db-01");
    seed("ctso-dc01");

    useSessions.getState().activate(second);
    useSessions.getState().remove(second);

    const state = useSessions.getState();
    expect(state.order).toHaveLength(2);
    expect(state.activeTabId).not.toBeNull();
    expect(state.activeTabId).not.toBe(second);
    expect(state.order[0]).toBe(first);
  });

  it("leaves the front tab alone when a background one goes", () => {
    const first = seed("web-01");
    const second = seed("db-01");
    useSessions.getState().activate(second);

    useSessions.getState().remove(first);
    expect(useSessions.getState().activeTabId).toBe(second);
  });

  it("empties the front when the last tab goes", () => {
    const only = seed("web-01");
    useSessions.getState().remove(only);
    expect(useSessions.getState().activeTabId).toBeNull();
  });
});

describe("stage marks", () => {
  it("records the first time a stage is seen and not the second", () => {
    const tabId = seed("web-01");
    useSessions.getState().markStage(tabId, "acquire");
    const first = useSessions.getState().byId[tabId]?.stageAt.acquire;

    useSessions.getState().markStage(tabId, "acquire");
    expect(useSessions.getState().byId[tabId]?.stageAt.acquire).toBe(first);
  });
});

describe("restarting a tab", () => {
  it("keeps the tab and its identity, and forgets the attempt", () => {
    const tabId = seed("web-01");
    useSessions.getState().patch(tabId, {
      phase: "failed",
      sessionId: 42,
      failure: { code: "transport.refused", message: "refused", detail: null, actions: [] },
    });

    useSessions.getState().restart(tabId);

    const record = useSessions.getState().byId[tabId];
    expect(record?.name).toBe("web-01");
    expect(record?.nodeId).toBe("node-web-01");
    expect(record?.phase).toBe("preparing");
    expect(record?.failure).toBeNull();
    expect(record?.sessionId).toBeNull();
  });

  it("keeps the renderer, which was probed once and does not change", () => {
    const tabId = seed("web-01");
    useSessions
      .getState()
      .patch(tabId, { renderer: { kind: "webgl", renderer: "Apple M2", reason: null } });

    useSessions.getState().restart(tabId);
    expect(useSessions.getState().byId[tabId]?.renderer?.kind).toBe("webgl");
  });
});
