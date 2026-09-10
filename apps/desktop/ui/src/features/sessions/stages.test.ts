/**
 * The connect progress only ever claims what was observed.
 */

import { describe, expect, it } from "vitest";

import { failedStage, isConnecting, stagesFor } from "./stages";

describe("the stage rows", () => {
  it("marks nothing done before the core has reported anything", () => {
    const rows = stagesFor("preparing");
    expect(rows[0]?.state).toBe("active");
    expect(rows.slice(1).every((r) => r.state === "pending")).toBe(true);
  });

  it("moves forward only as far as the transition the core announced", () => {
    // `opening` says stages 1 to 3 finished; it says nothing about the
    // handshake, so the handshake row stays pending rather than being guessed
    // into progress.
    const rows = stagesFor("connecting");
    expect(rows.map((r) => r.state)).toEqual(["done", "active", "pending", "pending"]);
  });

  it("shows a host key question as suspended, not as working", () => {
    const rows = stagesFor("verifying");
    const handshake = rows.find((r) => r.id === "handshake");
    expect(handshake?.state).toBe("suspended");
  });

  it("marks every stage done once the session is ready", () => {
    expect(stagesFor("running").every((r) => r.state === "done")).toBe(true);
  });

  it("blames the stage the core named, and only that one", () => {
    const rows = stagesFor("failed", "transport");
    expect(rows.map((r) => r.state)).toEqual(["done", "abandoned", "pending", "pending"]);
  });

  it("blames nothing when the core named a stage it does not recognise", () => {
    const rows = stagesFor("failed", "something-new");
    expect(rows.every((r) => r.state === "abandoned")).toBe(true);
  });
});

describe("mapping the core's nine stages onto the four rows", () => {
  it("folds resolve, authorise and acquire together", () => {
    expect(failedStage("resolve")).toBe("acquire");
    expect(failedStage("authorise")).toBe("acquire");
    expect(failedStage("acquire")).toBe("acquire");
  });

  it("folds attach in with authenticate", () => {
    expect(failedStage("authenticate")).toBe("authenticate");
    expect(failedStage("attach")).toBe("authenticate");
  });

  it("returns nothing for a stage it cannot place", () => {
    expect(failedStage("run")).toBeNull();
    expect(failedStage(null)).toBeNull();
  });
});

describe("whether an attempt is still in flight", () => {
  it("counts every phase before ready, including a suspended handshake", () => {
    expect(isConnecting("preparing")).toBe(true);
    expect(isConnecting("connecting")).toBe(true);
    expect(isConnecting("verifying")).toBe(true);
    expect(isConnecting("authenticating")).toBe(true);
  });

  it("counts nothing after it", () => {
    expect(isConnecting("running")).toBe(false);
    expect(isConnecting("failed")).toBe(false);
    expect(isConnecting("closed")).toBe(false);
  });
});
