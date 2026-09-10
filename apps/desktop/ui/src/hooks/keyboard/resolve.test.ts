/**
 * Resolution, conflicts, and the prefix rule.
 *
 * These are the three things the settings table and the window listener both
 * read. A conflict the table failed to name is a key the user watches do
 * nothing; a prefix rule the listener got wrong is `Ctrl+C` stolen from a
 * production shell.
 */

import { describe, expect, it } from "vitest";

import { SHORTCUT_ACTIONS, findAction } from "./actions";
import {
  checkBinding,
  coveredAccelerators,
  effectiveAccelerator,
  matchesChord,
  resolveShortcuts,
  type ResolvedShortcut,
} from "./resolve";

const PREFIX = "ctrl+alt";

function entry(id: string, overrides: Record<string, string> = {}): ResolvedShortcut {
  const found = resolveShortcuts(overrides).find((one) => one.action.id === id);
  if (found === undefined) throw new Error(`no action ${id}`);
  return found;
}

describe("the shipped map", () => {
  it("has a row for every action and an action for every row", () => {
    const resolved = resolveShortcuts({});
    expect(resolved).toHaveLength(SHORTCUT_ACTIONS.length);
    for (const one of resolved) {
      expect(findAction(one.action.id)).toBeDefined();
    }
  });

  it("ships with nothing bound twice", () => {
    const duplicates = resolveShortcuts({}).filter((one) => one.conflict?.kind === "duplicate");
    expect(duplicates).toEqual([]);
  });

  it("names the desktop conflict rather than leaving it to be discovered", () => {
    expect(entry("tab.next").conflict).toEqual({ kind: "desktop" });
  });

  it("expands the jump binding to all nine keys", () => {
    expect(coveredAccelerators(entry("tab.jump"))).toHaveLength(9);
  });

  it("takes an override, and says the row is no longer the default", () => {
    const changed = entry("tab.close", { "tab.close": "ctrl+j" });
    expect(changed.accelerator).toBe("ctrl+j");
    expect(changed.customised).toBe(true);
  });

  it("ignores an override for an action the core will not store", () => {
    // `node.edit` is not in the core's map, so an override for it could never
    // have been saved — showing one would describe a binding that is not real.
    expect(entry("node.edit", { "node.edit": "ctrl+j" }).accelerator).toBe("f2");
  });
});

describe("conflict detection", () => {
  it("refuses a combination another action already holds, and names it", () => {
    const refusal = checkBinding("sidebar.toggle", "ctrl+k", {});
    expect(refusal).toEqual({
      kind: "duplicate",
      accelerator: "ctrl+k",
      withId: "palette.open",
      withTitle: "Command palette and search",
    });
  });

  it("sees a clash with a series binding, not only with a single key", () => {
    const refusal = checkBinding("sidebar.toggle", "alt+4", {});
    expect(refusal).toMatchObject({ kind: "duplicate", withId: "tab.jump" });
  });

  it("counts the overrides, not only the defaults", () => {
    // Ctrl+B is free once the sidebar has been moved off it.
    expect(checkBinding("tab.close", "ctrl+b", { "sidebar.toggle": "ctrl+j" })).toBeNull();
    // And taken once something else has been moved onto it.
    expect(checkBinding("tab.close", "ctrl+j", { "sidebar.toggle": "ctrl+j" })).toMatchObject({
      kind: "duplicate",
      withId: "sidebar.toggle",
    });
  });

  it("does not name an unbound action as the holder", () => {
    // Nothing in this build opens a cheat sheet, so `?` is free — reporting it
    // as taken would refuse a key on behalf of a feature that does not exist.
    expect(checkBinding("sidebar.toggle", "?", {})).toBeNull();
  });

  it("will not let a universal binding take a key the remote shell needs", () => {
    expect(checkBinding("vault.lock", "ctrl+c", {})).toEqual({
      kind: "terminal-reserved",
      accelerator: "ctrl+c",
    });
  });

  it("refuses an action the core cannot store rather than failing the save", () => {
    expect(checkBinding("node.edit", "ctrl+j", {})).toMatchObject({ kind: "not-editable" });
    expect(checkBinding("terminal.find", "ctrl+j", {})).toMatchObject({ kind: "not-editable" });
  });

  it("refuses a chord that is not a chord", () => {
    expect(checkBinding("tab.close", "ctrl+", {})).toMatchObject({ kind: "invalid" });
  });

  it("accepts a free combination", () => {
    expect(checkBinding("tab.close", "ctrl+j", {})).toBeNull();
  });
});

describe("the prefix, inside a focused terminal", () => {
  it("gives an application binding its plain chord only outside a session", () => {
    const app = entry("connection.new");
    expect(matchesChord(app, "ctrl+n", false, PREFIX)).toEqual({ matched: true, seriesIndex: 0 });
    expect(matchesChord(app, "ctrl+n", true, PREFIX)).toEqual({ matched: false });
  });

  it("reaches an application binding through the prefix inside a session", () => {
    const app = entry("connection.new");
    expect(matchesChord(app, "ctrl+alt+n", true, PREFIX)).toEqual({ matched: true, seriesIndex: 0 });
    // And not outside one: the prefixed form is the session's form.
    expect(matchesChord(app, "ctrl+alt+n", false, PREFIX)).toEqual({ matched: false });
  });

  it("leaves the universal ones global, prefix or no prefix", () => {
    const universal = entry("palette.open");
    expect(matchesChord(universal, "ctrl+k", true, PREFIX)).toEqual({ matched: true, seriesIndex: 0 });
    expect(matchesChord(universal, "ctrl+alt+k", true, PREFIX)).toEqual({
      matched: true,
      seriesIndex: 0,
    });
  });

  it("follows a reconfigured prefix", () => {
    const app = entry("sidebar.toggle");
    expect(matchesChord(app, "ctrl+alt+b", true, "ctrl+shift")).toEqual({ matched: false });
    expect(matchesChord(app, "ctrl+shift+b", true, "ctrl+shift")).toEqual({
      matched: true,
      seriesIndex: 0,
    });
  });

  it("reports which key of a series was pressed", () => {
    expect(matchesChord(entry("tab.jump"), "alt+3", false, PREFIX)).toEqual({
      matched: true,
      seriesIndex: 2,
    });
    expect(matchesChord(entry("tab.jump"), "ctrl+alt+3", true, PREFIX)).toEqual({
      matched: true,
      seriesIndex: 2,
    });
  });

  it("shows the chord that is actually typed in the current context", () => {
    expect(effectiveAccelerator(entry("connection.new"), true, PREFIX)).toBe("ctrl+alt+n");
    expect(effectiveAccelerator(entry("connection.new"), false, PREFIX)).toBe("ctrl+n");
    expect(effectiveAccelerator(entry("palette.open"), true, PREFIX)).toBe("ctrl+k");
  });
});
