/**
 * The spelling the core and the interface have to agree on.
 *
 * If these two normalise differently, a binding saved from the settings screen
 * comes back as a different binding and the key the user pressed stops working
 * — silently, because both sides think they are right.
 */

import { describe, expect, it } from "vitest";

import {
  acceleratorCaps,
  acceleratorFromEvent,
  normaliseAccelerator,
  normalisePrefix,
  seriesAccelerators,
  withPrefix,
} from "./accelerator";

/** A keydown as the browser would deliver it. */
function press(init: KeyboardEventInit): KeyboardEvent {
  return new KeyboardEvent("keydown", init);
}

describe("canonical spelling", () => {
  it("puts modifiers in a fixed order so one binding is not stored as two", () => {
    expect(normaliseAccelerator("Shift+Ctrl+N")).toBe("ctrl+shift+n");
    expect(normaliseAccelerator("ctrl+shift+n")).toBe("ctrl+shift+n");
  });

  it("folds the platform aliases the core folds", () => {
    expect(normaliseAccelerator("Cmd+K")).toBe("meta+k");
    expect(normaliseAccelerator("Command+K")).toBe("meta+k");
    expect(normaliseAccelerator("Option+F")).toBe("alt+f");
  });

  it("refuses what the core refuses", () => {
    expect(normaliseAccelerator("ctrl+")).toBeNull();
    expect(normaliseAccelerator("ctrl+a+b")).toBeNull();
    expect(normaliseAccelerator("ctrl+shift")).toBeNull();
    expect(normaliseAccelerator("ctrl+f99")).toBeNull();
  });

  it("takes the named keys and the function keys", () => {
    expect(normaliseAccelerator("Ctrl+Tab")).toBe("ctrl+tab");
    expect(normaliseAccelerator("F11")).toBe("f11");
    expect(normaliseAccelerator("?")).toBe("?");
  });
});

describe("the terminal prefix", () => {
  it("is modifiers and nothing else", () => {
    expect(normalisePrefix("Alt+Ctrl")).toBe("ctrl+alt");
    expect(normalisePrefix("ctrl+k")).toBeNull();
    expect(normalisePrefix("")).toBeNull();
  });

  it("adds to an accelerator's own modifiers rather than replacing them", () => {
    expect(withPrefix("ctrl+n", "ctrl+alt")).toBe("ctrl+alt+n");
    expect(withPrefix("f11", "ctrl+alt")).toBe("ctrl+alt+f11");
    // Already carries the prefix's modifiers: the chord does not gain a second
    // copy of them.
    expect(withPrefix("ctrl+alt+n", "ctrl+alt")).toBe("ctrl+alt+n");
  });
});

describe("a series binding", () => {
  it("covers every key it claims", () => {
    expect(seriesAccelerators("alt+1", 9)).toEqual([
      "alt+1",
      "alt+2",
      "alt+3",
      "alt+4",
      "alt+5",
      "alt+6",
      "alt+7",
      "alt+8",
      "alt+9",
    ]);
  });

  it("reads as its span rather than nine rows", () => {
    expect(acceleratorCaps("alt+1", 9)).toEqual(["Alt", "1…9"]);
  });
});

describe("reading a keystroke", () => {
  it("keeps shift on a letter, where it is part of the chord", () => {
    expect(acceleratorFromEvent(press({ key: "N", ctrlKey: true, shiftKey: true, code: "KeyN" }))).toBe(
      "ctrl+shift+n",
    );
  });

  it("drops shift on a symbol, which is what shift produced", () => {
    // Otherwise the cheat-sheet binding the core ships as `?` could never be
    // typed: every `?` arrives with shift held.
    expect(acceleratorFromEvent(press({ key: "?", shiftKey: true, code: "Slash" }))).toBe("?");
  });

  it("is nothing at all while only modifiers are held", () => {
    expect(acceleratorFromEvent(press({ key: "Control", ctrlKey: true }))).toBeNull();
    expect(acceleratorFromEvent(press({ key: "Alt", altKey: true }))).toBeNull();
  });

  it("falls back to the physical key when the layout renames it", () => {
    // Alt+1 reports "¡" on some Mac layouts. "Jump to tab 1" has to keep
    // working there, so the code decides when the key cannot.
    expect(acceleratorFromEvent(press({ key: "¡", altKey: true, code: "Digit1" }))).toBe("alt+1");
  });

  it("names the arrow and editing keys the way the map spells them", () => {
    expect(acceleratorFromEvent(press({ key: "ArrowUp", ctrlKey: true }))).toBe("ctrl+up");
    expect(acceleratorFromEvent(press({ key: "Tab", ctrlKey: true, shiftKey: true }))).toBe(
      "ctrl+shift+tab",
    );
  });
});
