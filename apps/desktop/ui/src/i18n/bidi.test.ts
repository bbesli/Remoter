/**
 * The direction helpers, at unit scale.
 *
 * `isolate()` and its siblings are exercised through the screens that use them
 * (`interpolation.test.ts`); the two functions here are exercised through one
 * screen only — the connection tree's context menu — so their edges are worth
 * pinning directly. Both are about a thing the bidi algorithm cannot help with:
 * a number that came from a pointer, which is physical no matter what the
 * paragraph around it is doing.
 */

import { afterEach, describe, expect, it } from "vitest";

import { documentDirection, inlineStartOffset } from "./bidi";

afterEach(() => {
  document.documentElement.removeAttribute("dir");
});

describe("documentDirection", () => {
  it("reads rtl from the document root", () => {
    document.documentElement.setAttribute("dir", "rtl");
    expect(documentDirection()).toBe("rtl");
  });

  it("reads ltr from the document root", () => {
    document.documentElement.setAttribute("dir", "ltr");
    expect(documentDirection()).toBe("ltr");
  });

  it("falls back to ltr when the root carries no direction", () => {
    // Before `applyDocumentLanguage()` has run — the first paint of a cold
    // start — there is no attribute, and the browser is laying the page out
    // LTR. Anything that disagreed with the browser here would place a box
    // against a direction the layout is not using.
    expect(documentDirection()).toBe("ltr");
  });

  it("treats dir=\"auto\" as ltr rather than guessing", () => {
    // `auto` asks the browser to infer from content, which for a whole document
    // is not a question this function can answer. It resolves the same way the
    // fallback does, so a stray `auto` degrades to the default rather than to
    // a mirrored layout nobody asked for.
    document.documentElement.setAttribute("dir", "auto");
    expect(documentDirection()).toBe("ltr");
  });
});

describe("inlineStartOffset", () => {
  it("passes a left-to-right coordinate through unchanged", () => {
    expect(inlineStartOffset(300, 1024, "ltr")).toBe(300);
  });

  it("mirrors a right-to-left coordinate against the viewport", () => {
    // `inset-inline-start` measures from the right edge in an RTL containing
    // block, so 300px from the left is 724px from the start.
    expect(inlineStartOffset(300, 1024, "rtl")).toBe(724);
  });

  it("is its own inverse under rtl", () => {
    // The property this guarantees: the box lands under the pointer in both
    // directions. Mirroring twice has to return the physical coordinate, or
    // the menu drifts away from the click by however much the two disagree.
    const x = 137;
    expect(inlineStartOffset(inlineStartOffset(x, 1024, "rtl"), 1024, "rtl")).toBe(x);
  });

  it("puts the viewport edges at the far end of the inline axis", () => {
    expect(inlineStartOffset(0, 1024, "rtl")).toBe(1024);
    expect(inlineStartOffset(1024, 1024, "rtl")).toBe(0);
  });
});
