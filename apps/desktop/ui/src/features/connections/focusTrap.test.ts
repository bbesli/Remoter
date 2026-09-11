/**
 * The wrap arithmetic of the focus trap.
 *
 * The hook itself needs a DOM to test and this project has no DOM test
 * environment, so the part that is easy to get wrong is a pure function and
 * that is what is pinned here: tabbing off the last element must land on the
 * first, shift-tabbing off the first must land on the last, and a focus the
 * trap does not recognise must enter at the near end rather than at an
 * arbitrary index.
 */

import { describe, expect, it } from "vitest";

import { nextTrapIndex } from "./focusTrap";

describe("nextTrapIndex", () => {
  it("wraps forward off the last element", () => {
    expect(nextTrapIndex(3, 2, false)).toBe(0);
  });

  it("wraps backward off the first element", () => {
    expect(nextTrapIndex(3, 0, true)).toBe(2);
  });

  it("steps normally in the middle", () => {
    expect(nextTrapIndex(3, 1, false)).toBe(2);
    expect(nextTrapIndex(3, 1, true)).toBe(0);
  });

  it("enters at the near end when focus is outside the trap", () => {
    expect(nextTrapIndex(3, -1, false)).toBe(0);
    expect(nextTrapIndex(3, -1, true)).toBe(2);
  });

  it("stays on a single element", () => {
    expect(nextTrapIndex(1, 0, false)).toBe(0);
    expect(nextTrapIndex(1, 0, true)).toBe(0);
  });

  it("reports no destination when there is nothing to focus", () => {
    expect(nextTrapIndex(0, -1, false)).toBe(-1);
  });
});
