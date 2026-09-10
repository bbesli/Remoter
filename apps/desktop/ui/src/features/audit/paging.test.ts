/**
 * The virtualiser's arithmetic.
 *
 * Every failure mode here is silent: a window that is one row short shows a
 * blank strip at the bottom of the table, a page span that misses the boundary
 * shows "Loading" rows that never resolve, and an offset computed against the
 * requested page size rather than the returned one shows the wrong entry under
 * the right timestamp. None of those throw, so none of them would be noticed
 * without this.
 */

import { describe, expect, it } from "vitest";

import {
  DEFAULT_VISIBLE_ROWS,
  OVERSCAN,
  PAGE_SIZE,
  ROW_HEIGHT,
  firstRowAt,
  pageCount,
  pageOfRow,
  pageSpan,
  rowOffsetInPage,
  rowWindow,
  shownRange,
  visibleRowCount,
} from "./paging";

describe("firstRowAt", () => {
  it("is the row the scroll offset lands in", () => {
    expect(firstRowAt(0, 34)).toBe(0);
    expect(firstRowAt(33, 34)).toBe(0);
    expect(firstRowAt(34, 34)).toBe(1);
    expect(firstRowAt(34 * 500, 34)).toBe(500);
  });

  it("treats an elastic overscroll as the top", () => {
    // macOS reports a negative scrollTop while the view is rubber-banding.
    expect(firstRowAt(-120, 34)).toBe(0);
  });
});

describe("visibleRowCount", () => {
  it("rounds up, so a half-visible row is still rendered", () => {
    expect(visibleRowCount(340, 34)).toBe(10);
    expect(visibleRowCount(341, 34)).toBe(11);
  });

  it("assumes a screenful before the scroller has been measured", () => {
    expect(visibleRowCount(0, 34)).toBe(DEFAULT_VISIBLE_ROWS);
  });
});

describe("rowWindow", () => {
  it("is empty when the log is", () => {
    expect(rowWindow(0, 680, 0)).toEqual({ start: 0, end: 0 });
  });

  it("starts at the top with no overscan above it", () => {
    const w = rowWindow(0, 340, 10_000, 34, 6);
    expect(w.start).toBe(0);
    expect(w.end).toBe(16); // 10 visible + 6 below
  });

  it("overscans both edges once away from the top", () => {
    const w = rowWindow(34 * 500, 340, 10_000, 34, 6);
    expect(w).toEqual({ start: 494, end: 516 });
  });

  it("never runs past the last row", () => {
    const w = rowWindow(34 * 9_995, 340, 10_000, 34, 6);
    expect(w.end).toBe(10_000);
  });

  it("clamps a scroll offset left over from a longer list", () => {
    // Filtering 40,000 rows down to 12 while parked at row 30,000 must not
    // produce a window past the end — that reads as "the filter found nothing".
    const w = rowWindow(34 * 30_000, 340, 12, 34, 6);
    expect(w).toEqual({ start: 5, end: 12 });
  });
});

describe("pageOfRow", () => {
  it("maps rows onto pages of PAGE_SIZE", () => {
    expect(pageOfRow(0, 200)).toBe(0);
    expect(pageOfRow(199, 200)).toBe(0);
    expect(pageOfRow(200, 200)).toBe(1);
    expect(pageOfRow(41_999, 200)).toBe(209);
  });
});

describe("pageCount", () => {
  it("rounds up and treats an empty log as no pages", () => {
    expect(pageCount(0, 200)).toBe(0);
    expect(pageCount(1, 200)).toBe(1);
    expect(pageCount(200, 200)).toBe(1);
    expect(pageCount(201, 200)).toBe(2);
  });
});

describe("pageSpan", () => {
  it("asks for one page in the middle of one", () => {
    expect(pageSpan(0, 340, 200, 34, 6)).toEqual({ anchor: 0, next: null });
  });

  it("asks for the next page as soon as the viewport touches it", () => {
    // Row 195 at the top, ten visible plus six overscan reaches row 211.
    expect(pageSpan(34 * 195, 340, 200, 34, 6)).toEqual({ anchor: 0, next: 1 });
  });

  it("moves the anchor once the top row crosses the boundary", () => {
    expect(pageSpan(34 * 200, 340, 200, 34, 6)).toEqual({ anchor: 1, next: null });
  });

  it("names a page even before anything is known about the log", () => {
    // The first answer is what reports the total, so some page has to be asked
    // for; asking for page 0 of an empty filter costs one cached call.
    expect(pageSpan(0, 0, 200, 34, 6).anchor).toBe(0);
  });

  it("never spans more than two pages at the sizes actually used", () => {
    const span = pageSpan(34 * 12_345, 1_200, PAGE_SIZE, ROW_HEIGHT, OVERSCAN);
    expect(span.next === null || span.next === span.anchor + 1).toBe(true);
  });
});

describe("rowOffsetInPage", () => {
  it("finds a row on its own page", () => {
    expect(rowOffsetInPage(0, 0, 200)).toBe(0);
    expect(rowOffsetInPage(199, 0, 200)).toBe(199);
    expect(rowOffsetInPage(200, 1, 200)).toBe(0);
    expect(rowOffsetInPage(41_999, 209, 200)).toBe(199);
  });

  it("refuses a row that is not on the page", () => {
    expect(rowOffsetInPage(200, 0, 200)).toBeNull();
    expect(rowOffsetInPage(199, 1, 200)).toBeNull();
  });

  it("uses the page size it is given, which is the one the core returned", () => {
    // The command caps pageSize at 1000. A row indexed against the requested
    // size after the core clamped it would show the wrong entry, not an error.
    expect(rowOffsetInPage(1_500, 1, 1_000)).toBe(500);
  });
});

describe("shownRange", () => {
  it("counts from one, for people", () => {
    expect(shownRange({ start: 0, end: 16 }, 4_182)).toEqual({ first: 1, last: 16 });
    expect(shownRange({ start: 494, end: 516 }, 4_182)).toEqual({ first: 495, last: 516 });
  });

  it("reports nothing for an empty log", () => {
    expect(shownRange({ start: 0, end: 0 }, 0)).toEqual({ first: 0, last: 0 });
  });

  it("never claims more rows than exist", () => {
    expect(shownRange({ start: 0, end: 30 }, 3)).toEqual({ first: 1, last: 3 });
  });
});
