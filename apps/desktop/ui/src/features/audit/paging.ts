/**
 * The arithmetic behind the virtualised table.
 *
 * A vault that has been in daily use for a year holds tens of thousands of
 * audit rows. Two things follow, and both are pure functions here so that an
 * off-by-one in either is caught by a test rather than by a user scrolling past
 * a gap.
 *
 *  1. **Only the visible rows are in the DOM.** `rowWindow` says which ones,
 *     given the scroll offset and the height of the scroller. Everything above
 *     and below is a spacer of the right height, so the scrollbar reports the
 *     truth.
 *  2. **Only the visible rows are fetched.** `pageSpan` says which backend page
 *     the viewport is looking at, and whether it straddles the next one. That
 *     is at most two `audit_query` calls per scroll position, never the whole
 *     log.
 *
 * The window is deliberately computed from the scroll offset alone — not from
 * the total — because the total arrives *in* the first page's answer. Asking
 * "which page do I need?" must not require already knowing how many there are.
 */

/**
 * Row height in CSS pixels.
 *
 * Virtualisation needs a number, and the stylesheet needs the same number; the
 * table passes this into CSS as a custom property so there is one source rather
 * than two that drift. A token would be the usual answer, but this is a
 * measurement the layout maths owns, not a design scale value.
 */
export const ROW_HEIGHT = 34;

/**
 * Rows per `audit_query` call. The command caps a page at 1000 and defaults to
 * 100; 200 is large enough that ordinary scrolling stays inside one page and
 * small enough that the first paint is not waiting on a long read.
 */
export const PAGE_SIZE = 200;

/** Rows rendered beyond each edge, so a fast scroll does not show blank space. */
export const OVERSCAN = 6;

/**
 * How many rows to assume before the scroller has been measured.
 *
 * `clientHeight` is 0 on the first pass — the element exists but has not been
 * laid out. Rendering nothing then would leave the table blank for a frame and,
 * worse, would ask for no page at all.
 */
export const DEFAULT_VISIBLE_ROWS = 24;

/** A half-open range of row indices: `start` inclusive, `end` exclusive. */
export interface RowWindow {
  readonly start: number;
  readonly end: number;
}

/** Which backend pages the viewport is reading. */
export interface PageSpan {
  readonly anchor: number;
  /** The page after `anchor`, when the viewport straddles the boundary. */
  readonly next: number | null;
}

function clamp(value: number, low: number, high: number): number {
  if (high < low) return low;
  return Math.min(Math.max(value, low), high);
}

/** How many rows fit in the scroller, once it has a height. */
export function visibleRowCount(viewportHeight: number, rowHeight = ROW_HEIGHT): number {
  if (rowHeight <= 0) return DEFAULT_VISIBLE_ROWS;
  if (viewportHeight <= 0) return DEFAULT_VISIBLE_ROWS;
  return Math.max(1, Math.ceil(viewportHeight / rowHeight));
}

/**
 * The first row index at a scroll offset.
 *
 * Negative offsets are real: elastic scrolling on macOS reports them, and
 * `Math.floor` of a negative would index before the start of the log.
 */
export function firstRowAt(scrollTop: number, rowHeight = ROW_HEIGHT): number {
  if (rowHeight <= 0) return 0;
  return Math.floor(Math.max(0, scrollTop) / rowHeight);
}

/** The rows to render, clamped to what the log actually holds. */
export function rowWindow(
  scrollTop: number,
  viewportHeight: number,
  total: number,
  rowHeight = ROW_HEIGHT,
  overscan = OVERSCAN,
): RowWindow {
  if (total <= 0) return { start: 0, end: 0 };

  const visible = visibleRowCount(viewportHeight, rowHeight);
  const first = clamp(firstRowAt(scrollTop, rowHeight), 0, total - 1);

  return {
    start: Math.max(0, first - overscan),
    end: Math.min(total, first + visible + overscan),
  };
}

/** Which page a row lives on. */
export function pageOfRow(index: number, pageSize = PAGE_SIZE): number {
  if (pageSize <= 0) return 0;
  return Math.floor(Math.max(0, index) / pageSize);
}

/** How many pages a filter's total needs. Zero rows need zero pages. */
export function pageCount(total: number, pageSize = PAGE_SIZE): number {
  if (total <= 0 || pageSize <= 0) return 0;
  return Math.ceil(total / pageSize);
}

/**
 * The row's position inside a given page, or `null` when it is not on it.
 *
 * Called with the `page` and `pageSize` the core echoed back rather than the
 * ones that were asked for, so a page the core resized — it caps `pageSize` at
 * 1000 — still indexes correctly.
 */
export function rowOffsetInPage(index: number, page: number, pageSize: number): number | null {
  if (pageSize <= 0) return null;
  const offset = index - page * pageSize;
  if (offset < 0 || offset >= pageSize) return null;
  return offset;
}

/**
 * The page under the viewport, and the next one when the viewport crosses into
 * it.
 *
 * Always names a page, even before the total is known and even for an empty
 * log: some page has to be asked for, and its answer is what reports the total.
 * Asking for page 0 of an empty filter costs one cached call.
 */
export function pageSpan(
  scrollTop: number,
  viewportHeight: number,
  pageSize = PAGE_SIZE,
  rowHeight = ROW_HEIGHT,
  overscan = OVERSCAN,
): PageSpan {
  const first = firstRowAt(scrollTop, rowHeight);
  const last = first + visibleRowCount(viewportHeight, rowHeight) + overscan;

  const anchor = pageOfRow(first, pageSize);
  const lastPage = pageOfRow(last, pageSize);

  return { anchor, next: lastPage > anchor ? anchor + 1 : null };
}

/** The 1-based first and last rendered row, for the footer's count. */
export function shownRange(window: RowWindow, total: number): { first: number; last: number } {
  if (total <= 0 || window.end <= window.start) return { first: 0, last: 0 };
  return {
    first: clamp(window.start, 0, total - 1) + 1,
    last: clamp(window.end, 1, total),
  };
}
