/**
 * What the filter bar holds, and how it becomes an `AuditQuery`.
 *
 * Pure on purpose. The translation from "these chips are lit" to "this is the
 * query" is where an audit screen quietly lies: an empty category list sent as
 * `categories: []` means *no category matches* to a core that combines the
 * list with "or", so the screen would show an empty log and blame the vault.
 * The rule here is that an empty selection is an *absent* field, never an empty
 * array, and that is pinned by a test.
 *
 * The vocabulary itself is not written down here. Categories and outcomes come
 * from `audit_filters`, so a row written by a build that knows a category this
 * one does not still has a chip to be found under.
 */

import type {
  AuditActorSummary,
  AuditCategory,
  AuditFilters,
  AuditOutcome,
  AuditQuery,
} from "@/lib/ipc";

/** The time windows the bar offers. `all` sends no lower bound at all. */
export type TimeRange = "24h" | "7d" | "30d" | "90d" | "all";

export const TIME_RANGES: readonly TimeRange[] = ["24h", "7d", "30d", "90d", "all"] as const;

export interface AuditFilterState {
  range: TimeRange;
  /** Empty means every category, which is expressed by omitting the field. */
  categories: readonly AuditCategory[];
  /** Empty means every outcome. */
  outcomes: readonly AuditOutcome[];
  /** `null` means every node, and also the rows that concern no node at all. */
  nodeId: string | null;
  /**
   * `null` means everyone — including the rows written before identities were
   * recorded, which a filter on a person could never match.
   */
  actorId: number | null;
}

/**
 * Thirty days, matching the design. Not "everything": a first paint that walks
 * a vault's entire history is the slow first impression this screen is built
 * to avoid, and the range control says plainly what it is showing.
 */
export const DEFAULT_FILTERS: AuditFilterState = {
  range: "30d",
  categories: [],
  outcomes: [],
  nodeId: null,
  actorId: null,
};

const DAY_MS = 86_400_000;

const RANGE_MS: Record<Exclude<TimeRange, "all">, number> = {
  "24h": DAY_MS,
  "7d": 7 * DAY_MS,
  "30d": 30 * DAY_MS,
  "90d": 90 * DAY_MS,
};

/** The lower bound in milliseconds since the epoch, or `null` for no bound. */
export function rangeStart(range: TimeRange, now: number): number | null {
  if (range === "all") return null;
  return now - RANGE_MS[range];
}

export interface Paging {
  /** Zero-based, as the command expects. */
  page: number;
  pageSize: number;
}

/**
 * The filter as the core wants it.
 *
 * `now` is passed in rather than read from the clock so that the query is a
 * function of its arguments: a relative range recomputed on every render would
 * produce a new query key on every render, and the table would refetch forever.
 * The screen anchors `now` when the filter changes and keeps it until it
 * changes again.
 *
 * Omit `paging` for an export, which the core pages by itself.
 */
export function buildAuditQuery(
  state: AuditFilterState,
  now: number,
  paging?: Paging,
): AuditQuery {
  const since = rangeStart(state.range, now);

  return {
    ...(since === null ? {} : { since }),
    ...(state.categories.length > 0 ? { categories: [...state.categories] } : {}),
    ...(state.outcomes.length > 0 ? { outcomes: [...state.outcomes] } : {}),
    ...(state.nodeId === null ? {} : { nodeId: state.nodeId }),
    ...(state.actorId === null ? {} : { actorId: state.actorId }),
    ...(paging === undefined ? {} : { page: paging.page, pageSize: paging.pageSize }),
  };
}

/** Adds a value to a selection, or takes it out again. */
export function toggle<T>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
}

/** Whether the bar is showing less than everything, so "Clear" has work to do. */
export function isNarrowed(state: AuditFilterState): boolean {
  return (
    state.range !== DEFAULT_FILTERS.range ||
    state.categories.length > 0 ||
    state.outcomes.length > 0 ||
    state.nodeId !== null ||
    state.actorId !== null
  );
}

/**
 * Drops a "who" selection that is not one of this vault's identities.
 *
 * Identities are numbered per vault, so the selection a person made while one
 * vault was open means somebody else — or nobody — in the next. Sending it
 * would filter the second vault's log by a stranger and show an empty table
 * with the filter looking correct.
 *
 * Returns the same object when nothing was dropped.
 */
export function pruneActor(
  state: AuditFilterState,
  actors: readonly AuditActorSummary[] | undefined,
): AuditFilterState {
  if (actors === undefined || state.actorId === null) return state;
  return actors.some((summary) => summary.actor.id === state.actorId)
    ? state
    : { ...state, actorId: null };
}

/**
 * Drops selections the core no longer offers.
 *
 * The vocabulary is the core's, and it can shrink — a category can be retired,
 * and a vault opened by an older build reports fewer of them. A selection left
 * pointing at a word the core does not know is worse than a wrong list: it is
 * an empty table with every chip looking correct. Dropping it shows more rows
 * than asked for, which the bar makes visible, rather than fewer with no
 * explanation.
 *
 * Returns the same object when nothing was dropped, so this can sit in a render
 * without changing identity on every pass.
 */
export function pruneToAvailable(
  state: AuditFilterState,
  available: AuditFilters | undefined,
): AuditFilterState {
  if (available === undefined) return state;

  const categories = state.categories.filter((c) => available.categories.includes(c));
  const outcomes = state.outcomes.filter((o) => available.outcomes.includes(o));

  if (categories.length === state.categories.length && outcomes.length === state.outcomes.length) {
    return state;
  }
  return { ...state, categories, outcomes };
}
