/**
 * The filter bar's translation into a query.
 *
 * The case that matters most is the boring one: an empty selection must be an
 * absent field. The core combines a category list with "or", so `categories:
 * []` asks for entries in none of the categories — an empty table, from a bar
 * that looks like it is asking for everything.
 */

import { describe, expect, it } from "vitest";

import type { AuditFilters } from "@/lib/ipc";

import {
  DEFAULT_FILTERS,
  buildAuditQuery,
  isNarrowed,
  pruneToAvailable,
  rangeStart,
  toggle,
  type AuditFilterState,
} from "./filters";

const NOW = 1_757_500_000_000;
const DAY = 86_400_000;

describe("rangeStart", () => {
  it("measures back from the instant it is given", () => {
    expect(rangeStart("24h", NOW)).toBe(NOW - DAY);
    expect(rangeStart("7d", NOW)).toBe(NOW - 7 * DAY);
    expect(rangeStart("90d", NOW)).toBe(NOW - 90 * DAY);
  });

  it("has no lower bound for everything", () => {
    expect(rangeStart("all", NOW)).toBeNull();
  });
});

describe("buildAuditQuery", () => {
  it("omits an empty selection rather than sending an empty list", () => {
    const query = buildAuditQuery({ ...DEFAULT_FILTERS, range: "all" }, NOW);
    expect(query).toEqual({});
    expect("categories" in query).toBe(false);
    expect("outcomes" in query).toBe(false);
    expect("nodeId" in query).toBe(false);
    expect("since" in query).toBe(false);
  });

  it("sends the selections that are set", () => {
    const state: AuditFilterState = {
      range: "7d",
      categories: ["warning", "secret"],
      outcomes: ["failure"],
      nodeId: "node-1",
    };
    expect(buildAuditQuery(state, NOW)).toEqual({
      since: NOW - 7 * DAY,
      categories: ["warning", "secret"],
      outcomes: ["failure"],
      nodeId: "node-1",
    });
  });

  it("adds paging only when the caller pages", () => {
    const paged = buildAuditQuery(DEFAULT_FILTERS, NOW, { page: 3, pageSize: 200 });
    expect(paged.page).toBe(3);
    expect(paged.pageSize).toBe(200);

    // An export is the whole filter, not the page on screen.
    const exported = buildAuditQuery(DEFAULT_FILTERS, NOW);
    expect("page" in exported).toBe(false);
    expect("pageSize" in exported).toBe(false);
  });

  it("is stable for the same instant, so the table settles", () => {
    const a = buildAuditQuery(DEFAULT_FILTERS, NOW, { page: 0, pageSize: 200 });
    const b = buildAuditQuery(DEFAULT_FILTERS, NOW, { page: 0, pageSize: 200 });
    expect(a).toEqual(b);
  });

  it("copies the selection, so a later toggle cannot mutate a sent query", () => {
    const state: AuditFilterState = { ...DEFAULT_FILTERS, categories: ["vault"] };
    const query = buildAuditQuery(state, NOW);
    expect(query.categories).not.toBe(state.categories);
  });
});

describe("toggle", () => {
  it("adds a value that is not there and removes one that is", () => {
    expect(toggle(["vault"], "secret")).toEqual(["vault", "secret"]);
    expect(toggle(["vault", "secret"], "vault")).toEqual(["secret"]);
  });

  it("does not mutate the list it is given", () => {
    const list = ["vault"];
    toggle(list, "secret");
    expect(list).toEqual(["vault"]);
  });
});

describe("isNarrowed", () => {
  it("is false for the default view", () => {
    expect(isNarrowed(DEFAULT_FILTERS)).toBe(false);
  });

  it("is true for any narrowing, including a widened range", () => {
    expect(isNarrowed({ ...DEFAULT_FILTERS, range: "all" })).toBe(true);
    expect(isNarrowed({ ...DEFAULT_FILTERS, categories: ["vault"] })).toBe(true);
    expect(isNarrowed({ ...DEFAULT_FILTERS, outcomes: ["denied"] })).toBe(true);
    expect(isNarrowed({ ...DEFAULT_FILTERS, nodeId: "node-1" })).toBe(true);
  });
});

describe("pruneToAvailable", () => {
  const available: AuditFilters = {
    categories: ["vault", "node", "connection"],
    outcomes: ["success", "failure"],
    events: ["vault.unlocked"],
  };

  it("leaves the selection alone until the vocabulary arrives", () => {
    const state: AuditFilterState = { ...DEFAULT_FILTERS, categories: ["secret"] };
    expect(pruneToAvailable(state, undefined)).toBe(state);
  });

  it("drops a category the core does not offer", () => {
    const state: AuditFilterState = { ...DEFAULT_FILTERS, categories: ["vault", "secret"] };
    expect(pruneToAvailable(state, available).categories).toEqual(["vault"]);
  });

  it("drops an outcome the core does not offer", () => {
    const state: AuditFilterState = { ...DEFAULT_FILTERS, outcomes: ["failure", "denied"] };
    expect(pruneToAvailable(state, available).outcomes).toEqual(["failure"]);
  });

  it("keeps the same object when nothing was dropped", () => {
    // Identity matters: this runs in a render, and a fresh object every pass
    // would give the table a new query key every pass.
    const state: AuditFilterState = { ...DEFAULT_FILTERS, categories: ["vault"] };
    expect(pruneToAvailable(state, available)).toBe(state);
  });

  it("turns a stale selection into everything, not into nothing", () => {
    const state: AuditFilterState = { ...DEFAULT_FILTERS, categories: ["secret"] };
    const query = buildAuditQuery(pruneToAvailable(state, available), NOW);
    expect("categories" in query).toBe(false);
  });
});
