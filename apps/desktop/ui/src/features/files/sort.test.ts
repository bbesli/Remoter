/**
 * The comparator, and the one hazard it exists to avoid.
 *
 * `docs/features/i18n.md` records that four screens in this application folded
 * search with `toLowerCase()` and that the Turkish reader lost rows they could
 * see. A directory listing is where that would happen again, and worse: the
 * strings being matched are not words in anybody's language, so folding them in
 * the reader's is wrong for every reader whose rules differ from English's.
 *
 * So the two halves are asserted separately. Filtering must be **insensitive to
 * the reader's language**; ordering must **follow** it.
 */

import { describe, expect, it, beforeEach } from "vitest";

import type { DirectoryEntry, EntryKind } from "@/lib/ipc";

import { DEFAULT_SORT, matchesFilter, nextOrder, resetCollatorCacheForTests, sortEntries } from "./sort";

beforeEach(() => {
  resetCollatorCacheForTests();
});

function entry(
  displayName: string,
  extra: Partial<DirectoryEntry> = {},
): DirectoryEntry {
  const kind: EntryKind = extra.kind ?? "file";
  return {
    name: displayName,
    displayName,
    path: `/srv/${displayName}`,
    displayPath: `/srv/${displayName}`,
    kind,
    size: null,
    permissions: null,
    mode: null,
    uid: null,
    user: null,
    gid: null,
    group: null,
    modified: null,
    risks: { control: false, bidi: false, invisible: false, separator: false },
    ...extra,
  };
}

describe("matchesFilter", () => {
  it("ignores case", () => {
    expect(matchesFilter(entry("Deploy.log"), "deploy")).toBe(true);
    expect(matchesFilter(entry("deploy.log"), "DEPLOY")).toBe(true);
  });

  it("matches a file name the same way whatever language the reader uses", () => {
    // The regression this file exists for. A machine name with a capital I in
    // it — `IMG_0431.JPG`, `INSTALL`, `README` — must be found by typing the
    // same letters, and a Turkish fold would lower that I to a dotless one and
    // stop matching. Nothing in this call takes a locale, which is the fix:
    // `foldInvariant` folds in a fixed language for exactly this reason.
    expect(matchesFilter(entry("IMG_0431.JPG"), "img")).toBe(true);
    expect(matchesFilter(entry("INSTALL"), "install")).toBe(true);
    expect(matchesFilter(entry("İstanbul.txt"), "istanbul")).toBe(true);
  });

  it("folds a Turkish reader's dotless i into the match rather than out of it", () => {
    // The fold is invariant, so `ı` round-trips through the English `I` and
    // matches. That is a *widening*, and widening is the safe direction: the
    // same fold is applied to the needle and to the name, so it can never make
    // a search find less. What it must never do — and this is the regression
    // the whole module exists for — is the reverse: fold the machine's `I`
    // under Turkish rules into a letter the file name does not contain, and
    // drop a row the reader can see.
    expect(matchesFilter(entry("IMG_0431.JPG"), "ımg")).toBe(true);
    // And the row is still there when the reader types what is printed on it.
    expect(matchesFilter(entry("IMG_0431.JPG"), "IMG")).toBe(true);
  });

  it("restores the whole folder when it is cleared", () => {
    expect(matchesFilter(entry("anything"), "")).toBe(true);
    expect(matchesFilter(entry("anything"), "   ")).toBe(true);
  });

  it("reads the escaped name, not the raw one", () => {
    // The row draws the escaped form, and a user cannot search for a character
    // they were never shown.
    const hostile = entry("report.pdf", { name: "report\u202E.pdf", displayName: "report\\u{202E}.pdf" });
    expect(matchesFilter(hostile, "u{202E}")).toBe(true);
  });
});

describe("sortEntries", () => {
  it("puts folders above files, in both directions", () => {
    const rows = [entry("b.txt"), entry("a", { kind: "directory" }), entry("a.txt")];
    const up = sortEntries(rows, DEFAULT_SORT, "en");
    expect(up.map((e) => e.displayName)).toEqual(["a", "a.txt", "b.txt"]);

    // Reversing the sort reverses the files. It does not send the folders to
    // the bottom, which is what a naive sign on the whole comparison would do.
    const down = sortEntries(rows, { ...DEFAULT_SORT, direction: "desc" }, "en");
    expect(down[0]?.displayName).toBe("a");
    expect(down.slice(1).map((e) => e.displayName)).toEqual(["b.txt", "a.txt"]);
  });

  it("mixes folders in when asked to", () => {
    const rows = [entry("b", { kind: "directory" }), entry("a.txt")];
    const mixed = sortEntries(rows, { ...DEFAULT_SORT, foldersFirst: false }, "en");
    expect(mixed.map((e) => e.displayName)).toEqual(["a.txt", "b"]);
  });

  it("orders numbered files the way a person reads them", () => {
    const rows = [entry("part10"), entry("part2"), entry("part1")];
    expect(sortEntries(rows, DEFAULT_SORT, "en").map((e) => e.displayName)).toEqual([
      "part1",
      "part2",
      "part10",
    ]);
  });

  it("collates in the reader's language", () => {
    // Ordering is a presentation choice rather than an identity test: nothing
    // is included or excluded by it, so the reader's alphabet is the right one.
    // Swedish puts o-umlaut after z; German does not.
    const rows = [entry("zebra"), entry("öppna")];
    expect(sortEntries(rows, DEFAULT_SORT, "sv").map((e) => e.displayName)).toEqual([
      "zebra",
      "öppna",
    ]);
    expect(sortEntries(rows, DEFAULT_SORT, "de").map((e) => e.displayName)).toEqual([
      "öppna",
      "zebra",
    ]);
  });

  it("survives a language tag the runtime cannot parse", () => {
    // A settings file written by a newer build must not stop a folder listing.
    const rows = [entry("b"), entry("a")];
    expect(sortEntries(rows, DEFAULT_SORT, "not a locale").map((e) => e.displayName)).toEqual(["a", "b"]);
  });

  it("sorts an unreported value last in both directions", () => {
    // A file whose size the server declined to send is not a zero-byte file,
    // and putting it at the top of an ascending size sort says that it is.
    const rows = [entry("known", { size: 10 }), entry("unknown"), entry("bigger", { size: 99 })];
    const asc = sortEntries(rows, { column: "size", direction: "asc", foldersFirst: false }, "en");
    expect(asc.map((e) => e.displayName)).toEqual(["known", "bigger", "unknown"]);
    const desc = sortEntries(rows, { column: "size", direction: "desc", foldersFirst: false }, "en");
    expect(desc[desc.length - 1]?.displayName).toBe("unknown");
  });

  it("orders by date, permissions and owner", () => {
    const rows = [
      entry("old", { modified: 1_700_000_000, mode: "-rw-r--r--", user: "deploy" }),
      entry("new", { modified: 1_800_000_000, mode: "drwxr-xr-x", user: "alice" }),
    ];
    expect(
      sortEntries(rows, { column: "modified", direction: "desc", foldersFirst: false }, "en").map(
        (e) => e.displayName,
      ),
    ).toEqual(["new", "old"]);
    expect(
      sortEntries(rows, { column: "owner", direction: "asc", foldersFirst: false }, "en").map(
        (e) => e.displayName,
      ),
    ).toEqual(["new", "old"]);
    expect(
      sortEntries(rows, { column: "permissions", direction: "asc", foldersFirst: false }, "en").map(
        (e) => e.displayName,
      ),
    ).toEqual(["old", "new"]);
  });

  it("does not mutate what it is given", () => {
    // The array belongs to the query cache.
    const rows = [entry("b"), entry("a")];
    sortEntries(rows, DEFAULT_SORT, "en");
    expect(rows.map((e) => e.displayName)).toEqual(["b", "a"]);
  });
});

describe("nextOrder", () => {
  it("reverses the column that is already sorting", () => {
    expect(nextOrder(DEFAULT_SORT, "name").direction).toBe("desc");
  });

  it("starts text ascending and size and date descending", () => {
    // What someone sorting by size is looking for is the biggest file, and what
    // someone sorting by date is looking for is the newest change.
    expect(nextOrder(DEFAULT_SORT, "owner")).toMatchObject({ column: "owner", direction: "asc" });
    expect(nextOrder(DEFAULT_SORT, "size")).toMatchObject({ column: "size", direction: "desc" });
    expect(nextOrder(DEFAULT_SORT, "modified")).toMatchObject({ column: "modified", direction: "desc" });
  });

  it("keeps the folders-first choice across a column change", () => {
    const mixed = { ...DEFAULT_SORT, foldersFirst: false };
    expect(nextOrder(mixed, "size").foldersFirst).toBe(false);
  });
});
