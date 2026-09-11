/**
 * Ordering and filtering a directory listing.
 *
 * Two decisions here are not interchangeable, and this codebase has already
 * paid for confusing them once.
 *
 * # Filtering folds invariantly. Sorting collates in the reader's language.
 *
 * `docs/features/i18n.md`, "Locale-specific hazards", draws the line: a
 * case-insensitive comparison of **text a person reads and writes** folds in
 * that person's language, and a comparison of **text that is not language** —
 * an identifier, a key cap, a tag used as a flag — folds invariantly. A file
 * name is the second kind. It is a byte string a machine chose, and the
 * Turkish fold turns the `I` in `IMG_0431.JPG` into `ı`, so the row stops
 * matching a search for `img` typed on the same keyboard. That is the exact
 * shape of the bug the document records: four screens folded search with
 * `toLowerCase()` and the Turkish reader lost rows they could see.
 *
 * So {@link matchesFilter} puts both the needle and the name through
 * {@link foldInvariant}, which folds in a fixed language whatever the reader's
 * is. The needle is folded exactly as the names are, so `IMG` finds `img`,
 * `img` finds `IMG`, and — because the fixed language is English — a Turkish
 * reader's dotless `ımg` finds `IMG_0431.JPG` too.
 *
 * That last one is a **widening**, and widening is the safe direction. The fold
 * is applied to the needle and the haystack alike, so it can never make a
 * search find less; what it must never do is what a reader-language fold would
 * do here, which is turn the `I` a machine put in a file name into a letter the
 * file name does not contain and drop the row. `filter.note` in the catalogue
 * says on screen that only case is forgiven, rather than leaving it to be
 * discovered.
 *
 * **Sorting is the opposite case and needs the opposite answer.** Collation
 * order is a presentation choice, not an identity test: nothing is included or
 * excluded by it, so the reader's alphabet is exactly the right one to use. A
 * Turkish reader expects `ç` between `c` and `d`, a Swedish reader expects
 * `ö` after `z`, and `Intl.Collator` knows both. `numeric: true` additionally
 * puts `part2` before `part10`, which is what anyone looking at a directory of
 * numbered files means by alphabetical.
 *
 * # Everything here reads the escaped name
 *
 * `displayName` is what the row draws, so it is what the row sorts and filters
 * by: a user cannot search for a character they were never shown, and a name
 * that sorted by its raw form would jump to a position the reader cannot
 * account for. The raw `name` is for addressing and for nothing else.
 */

import { foldInvariant } from "@/i18n";
import type { DirectoryEntry } from "@/lib/ipc";

/** Which column the listing is ordered by. */
export type SortColumn = "name" | "size" | "modified" | "permissions" | "owner";

export type SortDirection = "asc" | "desc";

export interface SortOrder {
  column: SortColumn;
  direction: SortDirection;
  /**
   * Folders above files, whichever column is sorting.
   *
   * Every file manager does this and it is what makes a deep tree navigable,
   * but it is a toggle because a directory of build artefacts sorted by size
   * is a question about the files, and the folders are in the way of it.
   */
  foldersFirst: boolean;
}

export const DEFAULT_SORT: SortOrder = { column: "name", direction: "asc", foldersFirst: true };

/** Collators are expensive to build and cheap to keep. One per language. */
const COLLATORS = new Map<string, Intl.Collator>();

function collatorFor(locale: string): Intl.Collator {
  const cached = COLLATORS.get(locale);
  if (cached !== undefined) return cached;
  let collator: Intl.Collator;
  try {
    collator = new Intl.Collator(locale, {
      // A directory of `part2`, `part10`, `part11` reads in that order to a
      // human and in the opposite one to a code-point comparison.
      numeric: true,
      // `usage: "sort"` is the collation tailored to ordering rather than to
      // matching; the two differ in several languages, and this is ordering.
      usage: "sort",
      // Neither case nor accent excludes anything here, so both are allowed to
      // be tie-breakers rather than being flattened away.
      sensitivity: "variant",
    });
  } catch {
    // A settings file can name a language this runtime cannot parse. An
    // unusable tag must not stop a folder from being listed.
    collator = new Intl.Collator(undefined, { numeric: true, usage: "sort" });
  }
  COLLATORS.set(locale, collator);
  return collator;
}

/** Test seam. Nothing else should need to reach into the collator cache. */
export function resetCollatorCacheForTests(): void {
  COLLATORS.clear();
}

/**
 * Whether an entry matches what the user typed.
 *
 * An empty needle matches everything, so clearing the box restores the folder
 * rather than emptying it.
 */
export function matchesFilter(entry: DirectoryEntry, needle: string): boolean {
  const folded = foldInvariant(needle.trim());
  if (folded === "") return true;
  return foldInvariant(entry.displayName).includes(folded);
}

/**
 * Whether the server declined to report this column for this entry.
 *
 * Kept apart from the comparison because an unreported value must sort **last
 * in both directions**, and anything folded into the ordinary comparison is
 * multiplied by the direction sign along with everything else. A file whose
 * size the server never sent is not a zero-byte file, and it does not become
 * the largest file in the folder when the sort is reversed either.
 */
function isMissing(entry: DirectoryEntry, column: SortColumn): boolean {
  switch (column) {
    case "size":
      return entry.size === null;
    case "modified":
      return entry.modified === null;
    case "permissions":
      return entry.mode === null || entry.mode === "";
    case "owner":
      return entry.user === null || entry.user === "";
    case "name":
      // Always present: a directory entry the server sent without a name is not
      // an entry.
      return false;
  }
}

function isDirectory(entry: DirectoryEntry): boolean {
  return entry.kind === "directory";
}

/**
 * Orders a listing. Returns a new array; the query cache's copy is not touched.
 *
 * `locale` is passed in rather than read from a module-level "current
 * language", for the reason `i18n/format.ts` gives: a comparator that reads
 * hidden state cannot be tested against six languages in one file, and this one
 * is.
 */
export function sortEntries(
  entries: readonly DirectoryEntry[],
  order: SortOrder,
  locale: string,
): DirectoryEntry[] {
  const collator = collatorFor(locale);
  const sign = order.direction === "asc" ? 1 : -1;

  return [...entries].sort((a, b) => {
    if (order.foldersFirst && isDirectory(a) !== isDirectory(b)) {
      // Outside the direction sign on purpose: reversing the sort should
      // reverse the files, not move the folders to the bottom.
      return isDirectory(a) ? -1 : 1;
    }

    // Outside the direction sign, for the reason `isMissing` gives.
    const aMissing = isMissing(a, order.column);
    const bMissing = isMissing(b, order.column);
    if (aMissing !== bMissing) return aMissing ? 1 : -1;

    let primary = 0;
    if (!aMissing) {
      switch (order.column) {
        case "name":
          primary = collator.compare(a.displayName, b.displayName);
          break;
        case "size":
          primary = (a.size ?? 0) - (b.size ?? 0);
          break;
        case "modified":
          primary = (a.modified ?? 0) - (b.modified ?? 0);
          break;
        case "permissions":
          // `drwxr-xr-x` is ASCII by construction, produced by the core rather
          // than by any server, so it is compared as the identifier it is. The
          // reader's collation has nothing to say about it.
          primary = collatorFor("en-US").compare(a.mode ?? "", b.mode ?? "");
          break;
        case "owner":
          // A user name is text a person reads, so it collates in their
          // language — and unlike a file name it never addresses anything.
          primary = collator.compare(a.user ?? "", b.user ?? "");
          break;
      }
    }

    if (primary !== 0) return primary * sign;
    // A stable tie-break, so two files of the same size do not swap places on
    // every re-render. Also signed, so the whole listing reverses together.
    return collator.compare(a.displayName, b.displayName) * sign;
  });
}

/**
 * The direction a column should take when it is chosen.
 *
 * Choosing the active column reverses it; choosing a different one starts from
 * the direction that reads as "most interesting first" for that kind of value.
 * Size and date start descending — the biggest file and the newest change are
 * what someone sorting by them is looking for — and text starts ascending.
 */
export function nextOrder(current: SortOrder, column: SortColumn): SortOrder {
  if (current.column === column) {
    return { ...current, direction: current.direction === "asc" ? "desc" : "asc" };
  }
  const descendingFirst = column === "size" || column === "modified";
  return { ...current, column, direction: descendingFirst ? "desc" : "asc" };
}
