/**
 * One directory, as the remote pane shows it: read, filtered, ordered, capped.
 *
 * The read is a query because a listing is server state — the core owns it, the
 * same folder read twice should not be read twice, and a rename invalidates it
 * through `invalidatePane` rather than through a hand-rolled refresh. The
 * filter and the order are not: they are this screen's own, they change on
 * every keystroke, and putting them in the key would make each keystroke a
 * fetch.
 *
 * # The cap, and why there is one
 *
 * The core will return up to 250 000 entries before it refuses, which is
 * deliberate: a build directory with four hundred thousand files is a fact
 * about the user's server, and an empty pane would be a lie about it. Drawing
 * 250 000 rows is a different question. This hook therefore renders the first
 * {@link RENDER_CAP} of the ordered listing and reports the total, so the pane
 * can say what it is not showing and point at the filter. That is a stop-gap
 * for virtualisation rather than a design: the audit log is virtualised and
 * this should be too, and the honest version of "not yet" is a sentence on
 * screen rather than a slow one.
 */

import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { useLocale } from "@/i18n";
import { asFailure, ipc, type DirectoryEntry, type IpcFailure } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { DEFAULT_SORT, matchesFilter, nextOrder, sortEntries, type SortColumn, type SortOrder } from "./sort";

/** How many rows are drawn at once. See the header. */
export const RENDER_CAP = 1_000;

export interface DirectoryView {
  /** Everything the server sent, unordered. `undefined` until the first read. */
  entries: readonly DirectoryEntry[] | undefined;
  /** What the pane draws: filtered, ordered, and cut at {@link RENDER_CAP}. */
  visible: readonly DirectoryEntry[];
  /** How many entries matched the filter, before the cap. */
  matched: number;
  /** How many the folder holds. */
  total: number;
  /** True when more matched than are being drawn. */
  capped: boolean;
  loading: boolean;
  /** Why the folder could not be read. Rendered through the failure layer. */
  problem: IpcFailure | null;
  refresh: () => void;

  order: SortOrder;
  /** Choosing the active column reverses it; choosing another switches to it. */
  chooseColumn: (column: SortColumn) => void;
  setFoldersFirst: (foldersFirst: boolean) => void;

  filter: string;
  setFilter: (filter: string) => void;
}

export function useDirectory(paneId: number, path: string): DirectoryView {
  const { code: locale } = useLocale();
  const [order, setOrder] = useState<SortOrder>(DEFAULT_SORT);
  const [filter, setFilter] = useState("");

  const query = useQuery({
    queryKey: qk.sftpListing(paneId, path),
    queryFn: () => ipc.listDirectory(paneId, path),
    // A directory does not change under the user often enough to be worth
    // re-reading on every remount, and the pane invalidates it on every action
    // that could have changed it.
    staleTime: 10_000,
    // A listing that failed because the folder is over the core's cap will fail
    // again for the same reason; retrying three times only makes the user wait
    // three times as long for the same sentence.
    retry: false,
  });

  const entries = query.data;

  const { visible, matched, capped } = useMemo(() => {
    if (entries === undefined) return { visible: [] as DirectoryEntry[], matched: 0, capped: false };
    const kept = entries.filter((entry) => matchesFilter(entry, filter));
    const ordered = sortEntries(kept, order, locale);
    return {
      visible: ordered.slice(0, RENDER_CAP),
      matched: ordered.length,
      capped: ordered.length > RENDER_CAP,
    };
  }, [entries, filter, order, locale]);

  return {
    entries,
    visible,
    matched,
    total: entries?.length ?? 0,
    capped,
    loading: query.isPending,
    problem: query.error === null ? null : asFailure(query.error),
    refresh: () => {
      void query.refetch();
    },
    order,
    chooseColumn: (column) => {
      setOrder((current) => nextOrder(current, column));
    },
    setFoldersFirst: (foldersFirst) => {
      setOrder((current) => ({ ...current, foldersFirst }));
    },
    filter,
    setFilter,
  };
}
