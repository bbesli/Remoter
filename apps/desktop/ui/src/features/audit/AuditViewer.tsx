/**
 * The audit log viewer.
 *
 * A vault in daily use accumulates tens of thousands of rows, so the table is
 * virtualised in both directions at once: only the visible rows are in the DOM,
 * and only the pages under the viewport are asked for. `paging.ts` holds that
 * arithmetic as pure functions — it is the part that fails silently when it is
 * wrong, showing a gap where a row should be, so it is the part with tests.
 *
 * Three things this screen refuses to do:
 *
 *  - **Guess the vocabulary.** Chips come from `audit_filters`. A category this
 *    build has never heard of still gets a chip; an event it cannot name still
 *    gets a row, rendered as the stored spelling.
 *  - **Overstate the guarantee.** The line under the header says what the log
 *    format actually delivers, which is less than "tamper-evident". See
 *    docs/features/recording-audit.md and ADR-0012 — the hash chain was dropped
 *    precisely because it would have defended against nobody, and a screen that
 *    implies otherwise puts the claim back.
 *  - **Draw a player for recordings that do not exist.** Sessions land in v0.2.
 *    One line says so where someone would look for it.
 */

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { BusyStatus } from "@/components/Busy";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { useApp } from "@/stores/app";
import { asFailure, ipc } from "@/lib/ipc";
import type { AuditEntry } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { AuditExportDialog } from "./AuditExportDialog";
import { AuditFilterBar } from "./AuditFilterBar";
import { buildAuditQuery, DEFAULT_FILTERS, pruneToAvailable, type AuditFilterState } from "./filters";
import {
  eventLabel,
  formatCount,
  formatFullTime,
  formatRowTime,
  outcomeLook,
  rowCategoryLabel,
} from "./format";
import {
  PAGE_SIZE,
  ROW_HEIGHT,
  pageSpan,
  rowOffsetInPage,
  rowWindow,
  shownRange,
} from "./paging";
import { auditKeys } from "./queryKeys";
import s from "./AuditViewer.module.css";

const TEXT = {
  back: "Back",
  title: "Audit log",
  badge: "append-only · local",
  export: "Export…",
  refresh: "Refresh",

  /**
   * The honest guarantee, in one sentence. Taken from
   * docs/features/recording-audit.md, which states it precisely and explains
   * why a hash chain would not have improved it.
   */
  guarantee:
    "Nobody who cannot open this vault can read or change this log — but anyone who can open it can edit it, and Remoter would not be able to tell.",
  recordings:
    "There is no recording player yet: sessions arrive in v0.2, so there is nothing recorded to play.",

  columnTime: "Time",
  columnEvent: "Event",
  columnOutcome: "Outcome",
  columnNode: "Node",
  columnDetail: "Detail",

  table: "Audit entries",
  loading: "Reading the audit log…",
  loadFailed: "The audit log could not be read.",
  filtersFailed: "The log's filter list could not be read.",
  nodesFailed: "The tree could not be read, so the node filter is unavailable.",
  retry: "Try again",

  empty: "No entries match these filters.",
  emptyHint: "Widen the time range, or clear the filters.",
  clear: "Clear filters",

  rowLoading: "Loading",
  none: "—",
  removedNode: "(no longer in the tree)",

  appendOnly: "Entries are appended and never edited. Exporting copies them; it does not remove them.",
  shown: (first: string, last: string, total: string) =>
    `Rows ${first}–${last} of ${total} · rendered as you scroll`,
  shownNone: "No rows",
} as const;

export function AuditViewer() {
  const [filters, setFilters] = useState<AuditFilterState>(DEFAULT_FILTERS);

  /**
   * The instant a relative range is measured from.
   *
   * "Last 30 days" recomputed on every render would produce a new `since` — and
   * so a new query key — on every render, and the table would refetch forever
   * without ever settling. The anchor moves when the filter changes and when
   * Refresh is pressed, and at no other time.
   */
  const [anchor, setAnchor] = useState(() => Date.now());

  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(0);
  const [exporting, setExporting] = useState(false);

  const scrollerRef = useRef<HTMLDivElement | null>(null);

  const filtersQuery = useQuery({
    queryKey: auditKeys.filters(),
    queryFn: () => ipc.auditFilters(),
    staleTime: 5 * 60_000,
  });

  // The node filter's options. The tree is already cached by the shell, so this
  // is usually a read from the cache rather than a second command.
  const nodesQuery = useQuery({
    queryKey: qk.nodes(),
    queryFn: () => ipc.listNodes(),
  });

  // A selection the core no longer offers is dropped rather than sent: an
  // unknown category would match nothing and the table would look broken.
  const effective = pruneToAvailable(filters, filtersQuery.data);

  const span = pageSpan(scrollTop, viewport);

  const anchorQuery = usePage(effective, anchor, span.anchor, true);
  const nextQuery = usePage(effective, anchor, span.next ?? span.anchor + 1, span.next !== null);

  const total = anchorQuery.data?.total ?? nextQuery.data?.total ?? null;
  const visible = rowWindow(scrollTop, viewport, total ?? 0);

  const pages = useMemo(
    () => [anchorQuery.data, nextQuery.data].filter((page) => page !== undefined),
    [anchorQuery.data, nextQuery.data],
  );

  const entryAt = (index: number): AuditEntry | undefined => {
    for (const page of pages) {
      // The core echoes back the page and size it actually used — it caps the
      // size — so the offset is computed from its answer, not from the ask.
      const offset = rowOffsetInPage(index, page.page, page.pageSize);
      if (offset !== null) return page.entries[offset];
    }
    return undefined;
  };

  useEffect(() => {
    const el = scrollerRef.current;
    if (el === null) return;
    const measure = () => setViewport((prev) => (prev === el.clientHeight ? prev : el.clientHeight));
    measure();
    globalThis.addEventListener("resize", measure);
    return () => globalThis.removeEventListener("resize", measure);
  }, []);

  const applyFilters = (next: AuditFilterState) => {
    setFilters(next);
    setAnchor(Date.now());
    // A filter change renames every row. Staying at row 8,000 of a list that
    // now holds 12 is how a filter looks like it returned nothing.
    setScrollTop(0);
    if (scrollerRef.current !== null) scrollerRef.current.scrollTop = 0;
  };

  // This screen owns the whole window while it is open: MainWindow, which holds
  // every other route, is not rendered behind it. Without a way back it is a
  // dead end that only closing the application escapes.
  const goBack = useApp((state) => state.goBack);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") goBack();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goBack]);

  const firstLoad = anchorQuery.isPending && anchorQuery.data === undefined;
  const rows: number[] = [];
  for (let index = visible.start; index < visible.end; index += 1) rows.push(index);
  const range = shownRange(visible, total ?? 0);

  return (
    <section className={s.viewer} aria-label={TEXT.title}>
      <header className={s.header}>
        <Button variant="ghost" size="sm" onClick={goBack}>
          <Icon name="arrow-left" size={14} />
          {TEXT.back}
        </Button>
        <Icon name="file" size={15} />
        <h1 className={s.title}>{TEXT.title}</h1>
        <Badge tone="success" mono>
          {TEXT.badge}
        </Badge>
        <div className={s.spacer} />
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            // Moving the anchor is enough for a relative range — it changes
            // `since`, and so the key. "Everything" sends no `since` at all, so
            // its key does not move and it needs the explicit refetch.
            setAnchor(Date.now());
            void anchorQuery.refetch();
          }}
        >
          {TEXT.refresh}
        </Button>
        <Button variant="secondary" size="sm" onClick={() => setExporting(true)}>
          <Icon name="download" size={13} />
          {TEXT.export}
        </Button>
      </header>

      <div className={s.notes}>
        <p className={s.note}>
          <Icon name="shield" size={13} />
          {TEXT.guarantee}
        </p>
        <p className={s.note}>
          <Icon name="alert" size={13} />
          {TEXT.recordings}
        </p>
      </div>

      <AuditFilterBar
        value={effective}
        onChange={applyFilters}
        available={filtersQuery.data}
        nodes={nodesQuery.data}
        total={total}
      />

      {filtersQuery.isError && (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(filtersQuery.error)}
            title={TEXT.filtersFailed}
            tone="warning"
            onRetry={() => void filtersQuery.refetch()}
            retryLabel={TEXT.retry}
          />
        </div>
      )}

      {nodesQuery.isError && (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(nodesQuery.error)}
            title={TEXT.nodesFailed}
            tone="warning"
            onRetry={() => void nodesQuery.refetch()}
            retryLabel={TEXT.retry}
          />
        </div>
      )}

      {anchorQuery.isError ? (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(anchorQuery.error)}
            title={TEXT.loadFailed}
            onRetry={() => void anchorQuery.refetch()}
            retryLabel={TEXT.retry}
          />
        </div>
      ) : (
        <div
          className={s.table}
          role="table"
          aria-label={TEXT.table}
          aria-rowcount={(total ?? 0) + 1}
          // One number for the layout maths and the stylesheet both.
          style={{ "--audit-row-h": `${ROW_HEIGHT}px` } as CSSProperties}
        >
          <div className={clsx(s.row, s.headRow)} role="row" aria-rowindex={1}>
            <div className={s.cell} role="columnheader">
              {TEXT.columnTime}
            </div>
            <div className={s.cell} role="columnheader">
              {TEXT.columnEvent}
            </div>
            <div className={s.cell} role="columnheader">
              {TEXT.columnOutcome}
            </div>
            <div className={s.cell} role="columnheader">
              {TEXT.columnNode}
            </div>
            <div className={s.cell} role="columnheader">
              {TEXT.columnDetail}
            </div>
          </div>

          <div
            ref={scrollerRef}
            className={s.scroller}
            role="presentation"
            onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
          >
            {firstLoad ? (
              <div className={s.state}>
                <BusyStatus label={TEXT.loading} />
              </div>
            ) : total === 0 ? (
              <div className={s.state}>
                <p className={s.emptyTitle}>{TEXT.empty}</p>
                <p className={s.emptyHint}>{TEXT.emptyHint}</p>
                <Button variant="secondary" size="sm" onClick={() => applyFilters(DEFAULT_FILTERS)}>
                  {TEXT.clear}
                </Button>
              </div>
            ) : (
              <div
                className={s.sizer}
                role="presentation"
                // The scrollbar has to report the whole log, not the dozen rows
                // that happen to be mounted.
                style={{ height: `${(total ?? 0) * ROW_HEIGHT}px` }}
              >
                {rows.map((index) => (
                  <Row key={index} index={index} entry={entryAt(index)} />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <footer className={s.footer}>
        <Icon name="shield" size={12} />
        <span>{TEXT.appendOnly}</span>
        <div className={s.spacer} />
        {anchorQuery.isFetching && <BusyStatus label={TEXT.loading} size={12} compact />}
        <span className={s.count}>
          {total === null || total === 0
            ? TEXT.shownNone
            : TEXT.shown(
                formatCount(range.first),
                formatCount(range.last),
                formatCount(total),
              )}
        </span>
      </footer>

      {exporting && (
        <AuditExportDialog
          filters={effective}
          anchor={anchor}
          onClose={() => setExporting(false)}
        />
      )}
    </section>
  );
}

/**
 * One page of entries.
 *
 * `keepPreviousData` is what makes scrolling readable: without it, crossing a
 * page boundary blanks the table for the length of a round trip, which reads as
 * the log having lost its rows.
 *
 * The cost of that is stale data on a query that has since been disabled — the
 * second page, once the viewport stops straddling a boundary. It cannot show a
 * wrong row: `entryAt` indexes against the page number the core returned with
 * the data, so a page that is no longer wanted matches no visible index.
 */
function usePage(filters: AuditFilterState, anchor: number, page: number, enabled: boolean) {
  const query = buildAuditQuery(filters, anchor, { page, pageSize: PAGE_SIZE });
  return useQuery({
    queryKey: auditKeys.page(query),
    queryFn: () => ipc.queryAudit(query),
    enabled,
    placeholderData: keepPreviousData,
  });
}

interface RowProps {
  index: number;
  entry: AuditEntry | undefined;
}

function Row({ index, entry }: RowProps) {
  const top = index * ROW_HEIGHT;

  if (entry === undefined) {
    return (
      <div
        className={clsx(s.row, s.pendingRow)}
        role="row"
        aria-rowindex={index + 2}
        aria-busy="true"
        style={{ top: `${top}px` }}
      >
        <div className={s.cell} role="cell">
          {TEXT.rowLoading}
        </div>
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
      </div>
    );
  }

  const look = outcomeLook(entry.outcome);

  return (
    <div
      className={clsx(s.row, entry.warning && s.warningRow)}
      role="row"
      aria-rowindex={index + 2}
      style={{ top: `${top}px` }}
    >
      <div className={clsx(s.cell, s.mono)} role="cell" title={formatFullTime(entry.at)}>
        {formatRowTime(entry.at)}
      </div>

      <div className={s.cell} role="cell">
        {entry.warning && (
          <span className={s.warningGlyph}>
            <Icon name="alert" size={12} />
          </span>
        )}
        {/* The stored spelling stays reachable: it is what an export is grepped for. */}
        <span className={s.event} title={`${entry.event} · ${rowCategoryLabel(entry.category)}`}>
          {eventLabel(entry.event)}
        </span>
      </div>

      <div className={s.cell} role="cell">
        {/* Glyph, word and tint. The word is the one that is never optional. */}
        <span className={clsx(s.outcome, s[look.tone])}>
          <Icon name={look.icon} size={12} />
          {look.word}
        </span>
      </div>

      <div className={clsx(s.cell, s.mono)} role="cell">
        {entry.nodeName !== null && entry.nodeName !== "" ? (
          <span className={s.truncate} title={entry.nodeName}>
            {entry.nodeName}
          </span>
        ) : entry.nodeId !== null ? (
          <span className={s.subtle} title={entry.nodeId}>
            {TEXT.removedNode}
          </span>
        ) : (
          <span className={s.subtle}>{TEXT.none}</span>
        )}
      </div>

      <div className={s.cell} role="cell">
        {entry.detail !== null && entry.detail !== "" ? (
          <span className={s.truncate} title={entry.detail}>
            {entry.detail}
          </span>
        ) : (
          <span className={s.subtle}>{TEXT.none}</span>
        )}
      </div>
    </div>
  );
}
