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
 *    implies otherwise puts the claim back. `header.guarantee` in the catalogue
 *    is flagged for a second reader for the same reason.
 *  - **Draw a player for recordings that do not exist.** Sessions land in v0.2.
 *    One line says so where someone would look for it.
 *
 * One thing it does not translate: `entry.detail`. That note is written by the
 * core and arrives over IPC already worded, the same as a hostname or a remote
 * banner — it is data on this side of the boundary, and it is rendered as
 * untrusted text.
 */

import { useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import clsx from "clsx";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { BusyStatus } from "@/components/Busy";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { formatNumber, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import { useApp } from "@/stores/app";
import { asFailure, ipc } from "@/lib/ipc";
import type { AuditEntry } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { AuditExportDialog } from "./AuditExportDialog";
import { AuditFilterBar } from "./AuditFilterBar";
import {
  buildAuditQuery,
  DEFAULT_FILTERS,
  pruneActor,
  pruneToAvailable,
  type AuditFilterState,
} from "./filters";
import {
  eventLabel,
  formatFullTime,
  formatRowTime,
  osName,
  outcomeLook,
  rowCategoryLabel,
  type AuditT,
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

export function AuditViewer() {
  const t = useT("audit");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

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

  // Who has written to this log. Read from the vault, not gathered from the
  // rows on screen, so the filter can offer someone whose entries are all on a
  // page nobody has scrolled to.
  const actorsQuery = useQuery({
    queryKey: auditKeys.actors(),
    queryFn: () => ipc.auditActors(),
  });

  // A selection the core no longer offers is dropped rather than sent: an
  // unknown category would match nothing and the table would look broken.
  const effective = pruneActor(
    pruneToAvailable(filters, filtersQuery.data),
    actorsQuery.data,
  );

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
    <section className={s.viewer} aria-label={t("header.title")}>
      <header className={s.header}>
        <Button variant="ghost" size="sm" onClick={goBack}>
          <Icon name="arrow-left" size={14} />
          {t("header.back")}
        </Button>
        <Icon name="file" size={15} />
        <h1 className={s.title}>{t("header.title")}</h1>
        <Badge tone="success" mono>
          {t("header.badge")}
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
          {t("header.refresh")}
        </Button>
        <Button variant="secondary" size="sm" onClick={() => setExporting(true)}>
          <Icon name="download" size={13} />
          {t("header.export")}
        </Button>
      </header>

      <div className={s.notes}>
        <p className={s.note}>
          <Icon name="shield" size={13} />
          {t("header.guarantee")}
        </p>
        <p className={s.note}>
          <Icon name="alert" size={13} />
          {t("header.recordings")}
        </p>
      </div>

      <AuditFilterBar
        value={effective}
        onChange={applyFilters}
        available={filtersQuery.data}
        nodes={nodesQuery.data}
        actors={actorsQuery.data}
        total={total}
      />

      {filtersQuery.isError && (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(filtersQuery.error)}
            title={t("table.filtersFailed")}
            tone="warning"
            onRetry={() => void filtersQuery.refetch()}
            retryLabel={tCommon("action.retry")}
          />
        </div>
      )}

      {nodesQuery.isError && (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(nodesQuery.error)}
            title={t("table.nodesFailed")}
            tone="warning"
            onRetry={() => void nodesQuery.refetch()}
            retryLabel={tCommon("action.retry")}
          />
        </div>
      )}

      {actorsQuery.isError && (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(actorsQuery.error)}
            title={t("table.actorsFailed")}
            tone="warning"
            onRetry={() => void actorsQuery.refetch()}
            retryLabel={tCommon("action.retry")}
          />
        </div>
      )}

      {anchorQuery.isError ? (
        <div className={s.notice}>
          <FailureNotice
            failure={asFailure(anchorQuery.error)}
            title={t("table.loadFailed")}
            onRetry={() => void anchorQuery.refetch()}
            retryLabel={tCommon("action.retry")}
          />
        </div>
      ) : (
        <div
          className={s.table}
          role="table"
          aria-label={t("table.label")}
          aria-rowcount={(total ?? 0) + 1}
          // One number for the layout maths and the stylesheet both.
          style={{ "--audit-row-h": `${ROW_HEIGHT}px` } as CSSProperties}
        >
          <div className={clsx(s.row, s.headRow)} role="row" aria-rowindex={1}>
            <div className={s.cell} role="columnheader">
              {t("columns.time")}
            </div>
            <div className={s.cell} role="columnheader">
              {t("columns.event")}
            </div>
            <div className={s.cell} role="columnheader">
              {t("columns.outcome")}
            </div>
            <div className={s.cell} role="columnheader" title={t("columns.whoTitle")}>
              {t("columns.who")}
            </div>
            <div className={s.cell} role="columnheader">
              {t("columns.node")}
            </div>
            <div className={s.cell} role="columnheader">
              {t("columns.detail")}
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
                <BusyStatus label={t("table.loading")} />
              </div>
            ) : total === 0 ? (
              <div className={s.state}>
                <p className={s.emptyTitle}>{t("empty.title")}</p>
                <p className={s.emptyHint}>{t("empty.hint")}</p>
                <Button variant="secondary" size="sm" onClick={() => applyFilters(DEFAULT_FILTERS)}>
                  {t("empty.clear")}
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
                  // `t` and the locale are passed down rather than read again
                  // in every row: a virtualised table mounts and unmounts rows
                  // on every scroll tick, and one translation subscription per
                  // row buys nothing — this component re-renders them all when
                  // the language changes.
                  <Row
                    key={index}
                    index={index}
                    entry={entryAt(index)}
                    t={t}
                    locale={locale}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <footer className={s.footer}>
        <Icon name="shield" size={12} />
        <span>{t("table.appendOnly")}</span>
        <div className={s.spacer} />
        {anchorQuery.isFetching && <BusyStatus label={t("table.loading")} size={12} compact />}
        <span className={s.count}>
          {total === null || total === 0
            ? t("table.shownNone")
            : t("table.shown", {
                first: formatNumber(locale, range.first),
                last: formatNumber(locale, range.last),
                total: formatNumber(locale, total),
              })}
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
  t: AuditT;
  /** The BCP 47 tag the timestamps are formatted for. */
  locale: string;
}

function Row({ index, entry, t, locale }: RowProps) {
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
          {t("table.rowLoading")}
        </div>
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
        <div className={s.cell} role="cell" />
      </div>
    );
  }

  const look = outcomeLook(t, entry.outcome);

  return (
    <div
      className={clsx(s.row, entry.warning && s.warningRow)}
      role="row"
      aria-rowindex={index + 2}
      style={{ top: `${top}px` }}
    >
      <div className={clsx(s.cell, s.mono)} role="cell" title={formatFullTime(locale, entry.at)}>
        {formatRowTime(locale, entry.at)}
      </div>

      <div className={s.cell} role="cell">
        {entry.warning && (
          <span className={s.warningGlyph}>
            <Icon name="alert" size={12} />
          </span>
        )}
        {/* The stored spelling stays reachable: it is what an export is grepped
            for. It is a machine identifier and is never translated, which is
            why it is interpolated into the tooltip rather than being part of
            the message. */}
        <span
          className={s.event}
          title={t("table.eventTitle", {
            event: entry.event,
            category: rowCategoryLabel(t, entry.category),
          })}
        >
          {eventLabel(t, entry.event)}
        </span>
      </div>

      <div className={s.cell} role="cell">
        {/* Glyph, word and tint. The word is the one that is never optional. */}
        <span className={clsx(s.outcome, s[look.tone])}>
          <Icon name={look.icon} size={12} />
          {look.word}
        </span>
      </div>

      <div className={s.cell} role="cell">
        {entry.actor === null ? (
          // Not "nobody": the row was written by someone, before this build
          // recorded who, or by a process that could not tell.
          <span className={s.subtle}>{t("table.actorUnrecorded")}</span>
        ) : (
          <span
            className={s.actor}
            title={t("table.actorTitle", {
              account: isolate(entry.actor.account),
              machine: isolate(entry.actor.machine),
              os: osName(entry.actor.os),
            })}
          >
            {/* Both are names the operating system reported — data, in any
                script — so each is isolated from the other. An account name
                is written left to right whatever it contains. */}
            <span className={clsx(s.actorAccount, s.mono)}>{isolateLtr(entry.actor.account)}</span>
            <span className={s.actorMachine}>{isolate(entry.actor.machine)}</span>
          </span>
        )}
      </div>

      <div className={clsx(s.cell, s.mono)} role="cell">
        {entry.nodeName !== null && entry.nodeName !== "" ? (
          <span className={s.truncate} title={entry.nodeName}>
            {entry.nodeName}
          </span>
        ) : entry.nodeId !== null ? (
          <span className={s.subtle} title={entry.nodeId}>
            {t("table.removedNode")}
          </span>
        ) : (
          <span className={s.subtle}>{t("table.noValue")}</span>
        )}
      </div>

      <div className={s.cell} role="cell">
        {entry.detail !== null && entry.detail !== "" ? (
          <span className={s.truncate} title={entry.detail}>
            {entry.detail}
          </span>
        ) : (
          <span className={s.subtle}>{t("table.noValue")}</span>
        )}
      </div>
    </div>
  );
}
