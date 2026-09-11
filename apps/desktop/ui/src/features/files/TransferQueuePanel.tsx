/**
 * The transfer queue.
 *
 * Several transfers at once, each with its own progress and its own stop, and
 * the list outlives leaving this screen — because it never belonged to this
 * screen. The queue is the core's, and `sftp_transfers` is what this asks it
 * for; unmounting the panel stops nothing and remounting it asks again. That is
 * the whole of "surviving a tab switch", and it is a property of where the
 * state lives rather than of anything written here.
 *
 * A finished entry stays. `sftp_transfer_retry` queues a *new* transfer from a
 * finished one's request rather than resurrecting it, so a terminal state stays
 * terminal and the history of what happened stays readable. "Show finished" is
 * a view filter and nothing more — there is no command that forgets a transfer,
 * and a button offering to would be a button that did not work.
 *
 * Resume is off by default and says why. `resume_offset` refuses more often
 * than a user expects — it continues only when the destination is strictly
 * shorter than a source whose size is known — and where it refused, the row
 * says which of the two reasons applied. There is deliberately no setting that
 * overrides the refusal: appending to the wrong file corrupts it silently, and
 * re-copying one costs time.
 *
 * # What a row now says about time
 *
 * A byte count and a percentage answer "how much", and the question somebody
 * watching a transfer actually has is "how long". Every figure below — the
 * rate, the estimate, the elapsed time, and whether it has stalled — is a
 * subtraction on the timestamps the core puts on each transfer, computed by the
 * pure {@link timingOf} and rendered here.
 *
 * The only moving part is {@link useNow}: one clock, ticking once a second for
 * exactly as long as something is still live, shared by every row. It is a
 * subscription to the wall clock, not derived state — which is the distinction
 * that matters here, because the previous attempt at this measured the rate
 * from the panel's own successive readings, kept them in a `Map` rebuilt inside
 * an effect on every run, and never settled. It did not merely run slowly; it
 * hung the test suite.
 *
 * # It can be put away
 *
 * The panel used to take its share of the pane permanently, which on a laptop
 * is a third of the space the listing needs. Collapsing keeps the heading, the
 * live count and the failed count: a queue that hid how many had failed would
 * be a queue that hid a failure.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { formatBytes, formatPercent, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc, type IpcFailure, type TransferStatus } from "@/lib/ipc";
import { invalidateListings, qk } from "@/lib/queryKeys";

import { forgetLiveTransfers, reportLiveTransfers } from "./liveTransfers";
import { displayTail } from "./path";
import {
  failureOf,
  isLive,
  progressOf,
  refetchIntervalFor,
  remainingParts,
  resumeOutcome,
  summarise,
  timingOf,
  type Remaining,
} from "./queue";

import s from "./TransferQueuePanel.module.css";

const DECLINED_KEY = {
  download: { notShorter: "queue.resume.declinedDownloadNotShorter", unknownSize: "queue.resume.declinedDownloadUnknownSize" },
  upload: { notShorter: "queue.resume.declinedUploadNotShorter", unknownSize: "queue.resume.declinedUploadUnknownSize" },
} as const;

/** The tone each state carries, so the colour and the word agree. */
const TONE = {
  queued: "neutral",
  running: "info",
  completed: "success",
  cancelled: "neutral",
  failed: "danger",
} as const;

const STATE_KEY = {
  queued: "queue.state.queued",
  running: "queue.state.running",
  completed: "queue.state.completed",
  cancelled: "queue.state.cancelled",
  failed: "queue.state.failed",
} as const;

/** Three keys rather than one with a unit placeholder; see the catalogue. */
const REMAINING_KEY = {
  hours: "queue.remainingHours",
  minutes: "queue.remainingMinutes",
  seconds: "queue.remainingSeconds",
} as const satisfies Record<Remaining["unit"], string>;

const ELAPSED_KEY = {
  hours: "queue.elapsedHours",
  minutes: "queue.elapsedMinutes",
  seconds: "queue.elapsedSeconds",
} as const satisfies Record<Remaining["unit"], string>;

interface TransferQueuePanelProps {
  paneId: number;
  /**
   * The session this pane runs on.
   *
   * Not used to fetch anything — the queue is keyed by the pane — but a
   * transfer belongs to a *session* as far as the rest of the application is
   * concerned, and the one place that knows both ids is here. See
   * {@link reportLiveTransfers}: closing a tab interrupts these, and the
   * confirmation that says so is asked from three places that have no pane id.
   */
  sessionId: number;
  /** Whether new transfers ask to continue rather than start over. */
  resume: boolean;
  onResumeChange: (resume: boolean) => void;
  /** Why the last batch was refused before any of it started. */
  enqueueProblem: IpcFailure | null;
}

export function TransferQueuePanel({
  paneId,
  sessionId,
  resume,
  onResumeChange,
  enqueueProblem,
}: TransferQueuePanelProps) {
  const t = useT("files");
  const queryClient = useQueryClient();
  const [showFinished, setShowFinished] = useState(true);
  const [collapsed, setCollapsed] = useState(false);

  const transfers = useQuery({
    queryKey: qk.sftpTransfers(paneId),
    queryFn: () => ipc.listTransfers(paneId),
    // Re-read while anything is still moving, and stop the moment nothing is.
    // See `queue.ts` for why this is a poll and what would replace it.
    refetchInterval: (query) => refetchIntervalFor(query.state.data),
    retry: false,
  });

  const data = transfers.data;
  const list = data ?? EMPTY;
  const counts = summarise(list);
  const shown = showFinished ? list : list.filter(isLive);
  // One clock for every row, ticking only while something can still change.
  const now = useNow(counts.live > 0);

  // Which transfers this panel has already seen finish. A ref rather than
  // state: nothing renders from it, and writing it during an effect that also
  // set state is exactly the shape that looped forever last time.
  const settled = useRef(new Set<number>());

  useEffect(() => {
    if (data === undefined) return;
    const fresh = data.filter(
      (status) => status.state === "completed" && !settled.current.has(status.transferId),
    );
    if (fresh.length === 0) return;
    for (const status of fresh) settled.current.add(status.transferId);
    // A file that just arrived is in a folder on screen, and the pane had no
    // way to know: the listing was never invalidated when a transfer finished,
    // so an upload was simply absent from the directory it had gone into.
    //
    // `invalidateListings` and not `invalidatePane`: invalidating the transfer
    // list from inside its own subscriber would refetch it and notice again,
    // which is a loop with a network call in it.
    void invalidateListings(queryClient, paneId);
    // `data` is structurally shared by TanStack Query, so an unchanged list
    // keeps its identity and this does not re-run on the poll's every tick.
  }, [data, paneId, queryClient]);

  // What closing this session would interrupt, published for the confirmation
  // that asks about it. Cleared on the way out: a pane that has gone is not
  // moving bytes, and a stale count would overstate the stake on the next
  // session to be handed this id.
  const liveCount = counts.live;
  useEffect(() => {
    reportLiveTransfers(sessionId, liveCount);
    return () => {
      forgetLiveTransfers(sessionId);
    };
  }, [sessionId, liveCount]);

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: qk.sftpTransfers(paneId) });
  };

  const cancelAll = useMutation({
    mutationFn: () => ipc.cancelAllTransfers(paneId),
    onSettled: refresh,
  });

  return (
    <section className={s.panel} aria-label={t("queue.title")}>
      <header className={s.head}>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            setCollapsed((was) => !was);
          }}
          ariaLabel={collapsed ? t("queue.expand") : t("queue.collapse")}
          title={collapsed ? t("queue.expand") : t("queue.collapse")}
        >
          {/* Turned over rather than swapped for a sideways chevron: a
              directional icon mirrors in a right-to-left layout and "open" is
              not a direction. */}
          <span className={collapsed ? s.chevronCollapsed : s.chevron}>
            <Icon name="chevron-down" size={13} />
          </span>
        </Button>
        <h3 className={s.title}>{t("queue.title")}</h3>
        <span className={s.count}>{t("queue.active", { count: counts.live })}</span>
        {/* Shown collapsed as well. A failure nobody can see reads as nothing
            having happened. */}
        {counts.failed > 0 && (
          <Badge tone="danger">{t("queue.failedCount", { count: counts.failed })}</Badge>
        )}
        <div className={s.spacer} />
        {!collapsed && (
          <>
            <label className={s.toggle}>
              <input
                type="checkbox"
                checked={resume}
                onChange={(e) => {
                  onResumeChange(e.target.checked);
                }}
              />
              {t("queue.resumeToggle")}
            </label>
            <label className={s.toggle}>
              <input
                type="checkbox"
                checked={showFinished}
                onChange={(e) => {
                  setShowFinished(e.target.checked);
                }}
              />
              {t("queue.showFinished")}
            </label>
          </>
        )}
        <Button
          size="sm"
          variant="ghost"
          disabled={counts.live === 0 || cancelAll.isPending}
          onClick={() => {
            cancelAll.mutate();
          }}
        >
          {t("queue.cancelAll")}
        </Button>
      </header>

      {!collapsed && (
        <>
          {resume && <p className={s.note}>{t("queue.resumeExplain")}</p>}

          {enqueueProblem !== null && (
            <div className={s.notice}>
              <FailureNotice failure={enqueueProblem} title={t("queue.enqueueFailed")} />
              <p className={s.note}>{t("queue.enqueueFailedNote")}</p>
            </div>
          )}

          {transfers.error !== null && (
            <div className={s.notice}>
              {/* The list itself could not be read. An empty queue and an
                  unreadable one look identical, and only one of them is true. */}
              <FailureNotice failure={asFailure(transfers.error)} onRetry={refresh} />
            </div>
          )}

          {shown.length === 0 ? (
            <p className={s.empty}>{t("queue.empty")}</p>
          ) : (
            <ul className={s.list}>
              {shown.map((status) => (
                <TransferRow
                  key={status.transferId}
                  paneId={paneId}
                  status={status}
                  now={now}
                  onChanged={refresh}
                />
              ))}
            </ul>
          )}
        </>
      )}
    </section>
  );
}

/**
 * The empty list, as one value.
 *
 * `transfers.data ?? []` would build a new array on every render while the
 * first read is in flight, and that array is an effect dependency.
 */
const EMPTY: readonly TransferStatus[] = [];

/**
 * The wall clock, read on a tick rather than during a render.
 *
 * Two reasons it is a hook and not a `Date.now()` where the figure is drawn.
 * The first is correctness of a kind React enforces: reading a clock during
 * render is an impure call, and a render that is replayed would produce a
 * different answer. The second is that the figures have to move *between*
 * renders — a transfer's elapsed time changes while nothing else does, and the
 * poll that would have re-rendered stops the moment the last transfer ends.
 *
 * The interval exists only while `active`, so a pane with nothing in flight
 * keeps no timer at all. `setNow` is called from the interval's callback rather
 * than from the effect body, so this is a subscription to an external source
 * and not derived state chasing itself.
 */
function useNow(active: boolean): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      setNow(Date.now());
    }, TICK_MS);
    return () => {
      clearInterval(timer);
    };
  }, [active]);

  return now;
}

/**
 * How often the elapsed time and the rate are redrawn.
 *
 * A second: the figures are rounded to their leading unit, so anything faster
 * redraws the same characters.
 */
const TICK_MS = 1_000;

function TransferRow({
  paneId,
  status,
  now,
  onChanged,
}: {
  paneId: number;
  status: TransferStatus;
  /** The clock every row in this panel shares. See {@link useNow}. */
  now: number;
  onChanged: () => void;
}) {
  const t = useT("files");
  const { code: locale } = useLocale();

  const cancel = useMutation({
    mutationFn: () => ipc.cancelTransfer(paneId, status.transferId),
    onSettled: onChanged,
  });
  const retry = useMutation({
    mutationFn: () => ipc.retryTransfer(paneId, status.transferId),
    onSettled: onChanged,
  });

  const progress = progressOf(status);
  const outcome = resumeOutcome(status);
  const problem = failureOf(status);
  const live = isLive(status);
  const timing = timingOf(status, now);
  const remaining = remainingParts(timing.remainingMs);
  const elapsed = remainingParts(timing.elapsedMs);

  // The escaped twins throughout. The remote half was chosen by the server, and
  // so is the file-name half of the local path when a download went into a
  // folder — which is why that one carries an escaped form too.
  const name = displayTail(status.remoteDisplay);
  const destination =
    status.direction === "download"
      ? t("queue.toLocal", { path: isolateLtr(status.localDisplay) })
      : t("queue.toRemote", { path: isolate(status.remoteDisplay) });

  return (
    <li className={s.item}>
      <div className={s.itemHead}>
        {/* The badge carries the STATE, not the direction.
            It used to read "Downloading" or "Sending" whatever had happened —
            a progressive verb on a transfer that had finished minutes ago —
            with the real state in the quiet span beside it. The owner read a
            completed download as one that was stuck, which is exactly what the
            loudest element on the row was telling them. The direction is not
            lost: the line below says "to C:\..." or "to /srv/...", which is
            where it belongs anyway. */}
        <Badge tone={TONE[status.state]}>{t(STATE_KEY[status.state])}</Badge>
        <span className={s.name} title={status.remoteDisplay}>
          {isolate(name)}
        </span>
        <div className={s.spacer} />
        {live && (
          <Button
            size="sm"
            variant="ghost"
            disabled={cancel.isPending}
            onClick={() => {
              cancel.mutate();
            }}
          >
            {t("queue.cancel")}
          </Button>
        )}
        {/* Only where something went wrong. Offering "Try again" beside a
            transfer that completed says the opposite of what happened. */}
        {(status.state === "failed" || status.state === "cancelled") && (
          <Button
            size="sm"
            variant="ghost"
            disabled={retry.isPending}
            onClick={() => {
              retry.mutate();
            }}
          >
            {t("queue.retry")}
          </Button>
        )}
      </div>

      <p className={s.destination}>{destination}</p>

      {progress !== null && (
        <div
          className={s.bar}
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={progress.total ?? undefined}
          aria-valuenow={progress.done}
          aria-valuetext={
            progress.total === null
              ? t("queue.progressUnknown", { done: formatBytes(locale, progress.done) })
              : t("queue.progress", {
                  done: formatBytes(locale, progress.done),
                  total: formatBytes(locale, progress.total),
                })
          }
        >
          {/* A width, not a colour: an indeterminate bar would claim knowledge
              of a total the server never sent. */}
          <span
            className={progress.ratio === null ? s.fillUnknown : s.fill}
            style={progress.ratio === null ? undefined : { inlineSize: `${String(progress.ratio * 100)}%` }}
          />
        </div>
      )}

      {progress !== null && (
        <p className={s.figures}>
          {/* A finished transfer reads "412 KiB transferred", not "412 KiB of
              412 KiB" — the second is a bar's caption, and the bar is done. */}
          {status.state === "completed"
            ? t("queue.completedBytes", { bytes: formatBytes(locale, progress.done) })
            : progress.total === null
              ? t("queue.progressUnknown", { done: formatBytes(locale, progress.done) })
              : t("queue.progress", {
                  done: formatBytes(locale, progress.done),
                  total: formatBytes(locale, progress.total),
                })}
          {progress.ratio !== null && status.state !== "completed" && (
            <span className={s.percent}>{formatPercent(locale, progress.ratio)}</span>
          )}
          {/* Each of these appears only where it can be measured. A rate over a
              sample too short to be one, or an estimate past a day, is a figure
              that looks like knowledge and is not. */}
          {timing.bytesPerSecond !== null && status.state === "running" && (
            <span className={s.rate}>
              {t("queue.speed", { rate: formatBytes(locale, timing.bytesPerSecond) })}
            </span>
          )}
          {remaining !== null && (
            <span className={s.rate}>
              {t(REMAINING_KEY[remaining.unit], { [remaining.unit]: remaining.value })}
            </span>
          )}
          {elapsed !== null && (
            <span className={s.rate}>
              {t(ELAPSED_KEY[elapsed.unit], { [elapsed.unit]: elapsed.value })}
            </span>
          )}
        </p>
      )}

      {timing.stalled && <p className={s.note}>{t("queue.stalled")}</p>}

      {outcome !== null && (
        <p className={s.resume}>
          {outcome.kind === "continued"
            ? t("queue.resume.continued", { offset: formatBytes(locale, outcome.offset) })
            : t(DECLINED_KEY[status.direction][outcome.reason])}
        </p>
      )}

      {problem !== null && (
        <div className={s.notice}>
          <FailureNotice
            failure={problem}
            title={t("queue.failedTitle")}
            onRetry={
              retry.isPending
                ? undefined
                : () => {
                    retry.mutate();
                  }
            }
            retryLabel={t("queue.retry")}
          />
        </div>
      )}
    </li>
  );
}
