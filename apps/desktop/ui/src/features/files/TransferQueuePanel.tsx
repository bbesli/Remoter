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
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { formatBytes, formatPercent, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc, type IpcFailure, type TransferStatus } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { displayTail } from "./path";
import { failureOf, isLive, progressOf, refetchIntervalFor, resumeOutcome, summarise } from "./queue";

import s from "./TransferQueuePanel.module.css";

const DECLINED_KEY = {
  download: { notShorter: "queue.resume.declinedDownloadNotShorter", unknownSize: "queue.resume.declinedDownloadUnknownSize" },
  upload: { notShorter: "queue.resume.declinedUploadNotShorter", unknownSize: "queue.resume.declinedUploadUnknownSize" },
} as const;

const STATE_KEY = {
  queued: "queue.state.queued",
  running: "queue.state.running",
  completed: "queue.state.completed",
  cancelled: "queue.state.cancelled",
  failed: "queue.state.failed",
} as const;

interface TransferQueuePanelProps {
  paneId: number;
  /** Whether new transfers ask to continue rather than start over. */
  resume: boolean;
  onResumeChange: (resume: boolean) => void;
  /** Why the last batch was refused before any of it started. */
  enqueueProblem: IpcFailure | null;
}

export function TransferQueuePanel({ paneId, resume, onResumeChange, enqueueProblem }: TransferQueuePanelProps) {
  const t = useT("files");
  const queryClient = useQueryClient();
  const [showFinished, setShowFinished] = useState(true);

  const transfers = useQuery({
    queryKey: qk.sftpTransfers(paneId),
    queryFn: () => ipc.listTransfers(paneId),
    // Re-read while anything is still moving, and stop the moment nothing is.
    // See `queue.ts` for why this is a poll and what would replace it.
    refetchInterval: (query) => refetchIntervalFor(query.state.data),
    retry: false,
  });

  const list = transfers.data ?? [];
  const counts = summarise(list);
  const shown = showFinished ? list : list.filter(isLive);

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
        <h3 className={s.title}>{t("queue.title")}</h3>
        <span className={s.count}>{t("queue.active", { count: counts.live })}</span>
        <div className={s.spacer} />
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
            <TransferRow key={status.transferId} paneId={paneId} status={status} onChanged={refresh} />
          ))}
        </ul>
      )}
    </section>
  );
}

function TransferRow({
  paneId,
  status,
  onChanged,
}: {
  paneId: number;
  status: TransferStatus;
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
        <Badge tone={status.direction === "download" ? "info" : "accent"}>
          {status.direction === "download" ? t("queue.directionDownload") : t("queue.directionUpload")}
        </Badge>
        <span className={s.name} title={status.remoteDisplay}>
          {isolate(name)}
        </span>
        <span className={s.state}>{t(STATE_KEY[status.state])}</span>
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
        {!live && (
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
        </p>
      )}

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
