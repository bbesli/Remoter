/**
 * Reading a transfer's state. No React, no IPC, no copy — only derivations.
 *
 * The queue itself is not stored here. It lives in the core, which owns it, and
 * reaches the interface through `qk.sftpTransfers(paneId)` — server state, so
 * TanStack Query rather than Zustand (CLAUDE.md §6). That is also what makes
 * the queue survive leaving this screen and coming back: the transfers never
 * belonged to the component, so unmounting it stops nothing and remounting it
 * asks the core what happened while it was away.
 *
 * # How progress reaches a bar, and what is missing
 *
 * `docs/architecture/sftp-command-surface.md` is explicit that progress is
 * **pushed**: a running transfer reports every 512 KiB through its session's
 * own channel as a `progress` message, and `sftp_transfers` exists for the
 * first paint and for reconciliation. That channel is subscribed in
 * `features/sessions/manager.ts`, whose `progress` case says in so many words
 * that SFTP's events will land there — and it currently returns without doing
 * anything with them. Routing them into this feature is a three-line change in
 * that file, and that file belongs to another agent.
 *
 * So this build reconciles instead: {@link refetchIntervalFor} asks the core
 * for the list while anything is still moving, and stops as soon as everything
 * is terminal. It is a poll, it is the thing the document says not to build a
 * bar on, and it is written down here rather than left to be discovered. What
 * it costs is one in-memory list read per interval per open pane; what it buys
 * is that a two-gigabyte copy shows movement instead of looking like a hang,
 * which is the requirement the whole queue exists for.
 */

import type { IpcFailure, TransferStatus } from "@/lib/ipc";

/** How often the transfer list is re-read while anything is still moving. */
const LIVE_POLL_MS = 700;

/**
 * Whether a transfer can still change on its own.
 *
 * The three terminal states never change again — `sftp_transfer_retry` queues a
 * *new* transfer rather than resurrecting one — so a list of only terminal
 * entries needs no further reads at all.
 */
export function isLive(status: TransferStatus): boolean {
  return status.state === "queued" || status.state === "running";
}

/** True when at least one transfer is still queued or moving. */
export function anyLive(statuses: readonly TransferStatus[]): boolean {
  return statuses.some(isLive);
}

/**
 * The refetch interval for a pane's transfer list.
 *
 * `false` when nothing is live, which is the ordinary state of a pane: a screen
 * that keeps polling after the last transfer finished is a screen that keeps a
 * timer alive for the rest of the session.
 */
export function refetchIntervalFor(statuses: readonly TransferStatus[] | undefined): number | false {
  return statuses !== undefined && anyLive(statuses) ? LIVE_POLL_MS : false;
}

/** How far along a transfer is, where that can be said at all. */
export interface TransferProgress {
  /** Bytes moved, counted from the start of the file rather than of this attempt. */
  done: number;
  /** The source's size, where the source reported one. */
  total: number | null;
  /** `done / total` in 0..1, or `null` when the total is unknown. */
  ratio: number | null;
}

/**
 * A transfer's progress, or `null` where there is none to show.
 *
 * A queued transfer has moved nothing. A cancelled or failed one stopped
 * somewhere the core does not report, and inventing a bar for it would be
 * inventing a number.
 */
export function progressOf(status: TransferStatus): TransferProgress | null {
  if (status.state === "running") {
    const total = status.total;
    return {
      done: status.done,
      total,
      // Clamped: a server that under-reports a file's size would otherwise
      // produce a bar past its own end.
      ratio: total === null || total <= 0 ? null : Math.min(1, status.done / total),
    };
  }
  if (status.state === "completed") {
    return { done: status.bytes, total: status.bytes, ratio: 1 };
  }
  return null;
}

/**
 * What the transfer decided about continuing an interrupted copy.
 *
 * Composed from the facts rather than from `TransferStart.note`, which is the
 * core's English. This is the pattern `docs/features/i18n.md` calls "sentences
 * the core used to write": the kind is stable and never displayed, the
 * interface renders its own sentence for it, and the core's string stays on the
 * DTO as the fallback for a kind nobody has taught the interface yet.
 */
export type ResumeOutcome =
  | { kind: "continued"; offset: number }
  /**
   * Asked for and refused. `notShorter` is a destination at least as long as
   * the source; `unknownSize` is a source whose size nobody reported. The core
   * refuses in both cases because appending to the wrong file corrupts it
   * silently and re-copying one only costs time.
   */
  | { kind: "declined"; reason: "notShorter" | "unknownSize" };

/**
 * `null` where there is nothing worth saying.
 *
 * Two cases produce it, and both matter. A transfer that never asked to resume
 * has nothing to report. A transfer that asked, was allowed, and found nothing
 * to continue from also has nothing to report — the command surface is explicit
 * that a notice which fires on every first attempt is a notice people learn to
 * ignore, and the one that matters is the refusal.
 */
export function resumeOutcome(status: TransferStatus): ResumeOutcome | null {
  const start = status.start;
  if (start === null || !start.resumeRequested) return null;
  if (start.resumeDeclined) {
    return { kind: "declined", reason: start.total === null ? "unknownSize" : "notShorter" };
  }
  return start.resumeFrom > 0 ? { kind: "continued", offset: start.resumeFrom } : null;
}

/** The counts the queue heading shows. */
export interface QueueSummary {
  live: number;
  finished: number;
  failed: number;
}

export function summarise(statuses: readonly TransferStatus[]): QueueSummary {
  let live = 0;
  let finished = 0;
  let failed = 0;
  for (const status of statuses) {
    if (isLive(status)) live += 1;
    else if (status.state === "completed") finished += 1;
    else if (status.state === "failed") failed += 1;
  }
  return { live, finished, failed };
}

/**
 * The failure a failed transfer carries, in the shape the failure layer takes.
 *
 * Widened to `IpcFailure` rather than rendered here: the sentence and the
 * action labels come from `errors.json` keyed by the code, and a screen that
 * reads the core's English straight into JSX puts English in front of every
 * reader who chose another language.
 */
export function failureOf(status: TransferStatus): IpcFailure | null {
  if (status.state !== "failed") return null;
  return {
    code: status.code,
    message: status.message,
    detail: status.detail,
    actions: status.actions,
  };
}
