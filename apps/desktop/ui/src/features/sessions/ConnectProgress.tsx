/**
 * What is happening during a connect, stage by stage.
 *
 * A bare spinner is acceptable for an operation that takes 200 ms. A connect
 * through two bastions takes seconds and can stall at any one of them, and the
 * only useful question — *which hop?* — is exactly what a spinner cannot
 * answer. The design draws this panel for that reason.
 *
 * Every row here is observed, not simulated. See stages.ts: the core reports
 * four transitions and this shows four, with the elapsed time measured between
 * the events that produced them. A row that is still running says so; it does
 * not creep forwards on a timer.
 */

import { useEffect, useState } from "react";

import { Button } from "@/components/Button";
import { Spinner } from "@/components/Spinner";
import { Icon } from "@/components/Icon";
import type { SessionRecord } from "./store";
import { formatElapsed } from "./format";
import { stagesFor, STAGE_ORDER, type StageId } from "./stages";

import s from "./SessionSurface.module.css";

const TEXT = {
  connecting: (name: string) => `Connecting to ${name}`,
  via: "via",
  waiting: "waiting for your decision",
  running: "still running",
  cancel: "Cancel",
  cancelling: "Cancelling…",
  // Stated before the session opens, which is where a recording notice
  // belongs — but this build has no recorder, and a notice that promises
  // one is worse than no notice: a user who reads it believes there is a
  // recording to go back to. It says what is stored and what is not.
  recorded:
    "Recording is set to always for this connection. This build has no recorder, so nothing is written yet.",
  observed:
    "Timings are measured between the transitions the core reports; stages it groups together are shown together.",
} as const;

/** How often the running stage's elapsed time is redrawn. */
const TICK_MS = 500;

interface ConnectProgressProps {
  record: SessionRecord;
  onCancel: () => void;
  cancelling: boolean;
}

/**
 * When a stage started: the moment the one before it finished, or the moment
 * the attempt did. Elapsed is then a real interval rather than a guess.
 */
function startedAt(record: SessionRecord, stage: StageId): number {
  const index = STAGE_ORDER.indexOf(stage);
  for (let i = index - 1; i >= 0; i -= 1) {
    const previous = STAGE_ORDER[i];
    const at = previous === undefined ? undefined : record.stageAt[previous];
    if (at !== undefined) return at;
  }
  return record.startedAt;
}

export function ConnectProgress({ record, onCancel, cancelling }: ConnectProgressProps) {
  // The clock is state rather than a `Date.now()` in the body: reading a
  // moving value during render makes the render impure, and React is entitled
  // to call it twice. One interval for the whole panel beats a timer per row.
  const [now, setNow] = useState(Date.now);

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), TICK_MS);
    return () => window.clearInterval(id);
  }, []);

  const rows = stagesFor(record.phase);
  const via = record.opened?.via ?? [];

  return (
    <div className={s.overlay}>
      <div className={s.panel} role="status" aria-live="polite">
        <div className={s.panelHead}>
          <Spinner size={18} label={TEXT.connecting(record.name)} />
          <div className={s.panelHeadings}>
            <p className={s.panelTitle}>{TEXT.connecting(record.name)}</p>
            {record.target !== null && (
              <p className={s.panelTarget}>
                {record.target}
                {via.length > 0 && (
                  <>
                    {" · "}
                    {TEXT.via} {via.join(" → ")}
                  </>
                )}
              </p>
            )}
          </div>
        </div>

        <ol className={s.stages}>
          {rows.map((row) => {
            const finished = record.stageAt[row.id];
            const elapsed =
              finished === undefined
                ? row.state === "active" || row.state === "suspended"
                  ? now - startedAt(record, row.id)
                  : null
                : finished - startedAt(record, row.id);

            return (
              <li key={row.id} className={s.stage} data-state={row.state}>
                <span className={s.stageGlyph} aria-hidden="true">
                  {row.state === "done" ? (
                    <Icon name="check" size={13} />
                  ) : row.state === "active" ? (
                    <Spinner size={13} label={row.label} />
                  ) : row.state === "suspended" ? (
                    <Icon name="alert" size={13} />
                  ) : (
                    <span className={s.stagePending} />
                  )}
                </span>
                <span className={s.stageLabel}>
                  {row.label}
                  <span className={s.stagePipeline}>{row.pipeline}</span>
                </span>
                <span className={s.stageTime}>
                  {row.state === "suspended"
                    ? TEXT.waiting
                    : row.state === "pending"
                      ? ""
                      : elapsed === null
                        ? TEXT.running
                        : formatElapsed(elapsed)}
                </span>
              </li>
            );
          })}
        </ol>

        {/* Told before the session opens, never after — pipeline stage 2. */}
        {record.opened?.recording === "always" && <p className={s.recording}>{TEXT.recorded}</p>}

        <p className={s.panelNote}>{TEXT.observed}</p>

        <div className={s.panelActions}>
          <Button variant="secondary" size="sm" onClick={onCancel} disabled={cancelling}>
            {cancelling ? TEXT.cancelling : TEXT.cancel}
          </Button>
        </div>
      </div>
    </div>
  );
}
