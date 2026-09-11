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
import { isolate, isolateChain, isolateLtr, useLocale, useT } from "@/i18n";
import type { SessionRecord } from "./store";
import { formatElapsed } from "./format";
import { stagesFor, STAGE_ORDER, type StageId } from "./stages";

import s from "./SessionSurface.module.css";

/**
 * What each stage row says, and which pipeline stages its caption names.
 *
 * A record rather than a key assembled from `row.id`: a stage added to
 * `STAGE_ORDER` without copy for it then fails to compile, instead of drawing a
 * row with a humanised key where its label should be.
 */
const STAGE_KEYS = {
  acquire: { label: "connect.stage.acquire.label", pipeline: "connect.stage.acquire.pipeline" },
  transport: {
    label: "connect.stage.transport.label",
    pipeline: "connect.stage.transport.pipeline",
  },
  handshake: {
    label: "connect.stage.handshake.label",
    pipeline: "connect.stage.handshake.pipeline",
  },
  authenticate: {
    label: "connect.stage.authenticate.label",
    pipeline: "connect.stage.authenticate.pipeline",
  },
} as const satisfies Record<StageId, { label: string; pipeline: string }>;

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
  const t = useT("sessions");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

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
  const title = t("connect.title", { name: isolate(record.name) });

  return (
    <div className={s.overlay}>
      <div className={s.panel} role="status" aria-live="polite">
        <div className={s.panelHead}>
          <Spinner size={18} label={title} />
          <div className={s.panelHeadings}>
            <p className={s.panelTitle}>{title}</p>
            {record.target !== null && (
              // One message rather than a target with "via" and a chain glued
              // on after it: languages do not agree on where "via" goes, and
              // an address is left-to-right whatever characters are in it.
              <p className={s.panelTarget}>
                {via.length === 0
                  ? isolateLtr(record.target)
                  : t("connect.route", {
                      target: isolateLtr(record.target),
                      hops: isolateChain(via, tCommon("punctuation.chainSeparator")),
                    })}
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
                    <Spinner size={13} label={t(STAGE_KEYS[row.id].label)} />
                  ) : row.state === "suspended" ? (
                    <Icon name="alert" size={13} />
                  ) : (
                    <span className={s.stagePending} />
                  )}
                </span>
                <span className={s.stageLabel}>
                  {t(STAGE_KEYS[row.id].label)}
                  <span className={s.stagePipeline}>{t(STAGE_KEYS[row.id].pipeline)}</span>
                </span>
                <span className={s.stageTime}>
                  {row.state === "suspended"
                    ? t("connect.waiting")
                    : row.state === "pending"
                      ? ""
                      : elapsed === null
                        ? t("connect.running")
                        : formatElapsed(t, locale, elapsed)}
                </span>
              </li>
            );
          })}
        </ol>

        {/* Told before the session opens, never after — pipeline stage 2. */}
        {record.opened?.recording === "always" && (
          <p className={s.recording}>{t("connect.recordingNotice")}</p>
        )}

        <p className={s.panelNote}>{t("connect.observedNote")}</p>

        <div className={s.panelActions}>
          <Button variant="secondary" size="sm" onClick={onCancel} disabled={cancelling}>
            {cancelling ? t("connect.cancelling") : tCommon("action.cancel")}
          </Button>
        </div>
      </div>
    </div>
  );
}
