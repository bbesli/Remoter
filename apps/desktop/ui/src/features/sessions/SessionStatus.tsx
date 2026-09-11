/**
 * The status line for the session in front.
 *
 * The design fills this with live telemetry, and every figure here is one the
 * interface actually measures or the core actually reported. In particular:
 *
 * **"Latency" is echo latency, and it says so.** The core reports no round-trip
 * sample — nothing in `SessionEvent` carries one — so inventing a network
 * figure would be a number with no measurement behind it. What the interface
 * *can* measure is the gap between the last keystroke it sent and the next
 * frame of output that came back, which for an interactive shell is the
 * quantity the user actually feels. It is labelled `echo` for that reason, and
 * the tooltip says what it is.
 *
 * Byte counts are this tab's own, from the moment the terminal was created.
 * The core does not count them in this build — its audit row writes zeroes
 * rather than guesses — so these are the interface's, and they count what
 * crossed the channel rather than what crossed the wire.
 */

import { useEffect, useState } from "react";

import { Icon } from "@/components/Icon";
import { isolate, isolateChain, isolateLtr, useLocale, useT } from "@/i18n";
import type { RecordingPolicy } from "@/lib/ipc";
import { formatBytes, formatSize, formatUptime } from "./format";
import { describeRenderer } from "./renderer";
import type { ConnectPhase } from "./stages";
import type { SessionRecord } from "./store";

import s from "./SessionStatus.module.css";

/**
 * The phase in words, capitalised: this is the head of the bar rather than a
 * fragment inside a label, so it is a different set from `tab.state.*`.
 *
 * A record and not a key built from the phase, so a new phase without a word
 * for it stops the build rather than reaching the status bar as a key.
 */
const STATE_KEYS = {
  preparing: "status.state.preparing",
  connecting: "status.state.connecting",
  verifying: "status.state.verifying",
  authenticating: "status.state.authenticating",
  running: "status.state.running",
  failed: "status.state.failed",
  closed: "status.state.closed",
} as const satisfies Record<ConnectPhase, string>;

/**
 * The resolved recording policy in words.
 *
 * The core's own values are `never`, `on_request` and `always`; the old code
 * printed them with the underscore swapped for a space, which is not a
 * translation strategy — `on_request` is "on request" in English and something
 * else everywhere else.
 */
const RECORDING_KEYS = {
  never: "status.recordingPolicy.never",
  on_request: "status.recordingPolicy.on_request",
  always: "status.recordingPolicy.always",
} as const satisfies Record<RecordingPolicy, string>;

/** Which state token the dot takes. */
function dotState(record: SessionRecord): "connected" | "connecting" | "failed" | "idle" {
  switch (record.phase) {
    case "running":
      return "connected";
    case "failed":
      return "failed";
    case "closed":
      return "idle";
    default:
      return "connecting";
  }
}

export function SessionStatus({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

  // Uptime has to move on an idle session too, and an idle session pushes no
  // metrics. The clock is state rather than a `Date.now()` in the body, which
  // would make the render impure.
  const [now, setNow] = useState(Date.now);

  useEffect(() => {
    if (record.phase !== "running") return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [record.phase]);

  const opened = record.opened;
  const via = opened?.via ?? [];
  const running = record.phase === "running";
  const started = opened?.startedAtMs ?? record.startedAt;
  // Address, username and jump-host chain all come from the vault or the far
  // end. Each is isolated so a right-to-left character in one cannot reorder
  // the bar around it; the chain keeps its own order. See src/i18n/bidi.ts.
  const hopChain = isolateChain(via, tCommon("punctuation.chainSeparator"));

  return (
    <>
      <span className={s.dot} data-state={dotState(record)} aria-hidden="true" />
      <span className={s.state}>{t(STATE_KEYS[record.phase])}</span>

      {record.target !== null && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>{isolateLtr(record.target)}</span>
        </>
      )}

      {opened !== null && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span
            className={s.mono}
            title={t("status.authTitle", { method: isolate(opened.authMethod) })}
          >
            {isolate(opened.username)}
          </span>
        </>
      )}

      {via.length > 0 && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.hops} title={hopChain}>
            <Icon name="shield" size={12} />
            <span className={s.mono}>{hopChain}</span>
          </span>
        </>
      )}

      {running && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono} title={t("status.echoTitle")}>
            {record.metrics.echoMs === null
              ? t("status.echoUnknown")
              : t("status.echo", { milliseconds: record.metrics.echoMs })}
          </span>

          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>
            {t("status.transfer", {
              in: formatBytes(locale, record.metrics.bytesIn),
              out: formatBytes(locale, record.metrics.bytesOut),
            })}
          </span>

          {record.metrics.cols > 0 && (
            <>
              <span className={s.sep} aria-hidden="true">
                ·
              </span>
              <span className={s.mono}>
                {formatSize(locale, record.metrics.cols, record.metrics.rows)}
              </span>
            </>
          )}

          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono} title={t("status.uptimeTitle")}>
            {formatUptime(t, locale, now - started)}
          </span>
        </>
      )}

      <span className={s.spacer} />

      {record.renderer !== null && (
        <span className={s.note} title={t("status.rendererTitle")}>
          {describeRenderer(t, record.renderer)}
        </span>
      )}

      {opened !== null && opened.recording !== "never" && (
        <span className={s.recording} title={t("status.recordingTitle")}>
          {t("status.recording", { policy: t(RECORDING_KEYS[opened.recording]) })}
        </span>
      )}

      {running && (
        <span className={s.verified} title={t("status.hostKeyTitle")}>
          <Icon name="shield" size={12} />
          {t("status.hostKeyVerified")}
        </span>
      )}
    </>
  );
}
