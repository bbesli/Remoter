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
import { formatBytes, formatSize, formatUptime } from "./format";
import { describeRenderer } from "./renderer";
import type { SessionRecord } from "./store";

import s from "./SessionStatus.module.css";

const TEXT = {
  state: {
    preparing: "Connecting",
    connecting: "Connecting",
    verifying: "Waiting on a host key decision",
    authenticating: "Authenticating",
    running: "Connected",
    failed: "Failed",
    closed: "Ended",
  } as const,
  echo: "echo",
  echoTitle: "Time from the last keystroke sent to the next frame of output. Not a network round trip: the core reports no latency sample.",
  hostKeyVerified: "Host key verified",
  hostKeyTitle: "The handshake completed against a key this vault trusts.",
  recordingPolicy: (policy: string) => `recording policy: ${policy.replace(/_/g, " ")}`,
  recordingTitle:
    "The connection's resolved recording policy. This build has no recorder, so nothing is being written.",
  rendererTitle:
    "Which renderer the terminal got. WebKitGTK can hand out a software-rasterised WebGL context, so this is the checked answer rather than the assumed one.",
  uptime: "uptime",
  auth: "authenticated by",
} as const;

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

  return (
    <>
      <span className={s.dot} data-state={dotState(record)} aria-hidden="true" />
      <span className={s.state}>{TEXT.state[record.phase]}</span>

      {record.target !== null && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>{record.target}</span>
        </>
      )}

      {opened !== null && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono} title={`${TEXT.auth} ${opened.authMethod}`}>
            {opened.username}
          </span>
        </>
      )}

      {via.length > 0 && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.hops} title={via.join(" → ")}>
            <Icon name="shield" size={12} />
            <span className={s.mono}>{via.join(" → ")}</span>
          </span>
        </>
      )}

      {running && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono} title={TEXT.echoTitle}>
            {record.metrics.echoMs === null
              ? `— ${TEXT.echo}`
              : `${String(record.metrics.echoMs)} ms ${TEXT.echo}`}
          </span>

          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>
            ↓ {formatBytes(record.metrics.bytesIn)} ↑ {formatBytes(record.metrics.bytesOut)}
          </span>

          {record.metrics.cols > 0 && (
            <>
              <span className={s.sep} aria-hidden="true">
                ·
              </span>
              <span className={s.mono}>{formatSize(record.metrics.cols, record.metrics.rows)}</span>
            </>
          )}

          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono} title={TEXT.uptime}>
            {formatUptime(now - started)}
          </span>
        </>
      )}

      <span className={s.spacer} />

      {record.renderer !== null && (
        <span className={s.note} title={TEXT.rendererTitle}>
          {describeRenderer(record.renderer)}
        </span>
      )}

      {opened !== null && opened.recording !== "never" && (
        <span className={s.recording} title={TEXT.recordingTitle}>
          {TEXT.recordingPolicy(opened.recording)}
        </span>
      )}

      {running && (
        <span className={s.verified} title={TEXT.hostKeyTitle}>
          <Icon name="shield" size={12} />
          {TEXT.hostKeyVerified}
        </span>
      )}
    </>
  );
}
