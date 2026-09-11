/**
 * The connect progress, expressed only in transitions the interface can see.
 *
 * `docs/architecture/session-pipeline.md` has nine stages, and the design draws
 * them ticking past during a multi-hop connect — because a bare spinner during
 * a three-hop connect tells the user nothing about which hop is slow.
 *
 * What the core actually reports is narrower than nine, and pretending
 * otherwise would be a progress bar that moves on a timer. `session_open`
 * performs resolve, authorise and acquire under one lock and only then emits
 * `opening`; transport, handshake and authenticate happen between `opening`
 * and `ready`, with a host key question the one place inside that span the core
 * announces. So there are four observable phases and this file maps them onto
 * the pipeline's own vocabulary, marking the rest as "still running" rather
 * than inventing a moment for it.
 *
 * Every stage row therefore says something true: a stage that is done was seen
 * to finish, and its elapsed time was measured here between two real events.
 */

/** What the interface has actually observed about a connect attempt. */
export type ConnectPhase =
  /** `session_open` is in flight and has not yet reported a session id. */
  | "preparing"
  /** `opening` arrived: the transport is being built and the host verified. */
  | "connecting"
  /** A host key question is on screen. The handshake is suspended on it. */
  | "verifying"
  /** The host key was answered; the handshake and authentication continue. */
  | "authenticating"
  /** `ready` arrived. */
  | "running"
  /** The attempt or the session failed. */
  | "failed"
  /** The session ended without a failure. */
  | "closed";

export type StageId = "acquire" | "transport" | "handshake" | "authenticate";

export type StageState = "done" | "active" | "suspended" | "pending" | "abandoned";

/**
 * One row of the connect panel: which stage, and how far it got.
 *
 * No copy. What the row says — its label and the pipeline stages its caption
 * names — is in `locales/en/sessions.json` under `connect.stage`, looked up by
 * `id`. Keeping it out of here is what lets this module stay a pure function of
 * the phase, testable without a translation catalogue.
 */
export interface StageRow {
  id: StageId;
  state: StageState;
}

/** The order the rows are drawn in; also the order they complete in. */
export const STAGE_ORDER: readonly StageId[] = ["acquire", "transport", "handshake", "authenticate"];

/**
 * How far each phase has got. The index names the first stage that is *not*
 * finished; everything before it is done.
 *
 * `connecting` sits at `transport` because that is the last thing the core
 * announced. It is not a claim that the handshake has not started — only that
 * the interface has not been told it has, which is why the rows after the
 * active one read as pending rather than as failed.
 */
const REACHED: Record<ConnectPhase, number> = {
  preparing: 0,
  connecting: 1,
  verifying: 2,
  authenticating: 3,
  running: STAGE_ORDER.length,
  failed: -1,
  closed: -1,
};

/**
 * The stage rows for a phase.
 *
 * `failedAt` is the pipeline stage the core named in its failure, so the row
 * that broke is the one marked — the taxonomy's whole point is that the user
 * learns *where* it went wrong.
 */
export function stagesFor(phase: ConnectPhase, failedAt?: string | null): StageRow[] {
  const reached = REACHED[phase];

  if (reached < 0) {
    const broken = failedStage(failedAt ?? null);
    return STAGE_ORDER.map((id, index) => {
      const brokenIndex = broken === null ? -1 : STAGE_ORDER.indexOf(broken);
      const state: StageState =
        brokenIndex < 0
          ? "abandoned"
          : index < brokenIndex
            ? "done"
            : index === brokenIndex
              ? "abandoned"
              : "pending";
      return { id, state };
    });
  }

  return STAGE_ORDER.map((id, index) => {
    const state: StageState =
      index < reached
        ? "done"
        : index === reached
          ? phase === "verifying" && id === "handshake"
            ? "suspended"
            : "active"
          : "pending";
    return { id, state };
  });
}

/**
 * Maps the core's stage name onto the row that stands for it.
 *
 * The core names all nine; four rows carry them, so several map to one. An
 * unrecognised name returns null and no row is singled out, which is better
 * than blaming the wrong one.
 */
export function failedStage(stage: string | null): StageId | null {
  switch (stage) {
    case "resolve":
    case "authorise":
    case "acquire":
      return "acquire";
    case "transport":
      return "transport";
    case "handshake":
      return "handshake";
    case "authenticate":
    case "attach":
      return "authenticate";
    default:
      return null;
  }
}

/** Whether a phase means the attempt is still in flight. */
export function isConnecting(phase: ConnectPhase): boolean {
  return phase === "preparing" || phase === "connecting" || phase === "verifying" || phase === "authenticating";
}
