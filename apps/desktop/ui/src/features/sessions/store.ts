/**
 * What the interface knows about the sessions it opened.
 *
 * This is UI state, not server state, so it is Zustand rather than TanStack
 * Query (CLAUDE.md §6). A session's authority is the core — `session_list`
 * will always agree with it — but a *tab* is the interface's own object: it
 * exists before the core has a session id for it, it survives the session
 * ending so the failure can be read, and it is what the user closes.
 *
 * The tab id is therefore generated here and never changes. The core's
 * `sessionId` arrives with the `opening` event and is attached to the tab;
 * everything that talks to the core waits for it. That separation is what
 * makes "cancel this connect" work: the tab exists to be cancelled before the
 * core has named the session.
 */

import { create } from "zustand";

import type {
  CloseReason,
  HostKeyPrompt,
  IpcFailure,
  SessionFailure,
  SessionOpened,
  SessionPrompt,
} from "@/lib/ipc";
import type { ConnectPhase, StageId } from "./stages";
import type { RendererReport } from "./renderer";
import type { ScaleMode } from "./scaling";

/** A warning the session raised, kept so the panel can show more than the last. */
export interface SessionWarning {
  /** `unencrypted_transport` | `weak_algorithm` | `recording_started` | … */
  kind: string;
  detail: string | null;
  at: number;
}

/**
 * How a graphical session is fitted into its tab.
 *
 * User intent rather than presenter state, so it lives here: it has to survive
 * a tab switch, a reconnect and a server-driven resize, none of which the
 * canvas itself outlives in a meaningful way.
 */
export interface ScaleChoice {
  mode: ScaleMode;
  /** The magnification `zoom` uses. Integer — see `scaling.ts`. */
  zoom: number;
}

/** The live counters a session's surfaces read. */
export interface SessionMetrics {
  bytesIn: number;
  bytesOut: number;
  cols: number;
  rows: number;
  /** Round trip from the last keystroke to the next output frame, in ms. */
  echoMs: number | null;
}

export interface SessionRecord {
  /** Stable for the life of the tab. Not the core's id. */
  tabId: string;
  nodeId: string;
  /** The connection's name as the user called it, for the tab before `ready`. */
  name: string;
  /** The connection's colour from the tree, so the tab carries it. */
  colour: string | null;
  protocol: string | null;
  /** `host:port` as configured. Replaced by the core's own once `ready`. */
  target: string | null;

  /** The core's id, once it has one. Null while `session_open` is in flight. */
  sessionId: number | null;
  phase: ConnectPhase;
  /** Everything the core reported on success. */
  opened: SessionOpened | null;
  /** Why it failed, in the core's own words. Never replaced with a house one. */
  failure: IpcFailure | null;
  /** Which pipeline stage the core blamed, when it named one. */
  failedStage: string | null;
  /** Whether an automatic retry could plausibly work. False for a changed key. */
  retryable: boolean;
  closeReason: CloseReason | null;

  /** The suspended host key question, if one is on screen. */
  hostKey: HostKeyPrompt | null;
  /** Set while a decision is being sent. */
  hostKeyBusy: boolean;
  /** A refused decision — including `accept` on a changed key. */
  hostKeyError: IpcFailure | null;

  /**
   * Anything else the server asked for. This build has no command to answer
   * one, so it is shown and named rather than silently dropped.
   */
  prompt: SessionPrompt | null;

  /**
   * Why the last keystroke did not reach the far end.
   *
   * Almost always the vault locking under a `freeze_input` policy. A terminal
   * that stops accepting input without saying why reads as a hung session, and
   * the user's next move is to kill a tab that is in fact still connected.
   */
  inputError: IpcFailure | null;

  warnings: SessionWarning[];
  metrics: SessionMetrics;
  renderer: RendererReport | null;

  /**
   * How a graphical session is scaled. Meaningless for a terminal tab, which
   * is why nothing reads it there rather than why it is absent: one record
   * shape keeps `patch` honest.
   */
  scale: ScaleChoice;
  /**
   * Whether the connection is configured to send nothing to the remote host.
   *
   * `settings.view_only`, resolved from the vault when a graphical session
   * opens. `null` means it has not been read — not that it is false. The
   * difference matters: a surface that says "view only" when it does not know
   * is as wrong as one that stays silent when it does.
   */
  viewOnly: boolean | null;

  /** Client clock. Uptime runs from here until the core reports its own. */
  startedAt: number;
  /** When each stage was seen to finish, measured between real events. */
  stageAt: Partial<Record<StageId, number>>;
}

interface SessionStore {
  /** Tabs in the order they were opened. */
  order: string[];
  byId: Record<string, SessionRecord>;
  activeTabId: string | null;

  open: (seed: {
    tabId: string;
    nodeId: string;
    name: string;
    colour: string | null;
    protocol: string | null;
    target: string | null;
  }) => void;
  patch: (tabId: string, patch: Partial<SessionRecord>) => void;
  /** Records that a stage finished, at the moment it was observed to. */
  markStage: (tabId: string, stage: StageId) => void;
  /**
   * Puts a tab back to the start of a connect attempt.
   *
   * The tab, its terminal and its scrollback stay — the design's reconnect
   * notice promises "Scrollback is kept", and a reconnect that cleared the
   * screen would throw away the output the user is reconnecting to look at.
   */
  restart: (tabId: string) => void;
  addWarning: (tabId: string, warning: SessionWarning) => void;
  setMetrics: (tabId: string, metrics: SessionMetrics) => void;
  /** How a graphical session is fitted into its tab. */
  setScale: (tabId: string, scale: ScaleChoice) => void;
  remove: (tabId: string) => void;
  activate: (tabId: string | null) => void;
}

/**
 * Tab ids are opaque and unique.
 *
 * `crypto.randomUUID` is not universally available in every WebView this ships
 * to, so a counter with a timestamp does the job — this is a DOM key, not a
 * security value, and saying so here stops someone "upgrading" it later.
 */
let counter = 0;
export function newTabId(): string {
  counter += 1;
  return `t${String(Date.now())}-${String(counter)}`;
}

function seedRecord(seed: {
  tabId: string;
  nodeId: string;
  name: string;
  colour: string | null;
  protocol: string | null;
  target: string | null;
}): SessionRecord {
  return {
    ...seed,
    sessionId: null,
    phase: "preparing",
    opened: null,
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    inputError: null,
    warnings: [],
    metrics: { bytesIn: 0, bytesOut: 0, cols: 0, rows: 0, echoMs: null },
    renderer: null,
    // `fit` until the session reports whether it is resizable, at which point
    // `manager.ts` moves a resizable one to `smart`. Seeding `smart` here would
    // be a promise made before anything had said it could be kept.
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
  };
}

export const useSessions = create<SessionStore>((set) => ({
  order: [],
  byId: {},
  activeTabId: null,

  open: (seed) =>
    set((s) => ({
      order: [...s.order, seed.tabId],
      byId: { ...s.byId, [seed.tabId]: seedRecord(seed) },
      activeTabId: seed.tabId,
    })),

  patch: (tabId, patch) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined) return {};
      return { byId: { ...s.byId, [tabId]: { ...current, ...patch } } };
    }),

  markStage: (tabId, stage) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined || current.stageAt[stage] !== undefined) return {};
      return {
        byId: {
          ...s.byId,
          [tabId]: { ...current, stageAt: { ...current.stageAt, [stage]: Date.now() } },
        },
      };
    }),

  restart: (tabId) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined) return {};
      const fresh = seedRecord({
        tabId,
        nodeId: current.nodeId,
        name: current.name,
        colour: current.colour,
        protocol: current.protocol,
        target: current.target,
      });
      // The renderer was probed once and does not change between attempts, and
      // the scale is the user's choice about this tab rather than about the
      // session that just ended — a reconnect that reset it to Fit would undo
      // a zoom the user set precisely because they were reading something.
      return {
        byId: {
          ...s.byId,
          [tabId]: { ...fresh, renderer: current.renderer, scale: current.scale },
        },
      };
    }),

  addWarning: (tabId, warning) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined) return {};
      return {
        byId: { ...s.byId, [tabId]: { ...current, warnings: [...current.warnings, warning] } },
      };
    }),

  setMetrics: (tabId, metrics) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined) return {};
      return { byId: { ...s.byId, [tabId]: { ...current, metrics } } };
    }),

  setScale: (tabId, scale) =>
    set((s) => {
      const current = s.byId[tabId];
      if (current === undefined) return {};
      return { byId: { ...s.byId, [tabId]: { ...current, scale } } };
    }),

  remove: (tabId) =>
    set((s) => {
      if (s.byId[tabId] === undefined) return {};
      const order = s.order.filter((id) => id !== tabId);
      const byId = { ...s.byId };
      delete byId[tabId];
      // Focus moves to the neighbour rather than to nothing: closing the last
      // of several tabs should not empty the session area.
      const closedIndex = s.order.indexOf(tabId);
      const next = order[Math.min(closedIndex, order.length - 1)] ?? null;
      return {
        order,
        byId,
        activeTabId: s.activeTabId === tabId ? next : s.activeTabId,
      };
    }),

  activate: (activeTabId) => set({ activeTabId }),
}));

/** The failure a `Closed` message carried, flattened to the shape the notice takes. */
export function failureFromClose(failure: SessionFailure): IpcFailure {
  return {
    code: failure.code,
    message: failure.message,
    detail: failure.detail,
    actions: failure.actions,
  };
}
