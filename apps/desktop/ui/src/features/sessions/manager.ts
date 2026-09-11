/**
 * Opening, driving and closing a session.
 *
 * These are plain functions rather than a hook because the three places that
 * open a session — a double-click in the tree, Enter in the palette, the
 * context menu — are three different components, and a session must not depend
 * on which of them is mounted. They read and write the Zustand store directly
 * (`useSessions.getState()`), which is the supported way to drive it from
 * outside React.
 *
 * The event channel is subscribed **before** `session_open` is called, because
 * a host key question arrives while that call is still outstanding — that is
 * what "the pipeline suspends" means in `docs/architecture/session-pipeline.md`
 * §5. A channel wired up after the await would miss it and the connect would
 * hang with nothing on screen.
 */

import {
  asFailure,
  ipc,
  sessionChannel,
  type HostKeyDecision,
  type SessionMessage,
  type SessionOpened,
  type TreeNode,
} from "@/lib/ipc";
import { i18n } from "@/i18n";

import { failureFromClose, newTabId, useSessions } from "./store";
import {
  disposeTerminal,
  ensureTerminal,
  focusTerminal,
  rendererFor,
  sizeOf,
  writeNotice,
  writeToTerminal,
} from "./terminals";
import {
  disposeSurface,
  ensureSurface,
  hasSurface,
  resizeSurface,
  writeFrame,
} from "./surfaces";
import { defaultScaleMode, smartResizeRequest, type Size } from "./scaling";

/**
 * The vault setting that makes a graphical session send nothing.
 *
 * `node_resolve` returns every protocol setting as a resolved field named
 * `settings.<key>`, so this is the key as the VNC adapter declares it
 * (`crates/remoter-proto-vnc/src/protocol.rs`, `SETTING_VIEW_ONLY`).
 */
const VIEW_ONLY_FIELD = "settings.view_only";

/** `host:port` as configured, for the tab before the core reports its own. */
function targetOf(node: Pick<TreeNode, "host" | "port">): string | null {
  if (node.host === null || node.host === "") return null;
  return node.port === null ? node.host : `${node.host}:${String(node.port)}`;
}

/** Whether a node can have a session opened against it at all. */
export function isConnectable(node: TreeNode | undefined | null): node is TreeNode {
  return node !== undefined && node !== null && node.kind === "connection";
}

/**
 * Opens a session for a node and returns the tab it opened.
 *
 * Idempotent per node only by the user's choice: opening the same connection
 * twice gives two tabs, which is what a jump box or a pair of shells on one
 * host needs.
 */
export function openSession(node: TreeNode): string {
  const tabId = newTabId();
  useSessions.getState().open({
    tabId,
    nodeId: node.id,
    name: node.name,
    colour: node.colour,
    protocol: node.protocol,
    target: targetOf(node),
  });
  startAttempt(tabId);
  return tabId;
}

/** Re-runs the connect for an existing tab, keeping its terminal and scrollback. */
export function reconnect(tabId: string): void {
  const record = useSessions.getState().byId[tabId];
  if (record === undefined) return;

  // A session that is still registered has to be told to go before another is
  // opened on the same tab, or the core keeps a task and a socket for a tab
  // nothing points at any more.
  if (record.sessionId !== null) {
    void ipc.closeSession(record.sessionId).catch(() => undefined);
  }
  // A reconnect may land on a different desktop size, or on a server that is
  // not resizable this time. The surface is rebuilt from the new session's
  // first keyframe rather than carried over half-valid.
  disposeSurface(tabId);
  useSessions.getState().restart(tabId);
  // The scrollback is kept — the design's reconnect notice promises it — so
  // the terminal needs a mark saying where the old session stopped. Otherwise
  // the new session's first output looks like a continuation of the old one.
  // No component around this, so the instance is asked directly rather than
  // through `useT`. The rules and the line breaks are decoration and stay
  // here; the word is copy and comes from the catalogue.
  const notice = i18n().t("sessions:surface.reconnectNotice");
  writeNotice(tabId, `\r\n── ${notice} ──\r\n`);
  startAttempt(tabId);
}

/**
 * Runs one connect attempt on a tab that already exists in the store.
 *
 * Everything after this point is driven by the channel: the promise's only job
 * is to catch a failure raised before the session was ever registered, which
 * is the one case the channel cannot report because there is no channel yet.
 */
function startAttempt(tabId: string): void {
  const store = useSessions.getState();
  const record = store.byId[tabId];
  if (record === undefined) return;

  ensureTerminal(tabId, {
    onInput: (bytes) => {
      const id = useSessions.getState().byId[tabId]?.sessionId ?? null;
      // Keystrokes before the shell is open have nowhere to go. Dropping them
      // is right: the far end has no PTY yet, so buffering them would replay a
      // password prompt's worth of typing into a shell that just opened.
      if (id === null) return;
      void ipc
        .sendInput(id, bytes)
        .then(() => {
          if (useSessions.getState().byId[tabId]?.inputError !== null) {
            useSessions.getState().patch(tabId, { inputError: null });
          }
        })
        .catch((error: unknown) => {
          useSessions.getState().patch(tabId, { inputError: asFailure(error) });
        });
    },
    onResize: (cols, rows) => {
      const id = useSessions.getState().byId[tabId]?.sessionId ?? null;
      if (id === null) return;
      // A resize the far end refuses is not worth interrupting the user for;
      // the next one supersedes it, and the terminal is already the right size
      // locally either way.
      void ipc.resizeSession(id, cols, rows).catch(() => undefined);
    },
    onMetrics: (metrics) => {
      useSessions.getState().setMetrics(tabId, metrics);
    },
  });
  useSessions.getState().patch(tabId, { renderer: rendererFor(tabId) });

  const channel = sessionChannel({
    // One channel, two decoders. `SessionEvent::Data` carries terminal bytes
    // *or* an encoded framebuffer update, and which it is follows from the
    // session's kind rather than from anything in the bytes — no sniffing.
    //
    // There is no window in which this can pick wrongly: a framebuffer surface
    // is created synchronously when `ready` names the kind, and the adapters
    // emit `Ready` before their first frame on a channel that delivers in
    // order.
    onData: (bytes) => {
      if (hasSurface(tabId)) writeFrame(tabId, bytes);
      else writeToTerminal(tabId, bytes);
    },
    onMessage: (message) => handleMessage(tabId, message),
  });

  void ipc
    .openSession(record.nodeId, channel)
    .then((opened) => onReady(tabId, opened))
    .catch((error: unknown) => {
      const current = useSessions.getState().byId[tabId];
      // A `closed` message may already have carried the real failure. The
      // command's rejection then repeats it, and the first one is the one that
      // named the stage.
      if (current === undefined || current.failure !== null) return;
      useSessions.getState().patch(tabId, {
        phase: "failed",
        failure: asFailure(error),
        hostKey: null,
      });
    });
}

/** Applies the `ready` state, from whichever of the two paths reports it first. */
function onReady(tabId: string, opened: SessionOpened): void {
  const store = useSessions.getState();
  const record = store.byId[tabId];
  if (record === undefined || record.phase === "running") return;

  store.markStage(tabId, "acquire");
  store.markStage(tabId, "transport");
  store.markStage(tabId, "handshake");
  store.markStage(tabId, "authenticate");
  store.patch(tabId, {
    phase: "running",
    sessionId: opened.sessionId,
    opened,
    target: opened.target,
    hostKey: null,
    hostKeyError: null,
    prompt: null,
    failure: null,
  });

  if (opened.capabilities.kind === "framebuffer") {
    startFramebuffer(tabId, opened);
    return;
  }

  // The PTY was opened at the core's default size. The tab knows the real one,
  // and a terminal told the wrong width draws wrongly rather than safely.
  const size = sizeOf(tabId);
  if (size !== null) {
    void ipc.resizeSession(opened.sessionId, size.cols, size.rows).catch(() => undefined);
  }
  if (useSessions.getState().activeTabId === tabId) focusTerminal(tabId);
}

/**
 * Turns a tab into a graphical one, at the moment the core names its kind.
 *
 * The terminal that was created speculatively at the start of the attempt goes
 * here. It was never opened — nothing mounted it — so it holds no WebGL
 * context and no scrollback, but it does hold an xterm instance, and a tab
 * showing a remote desktop has no use for one.
 */
function startFramebuffer(tabId: string, opened: SessionOpened): void {
  disposeTerminal(tabId);
  ensureSurface(tabId, {
    onMetrics: (metrics) => {
      const current = useSessions.getState().byId[tabId];
      if (current === undefined) return;
      // `cols` and `rows` are pixels for a graphical session, which is what the
      // status bar's size field already shows correctly: 1920x1080 reads the
      // same way 80x24 does.
      useSessions.getState().setMetrics(tabId, {
        ...current.metrics,
        bytesIn: metrics.bytesIn,
        cols: metrics.width,
        rows: metrics.height,
      });
    },
  });

  useSessions.getState().patch(tabId, {
    // rendering.md makes smart resize the default where it is supported, and
    // `capabilities.resizable` is the adapter's report of whether the channel
    // that performs it is actually open — not a guess from the protocol name.
    scale: { mode: defaultScaleMode(opened.capabilities.resizable), zoom: 2 },
    // The renderer probe belongs to the terminal that was just disposed of.
    renderer: null,
  });

  void readViewOnly(tabId);
}

/**
 * Reads whether this connection is configured to send nothing.
 *
 * A separate call because `SessionOpened` does not carry protocol settings;
 * `node_resolve` is where an inherited `view_only` resolves, with the folder it
 * came from. A failure leaves the flag `null` — unknown, and said as unknown —
 * rather than defaulting to "not view only", which would be the interface
 * asserting something it had failed to read.
 */
async function readViewOnly(tabId: string): Promise<void> {
  const record = useSessions.getState().byId[tabId];
  if (record === undefined) return;
  try {
    const resolved = await ipc.resolveNode(record.nodeId);
    const field = resolved.fields.find((entry) => entry.field === VIEW_ONLY_FIELD);
    if (field === undefined) {
      // The protocol has no such setting — RDP does not — so the session is not
      // view-only. That is a read, not a default.
      useSessions.getState().patch(tabId, { viewOnly: false });
      return;
    }
    useSessions.getState().patch(tabId, { viewOnly: field.value === "true" });
  } catch {
    // Left unknown on purpose. See the doc comment.
  }
}

/**
 * Asks a resizable server to make its desktop the size of the tab.
 *
 * This is "smart resize" in `docs/architecture/rendering.md`, and it is the one
 * thing the surface's scaling controls can do to the far end. `session_resize`
 * carries pixels for a graphical session — MS-RDPEDISP for RDP, `SetDesktopSize`
 * for VNC — so the same command the terminal uses for columns and rows does
 * this without a second one.
 *
 * A refusal is not reported here: the adapter raises a warning the surface
 * already shows (`rdp.display_control_unavailable`), and the next request would
 * only repeat it.
 */
export function requestDesktopSize(tabId: string, viewport: Size, devicePixelRatio: number): void {
  const record = useSessions.getState().byId[tabId];
  if (record === undefined || record.sessionId === null) return;
  if (record.opened?.capabilities.resizable !== true) return;
  const wanted = smartResizeRequest(viewport, devicePixelRatio);
  if (wanted === null) return;
  void ipc.resizeSession(record.sessionId, wanted.width, wanted.height).catch(() => undefined);
}

/** Everything the core says about a session while it is alive. */
function handleMessage(tabId: string, message: SessionMessage): void {
  const store = useSessions.getState();
  const record = store.byId[tabId];
  if (record === undefined) return;

  switch (message.event) {
    case "opening":
      // Stages 1 to 3 are done: the core performed them under one lock and
      // only then registered the session. This is the first moment the tab can
      // be cancelled, because it is the first moment it has an id.
      store.markStage(tabId, "acquire");
      store.patch(tabId, {
        sessionId: message.sessionId,
        phase: record.phase === "preparing" ? "connecting" : record.phase,
      });
      return;

    case "ready": {
      const { event: _event, ...opened } = message;
      onReady(tabId, opened);
      return;
    }

    case "hostKey":
      // The handshake reached the far end and is now suspended on a decision.
      store.markStage(tabId, "transport");
      store.patch(tabId, {
        phase: "verifying",
        hostKey: {
          promptId: message.promptId,
          host: message.host,
          algorithm: message.algorithm,
          fingerprint: message.fingerprint,
          randomart: message.randomart,
          status: message.status,
          previouslyTrusted: message.previouslyTrusted,
          confirmationLen: message.confirmationLen,
        },
        hostKeyError: null,
      });
      return;

    case "prompt":
      // There is no command in this build that answers a password, passphrase
      // or keyboard-interactive question. Saying so beats a dialog whose
      // answer would go nowhere.
      store.patch(tabId, {
        prompt: { promptId: message.promptId, kind: message.kind, text: message.text, echo: message.echo },
      });
      return;

    case "resized":
      // The far end changed the display size on its own — a `resize` in a
      // multiplexer, a server-driven change, or the Deactivate All that answers
      // a smart-resize request. The tab follows.
      //
      // For a graphical session this has to reach the surface before the
      // pixels for the new size do, or the first frame of it is cropped to the
      // old backing store.
      resizeSurface(tabId, message.width, message.height);
      store.setMetrics(tabId, {
        ...record.metrics,
        cols: message.width,
        rows: message.height,
      });
      return;

    case "warning":
      store.addWarning(tabId, { kind: message.kind, detail: message.detail, at: Date.now() });
      return;

    case "progress":
      // Nothing in an SSH terminal session reports progress yet; when SFTP
      // does, it lands here rather than in a second channel.
      return;

    case "clipboardOffer":
      // Capability-gated, and SSH declares no clipboard. Recorded as nothing
      // rather than acted on.
      return;

    case "closed": {
      const failure = message.failure;
      store.patch(tabId, {
        phase: failure === null ? "closed" : "failed",
        closeReason: message.reason,
        failure: failure === null ? null : failureFromClose(failure),
        failedStage: failure?.stage ?? null,
        retryable: failure?.retryable ?? false,
        hostKey: null,
        prompt: null,
        // The core has deregistered it; the id would only be refused.
        sessionId: null,
      });
      return;
    }

    default:
      return;
  }
}

/**
 * Answers a suspended host key question.
 *
 * The three decisions travel as they came from the core: `accept` for a first
 * use, `replace` with the typed confirmation for a changed key, `reject` for
 * either. Nothing here turns one into another — the core refuses `accept` on a
 * changed key, and the refusal is shown rather than worked around.
 */
export async function decideHostKey(tabId: string, decision: HostKeyDecision): Promise<void> {
  const store = useSessions.getState();
  const record = store.byId[tabId];
  if (record === undefined || record.sessionId === null) return;

  store.patch(tabId, { hostKeyBusy: true, hostKeyError: null });
  try {
    await ipc.decideHostKey(record.sessionId, decision);
    useSessions.getState().patch(tabId, {
      hostKeyBusy: false,
      hostKey: null,
      // Rejecting ends the session; the `closed` message will say so. Accepting
      // hands the handshake back its answer, so the next observable stage is
      // authentication.
      phase: decision.decision === "reject" ? record.phase : "authenticating",
    });
    if (decision.decision !== "reject") {
      useSessions.getState().markStage(tabId, "handshake");
    }
  } catch (error) {
    useSessions.getState().patch(tabId, { hostKeyBusy: false, hostKeyError: asFailure(error) });
  }
}

/**
 * Closes a session and removes its tab.
 *
 * The core's close is awaited: it returns once sockets are shut, buffers
 * dropped and cached secrets zeroized, and a tab that vanished before that
 * would be telling the user something had finished which had not.
 */
export async function closeTab(tabId: string): Promise<void> {
  const record = useSessions.getState().byId[tabId];
  if (record === undefined) return;

  if (record.sessionId !== null) {
    // The record is left alone while the close runs. Marking it "ended" here
    // would raise the ended-session panel over a terminal that is about to
    // disappear; the tab's own close control already shows the wait.
    try {
      await ipc.closeSession(record.sessionId);
    } catch {
      // Already gone — the server hung up while the click was in flight. The
      // tab still goes.
    }
  }
  disposeTerminal(tabId);
  disposeSurface(tabId);
  useSessions.getState().remove(tabId);
}

/** Cancels an attempt that has not finished connecting. */
export async function cancelConnect(tabId: string): Promise<void> {
  await closeTab(tabId);
}

/** Dismisses a tab whose session has already ended, without asking the core. */
export function dismissTab(tabId: string): void {
  disposeTerminal(tabId);
  disposeSurface(tabId);
  useSessions.getState().remove(tabId);
}
