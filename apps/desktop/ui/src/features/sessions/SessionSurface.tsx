/**
 * The session area: the terminals, and everything that interrupts them.
 *
 * Every open tab has its host element mounted here at all times, with the
 * inactive ones made invisible rather than unmounted. Unmounting would destroy
 * the xterm instance and its scrollback, and re-mounting would re-run the WebGL
 * setup on every tab switch. Hidden-but-laid-out also keeps the fit addon
 * honest: a display:none element has no dimensions, so a terminal switched back
 * to would come back at the wrong size.
 *
 * The overlays belong to the active tab only. A host key question on a
 * background tab still holds that session suspended — the tab's status dot says
 * so, and switching to it brings the dialog up.
 */

import { useEffect, useRef, useState, type ReactNode } from "react";

import { useApp } from "@/stores/app";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { useSessions, type SessionRecord } from "./store";
import { attachTerminal, focusTerminal, hasTerminal } from "./terminals";
import { cancelConnect, closeTab, decideHostKey, dismissTab, reconnect } from "./manager";
import { ConnectProgress } from "./ConnectProgress";
import { FindBar } from "./FindBar";
import { HostKeyDialog } from "./HostKeyDialog";
import { isConnecting } from "./stages";

import s from "./SessionSurface.module.css";

const TEXT = {
  terminal: (name: string) => `Terminal for ${name}`,
  failedTitle: (name: string) => `${name} did not connect`,
  endedTitle: (name: string) => `${name} has ended`,
  endedBody: {
    disconnected: "The server closed the connection.",
    closed_by_user: "You closed this session.",
    application_exit: "Remoter closed this session as it shut down.",
    failed: "The session ended with a failure.",
    panicked:
      "The session task panicked and was destroyed rather than resumed. Its sockets are closed and its secrets are zeroized.",
    aborted: "The session overran its shutdown grace period and was aborted.",
  } as const,
  reconnect: "Reconnect",
  closeTab: "Close this tab",
  promptTitle: "The server is asking for something this version cannot answer",
  promptBody: (kind: string) =>
    `It asked for ${kind.replace(/_/g, " ")}. This build can answer a host key question and nothing else, so the attempt will not complete.`,
  promptServerText: "What the server said:",
  cancel: "Cancel the attempt",
  inputRefused: "The last keystroke did not reach the server",
} as const;

/** Mounts one session's terminal element and keeps it fitted to the area. */
function TerminalHost({ tabId, name, active }: { tabId: string; name: string; active: boolean }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = ref.current;
    if (container === null || !hasTerminal(tabId)) return;
    return attachTerminal(tabId, container);
  }, [tabId]);

  // Focus follows the tab, so typing after a switch goes to the shell the user
  // is looking at rather than to the one they left.
  useEffect(() => {
    if (active) focusTerminal(tabId);
  }, [active, tabId]);

  return (
    <div
      ref={ref}
      className={active ? s.terminal : [s.terminal, s.terminalHidden].join(" ")}
      // Hidden tabs are hidden from assistive technology too: two terminals in
      // the accessibility tree with the same content is worse than one.
      aria-hidden={active ? undefined : true}
      aria-label={TEXT.terminal(name)}
      data-tab={tabId}
    />
  );
}

function EndedPanel({ record }: { record: SessionRecord }) {
  const failure = record.failure;

  return (
    <div className={s.overlay}>
      <div className={s.notice}>
        {failure !== null ? (
          <FailureNotice
            failure={failure}
            title={TEXT.failedTitle(record.name)}
            // The core says whether a retry could plausibly work. It is always
            // false for a changed host key, so auto-reconnect can never retry a
            // possible man-in-the-middle — and neither can this button.
            {...(record.retryable ? { onRetry: () => reconnect(record.tabId) } : {})}
            retryLabel={TEXT.reconnect}
          >
            <Button variant="ghost" size="sm" onClick={() => dismissTab(record.tabId)}>
              {TEXT.closeTab}
            </Button>
          </FailureNotice>
        ) : (
          <Callout tone="neutral" title={TEXT.endedTitle(record.name)}>
            <p className={s.noticeBody}>
              {TEXT.endedBody[record.closeReason ?? "closed_by_user"]}
            </p>
            <div className={s.noticeActions}>
              <Button variant="primary" size="sm" onClick={() => reconnect(record.tabId)}>
                {TEXT.reconnect}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => dismissTab(record.tabId)}>
                {TEXT.closeTab}
              </Button>
            </div>
          </Callout>
        )}
      </div>
    </div>
  );
}

function PromptPanel({ record }: { record: SessionRecord }) {
  const prompt = record.prompt;
  if (prompt === null) return null;

  return (
    <div className={s.overlay}>
      <div className={s.notice}>
        <Callout tone="warning" title={TEXT.promptTitle}>
          <p className={s.noticeBody}>{TEXT.promptBody(prompt.kind)}</p>
          {prompt.text !== "" && (
            <>
              <p className={s.noticeBody}>{TEXT.promptServerText}</p>
              {/* The server's own text. Untrusted, and rendered as text. */}
              <pre className={s.serverText}>{prompt.text}</pre>
            </>
          )}
          <div className={s.noticeActions}>
            <Button variant="secondary" size="sm" onClick={() => void cancelConnect(record.tabId)}>
              {TEXT.cancel}
            </Button>
          </div>
        </Callout>
      </div>
    </div>
  );
}

export function SessionSurface({ empty }: { empty: ReactNode }) {
  const order = useSessions((st) => st.order);
  const byId = useSessions((st) => st.byId);
  const activeTabId = useSessions((st) => st.activeTabId);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [finding, setFinding] = useState(false);

  const active = activeTabId === null ? undefined : byId[activeTabId];

  // Ctrl/Cmd+Shift+F opens the find bar. Shift, because `Ctrl+F` belongs to
  // readline and to vi, and the terminal has the keyboard.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!(event.ctrlKey || event.metaKey) || !event.shiftKey) return;
      if (event.key.toLowerCase() !== "f") return;
      if (useApp.getState().openModals.size > 0) return;
      event.preventDefault();
      setFinding(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  if (order.length === 0) return <>{empty}</>;

  const connecting = active !== undefined && isConnecting(active.phase);
  const promptId = active?.hostKey?.promptId ?? 0;

  return (
    <>
      {order.map((tabId) => (
        <TerminalHost
          key={tabId}
          tabId={tabId}
          name={byId[tabId]?.name ?? tabId}
          active={tabId === activeTabId}
        />
      ))}

      {/* Only over a live session: searching the scrollback of a tab that is
          showing a failure notice would be searching an empty buffer. */}
      {finding && active !== undefined && active.phase === "running" && (
        <FindBar tabId={active.tabId} onClose={() => setFinding(false)} />
      )}

      {active !== undefined && active.inputError !== null && (
        <div className={s.inputBar}>
          <FailureNotice
            failure={active.inputError}
            title={TEXT.inputRefused}
            tone="warning"
          />
        </div>
      )}

      {active !== undefined && connecting && active.hostKey === null && (
        <ConnectProgress
          record={active}
          cancelling={cancelling === active.tabId}
          onCancel={() => {
            setCancelling(active.tabId);
            void cancelConnect(active.tabId).finally(() => setCancelling(null));
          }}
        />
      )}

      {active !== undefined && active.prompt !== null && active.hostKey === null && (
        <PromptPanel record={active} />
      )}

      {active !== undefined && (active.phase === "failed" || active.phase === "closed") && (
        <EndedPanel record={active} />
      )}

      {active !== undefined && active.hostKey !== null && (
        <HostKeyDialog
          prompt={active.hostKey}
          sessionName={active.name}
          busy={active.hostKeyBusy}
          failure={active.hostKeyError}
          // Three decisions, passed through as the core defines them. There is
          // no accept path for a changed key: the dialog does not draw the
          // button, and the core would refuse it if it did.
          onAccept={() =>
            void decideHostKey(active.tabId, { decision: "accept", promptId })
          }
          onReplace={(confirmation) =>
            void decideHostKey(active.tabId, { decision: "replace", promptId, confirmation })
          }
          onReject={() =>
            void decideHostKey(active.tabId, { decision: "reject", promptId })
          }
        />
      )}
    </>
  );
}

/** Closes every tab, for the vault locking or the window going away. */
export async function closeAllSessions(): Promise<void> {
  const tabs = [...useSessions.getState().order];
  await Promise.all(tabs.map((tabId) => closeTab(tabId)));
}
