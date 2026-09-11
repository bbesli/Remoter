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
import { isolate, useT } from "@/i18n";
import type { CloseReason, SessionPrompt } from "@/lib/ipc";
import { useSessions, type SessionRecord } from "./store";
import { attachTerminal, focusTerminal, hasTerminal } from "./terminals";
import { cancelConnect, closeTab, decideHostKey, dismissTab, reconnect } from "./manager";
import { ConnectProgress } from "./ConnectProgress";
import { FindBar } from "./FindBar";
import { FramebufferHost } from "./FramebufferHost";
import { HostKeyDialog } from "./HostKeyDialog";
import { SessionWarnings } from "./SessionWarnings";
import { isConnecting } from "./stages";

import s from "./SessionSurface.module.css";

/**
 * Why a session ended, said in words.
 *
 * A record rather than a key built from the reason, so a reason the core adds
 * without copy for it is a compile error here. The panic case in particular is
 * a promise about what was destroyed, and a humanised key in its place would
 * say nothing at all.
 */
const ENDED_KEYS = {
  disconnected: "surface.endedReason.disconnected",
  closed_by_user: "surface.endedReason.closed_by_user",
  application_exit: "surface.endedReason.application_exit",
  failed: "surface.endedReason.failed",
  panicked: "surface.endedReason.panicked",
  aborted: "surface.endedReason.aborted",
} as const satisfies Record<CloseReason, string>;

/**
 * What the server asked for, as the object of "It asked for …".
 *
 * The old code printed the core's own token with the underscores swapped for
 * spaces, which produced "key passphrase" in English and nothing usable in any
 * other language.
 */
const PROMPT_KIND_KEYS = {
  password: "surface.prompt.kind.password",
  key_passphrase: "surface.prompt.kind.key_passphrase",
  keyboard_interactive: "surface.prompt.kind.keyboard_interactive",
  certificate: "surface.prompt.kind.certificate",
} as const satisfies Record<SessionPrompt["kind"], string>;

/** Mounts one session's terminal element and keeps it fitted to the area. */
function TerminalHost({ tabId, name, active }: { tabId: string; name: string; active: boolean }) {
  const t = useT("sessions");
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
      aria-label={t("surface.terminalLabel", { name: isolate(name) })}
      data-tab={tabId}
    />
  );
}

function EndedPanel({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const failure = record.failure;
  // The connection's own name, from the vault, inside a sentence.
  const name = isolate(record.name);

  return (
    <div className={s.overlay}>
      <div className={s.notice}>
        {failure !== null ? (
          <FailureNotice
            failure={failure}
            title={t("surface.failedTitle", { name })}
            // The core says whether a retry could plausibly work. It is always
            // false for a changed host key, so auto-reconnect can never retry a
            // possible man-in-the-middle — and neither can this button.
            {...(record.retryable ? { onRetry: () => reconnect(record.tabId) } : {})}
            retryLabel={t("surface.reconnect")}
          >
            <Button variant="ghost" size="sm" onClick={() => dismissTab(record.tabId)}>
              {t("surface.closeTab")}
            </Button>
          </FailureNotice>
        ) : (
          <Callout tone="neutral" title={t("surface.endedTitle", { name })}>
            <p className={s.noticeBody}>{t(ENDED_KEYS[record.closeReason ?? "closed_by_user"])}</p>
            <div className={s.noticeActions}>
              <Button variant="primary" size="sm" onClick={() => reconnect(record.tabId)}>
                {t("surface.reconnect")}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => dismissTab(record.tabId)}>
                {t("surface.closeTab")}
              </Button>
            </div>
          </Callout>
        )}
      </div>
    </div>
  );
}

function PromptPanel({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const prompt = record.prompt;
  if (prompt === null) return null;

  return (
    <div className={s.overlay}>
      <div className={s.notice}>
        <Callout tone="warning" title={t("surface.prompt.title")}>
          <p className={s.noticeBody}>
            {t("surface.prompt.body", { kind: t(PROMPT_KIND_KEYS[prompt.kind]) })}
          </p>
          {prompt.text !== "" && (
            <>
              <p className={s.noticeBody}>{t("surface.prompt.serverText")}</p>
              {/* The server's own text. Untrusted, and rendered as text. */}
              <pre className={s.serverText}>{prompt.text}</pre>
            </>
          )}
          <div className={s.noticeActions}>
            <Button variant="secondary" size="sm" onClick={() => void cancelConnect(record.tabId)}>
              {t("surface.prompt.cancel")}
            </Button>
          </div>
        </Callout>
      </div>
    </div>
  );
}

export function SessionSurface({ empty }: { empty: ReactNode }) {
  const t = useT("sessions");
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
      {order.map((tabId) => {
        const tab = byId[tabId];
        // Which surface a session gets follows from the core's own
        // `capabilities.kind`, never from the protocol name: a plugin protocol
        // that reports `framebuffer` gets the canvas, and nothing here has to
        // learn a list of protocol strings. The kind is not known until
        // `ready`, and until then the connect panel is over the area anyway.
        if (tab !== undefined && tab.opened?.capabilities.kind === "framebuffer") {
          return <FramebufferHost key={tabId} record={tab} active={tabId === activeTabId} />;
        }
        return (
          <TerminalHost
            key={tabId}
            tabId={tabId}
            name={tab?.name ?? tabId}
            active={tabId === activeTabId}
          />
        );
      })}

      {/* Only over a live terminal: searching the scrollback of a tab that is
          showing a failure notice would be searching an empty buffer, and a
          framebuffer session has no scrollback to search at all. */}
      {finding &&
        active !== undefined &&
        active.phase === "running" &&
        active.opened?.capabilities.kind !== "framebuffer" && (
          <FindBar tabId={active.tabId} onClose={() => setFinding(false)} />
        )}

      {/* Everything the session warned about, over the session. Terminal and
          graphical alike: an SSH login banner and a VNC security type land in
          the same place. */}
      {active !== undefined && <SessionWarnings record={active} />}

      {active !== undefined && active.inputError !== null && (
        <div className={s.inputBar}>
          <FailureNotice
            failure={active.inputError}
            title={t("surface.inputRefused")}
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
