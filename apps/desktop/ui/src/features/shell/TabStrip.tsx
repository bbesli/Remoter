/**
 * The session tab strip.
 *
 * It owns the sidebar toggle, the tabs themselves, the Files toggle and the
 * inspector toggle, and the 36px it occupies is part of the chrome budget the
 * session area is sized against.
 *
 * The two right-hand toggles are both "show me more about the tab in front",
 * which is why the file pane is reached from here rather than from the title
 * bar: the title bar's screens belong to the vault, and a file pane belongs to
 * one session.
 *
 * The tabs come from the sessions store rather than from `session_list`: a tab
 * exists before the core has an id for it, which is what makes a connect
 * cancellable while it is still connecting.
 */

import { Icon } from "@/components/Icon";
import { SessionTabs, useSessions } from "@/features/sessions";
import { useT } from "@/i18n";
import { useApp } from "@/stores/app";
import { filePaneBlocker, type FilePaneBlocker } from "./filePanes";
import s from "./TabStrip.module.css";

/**
 * Why the Files control is doing nothing, in words.
 *
 * A record rather than a key built from the blocker, so a reason added to
 * `filePanes.ts` is a compile error here until it has a sentence. A disabled
 * control that cannot say why is the failure this bar keeps being asked not to
 * ship.
 */
const BLOCKED_KEYS = {
  noSession: "tabStrip.filesNoSession",
  notRunning: "tabStrip.filesNotRunning",
  noFileChannel: "tabStrip.filesNoFileChannel",
  isFileSession: "tabStrip.filesIsFileSession",
} as const satisfies Record<FilePaneBlocker, string>;

export function TabStrip() {
  const t = useT("shell");
  const sidebarOpen = useApp((st) => st.sidebarOpen);
  const toggleSidebar = useApp((st) => st.toggleSidebar);
  const inspectorOpen = useApp((st) => st.inspectorOpen);
  const toggleInspector = useApp((st) => st.toggleInspector);
  const anySessions = useSessions((st) => st.order.length > 0);

  // The file pane belongs to the tab in front: it opens one more channel on
  // that connection — RFC 4254 §6.5 — rather than connecting again, which is
  // why this control offers nothing when nothing is connected.
  const activeTabId = useSessions((st) => st.activeTabId);
  const byId = useSessions((st) => st.byId);
  const activeRecord = activeTabId === null ? undefined : byId[activeTabId];
  const blocker = filePaneBlocker(activeRecord);
  const filePaneTabs = useApp((st) => st.filePaneTabs);
  const toggleFilePane = useApp((st) => st.toggleFilePane);
  const filesOpen = activeTabId !== null && filePaneTabs.has(activeTabId);

  const filesTitle =
    blocker !== null
      ? t(BLOCKED_KEYS[blocker])
      : filesOpen
        ? t("tabStrip.filesClose")
        : t("tabStrip.filesOpen");

  const sidebarTitle = sidebarOpen ? t("tabStrip.sidebarHide") : t("tabStrip.sidebarShow");

  return (
    <div className={s.strip}>
      <button
        type="button"
        className={s.edgeButton}
        onClick={toggleSidebar}
        title={sidebarTitle}
        aria-label={sidebarTitle}
        aria-pressed={sidebarOpen}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth="1.9" />
          <path d="M9 4v16" stroke="currentColor" strokeWidth="1.9" />
        </svg>
      </button>

      {anySessions ? (
        <SessionTabs />
      ) : (
        <span className={s.placeholder}>{t("tabStrip.noSessions")}</span>
      )}

      <div className={s.spacer} />

      {/* The route to the file manager for a session that already has a shell.
          The pane appears under the terminal, on the connection this tab
          authenticated with. An SFTP connection needs no control here: its tab
          is the file manager. */}
      <button
        type="button"
        className={[s.edgeButton, filesOpen ? s.active : ""].join(" ")}
        onClick={() => {
          if (activeTabId !== null) toggleFilePane(activeTabId);
        }}
        title={filesTitle}
        aria-label={filesTitle}
        aria-pressed={filesOpen}
        disabled={blocker !== null}
      >
        <Icon name="folder" size={15} />
      </button>

      <button
        type="button"
        className={[s.edgeButton, s.rightEdge, inspectorOpen ? s.active : ""].join(" ")}
        onClick={toggleInspector}
        title={t("tabStrip.inspector")}
        aria-label={t("tabStrip.inspector")}
        aria-pressed={inspectorOpen}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <rect x="3" y="4" width="18" height="16" rx="2" stroke="currentColor" strokeWidth="1.9" />
          <path d="M15 4v16" stroke="currentColor" strokeWidth="1.9" />
        </svg>
      </button>
    </div>
  );
}
