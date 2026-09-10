/**
 * The session tab strip.
 *
 * It owns the sidebar toggle, the tabs themselves and the inspector toggle,
 * and the 36px it occupies is part of the chrome budget the session area is
 * sized against.
 *
 * The tabs come from the sessions store rather than from `session_list`: a tab
 * exists before the core has an id for it, which is what makes a connect
 * cancellable while it is still connecting.
 */

import { SessionTabs, useSessions } from "@/features/sessions";
import { useApp } from "@/stores/app";
import s from "./TabStrip.module.css";

const TEXT = {
  sidebarShow: "Show the connection tree",
  sidebarHide: "Hide the connection tree",
  noSessions: "No open sessions — double-click a connection to start one",
  inspector: "Effective values · F4",
} as const;

export function TabStrip() {
  const sidebarOpen = useApp((st) => st.sidebarOpen);
  const toggleSidebar = useApp((st) => st.toggleSidebar);
  const inspectorOpen = useApp((st) => st.inspectorOpen);
  const toggleInspector = useApp((st) => st.toggleInspector);
  const anySessions = useSessions((st) => st.order.length > 0);

  const sidebarTitle = sidebarOpen ? TEXT.sidebarHide : TEXT.sidebarShow;

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
        <span className={s.placeholder}>{TEXT.noSessions}</span>
      )}

      <div className={s.spacer} />

      <button
        type="button"
        className={[s.edgeButton, s.rightEdge, inspectorOpen ? s.active : ""].join(" ")}
        onClick={toggleInspector}
        title={TEXT.inspector}
        aria-label={TEXT.inspector}
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
