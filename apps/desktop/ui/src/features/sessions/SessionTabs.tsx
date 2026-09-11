/**
 * One tab per session.
 *
 * The connection's colour, a live status dot, close, and — once a session has
 * ended — reconnect. The dot is never the only signal: it carries a title and
 * the tab's `aria-label` says the state in words, because "green means
 * connected" is exactly the convention a colour-blind user cannot use
 * (docs/ui/information-architecture.md).
 *
 * Closing a tab closes the session. That is not a shortcut — `closeTab` awaits
 * the core's close, which returns once sockets are shut and cached secrets are
 * zeroized. A tab that disappeared first would be claiming something had
 * finished that had not.
 *
 * All three of this file's ways out — the `x`, a middle click, and the
 * `tab.close` shortcut — go through `requestCloseTab`, which asks before it
 * disconnects a session that is actually connected and goes straight through
 * for one that has already ended. They are not allowed to differ: a
 * confirmation the `x` respects and the shortcut does not is a confirmation
 * that has taught the user the wrong thing.
 *
 * The spinner they used to set locally is gone with them. A close that is
 * waiting on an answer is not in progress, and a control that spun while a
 * dialog was up would be claiming otherwise; the dialog carries the wait now.
 */

import { useCallback } from "react";
import clsx from "clsx";

import { Icon } from "@/components/Icon";
import { useShortcutGroup, type ShortcutEvent } from "@/hooks/keyboard";
import { isolate, useT } from "@/i18n";
import { useSessions, type SessionRecord } from "./store";
import { requestCloseTab } from "./closing";
import { reconnect } from "./manager";
import { focusTerminal } from "./terminals";
import type { ConnectPhase } from "./stages";

import s from "./SessionTabs.module.css";

/**
 * The phase, said in words.
 *
 * A record rather than a key built from the phase, so a phase added to
 * `ConnectPhase` without a word for it is a compile error here rather than a
 * humanised key in a tab's accessible name — which nobody would see, because
 * only a screen reader reads it.
 */
const STATE_KEYS = {
  preparing: "tab.state.preparing",
  connecting: "tab.state.connecting",
  verifying: "tab.state.verifying",
  authenticating: "tab.state.authenticating",
  running: "tab.state.running",
  failed: "tab.state.failed",
  closed: "tab.state.closed",
} as const satisfies Record<ConnectPhase, string>;

/** Which state token the dot takes. Four states, four tokens, no others. */
function dotState(record: SessionRecord): "connected" | "connecting" | "failed" | "locked" {
  switch (record.phase) {
    case "running":
      return "connected";
    case "failed":
      return "failed";
    case "closed":
      return "locked";
    default:
      return "connecting";
  }
}

function SessionTab({ record, active }: { record: SessionRecord; active: boolean }) {
  const t = useT("sessions");
  const activate = useSessions((st) => st.activate);

  const state = t(STATE_KEYS[record.phase]);
  const ended = record.phase === "failed" || record.phase === "closed";
  // The connection's name is the user's own text, in any script. Isolated so
  // one right-to-left character in it cannot reorder the label around it.
  const name = isolate(record.name);
  const close = t("tab.close", { name });
  const reconnectLabel = t("tab.reconnect", { name });

  return (
    <div
      className={clsx(s.tab, active && s.active)}
      // The colour is the connection's own, from the tree. It is a stripe
      // rather than a fill so it never competes with the state dot.
      style={record.colour === null ? undefined : { borderBlockStartColor: record.colour }}
      data-active={active ? "true" : "false"}
    >
      <button
        type="button"
        className={s.body}
        aria-label={t("tab.accessibleName", { name, state })}
        aria-current={active ? "true" : undefined}
        title={record.target ?? record.name}
        onClick={() => {
          activate(record.tabId);
          focusTerminal(record.tabId);
        }}
        onAuxClick={(event) => {
          // Middle click closes, as it does everywhere else tabs exist — and
          // it is the easiest of the three to do by accident, so it asks
          // exactly as the others do.
          if (event.button !== 1) return;
          event.preventDefault();
          requestCloseTab(record.tabId);
        }}
      >
        <span className={s.dot} data-state={dotState(record)} title={state} aria-hidden="true" />
        <span className={s.name}>{record.name}</span>
      </button>

      {ended && (
        <button
          type="button"
          className={s.control}
          title={reconnectLabel}
          aria-label={reconnectLabel}
          onClick={() => reconnect(record.tabId)}
        >
          <Icon name="arrow-right" size={12} />
        </button>
      )}

      <button
        type="button"
        className={s.control}
        title={close}
        aria-label={close}
        onClick={() => {
          requestCloseTab(record.tabId);
        }}
      >
        <Icon name="x" size={12} />
      </button>
    </div>
  );
}

export function SessionTabs() {
  const t = useT("sessions");
  const order = useSessions((st) => st.order);
  const byId = useSessions((st) => st.byId);
  const activeTabId = useSessions((st) => st.activeTabId);
  const activate = useSessions((st) => st.activate);

  /*
   * Moving between tabs puts the keyboard back in the terminal it moved to.
   * Switching tab without focusing it leaves the next keystroke going nowhere,
   * which reads as a session that has hung.
   */
  const show = useCallback(
    (tabId: string | undefined) => {
      if (tabId === undefined) return;
      activate(tabId);
      focusTerminal(tabId);
    },
    [activate],
  );

  const step = useCallback(
    (delta: number) => {
      if (order.length === 0) return;
      const current = activeTabId === null ? -1 : order.indexOf(activeTabId);
      // Wraps, so Next on the last tab is the first — the behaviour every
      // tabbed application has, and the one the table implies by not saying
      // otherwise.
      const next = (((current + delta) % order.length) + order.length) % order.length;
      show(order[next]);
    },
    [order, activeTabId, show],
  );

  /*
   * The tab strip's bindings.
   *
   * `null` where there is nothing to do: closing with no tab in front,
   * stepping through a single tab, or jumping into a strip with no tabs in it
   * must leave the keystroke to whatever else wants it rather than swallowing
   * it into a no-op.
   */
  useShortcutGroup("tabs", {
    "tab.close":
      activeTabId === null
        ? null
        : () => {
            requestCloseTab(activeTabId);
          },
    "tab.next": order.length < 2 ? null : () => step(1),
    "tab.previous": order.length < 2 ? null : () => step(-1),
    // The series index is which of Alt+1…Alt+9 was pressed. With no session
    // open there is no tab behind any of the nine, so the whole series is
    // handed back as `null` and every one of those keystrokes is left to
    // whatever else wants it — the same contract as Close and Next above,
    // which used to be broken here by a handler that was always a function and
    // therefore always swallowed the key.
    //
    // The registry resolves a handler per action, not per key of a series, so
    // Alt+5 with two tabs open still reaches this and still does nothing
    // visible. Left as it is on purpose rather than fixed halfway: making that
    // case leave the keystroke alone means the lookup has to be told which key
    // of the series fired, which is a change to `hooks/keyboard/registry.ts`
    // and to every caller's handler type.
    "tab.jump":
      order.length === 0
        ? null
        : (event: ShortcutEvent) => {
            show(order[event.seriesIndex]);
          },
  });

  if (order.length === 0) return null;

  return (
    // Not a `tablist`: each tab carries its own close and reconnect controls,
    // and the ARIA tab pattern has no room for them — a `tab` may not contain
    // other interactive elements.
    <div className={s.tabs} role="group" aria-label={t("tab.label")}>
      {order.map((tabId) => {
        const record = byId[tabId];
        if (record === undefined) return null;
        return <SessionTab key={tabId} record={record} active={tabId === activeTabId} />;
      })}
    </div>
  );
}
