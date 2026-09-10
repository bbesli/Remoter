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
 */

import { useCallback, useState } from "react";
import clsx from "clsx";

import { Icon } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { useShortcutGroup, type ShortcutEvent } from "@/hooks/keyboard";
import { useSessions, type SessionRecord } from "./store";
import { closeTab, reconnect } from "./manager";
import { focusTerminal } from "./terminals";

import s from "./SessionTabs.module.css";

const TEXT = {
  close: (name: string) => `Close ${name}`,
  reconnect: (name: string) => `Reconnect ${name}`,
  state: {
    preparing: "preparing",
    connecting: "connecting",
    verifying: "waiting on a host key decision",
    authenticating: "authenticating",
    running: "connected",
    failed: "failed",
    closed: "ended",
  } as const,
  tab: (name: string, state: string) => `${name} — ${state}`,
} as const;

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
  const activate = useSessions((st) => st.activate);
  const [closing, setClosing] = useState(false);

  const state = TEXT.state[record.phase];
  const ended = record.phase === "failed" || record.phase === "closed";

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
        aria-label={TEXT.tab(record.name, state)}
        aria-current={active ? "true" : undefined}
        title={record.target ?? record.name}
        onClick={() => {
          activate(record.tabId);
          focusTerminal(record.tabId);
        }}
        onAuxClick={(event) => {
          // Middle click closes, as it does everywhere else tabs exist.
          if (event.button !== 1) return;
          event.preventDefault();
          setClosing(true);
          void closeTab(record.tabId);
        }}
      >
        <span className={s.dot} data-state={dotState(record)} title={state} aria-hidden="true" />
        <span className={s.name}>{record.name}</span>
      </button>

      {ended && (
        <button
          type="button"
          className={s.control}
          title={TEXT.reconnect(record.name)}
          aria-label={TEXT.reconnect(record.name)}
          onClick={() => reconnect(record.tabId)}
        >
          <Icon name="arrow-right" size={12} />
        </button>
      )}

      <button
        type="button"
        className={s.control}
        title={TEXT.close(record.name)}
        aria-label={TEXT.close(record.name)}
        disabled={closing}
        onClick={() => {
          setClosing(true);
          void closeTab(record.tabId);
        }}
      >
        {closing ? <Spinner size={12} label={TEXT.close(record.name)} /> : <Icon name="x" size={12} />}
      </button>
    </div>
  );
}

export function SessionTabs() {
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
            void closeTab(activeTabId);
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
    <div className={s.tabs} role="group" aria-label="Open sessions">
      {order.map((tabId) => {
        const record = byId[tabId];
        if (record === undefined) return null;
        return <SessionTab key={tabId} record={record} active={tabId === activeTabId} />;
      })}
    </div>
  );
}
