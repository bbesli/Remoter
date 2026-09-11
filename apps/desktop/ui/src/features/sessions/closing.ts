/**
 * Asking before a session is disconnected.
 *
 * # Why there is a question at all
 *
 * Closing a tab ends the session. That is not undoable, it interrupts whatever
 * is running on the far machine, and the control that does it sits a few pixels
 * from the tab the user meant to switch to. One slip and a deployment is half
 * finished on a domain controller with nothing to reconnect to but a new
 * session.
 *
 * # Why the question lives here and not in a component
 *
 * There are five ways out of a session and a confirmation that only one of them
 * respects is worse than none — it teaches the user that closing is guarded,
 * and then it is not. So every route goes through {@link requestCloseTab} or
 * {@link requestCloseWindow}, and the routes themselves stay dumb:
 *
 * | Route | Where |
 * |---|---|
 * | The tab's `x` | `SessionTabs.tsx` |
 * | Middle-click on a tab | `SessionTabs.tsx` |
 * | The `tab.close` shortcut | `SessionTabs.tsx`, `useShortcutGroup("tabs")` |
 * | Disconnect in the sessions panel | `SessionPanels.tsx` |
 * | The window's close control | `TitleBar.tsx` and `components/WindowChrome.tsx` |
 *
 * There is no context menu on a session tab — the tree has one, the tab strip
 * does not — so there is no sixth route today. A route added later that calls
 * `closeTab` directly is the defect this module exists to prevent, which is why
 * `closeTab` keeps its name and this one is `request…`: the two read
 * differently at a call site.
 *
 * The window is one question, not one per tab. "Disconnect four sessions and
 * close Remoter?" is the decision the user is actually making; four dialogs in
 * a row is a thing to click through rather than a thing to read.
 *
 * # Where it does not ask
 *
 * **A tab whose session has ended.** A failed or closed tab is a photograph of
 * something that already happened — `dismissTab` does not even call the core —
 * and confirming its dismissal is noise that trains the user to confirm without
 * reading. {@link atRisk} is what draws that line, from the record's own phase.
 *
 * **A connect that has not finished.** `cancelConnect` is reached from a button
 * on the connect panel and from the prompt panel, both of which say Cancel and
 * are pressed by someone watching the attempt they are cancelling. There is no
 * established session to interrupt, and asking "are you sure you want to cancel"
 * about a cancel button is the parody of this pattern.
 *
 * **Locking the vault.** `MainWindow` closes every session before it locks, and
 * that is a security action — putting a dialog in front of "I am leaving this
 * machine" is exactly the wrong place to add friction. It is also not a slip:
 * the lock button is nowhere near a tab.
 *
 * # What the question has to say
 *
 * "Are you sure?" is not information. The host is, and so is anything the
 * session knows it would interrupt — a file transfer still moving is the one
 * this build can see, through `liveTransfersFor`. Everything the dialog needs is
 * gathered here, at the moment the question is asked, rather than read again
 * when it is answered: the answer is about what the user was shown.
 */

import { create } from "zustand";

import { liveTransfersFor } from "@/features/files";

import { closeTab } from "./manager";
import { useSessions, type SessionRecord } from "./store";

/** One session the question is about. */
export interface SessionAtRisk {
  tabId: string;
  /** The connection's name as the user called it. Vault data, in any script. */
  name: string;
  /** `host:port`, the core's own once it has reported it. May be absent. */
  target: string | null;
  /** Transfers on this session still queued or moving. */
  transfers: number;
}

/** Whether closing this tab would end a session that is actually connected. */
export function isLiveSession(record: SessionRecord): boolean {
  // Both halves matter. `running` excludes the photograph a failed or closed
  // tab has become; a non-null `sessionId` excludes the window between the core
  // deregistering a session and the phase catching up, where there is nothing
  // left to disconnect.
  return record.phase === "running" && record.sessionId !== null;
}

/** The live sessions among these tabs, in tab order, with what each would lose. */
export function atRisk(tabIds: readonly string[]): SessionAtRisk[] {
  const { byId } = useSessions.getState();
  const out: SessionAtRisk[] = [];
  for (const tabId of tabIds) {
    const record = byId[tabId];
    if (record === undefined || !isLiveSession(record)) continue;
    out.push({
      tabId,
      name: record.name,
      target: record.target,
      transfers: liveTransfersFor(record.sessionId),
    });
  }
  return out;
}

/** A question waiting on screen. */
export interface CloseRequest {
  /** Which control asked, so the dialog can word it. */
  kind: "tab" | "window";
  /** Every tab this would close — the ended ones included, they go too. */
  tabIds: readonly string[];
  /** The live ones. Never empty: a request with nothing at risk is not asked. */
  atRisk: readonly SessionAtRisk[];
  /**
   * What follows the sessions being closed.
   *
   * The window's own close, for a window request. Null for a tab, which has
   * nothing after it. Held rather than re-derived so that the thing that
   * happens is the thing the control that asked was going to do — including its
   * own failure handling, which belongs to that control's bar.
   */
  then: (() => void) | null;
}

interface ClosingStore {
  pending: CloseRequest | null;
  /** True while the accepted close is running. */
  busy: boolean;
  ask: (request: CloseRequest) => void;
  setBusy: (busy: boolean) => void;
  clear: () => void;
}

export const useClosing = create<ClosingStore>((set) => ({
  pending: null,
  busy: false,
  // A second question cannot open over the first: the routes are all one click,
  // and the dialog traps focus, so there is no way to reach another of them
  // while one is up. Asserted by replacing rather than stacking, so a bug that
  // did reach here leaves one dialog rather than two focus traps.
  ask: (request) => {
    set({ pending: request, busy: false });
  },
  setBusy: (busy) => {
    set({ busy });
  },
  clear: () => {
    set({ pending: null, busy: false });
  },
}));

/**
 * Closes one tab, asking first if there is a session to lose.
 *
 * Every route to closing a single tab calls this. A tab whose session has
 * already ended goes straight through to `closeTab`, which for that tab is the
 * local tidy-up it always was.
 */
export function requestCloseTab(tabId: string): void {
  const record = useSessions.getState().byId[tabId];
  if (record === undefined) return;
  if (!isLiveSession(record)) {
    void closeTab(tabId);
    return;
  }
  useClosing.getState().ask({
    kind: "tab",
    tabIds: [tabId],
    atRisk: atRisk([tabId]),
    then: null,
  });
}

/**
 * Closes the window, asking once about every session it would take with it.
 *
 * `proceed` is the caller's own close — the title bar's and the overlay's each
 * report a refusal in their own bar — and it runs only after the sessions are
 * down, because the core's close is what zeroizes their cached secrets and a
 * window that vanished first would not have waited for it.
 */
export function requestCloseWindow(proceed: () => void): void {
  const tabIds = [...useSessions.getState().order];
  const risk = atRisk(tabIds);
  if (risk.length === 0) {
    // Nothing connected. Any ended tabs go with the window as they always did,
    // and there is no question to ask about a photograph.
    proceed();
    return;
  }
  useClosing.getState().ask({ kind: "window", tabIds, atRisk: risk, then: proceed });
}

/** Carries out the pending request. The dialog's "Disconnect". */
export async function confirmClose(): Promise<void> {
  const { pending, busy } = useClosing.getState();
  if (pending === null || busy) return;
  useClosing.getState().setBusy(true);
  try {
    // Awaited, all of them: `closeTab` returns once the core has shut the
    // sockets and zeroized what it cached, and the window close queued behind
    // this must not overtake that.
    await Promise.all(pending.tabIds.map((tabId) => closeTab(tabId)));
  } finally {
    useClosing.getState().clear();
  }
  pending.then?.();
}

/** Leaves everything connected. The dialog's Escape, backdrop and Cancel. */
export function declineClose(): void {
  // Deliberately nothing but closing the question. Not a single `closeSession`
  // runs down this path, which is the property the tests assert.
  if (useClosing.getState().busy) return;
  useClosing.getState().clear();
}
