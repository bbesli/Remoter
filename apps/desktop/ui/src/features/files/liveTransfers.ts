/**
 * How many transfers a session would interrupt if it were disconnected now.
 *
 * # Why this exists at all
 *
 * The transfer queue is the core's and reaches the interface as server state
 * through `qk.sftpTransfers(paneId)` — TanStack Query, per CLAUDE.md §6, and
 * keyed by the *pane* rather than by the session. That is the right key for the
 * panel and the wrong one for everybody else: the question "would disconnecting
 * this tab stop a copy that is half done?" is asked from the tab strip, from a
 * keyboard shortcut and from the window's close control, none of which knows a
 * pane id, and two of which are not inside the pane's React tree at all.
 *
 * So the panel — the one component that already holds both the pane and its
 * transfers — publishes the count here, keyed by the session the pane runs on.
 * Everything else reads it synchronously. This is a *derived* fact about state
 * that lives elsewhere, deliberately: nothing here is authoritative, nothing is
 * written to it except by the panel that is looking at the real list, and a
 * session with no open pane simply reads zero.
 *
 * # Why a module registry rather than a store
 *
 * The readers are not components. `closing.ts` decides what a confirmation
 * says from a plain function called out of a click handler, and a Zustand
 * selector would buy a subscription nobody needs for a value read once at the
 * moment the question is asked.
 *
 * A count that is stale is a count that over- or under-states the stake, so the
 * panel clears its entry on unmount: a pane that is gone is not moving bytes.
 */

/** Session id to the number of its transfers still queued or moving. */
const live = new Map<number, number>();

/**
 * Publishes what one pane's queue is doing.
 *
 * A count of zero removes the entry rather than storing it, so the map holds
 * only sessions that would actually lose something — and so a session whose
 * pane has closed leaves nothing behind for the next session to inherit if the
 * core reuses its id.
 */
export function reportLiveTransfers(sessionId: number, count: number): void {
  if (count <= 0) live.delete(sessionId);
  else live.set(sessionId, count);
}

/** Stops reporting for a session, for a pane that is going away. */
export function forgetLiveTransfers(sessionId: number): void {
  live.delete(sessionId);
}

/**
 * Transfers this session would interrupt. Zero for a session with no pane open,
 * which is the ordinary case and is not a guess: with no pane there is no SFTP
 * channel on the session and therefore nothing queued on it.
 */
export function liveTransfersFor(sessionId: number | null): number {
  if (sessionId === null) return 0;
  return live.get(sessionId) ?? 0;
}

/** Drops every entry. For tests, which must not inherit each other's panes. */
export function resetLiveTransfers(): void {
  live.clear();
}
