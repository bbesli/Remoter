/**
 * What the interface does when the vault locks under it.
 *
 * A locked vault is a state of the application, not a failed read. It used to
 * be the latter, and the difference was the whole defect: the owner walked
 * away for fifteen minutes, the core locked the vault, the next `list_nodes`
 * came back `vault.auto-locked` — and the shell drew that rejection as a red
 * card over the session area while the connection tree behind it went on
 * rendering the copy TanStack had cached before the lock. Every folder, every
 * server name and every address stayed on screen, in front of a machine its
 * owner had deliberately left. The card's "Try again" retried the read, which
 * is the one thing that cannot succeed against a locked vault.
 *
 * So: one transition, {@link enterLockedState}, and three things happen at
 * once.
 *
 *  1. Everything the vault fed is dropped from the query cache — see
 *     `clearVaultScopedQueries`, whose boundary is default-deny so a query
 *     added later is covered without anybody remembering this file.
 *  2. The shell is left behind for the unlock screen, which is where a locked
 *     vault belongs: it asks for the password rather than explaining that
 *     something could not be read. The screen carries a {@link RelockNotice}
 *     saying why it locked and what became of the sessions.
 *  3. The tree selection is dropped, because it names a node that is no longer
 *     readable.
 *
 * No secret passes through here. The password is typed on the unlock screen
 * and goes straight to the core; this module moves screens and forgets caches.
 */

import type { QueryClient } from "@tanstack/react-query";

import { asFailure } from "@/lib/ipc";
import { clearVaultScopedQueries } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useSessions } from "@/features/sessions";

/**
 * The `IpcFailure.code`s the core raises when a command needed an open vault
 * and did not have one.
 *
 * Raised in `crates/remoter-ipc/src/error.rs`; each has its sentence in
 * `locales/*\/errors.json` under `vault.*`. They are the interface's earliest
 * notice that the lock happened — sooner than the `vault_state` poll, which
 * runs on a thirty-second interval and so can be most of a minute behind.
 */
const LOCK_CODES: ReadonlyMap<string, LockReason> = new Map([
  ["vault.auto-locked", "idle"],
  ["vault.locked-by-trigger", "trigger"],
  ["vault.locked", "unknown"],
]);

/**
 * Why the vault is locked, as far as the interface can honestly tell.
 *
 * `unknown` is a real answer and is worded as one: `vault.locked` is raised
 * for "no vault is open" whatever put it in that state, and a poll that simply
 * finds `unlocked: false` carries no reason at all. Guessing "it timed out"
 * there would be a sentence the application cannot stand behind.
 */
export type LockReason = "idle" | "trigger" | "manual" | "unknown";

/** Was this rejection the core saying the vault is not open? */
export function lockReasonOf(error: unknown): LockReason | null {
  return LOCK_CODES.get(asFailure(error).code) ?? null;
}

/**
 * What became of the sessions that were open when the vault locked.
 *
 * Observed, never assumed. The vault's `sessionOnLock` policy would answer
 * this directly, but it is stored *inside* the vault and so is unreadable at
 * exactly the moment it is wanted. What the interface does have is its own tab
 * list, which the core's close events keep current — so the honest report is
 * "you had this many; this many are still connected", measured rather than
 * inferred from a policy nobody can read.
 */
export interface SessionsAtLock {
  /** Session tabs open at the moment the lock was noticed. */
  total: number;
  /** Of those, how many were still `running` a moment later. */
  running: number;
}

/** Why the unlock screen is showing, when it is showing because of a lock. */
export interface RelockNotice {
  reason: LockReason;
  sessions: SessionsAtLock;
}

/**
 * The tab list as it stands right now.
 *
 * Taken by the caller rather than inside {@link enterLockedState}, because the
 * two callers measure at different moments and both are right to. A lock the
 * core imposed is measured as the rejection lands, while the tabs are still
 * whatever the core left them. A lock the user asked for closes its sessions
 * first — deliberately, so no shell is left attached to a vault nobody is
 * watching — and has to count them before it does, or it would report nothing
 * open and tell the user nothing about the four terminals it just ended.
 */
export function captureSessions(): SessionsAtLock {
  const { order, byId } = useSessions.getState();
  return {
    total: order.length,
    running: order.filter((tabId) => byId[tabId]?.phase === "running").length,
  };
}

/**
 * Leave the shell for the unlock screen, taking the vault's contents with it.
 *
 * Idempotent by construction: several queries fail at once when a vault locks
 * — the tree, the resolve, the tunnel count — and each of them reports it. The
 * guard is the screen itself. Once the unlock screen is showing for this
 * vault, a second report changes nothing, so the first reason and the first
 * session count are the ones kept. They are also the accurate ones: by the
 * time the third rejection lands, the core may already have torn the sessions
 * down.
 *
 * With no path there is no vault to ask a password for — the core is not
 * holding one — so the picker is the destination instead.
 */
export function enterLockedState(
  client: QueryClient,
  path: string | null,
  reason: LockReason,
  sessions: SessionsAtLock,
): void {
  const app = useApp.getState();
  if (app.screen.name === "unlock" && app.screen.relock !== null) return;

  // Before the navigation, not after: the shell is still mounted, and an
  // observer that re-reads a vault-scoped key between the two would put the
  // tree back on screen for a frame.
  clearVaultScopedQueries(client);
  app.select(null);
  app.go(
    path === null
      ? { name: "picker" }
      : { name: "unlock", path, relock: { reason, sessions } },
  );
}
