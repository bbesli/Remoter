/**
 * The one place query keys are defined.
 *
 * They were not, and it cost a real bug: the connection editor invalidated
 * `["nodes"]` and `["resolve", id]` while the shell read the same data from
 * `["tree", "list"]` and `["node", "resolve", id]`. Saving an edit therefore
 * updated the tree and left the status bar and inspector showing the old host,
 * port and username — for the rest of the session, because `refetchOnWindowFocus`
 * is off and nothing else would ever refetch them.
 *
 * Two rules follow, and both are checked in review:
 *   - Never write a key literal at a call site. Use these builders.
 *   - After a mutation, invalidate through `invalidateAfterTreeChange`, which
 *     knows the whole set. A mutation that hand-picks two of the four keys is
 *     how the bug above happened.
 */

import type { QueryClient } from "@tanstack/react-query";

export const qk = {
  /** Whether a vault is open, and its counters. */
  vaultState: () => ["vault", "state"] as const,
  /** A vault file's header, read without any key. */
  vaultProbe: (path: string) => ["vault", "probe", path] as const,
  /** Recently opened vaults, from this machine's own list. */
  recentVaults: () => ["vault", "recents"] as const,

  /** Every node in the open vault. */
  nodes: () => ["nodes"] as const,
  /** One node's inheritance resolved, with provenance. */
  resolve: (id: string) => ["nodes", "resolve", id] as const,
  /** A tree search, including the palette's. */
  search: (query: string) => ["nodes", "search", query] as const,

  /** Application settings. */
  settings: () => ["settings"] as const,

  /**
   * Every session the core has, as the core sees them.
   *
   * The tabs are the interface's own object and live in the sessions store;
   * this is the core's list, which the session panel shows so that a session
   * the interface has lost track of — one the vault's lock policy disconnected,
   * say — is still visible and still closeable.
   */
  sessions: () => ["sessions"] as const,
  /** Every running forward, with its live counters. */
  tunnels: () => ["tunnels"] as const,
} as const;

/**
 * Invalidates everything a change to the tree can affect.
 *
 * `["nodes"]` is a prefix of `resolve` and `search`, so one call covers all
 * three — which is the point of nesting them. The vault state is separate
 * because it carries the connection and credential counts shown in the footer.
 */
export async function invalidateAfterTreeChange(client: QueryClient): Promise<void> {
  await Promise.all([
    client.invalidateQueries({ queryKey: qk.nodes() }),
    client.invalidateQueries({ queryKey: qk.vaultState() }),
  ]);
}
