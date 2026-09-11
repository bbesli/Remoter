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

  /**
   * Every protocol's settings schema, as the adapters declare them.
   *
   * Not under `nodes`: a schema is the build's, not the vault's, so nothing a
   * tree change does can affect it. It is fixed for the life of the process
   * and wants a long `staleTime` rather than an invalidation.
   */
  protocolSchemas: () => ["protocols", "schemas"] as const,

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

  /**
   * Everything one SFTP file pane owns.
   *
   * A prefix of the two below, so closing a pane or acting on it invalidates
   * the listing and the transfer list together. The pane id is part of every
   * key because two panes on two hosts show two different `/home/deploy`.
   */
  sftpPane: (paneId: number) => ["sftp", paneId] as const,
  /**
   * One directory as that pane sees it.
   *
   * The path is the raw, server-supplied one — the same string that goes back
   * on the wire — and never the escaped display form, which would key two
   * genuinely different directories to one entry.
   */
  sftpListing: (paneId: number, path: string) => ["sftp", paneId, "listing", path] as const,
  /**
   * The pane's transfer list.
   *
   * For the first paint and for reconciling after a tab switch. A running
   * transfer's progress does not come from here; see
   * `features/files/queue.ts`.
   */
  sftpTransfers: (paneId: number) => ["sftp", paneId, "transfers"] as const,
} as const;

/**
 * Invalidates everything a change inside one file pane can affect.
 *
 * A rename shows up in the listing, a delete shows up in the listing, and a
 * queued transfer shows up in the transfer list — and a caller that picks one
 * of the two is how the tree's stale-inspector bug above happened, one layer
 * down.
 */
export async function invalidatePane(client: QueryClient, paneId: number): Promise<void> {
  await client.invalidateQueries({ queryKey: qk.sftpPane(paneId) });
}

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
