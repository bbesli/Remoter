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
   * Every directory this pane has read, as a prefix of the one above.
   *
   * For the case where something changed on the server and the pane does not
   * know which folder it landed in: a finished upload is in the folder it was
   * sent to, which is usually but not always the one on screen.
   */
  sftpListings: (paneId: number) => ["sftp", paneId, "listing"] as const,
  /**
   * The pane's transfer list.
   *
   * For the first paint and for reconciling after a tab switch. A running
   * transfer's progress does not come from here; see
   * `features/files/queue.ts`.
   */
  sftpTransfers: (paneId: number) => ["sftp", paneId, "transfers"] as const,
  /**
   * One entry's own metadata, read fresh rather than taken from the listing.
   *
   * Under the pane's prefix and under `listing`'s sibling rather than its
   * child, so the stat of a path is invalidated by anything that changes the
   * pane and not by a directory being re-read. The path is the raw one, for
   * the reason {@link sftpListing} gives.
   */
  sftpStat: (paneId: number, path: string) => ["sftp", paneId, "stat", path] as const,
  /**
   * Where a symbolic link points, without following it.
   *
   * Its own key rather than part of the stat above, because they are different
   * questions: `sftp_stat` follows the link and this one does not, and a dialog
   * showing a link needs both answers.
   */
  sftpLinkTarget: (paneId: number, path: string) => ["sftp", paneId, "link", path] as const,
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
 * Invalidates only the directories a pane has read, leaving its queue alone.
 *
 * For the one case where {@link invalidatePane} is the wrong tool: a transfer
 * that just finished changed the folder it landed in, and the thing that
 * noticed is the transfer list itself. Invalidating that list from inside its
 * own subscriber would refetch it and notice again.
 */
export async function invalidateListings(client: QueryClient, paneId: number): Promise<void> {
  await client.invalidateQueries({ queryKey: qk.sftpListings(paneId) });
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

// ------------------------------------------------------- the lock boundary --

/**
 * The key prefixes whose answers do NOT come from inside the vault.
 *
 * This list is deliberately the *short* one, and the boundary is drawn as
 * default-deny: {@link isVaultScoped} treats every key not matched here as
 * vault data, so a query added tomorrow — in this file, in
 * `features/audit/queryKeys.ts`, in `features/vaultsettings/keys.ts`, or in a
 * feature that does not exist yet — is cleared when the vault locks without
 * anyone remembering to come back here and add it.
 *
 * That direction matters. The opposite list — "here is everything to wipe" —
 * is the one this application shipped, as `queryClient.clear()` on the lock
 * button and nothing at all on the idle timeout, and the failure it produced
 * is the one this comment exists to prevent: the vault locked itself after
 * fifteen minutes, the shell kept rendering the tree TanStack still held, and
 * every folder, server name and address in the estate stayed legible to
 * whoever walked up to the unattended machine. A lock that leaves the contents
 * on screen is not a lock.
 *
 * Each entry is a prefix, compared element by element, so `["vault", "probe"]`
 * covers `qk.vaultProbe(path)` for every path.
 *
 *   - `["vault", "state"]`  — whether a vault is open. Clearing the fact of
 *     the lock along with everything the lock is hiding would leave the shell
 *     unable to say why it emptied.
 *   - `["vault", "probe"]`  — the cleartext header: label, slots, KDF cost,
 *     backups. Read without any key, and the unlock screen's whole content —
 *     so wiping it would replace the way back in with a spinner.
 *   - `["vault", "recents"]` — this machine's own list of files. Not the
 *     vault's, and the picker needs it while nothing is open.
 *   - `["settings"]`        — this installation's preferences: theme, language,
 *     key bindings. Wiping these dropped the reader back into English for a
 *     frame on every lock.
 *   - `["protocols"]`       — the adapters' settings schemas. A property of the
 *     build, fixed for the life of the process.
 *   - `["appVersion"]`      — likewise: a build constant.
 *
 * Note what is NOT here: `["vault", "slots"]` and `["vault", "settings"]` from
 * `features/vaultsettings/keys.ts` share the `"vault"` head but are read out
 * of the open vault, so they go when it locks. That is why these are prefixes
 * matched in full rather than a set of first segments.
 */
const VAULT_INDEPENDENT_PREFIXES: readonly (readonly unknown[])[] = [
  ["vault", "state"],
  ["vault", "probe"],
  ["vault", "recents"],
  ["settings"],
  ["protocols"],
  ["appVersion"],
];

/** Does `key` begin with every element of `prefix`? */
function hasPrefix(key: readonly unknown[], prefix: readonly unknown[]): boolean {
  return prefix.length <= key.length && prefix.every((part, i) => key[i] === part);
}

/**
 * Was this query's answer read out of the open vault?
 *
 * True for everything except the prefixes above — see why the default runs
 * that way round in {@link VAULT_INDEPENDENT_PREFIXES}.
 */
export function isVaultScoped(key: readonly unknown[]): boolean {
  return !VAULT_INDEPENDENT_PREFIXES.some((prefix) => hasPrefix(key, prefix));
}

/**
 * Drops every cached answer that came out of the vault.
 *
 * `removeQueries`, not `invalidateQueries`: invalidation marks data stale and
 * keeps rendering it until a refetch lands, which against a locked vault never
 * does — the tree would stay on screen for as long as the window was open.
 * Removal takes the data out of the cache, so an observer still mounted falls
 * back to its pending state with nothing to draw.
 *
 * Not `client.clear()` either, which is what the lock button used to call: it
 * also threw away the language, the theme and the key bindings, and — worse —
 * the vault header the unlock screen needs to draw itself.
 */
export function clearVaultScopedQueries(client: QueryClient): void {
  client.removeQueries({ predicate: (query) => isVaultScoped(query.queryKey) });
}
