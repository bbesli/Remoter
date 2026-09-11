/**
 * Query keys for the vault administration surface.
 *
 * These belong beside `qk` in lib/queryKeys.ts, for exactly the reason that
 * file gives: a key literal written at a call site is how the tree and the
 * inspector once ended up reading two different caches for the same node. They
 * are declared here only because this screen was built while another change
 * owned that file. The discipline is unchanged — a component never writes a
 * key, it calls a builder — and folding these two builders into `qk` is a
 * rename with no behaviour in it.
 *
 * The `"vault"` prefix is shared with `qk.vaultState()` on purpose. Adding or
 * revoking a slot changes what the footer counts and whether the KDF upgrade
 * offer still applies, so the two are invalidated together and never
 * separately.
 */

import type { QueryClient } from "@tanstack/react-query";

import { qk } from "@/lib/queryKeys";

export const vaultAdminKeys = {
  /** The open vault's key slots. */
  slots: () => ["vault", "slots"] as const,
  /** The settings stored in the vault file rather than on this machine. */
  settings: () => ["vault", "settings"] as const,
} as const;

/**
 * Invalidates everything a change to the slot table can affect.
 *
 * A slot write also rewrites the vault header, which is where the backup count
 * and the KDF parameters live — so the settings read is stale afterwards too,
 * and hand-picking two of the three keys is how a screen ends up showing a
 * slot that no longer exists.
 */
export async function invalidateAfterSlotChange(client: QueryClient): Promise<void> {
  await Promise.all([
    client.invalidateQueries({ queryKey: vaultAdminKeys.slots() }),
    client.invalidateQueries({ queryKey: vaultAdminKeys.settings() }),
    client.invalidateQueries({ queryKey: qk.vaultState() }),
  ]);
}
