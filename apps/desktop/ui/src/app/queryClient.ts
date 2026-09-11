/**
 * The one query client, built in one place.
 *
 * It is a factory rather than a module-level constant because the lock
 * detector below is the only thing standing between an idle timeout and a
 * connection tree left legible on an unattended screen — and a detector that
 * only exists in `main.tsx` is a detector no test can reach. `main.tsx` calls
 * this; so does every test that renders the application, which is what makes
 * the tests assert the behaviour the user gets rather than a mock of it.
 */

import { QueryCache, QueryClient } from "@tanstack/react-query";

import { qk } from "@/lib/queryKeys";
import type { VaultState } from "@/lib/ipc";
import { captureSessions, enterLockedState, lockReasonOf } from "@/features/vault/lock";

export function createQueryClient(): QueryClient {
  /*
   * The cache reports every rejection, so this catches the lock wherever it is
   * noticed — the tree read, the resolve, the tunnel count, the audit page, a
   * query some future feature adds. That breadth is the point: the shipped
   * version handled the lock in the one component that happened to render the
   * failure, which is why the tree, the inspector and the sidebar each drew
   * their own version of the same dead end.
   *
   * The handler needs the client that is about to be built *around* this
   * cache, so the reference arrives through a holder: the cache has to exist
   * before the client, and `onError` cannot fire until a query has been
   * observed, which cannot happen until both exist.
   */
  const self: { client: QueryClient | null } = { client: null };

  const queryCache = new QueryCache({
    onError: (error) => {
      const client = self.client;
      // Unreachable — nothing can observe a query before the constructor
      // below has returned — but typed rather than asserted.
      if (client === null) return;
      const reason = lockReasonOf(error);
      if (reason === null) return;
      const vault = client.getQueryData<VaultState>(qk.vaultState());
      // Measured here, while the tab list still holds whatever the core left
      // it — not inside the transition, which runs after the screen changes.
      enterLockedState(client, vault?.path ?? null, reason, captureSessions());
    },
  });

  const client = new QueryClient({
    queryCache,
    defaultOptions: {
      queries: {
        // The vault is local. Refetching on focus buys nothing and costs a
        // round trip through IPC on every window activation.
        refetchOnWindowFocus: false,
        retry: false,
        staleTime: 5_000,
      },
    },
  });

  self.client = client;
  return client;
}
