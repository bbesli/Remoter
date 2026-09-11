import { useCallback, useRef } from "react";

/**
 * Holds a secret-bearing request outside TanStack's mutation cache.
 *
 * TanStack keeps `mutation.state.variables` after a call settles, and the
 * retry paths in this application rely on that — they re-submit
 * `mutation.variables`. For an ordinary request that is convenient. For one
 * carrying a master password it means the plaintext stays reachable in memory
 * for the life of the cache, long after the call it was for.
 *
 * So the request is staged here instead: the mutation takes no variables, its
 * `mutationFn` reads the staged value, and retry re-runs against the same
 * staging rather than against the cache. `clear()` is called when the work is
 * done or the dialog is dismissed — the two moments after which the secret has
 * no further use.
 */
export interface StagedSecret<T> {
  /** Stage a request, replacing whatever was there. */
  stage: (value: T) => void;
  /** The staged request, or null. Throws nothing; the caller decides. */
  read: () => T | null;
  /** Whether something is staged, for enabling a retry control. */
  has: () => boolean;
  /** Drop it. Call this on success and on dismissal. */
  clear: () => void;
}

export function useStagedSecret<T>(): StagedSecret<T> {
  const held = useRef<T | null>(null);

  const stage = useCallback((value: T) => {
    held.current = value;
  }, []);
  const read = useCallback(() => held.current, []);
  const has = useCallback(() => held.current !== null, []);
  const clear = useCallback(() => {
    held.current = null;
  }, []);

  return { stage, read, has, clear };
}
