import { useEffect } from "react";

import { useApp } from "@/stores/app";

/**
 * Registers a modal surface while it is open, so global shortcuts can tell.
 *
 * Anything that traps focus or takes over the keyboard should call this. See
 * the note on `openModals` in the store for what went wrong without it.
 */
export function useModalRegistration(id: string, open: boolean): void {
  const pushModal = useApp((s) => s.pushModal);
  const popModal = useApp((s) => s.popModal);

  useEffect(() => {
    if (!open) return;
    pushModal(id);
    return () => popModal(id);
  }, [id, open, pushModal, popModal]);
}

/** True when any modal surface is open. */
export function useAnyModalOpen(): boolean {
  return useApp((s) => s.openModals.size > 0);
}

/**
 * Registers a modal that must not be dismissed while it is open.
 *
 * `atStake` is shown to the user if they try to close the window anyway — it
 * should name what would be lost, in their terms, not the mechanism.
 */
export function useBlockingModal(id: string, open: boolean, atStake: string): void {
  const push = useApp((s) => s.pushBlockingModal);
  const pop = useApp((s) => s.popBlockingModal);

  useEffect(() => {
    if (!open) return;
    push(id, atStake);
    return () => pop(id);
  }, [id, open, atStake, push, pop]);
}

/** What is at stake right now, or null when nothing is blocking. */
export function useBlockingReason(): string | null {
  return useApp((s) => {
    const first = s.blockingModals.values().next();
    return first.done === true ? null : first.value;
  });
}
