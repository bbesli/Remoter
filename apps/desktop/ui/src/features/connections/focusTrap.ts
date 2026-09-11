/**
 * A focus trap for the overlays in this feature.
 *
 * `role="dialog" aria-modal="true"` is a promise to assistive technology that
 * the rest of the page is inert. Nothing in the browser enforces that promise:
 * without a trap, Tab walks straight out of the sheet and into the tree behind
 * it while the screen reader still says the tree is not there. Every overlay
 * here therefore either traps focus or drops the attribute.
 *
 * This is deliberately not a dependency. The design system names Radix, but no
 * Radix primitive is installed, and pulling one in mid-milestone for thirty
 * lines of behaviour would mean re-styling every overlay it touches. The
 * design-system document is the thing that is wrong, not this file.
 */

import { useEffect, type RefObject } from "react";

/**
 * What the browser would put in the tab order. `[tabindex="-1"]` is excluded
 * on purpose: a container made focusable only so that focus has somewhere to
 * land is not a stop on the way round.
 */
const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

/** The tabbable elements inside `root`, in document order, minus the hidden. */
export function focusableWithin(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    // `getClientRects` is empty for anything display:none or visibility:hidden,
    // including an ancestor of it, which `offsetParent` would miss on a fixed
    // element — and every overlay here is fixed.
    (el) => el.getClientRects().length > 0,
  );
}

/**
 * Where Tab lands when it would otherwise leave the trap.
 *
 * Exported because the wrap is the whole behaviour and an off-by-one in it is
 * invisible until someone tabs off the end of a dialog.
 *
 * `current < 0` means focus is somewhere the trap does not know about — the
 * container itself, or an element that has since been removed — so Tab enters
 * at the near end rather than guessing.
 */
export function nextTrapIndex(count: number, current: number, backwards: boolean): number {
  if (count === 0) return -1;
  if (current < 0) return backwards ? count - 1 : 0;
  return backwards ? (current - 1 + count) % count : (current + 1) % count;
}

/**
 * Keeps keyboard focus inside `containerRef` while `active`.
 *
 * On activation focus moves in, because a dialog that opens behind the caret
 * is one a keyboard user has to hunt for. On deactivation it returns to
 * whatever held it before — the tree row, the menu item — so closing a dialog
 * puts the user back where they were rather than at the top of the document.
 *
 * The container should carry `tabIndex={-1}` so there is somewhere to land
 * when it holds nothing focusable yet, which is the case while a dialog is
 * still loading.
 */
export function useFocusTrap(active: boolean, containerRef: RefObject<HTMLElement | null>): void {
  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (container === null) return;

    const restoreTo = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    if (!container.contains(document.activeElement)) {
      const first = focusableWithin(container)[0];
      if (first !== undefined) first.focus();
      else container.focus();
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Tab") return;
      const items = focusableWithin(container);
      if (items.length === 0) {
        e.preventDefault();
        container.focus();
        return;
      }
      const current = items.findIndex((el) => el === document.activeElement);
      // Only the ends are intercepted. In the middle the browser's own order is
      // already right, and leaving it alone keeps anything this selector fails
      // to name — a custom control, a future component — reachable.
      const atEdge = current < 0 || (e.shiftKey ? current === 0 : current === items.length - 1);
      if (!atEdge) return;
      const next = items[nextTrapIndex(items.length, current, e.shiftKey)];
      if (next === undefined) return;
      e.preventDefault();
      next.focus();
    };

    // Capture: the tree and the palette both handle keys on their own
    // containers, and the trap has to win before they see the press.
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      if (restoreTo !== null && restoreTo.isConnected) restoreTo.focus();
    };
  }, [active, containerRef]);
}
