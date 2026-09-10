/**
 * One registry, one listener.
 *
 * Before this there was a `keydown` listener per component — the palette had
 * one, the shell had one, the session surface had one — and each carried its
 * own idea of when a terminal, a modal or a text field should win. That is why
 * the settings table drifted away from reality: nothing tied the list of
 * bindings to the code that fires them, so a row could be written for a key
 * nobody had bound and no test or type could notice.
 *
 * Now a component declares handlers for the actions it owns, the ownership is
 * checked by the type system (`ActionIdOwnedBy`), and exactly one window-level
 * listener decides what fires. A handler of `null` means "not available right
 * now" — the keystroke is left alone and reaches whatever was going to get it.
 */

import { useEffect, useRef, useState } from "react";
import { create } from "zustand";
import { useQuery } from "@tanstack/react-query";

import { ipc } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { acceleratorFromEvent, isTypeableChord, normalisePrefix } from "./accelerator";
import {
  DEFAULT_TERMINAL_PREFIX,
  isRegistryOwned,
  type ActionIdOwnedBy,
  type RegistryOwner,
  type ShortcutActionId,
} from "./actions";
import { matchesChord, resolveShortcuts, type ShortcutOverrides } from "./resolve";

/** What a handler is told about the keystroke that reached it. */
export interface ShortcutEvent {
  actionId: ShortcutActionId;
  /** The binding as stored, before the prefix was applied. */
  accelerator: string;
  /**
   * Which key of a series fired: 0 for `Alt+1`, 8 for `Alt+9`. Always 0 for a
   * binding that covers one key.
   */
  seriesIndex: number;
}

/**
 * An action's handler, or `null` while the action cannot be performed.
 *
 * `null` is not "ignore the key" — it is "this window has nothing to do with
 * that keystroke", so the key is not swallowed. Full-screening a session with
 * no session open must leave `F11` to whatever else wants it.
 */
export type ShortcutHandler = ((event: ShortcutEvent) => void) | null;

type OwnerLookup = (id: string) => ShortcutHandler;

interface RegistryState {
  /**
   * Owner to lookup. The lookup reads the component's latest handlers, so a
   * handler that closes over changing state is never stale at fire time.
   */
  lookups: Readonly<Record<string, OwnerLookup>>;
  attach: (owner: string, lookup: OwnerLookup) => void;
  detach: (owner: string) => void;
}

export const useKeyboardRegistry = create<RegistryState>((set) => ({
  lookups: {},
  attach: (owner, lookup) =>
    set((state) => ({ lookups: { ...state.lookups, [owner]: lookup } })),
  detach: (owner) =>
    set((state) => {
      if (!(owner in state.lookups)) return {};
      const next = { ...state.lookups };
      delete next[owner];
      return { lookups: next };
    }),
}));

/** The handler for an action right now, or `null` when there is none. */
export function handlerFor(owner: string, actionId: string): ShortcutHandler {
  const lookup = useKeyboardRegistry.getState().lookups[owner];
  return lookup === undefined ? null : lookup(actionId);
}

/**
 * Declares the handlers for every action this owner is responsible for.
 *
 * The `Record` is exhaustive by type: adding an action to the catalogue with
 * `owner: "shell"` fails the build until `MainWindow` gives it a handler. That
 * is the check that keeps the settings table honest — a documented action with
 * nothing behind it cannot compile.
 */
export function useShortcutGroup<O extends RegistryOwner>(
  owner: O,
  handlers: Record<ActionIdOwnedBy<O>, ShortcutHandler>,
): void {
  const latest = useRef(handlers);
  // After every render, so a handler that reads changing state is current when
  // the key is pressed. Writing the ref during render would make a discarded
  // render's handlers visible to the listener.
  useEffect(() => {
    latest.current = handlers;
  });

  const attach = useKeyboardRegistry((state) => state.attach);
  const detach = useKeyboardRegistry((state) => state.detach);

  useEffect(() => {
    attach(owner, (id) => {
      const table = latest.current as Record<string, ShortcutHandler>;
      return table[id] ?? null;
    });
    return () => detach(owner);
  }, [owner, attach, detach]);
}

/** No overrides, as one object, so an unchanged read keeps its identity. */
const NO_OVERRIDES: ShortcutOverrides = {};

export interface KeyboardSettings {
  /** Canonical, modifiers only. */
  prefix: string;
  overrides: ShortcutOverrides;
  /** False until the core has answered; the shipped map is used until then. */
  loaded: boolean;
}

/**
 * The stored map and the terminal prefix.
 *
 * Read through TanStack Query under the shared settings key, so the settings
 * screen writing a binding updates the listener in the same tick rather than
 * on the next restart.
 */
export function useKeyboardSettings(): KeyboardSettings {
  const query = useQuery({ queryKey: qk.settings(), queryFn: ipc.getSettings });
  const data = query.data;
  return {
    prefix: normalisePrefix(data?.terminalPrefix ?? "") ?? DEFAULT_TERMINAL_PREFIX,
    overrides: data?.shortcuts ?? NO_OVERRIDES,
    loaded: data !== undefined,
  };
}

/**
 * Whether the keystroke would otherwise be typed into something.
 *
 * A binding with no `Ctrl`, `Alt` or `Meta` is a character someone may be
 * trying to type, and a settings screen that ate the `?` out of a search box
 * would be worse than having no cheat-sheet key at all.
 */
function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  if (target.closest('[contenteditable="true"], [contenteditable=""]') !== null) return true;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT";
}

/**
 * The one window-level listener.
 *
 * `isTerminalFocused` is passed in rather than imported so this module stays
 * below the session feature — and so a test can put the dispatcher in a
 * terminal without an xterm instance.
 */
export function useShortcutDispatcher(isTerminalFocused: () => boolean): void {
  const { prefix, overrides } = useKeyboardSettings();

  useEffect(() => {
    const resolved = resolveShortcuts(overrides).filter((entry) =>
      isRegistryOwned(entry.action),
    );

    const onKeyDown = (event: KeyboardEvent) => {
      // Something nearer the key already dealt with it — the tree's own F2, a
      // dialog's Escape. Two handlers acting on one keystroke is how the same
      // press opened two editors on two different nodes.
      if (event.defaultPrevented) return;
      // A modal owns the keyboard while it is up. Toggling a panel the user
      // cannot see, or opening a second focus trap over the first, is a change
      // they did not ask for and cannot undo without closing the dialog.
      if (useApp.getState().openModals.size > 0) return;

      const chord = acceleratorFromEvent(event);
      if (chord === null) return;

      const terminal = isTerminalFocused();
      const typing = !terminal && isTypingTarget(event.target);

      for (const entry of resolved) {
        if (typing && isTypeableChord(entry.accelerator)) continue;
        const match = matchesChord(entry, chord, terminal, prefix);
        if (!match.matched) continue;

        const run = handlerFor(entry.action.owner, entry.action.id);
        // Nothing can perform it at this moment, so the key is left alone
        // rather than swallowed by an action that would do nothing.
        if (run === null) continue;

        event.preventDefault();
        run({
          actionId: entry.action.id as ShortcutActionId,
          accelerator: entry.accelerator,
          seriesIndex: match.seriesIndex,
        });
        return;
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [overrides, prefix, isTerminalFocused]);
}

/**
 * Whether the keyboard is inside a terminal right now, as React state.
 *
 * The dispatcher asks the probe directly at fire time; this is for the parts
 * of the interface that have to *show* the answer, which is the status bar.
 */
export function useTerminalFocused(isTerminalFocused: () => boolean): boolean {
  const [focused, setFocused] = useState(false);

  useEffect(() => {
    const update = () => setFocused(isTerminalFocused());
    update();

    // `focusout` fires before the new element has focus, so reading the
    // document then would report "no terminal" for one frame every time focus
    // moves within one. Deferring lets the matching `focusin` land first.
    const timers: number[] = [];
    const deferred = () => {
      timers.push(window.setTimeout(update, 0));
    };

    document.addEventListener("focusin", update);
    document.addEventListener("focusout", deferred);
    window.addEventListener("blur", deferred);
    return () => {
      for (const timer of timers) window.clearTimeout(timer);
      document.removeEventListener("focusin", update);
      document.removeEventListener("focusout", deferred);
      window.removeEventListener("blur", deferred);
    };
  }, [isTerminalFocused]);

  return focused;
}
