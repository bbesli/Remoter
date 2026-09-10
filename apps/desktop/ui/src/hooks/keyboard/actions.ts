/**
 * Every keyboard action this build has, in one array.
 *
 * This array is the single source of truth for three things that used to be
 * three separate lists and therefore drifted apart: what the settings table
 * shows, what the window listener dispatches, and what the core is asked to
 * store. The table is rendered *from* this array, so a row can no longer
 * document a binding nothing implements — the row and the binding are the same
 * record.
 *
 * The defaults and the `editable` flags mirror `SHORTCUTS` in
 * `crates/remoter-ipc/src/state.rs`. The core validates every write against
 * its own copy and rejects an id it does not carry, so an action marked
 * `editable: false` here is one the core genuinely cannot store — not a
 * preference. Where that is the case the row says so rather than offering a
 * control that would fail.
 */

import type { Modifier } from "./accelerator";

/**
 * How far a binding reaches.
 *
 * `universal` fires even inside a focused terminal; `application` is reached
 * through the terminal prefix while a session has the keyboard, because
 * `docs/ui/information-architecture.md` gives the session almost every
 * keystroke.
 */
export type ShortcutScope = "universal" | "application";

/**
 * Who binds the action.
 *
 * The first three are dispatched by this module's one window listener. The
 * rest exist so the settings table can say, truthfully, that an action is
 * reached some other way — or not at all.
 */
export type ShortcutOwner =
  /** The main window: the shell, the tree, the vault. */
  | "shell"
  /** The tab strip. */
  | "tabs"
  /** The command palette. */
  | "palette"
  /** The session view binds this one itself; it is not in the registry. */
  | "session-view"
  /** Fixed to one focused surface, not a global binding. */
  | "context"
  /** Nothing in this build is behind it. */
  | "none";

/** The owners whose actions this module's listener dispatches. */
export const REGISTRY_OWNERS = ["shell", "tabs", "palette"] as const;

export type RegistryOwner = (typeof REGISTRY_OWNERS)[number];

export interface ShortcutAction {
  /** Stable, dotted, ASCII. The core stores overrides under this id. */
  id: string;
  /** What the action does, as the settings table names it. */
  title: string;
  scope: ShortcutScope;
  /** Canonical, and equal to the core's shipped default for editable actions. */
  defaultAccelerator: string;
  /** How many consecutive keys the binding covers. Nine for "jump to tab 1–9". */
  seriesLen: number;
  owner: ShortcutOwner;
  /** True only when the core will store an override for this id. */
  editable: boolean;
  /**
   * Why it cannot be rebound, when it cannot. Shown in the row: an editor that
   * refused the save afterwards would be a control that lied about itself.
   */
  unrebindableReason: string | null;
  /**
   * What the row must say about where this binding does and does not fire.
   * `null` when the plain scope description is the whole truth.
   */
  reachNote: string | null;
  /** Set when the desktop environment takes the combination first and wins. */
  desktopConflict: boolean;
}

/**
 * Keystrokes a focused terminal has to receive.
 *
 * Same list as `TERMINAL_RESERVED` in the core. Binding one of these sends an
 * interrupt to this window instead of to the remote shell, which is a
 * data-loss bug wearing a preferences dialogue.
 */
export const TERMINAL_RESERVED: readonly string[] = ["ctrl+c", "ctrl+d", "alt+f"];

/** The prefix the core ships. Used until `settings_get` has answered. */
export const DEFAULT_TERMINAL_PREFIX = "ctrl+alt";

/**
 * The prefixes this screen offers.
 *
 * Modifiers only — the core rejects anything else — and never a bare `Shift`,
 * which would take every shifted character from the session.
 */
export const TERMINAL_PREFIX_CHOICES: readonly { value: string; modifiers: readonly Modifier[] }[] =
  [
    { value: "ctrl+alt", modifiers: ["ctrl", "alt"] },
    { value: "ctrl+shift", modifiers: ["ctrl", "shift"] },
    { value: "alt+shift", modifiers: ["alt", "shift"] },
  ];

/**
 * The keyboard map, in the order `docs/features/connections.md` lists it.
 *
 * Every row of that table appears here, including the ones this build reaches
 * some other way and the one it does not reach at all. Leaving those out would
 * make the table shorter and less honest.
 */
export const SHORTCUT_ACTIONS = [
  {
    id: "palette.open",
    title: "Command palette and search",
    scope: "universal",
    defaultAccelerator: "ctrl+k",
    seriesLen: 1,
    owner: "palette",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "vault.lock",
    title: "Lock vault",
    scope: "universal",
    defaultAccelerator: "ctrl+l",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "shortcuts.cheatsheet",
    title: "Shortcut cheat sheet",
    scope: "universal",
    defaultAccelerator: "?",
    seriesLen: 1,
    owner: "none",
    editable: false,
    unrebindableReason:
      "There is nothing to rebind: this build has no cheat sheet, so no key opens one.",
    reachNote:
      "Not bound. This build has no cheat-sheet overlay — the table on this screen is the reference.",
    desktopConflict: false,
  },
  {
    id: "connection.new",
    title: "New connection",
    scope: "application",
    defaultAccelerator: "ctrl+n",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "folder.new",
    title: "New folder",
    scope: "application",
    defaultAccelerator: "ctrl+shift+n",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "connection.connect",
    title: "Connect selected",
    scope: "application",
    defaultAccelerator: "enter",
    seriesLen: 1,
    owner: "context",
    editable: false,
    unrebindableReason:
      "Enter belongs to whatever has focus — a button, a field, a list row — so it is not taken as a global binding and cannot be rebound here.",
    reachNote:
      "Enter connects from the command palette. In the connection tree it selects; connect with a double-click or the row's context menu.",
    desktopConflict: false,
  },
  {
    id: "node.edit",
    title: "Edit selected",
    scope: "application",
    defaultAccelerator: "f2",
    seriesLen: 1,
    owner: "shell",
    editable: false,
    unrebindableReason:
      "This build's settings file has no entry for it, so a change could not be stored. The binding works; it is fixed.",
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "tab.close",
    title: "Close tab",
    scope: "application",
    defaultAccelerator: "ctrl+w",
    seriesLen: 1,
    owner: "tabs",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "tab.next",
    title: "Next tab",
    scope: "application",
    defaultAccelerator: "ctrl+tab",
    seriesLen: 1,
    owner: "tabs",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    // The window switcher on some desktops takes this one, and Remoter yields
    // to the desktop rather than fighting it.
    desktopConflict: true,
  },
  {
    id: "tab.previous",
    title: "Previous tab",
    scope: "application",
    defaultAccelerator: "ctrl+shift+tab",
    seriesLen: 1,
    owner: "tabs",
    editable: false,
    unrebindableReason:
      "This build's settings file has no entry for it, so a change could not be stored. The binding works; it is fixed.",
    reachNote: null,
    desktopConflict: true,
  },
  {
    id: "tab.jump",
    title: "Jump to tab 1–9",
    scope: "application",
    defaultAccelerator: "alt+1",
    seriesLen: 9,
    owner: "tabs",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "sidebar.toggle",
    title: "Toggle sidebar",
    scope: "application",
    defaultAccelerator: "ctrl+b",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableReason: null,
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "inspector.toggle",
    title: "Toggle inspector",
    scope: "application",
    defaultAccelerator: "f4",
    seriesLen: 1,
    owner: "shell",
    editable: false,
    unrebindableReason:
      "This build's settings file has no entry for it, so a change could not be stored. The binding works; it is fixed.",
    reachNote: null,
    desktopConflict: false,
  },
  {
    id: "session.fullscreen",
    title: "Full screen session",
    scope: "application",
    defaultAccelerator: "f11",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableReason: null,
    reachNote: "Needs a session open: it full-screens the window around one.",
    desktopConflict: false,
  },
  {
    id: "terminal.find",
    title: "Find in the terminal",
    scope: "application",
    defaultAccelerator: "ctrl+shift+f",
    seriesLen: 1,
    owner: "session-view",
    editable: false,
    unrebindableReason:
      "The session view binds this one itself rather than through the shortcut map, so this screen cannot change it.",
    reachNote:
      "Works inside a focused terminal without the prefix: Ctrl+Shift chords belong to the terminal window, not to the remote shell.",
    desktopConflict: false,
  },
] as const satisfies readonly ShortcutAction[];

export type ShortcutActionId = (typeof SHORTCUT_ACTIONS)[number]["id"];

/** The ids one owner is responsible for registering a handler for. */
export type ActionIdOwnedBy<O extends RegistryOwner> = Extract<
  (typeof SHORTCUT_ACTIONS)[number],
  { owner: O }
>["id"];

/** Whether this module's listener is what dispatches an action. */
export function isRegistryOwned(action: ShortcutAction): boolean {
  return (REGISTRY_OWNERS as readonly string[]).includes(action.owner);
}

/** One action by id, or `undefined` for an id this build does not carry. */
export function findAction(id: string): ShortcutAction | undefined {
  return SHORTCUT_ACTIONS.find((action) => action.id === id);
}
