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
 *
 * What the table does *not* hold is the English. Every word a user reads here
 * — the action's name, and the sentences explaining a binding they cannot
 * change — lives in `locales/en/common.json` under `shortcut.`, and the table
 * carries the catalogue key instead. See {@link SHORTCUT_ACTIONS} for why the
 * lookup is a getter rather than a value.
 */

import { i18n } from "@/i18n";

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
  /** How many consecutive keys the binding covers. Nine for "jump to tab 1-9". */
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
 *
 * The three fields ending in `Key` are catalogue keys, not sentences: this is a
 * data table, and the words a user reads live in `locales/en/common.json` under
 * `shortcut.` like every other string in the interface. They are written out
 * rather than derived from the id so that a translator's key is greppable from
 * the catalogue back to the action it describes — and so that three actions can
 * share one explanation (`unrebindableNoSetting`) instead of carrying three
 * copies of the same sentence for nine translators to keep in step.
 */
const ACTION_DATA = [
  {
    id: "palette.open",
    titleKey: "paletteOpen.title",
    scope: "universal",
    defaultAccelerator: "ctrl+k",
    seriesLen: 1,
    owner: "palette",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "vault.lock",
    titleKey: "vaultLock.title",
    scope: "universal",
    defaultAccelerator: "ctrl+l",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "shortcuts.cheatsheet",
    titleKey: "shortcutsCheatsheet.title",
    scope: "universal",
    defaultAccelerator: "?",
    seriesLen: 1,
    owner: "none",
    editable: false,
    unrebindableKey: "shortcutsCheatsheet.unrebindable",
    reachNoteKey: "shortcutsCheatsheet.reachNote",
    desktopConflict: false,
  },
  {
    id: "connection.new",
    titleKey: "connectionNew.title",
    scope: "application",
    defaultAccelerator: "ctrl+n",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "folder.new",
    titleKey: "folderNew.title",
    scope: "application",
    defaultAccelerator: "ctrl+shift+n",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "connection.connect",
    titleKey: "connectionConnect.title",
    scope: "application",
    defaultAccelerator: "enter",
    seriesLen: 1,
    owner: "context",
    editable: false,
    unrebindableKey: "connectionConnect.unrebindable",
    reachNoteKey: "connectionConnect.reachNote",
    desktopConflict: false,
  },
  {
    id: "node.edit",
    titleKey: "nodeEdit.title",
    scope: "application",
    defaultAccelerator: "f2",
    seriesLen: 1,
    owner: "shell",
    editable: false,
    unrebindableKey: "unrebindableNoSetting",
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "tab.close",
    titleKey: "tabClose.title",
    scope: "application",
    defaultAccelerator: "ctrl+w",
    seriesLen: 1,
    owner: "tabs",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "tab.next",
    titleKey: "tabNext.title",
    scope: "application",
    defaultAccelerator: "ctrl+tab",
    seriesLen: 1,
    owner: "tabs",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    // The window switcher on some desktops takes this one, and Remoter yields
    // to the desktop rather than fighting it.
    desktopConflict: true,
  },
  {
    id: "tab.previous",
    titleKey: "tabPrevious.title",
    scope: "application",
    defaultAccelerator: "ctrl+shift+tab",
    seriesLen: 1,
    owner: "tabs",
    editable: false,
    unrebindableKey: "unrebindableNoSetting",
    reachNoteKey: null,
    desktopConflict: true,
  },
  {
    id: "tab.jump",
    titleKey: "tabJump.title",
    scope: "application",
    defaultAccelerator: "alt+1",
    seriesLen: 9,
    owner: "tabs",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "sidebar.toggle",
    titleKey: "sidebarToggle.title",
    scope: "application",
    defaultAccelerator: "ctrl+b",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "inspector.toggle",
    titleKey: "inspectorToggle.title",
    scope: "application",
    defaultAccelerator: "f4",
    seriesLen: 1,
    owner: "shell",
    editable: false,
    unrebindableKey: "unrebindableNoSetting",
    reachNoteKey: null,
    desktopConflict: false,
  },
  {
    id: "session.fullscreen",
    titleKey: "sessionFullscreen.title",
    scope: "application",
    defaultAccelerator: "f11",
    seriesLen: 1,
    owner: "shell",
    editable: true,
    unrebindableKey: null,
    reachNoteKey: "sessionFullscreen.reachNote",
    desktopConflict: false,
  },
  {
    id: "terminal.find",
    titleKey: "terminalFind.title",
    scope: "application",
    defaultAccelerator: "ctrl+shift+f",
    seriesLen: 1,
    owner: "session-view",
    editable: false,
    unrebindableKey: "terminalFind.unrebindable",
    reachNoteKey: "terminalFind.reachNote",
    desktopConflict: false,
  },
] as const satisfies readonly ShortcutActionData[];

/** One row of {@link ACTION_DATA}: structure, plus the keys of its copy. */
interface ShortcutActionData {
  readonly id: string;
  /** Under `shortcut.` in the `common` catalogue. */
  readonly titleKey: string;
  readonly scope: ShortcutScope;
  readonly defaultAccelerator: string;
  readonly seriesLen: number;
  readonly owner: ShortcutOwner;
  readonly editable: boolean;
  /** Under `shortcut.`, or `null` when the action can be rebound. */
  readonly unrebindableKey: string | null;
  /** Under `shortcut.`, or `null` when the scope says the whole truth. */
  readonly reachNoteKey: string | null;
  readonly desktopConflict: boolean;
}

/**
 * One `shortcut.` message out of the `common` catalogue.
 *
 * i18next types `t` against the literal keys of the catalogue, and these keys
 * are fields of the table above rather than literals at the call site — so the
 * cast is what the pattern costs. It is not a hole: `actions.test.ts` walks the
 * table and asserts that every key resolves to a real message, which is the
 * check the type would otherwise have performed.
 */
function message(key: string): string {
  return String(i18n().t(`shortcut.${key}` as never));
}

/**
 * The keyboard map, with its copy resolved.
 *
 * `title`, `unrebindableReason` and `reachNote` are getters rather than
 * strings, and that is deliberate. This array is module state, built once; the
 * language is not, and it can change while the settings table is on screen. A
 * getter reads the catalogue at the moment the row is rendered, so a table
 * memoised on the stored overrides — which is what the settings screen does —
 * still comes back in the new language on the render that follows the switch.
 * A snapshot taken at import time would be English for the life of the process.
 */
export const SHORTCUT_ACTIONS: readonly ShortcutAction[] = ACTION_DATA.map(
  (data): ShortcutAction => ({
    id: data.id,
    scope: data.scope,
    defaultAccelerator: data.defaultAccelerator,
    seriesLen: data.seriesLen,
    owner: data.owner,
    editable: data.editable,
    desktopConflict: data.desktopConflict,
    get title() {
      return message(data.titleKey);
    },
    get unrebindableReason() {
      return data.unrebindableKey === null ? null : message(data.unrebindableKey);
    },
    get reachNote() {
      return data.reachNoteKey === null ? null : message(data.reachNoteKey);
    },
  }),
);

export type ShortcutActionId = (typeof ACTION_DATA)[number]["id"];

/** The ids one owner is responsible for registering a handler for. */
export type ActionIdOwnedBy<O extends RegistryOwner> = Extract<
  (typeof ACTION_DATA)[number],
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
