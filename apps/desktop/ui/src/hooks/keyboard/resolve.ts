/**
 * Turning the catalogue plus the stored overrides into the map that is both
 * dispatched and displayed.
 *
 * Everything here is pure, and deliberately so: the settings table and the
 * window listener call the same functions on the same input, which is what
 * makes it impossible for the table to describe a binding the listener would
 * not fire.
 */

import {
  isBindableKey,
  normaliseAccelerator,
  parseAccelerator,
  seriesAccelerators,
  withPrefix,
} from "./accelerator";
import {
  SHORTCUT_ACTIONS,
  TERMINAL_RESERVED,
  findAction,
  type ShortcutAction,
} from "./actions";

/** Why a binding cannot be relied on as typed. */
export type ShortcutConflict =
  /** Another action holds the same keys. Only one of them can win. */
  | { kind: "duplicate"; withIds: string[]; withTitles: string[] }
  /** The remote host owns these keys; a focused terminal has to receive them. */
  | { kind: "terminal-reserved" }
  /** The desktop environment takes it first, and wins. */
  | { kind: "desktop" };

export interface ResolvedShortcut {
  action: ShortcutAction;
  /** The override if there is one, otherwise the shipped default. */
  accelerator: string;
  customised: boolean;
  /** `null` when the binding works as typed. */
  conflict: ShortcutConflict | null;
}

/** The overrides as the core stores them: action id to accelerator. */
export type ShortcutOverrides = Readonly<Record<string, string>>;

/**
 * Whether an action's keys can actually fire.
 *
 * An action nothing implements cannot collide with anything, so it must not be
 * reported as a duplicate — that would refuse a perfectly free combination and
 * name a phantom as the holder.
 */
function canFire(action: ShortcutAction): boolean {
  return action.owner !== "none";
}

/** Every key one resolved binding covers, series expanded. */
export function coveredAccelerators(entry: ResolvedShortcut): string[] {
  return seriesAccelerators(entry.accelerator, entry.action.seriesLen);
}

/**
 * The whole map, in the order `docs/features/connections.md` documents it.
 *
 * An override naming an accelerator this build cannot parse is ignored rather
 * than shown: the row falls back to the default, which is what the listener
 * would fire anyway.
 */
export function resolveShortcuts(overrides: ShortcutOverrides): ResolvedShortcut[] {
  const base = SHORTCUT_ACTIONS.map((action): ResolvedShortcut => {
    const stored = action.editable ? overrides[action.id] : undefined;
    const override = stored === undefined ? null : normaliseAccelerator(stored);
    const accelerator = override ?? action.defaultAccelerator;
    return {
      action,
      accelerator,
      customised: accelerator !== action.defaultAccelerator,
      conflict: null,
    };
  });

  return base.map((entry) => ({ ...entry, conflict: conflictFor(entry, base) }));
}

function conflictFor(entry: ResolvedShortcut, all: readonly ResolvedShortcut[]): ShortcutConflict | null {
  const mine = new Set(coveredAccelerators(entry));

  const clashes = canFire(entry.action)
    ? all.filter(
        (other) =>
          other.action.id !== entry.action.id &&
          canFire(other.action) &&
          coveredAccelerators(other).some((accelerator) => mine.has(accelerator)),
      )
    : [];

  // A duplicate is the one the user can fix on this screen, so it is named
  // first when a binding has more than one problem.
  if (clashes.length > 0) {
    return {
      kind: "duplicate",
      withIds: clashes.map((other) => other.action.id),
      withTitles: clashes.map((other) => other.action.title),
    };
  }
  if ([...mine].some((accelerator) => TERMINAL_RESERVED.includes(accelerator))) {
    return { kind: "terminal-reserved" };
  }
  if (entry.action.desktopConflict) return { kind: "desktop" };
  return null;
}

/** Why a proposed binding was not accepted. */
export type BindingRefusal =
  | { kind: "unknown-action" }
  | { kind: "not-editable"; reason: string }
  | { kind: "invalid"; text: string }
  | { kind: "terminal-reserved"; accelerator: string }
  | { kind: "duplicate"; accelerator: string; withId: string; withTitle: string };

/**
 * Checks a proposed binding before it is sent to the core.
 *
 * The core refuses a reserved combination too, and would simply report a
 * duplicate rather than refuse it. This refuses both, because a duplicate that
 * saves cleanly is a binding the user watches do nothing — the first action in
 * the map wins the key and the second silently never fires.
 */
export function checkBinding(
  actionId: string,
  text: string,
  overrides: ShortcutOverrides,
): BindingRefusal | null {
  const action = findAction(actionId);
  if (action === undefined) return { kind: "unknown-action" };
  if (!action.editable) {
    return { kind: "not-editable", reason: action.unrebindableReason ?? "" };
  }

  const accelerator = normaliseAccelerator(text);
  if (accelerator === null) return { kind: "invalid", text };

  // Mirrors the core: a universal binding may not take a key the remote shell
  // needs, because a universal binding fires inside a focused terminal.
  if (action.scope === "universal" && TERMINAL_RESERVED.includes(accelerator)) {
    return { kind: "terminal-reserved", accelerator };
  }

  const proposed: ResolvedShortcut = {
    action,
    accelerator,
    customised: accelerator !== action.defaultAccelerator,
    conflict: null,
  };
  const mine = new Set(coveredAccelerators(proposed));

  for (const other of resolveShortcuts(overrides)) {
    if (other.action.id === actionId || !canFire(other.action)) continue;
    if (!coveredAccelerators(other).some((one) => mine.has(one))) continue;
    return {
      kind: "duplicate",
      accelerator,
      withId: other.action.id,
      withTitle: other.action.title,
    };
  }

  return null;
}

/**
 * Whether a chord typed right now should fire this binding.
 *
 * Outside a session the accelerator is what it says it is. Inside a focused
 * terminal almost every keystroke belongs to the remote host, so an
 * application binding is reached only through the prefix — and a universal one
 * answers to either form, so that "prefix, then the key" is never wrong.
 */
export function matchesChord(
  entry: ResolvedShortcut,
  chord: string,
  terminalFocused: boolean,
  prefix: string,
): { matched: true; seriesIndex: number } | { matched: false } {
  const covered = coveredAccelerators(entry);

  const plain = covered.indexOf(chord);
  const prefixed = covered.findIndex((one) => withPrefix(one, prefix) === chord);

  if (!terminalFocused) {
    return plain >= 0 ? { matched: true, seriesIndex: plain } : { matched: false };
  }
  if (prefixed >= 0) return { matched: true, seriesIndex: prefixed };
  if (entry.action.scope === "universal" && plain >= 0) {
    return { matched: true, seriesIndex: plain };
  }
  return { matched: false };
}

/**
 * The keys a binding is typed with in the current context, for display.
 *
 * The status bar and the settings table both need this: inside a session
 * `Ctrl+N` is not `Ctrl+N`, and showing the unprefixed form there would be the
 * table telling the user something the application will not do.
 */
export function effectiveAccelerator(
  entry: ResolvedShortcut,
  terminalFocused: boolean,
  prefix: string,
): string {
  if (!terminalFocused || entry.action.scope === "universal") return entry.accelerator;
  return withPrefix(entry.accelerator, prefix);
}

/**
 * Whether a captured chord is worth offering as a binding at all.
 *
 * Rejected here rather than by the core so the capture control can say why
 * while the user is still holding the keyboard.
 */
export function isCapturableChord(accelerator: string): boolean {
  const parsed = parseAccelerator(accelerator);
  return parsed !== null && isBindableKey(parsed.key);
}
