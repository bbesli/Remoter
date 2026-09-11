/**
 * The keyboard module's public surface.
 *
 * Components declare handlers and read the map through here; nothing outside
 * reaches into a file of it. The one exception a reader should expect is the
 * settings screen, which needs the resolution and conflict functions in order
 * to describe — and edit — exactly what the listener will fire.
 */

export {
  acceleratorCaps,
  acceleratorFromEvent,
  acceleratorLabel,
  isModifierKey,
  normaliseAccelerator,
  normalisePrefix,
  withPrefix,
} from "./accelerator";

export {
  DEFAULT_TERMINAL_PREFIX,
  SHORTCUT_ACTIONS,
  TERMINAL_PREFIX_CHOICES,
  TERMINAL_RESERVED,
  findAction,
  isRegistryOwned,
  type ActionIdOwnedBy,
  type RegistryOwner,
  type ShortcutAction,
  type ShortcutActionId,
  type ShortcutScope,
} from "./actions";

export {
  checkBinding,
  coveredAccelerators,
  effectiveAccelerator,
  isCapturableChord,
  matchesChord,
  resolveShortcuts,
  type BindingRefusal,
  type ResolvedShortcut,
  type ShortcutConflict,
  type ShortcutOverrides,
} from "./resolve";

export {
  handlerFor,
  useKeyboardRegistry,
  useKeyboardSettings,
  useShortcutDispatcher,
  useShortcutGroup,
  useTerminalFocused,
  type KeyboardSettings,
  type ShortcutEvent,
  type ShortcutHandler,
} from "./registry";

export { StatusBarPrefixRow, TerminalPrefixIndicator } from "./PrefixIndicator";
