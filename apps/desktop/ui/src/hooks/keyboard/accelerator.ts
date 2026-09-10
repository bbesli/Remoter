/**
 * Accelerators, in one canonical spelling.
 *
 * The core normalises the same strings in `crates/remoter-ipc/src/state.rs`
 * (`normalise_accelerator`, `normalise_prefix`) and stores the result. If the
 * two sides disagreed about what "Shift+Ctrl+N" means, a binding saved here
 * would come back as a different binding — so the modifier aliases, the named
 * keys and the fixed modifier order below are deliberately the same lists as
 * the ones in that file. Change one, change both.
 *
 * Canonical form: modifiers in `ctrl, alt, shift, meta` order, then exactly one
 * key, all lower case, joined with `+`. `ctrl+shift+n`, `f11`, `alt+1`, `?`.
 */

/** The fixed order modifiers are written in. Not the order they were typed. */
export const MODIFIER_ORDER = ["ctrl", "alt", "shift", "meta"] as const;

export type Modifier = (typeof MODIFIER_ORDER)[number];

/**
 * Every spelling a modifier may arrive in, folded to its canonical one.
 *
 * Platform aliases collapse here so a binding made on a Mac reads the same on
 * a Linux machine — which is what makes the stored map portable between the
 * two rather than silently wrong on one of them.
 */
const MODIFIER_ALIASES: Readonly<Record<string, Modifier>> = {
  ctrl: "ctrl",
  control: "ctrl",
  alt: "alt",
  option: "alt",
  shift: "shift",
  meta: "meta",
  cmd: "meta",
  command: "meta",
  super: "meta",
  win: "meta",
};

/** The named keys an accelerator may end on, beside one character and f1–f24. */
const NAMED_KEYS: readonly string[] = [
  "tab",
  "space",
  "enter",
  "return",
  "escape",
  "backspace",
  "delete",
  "insert",
  "home",
  "end",
  "pageup",
  "pagedown",
  "up",
  "down",
  "left",
  "right",
];

/** How a `KeyboardEvent.key` for a named key is spelt in an accelerator. */
const EVENT_KEY_NAMES: Readonly<Record<string, string>> = {
  " ": "space",
  spacebar: "space",
  tab: "tab",
  enter: "enter",
  escape: "escape",
  esc: "escape",
  backspace: "backspace",
  delete: "delete",
  del: "delete",
  insert: "insert",
  home: "home",
  end: "end",
  pageup: "pageup",
  pagedown: "pagedown",
  arrowup: "up",
  arrowdown: "down",
  arrowleft: "left",
  arrowright: "right",
};

/** How each key cap is written on screen. Anything absent is upper-cased. */
const KEY_LABELS: Readonly<Record<string, string>> = {
  space: "Space",
  tab: "Tab",
  enter: "Enter",
  return: "Enter",
  escape: "Esc",
  backspace: "Backspace",
  delete: "Delete",
  insert: "Insert",
  home: "Home",
  end: "End",
  pageup: "Page Up",
  pagedown: "Page Down",
  up: "↑",
  down: "↓",
  left: "←",
  right: "→",
};

export interface ParsedAccelerator {
  /** In {@link MODIFIER_ORDER}, deduplicated. */
  modifiers: readonly Modifier[];
  /** Exactly one, lower case. */
  key: string;
}

/**
 * Case folding pinned to one locale.
 *
 * `toLowerCase` is locale-sensitive: in Turkish "I" folds to "ı", which would
 * turn `Ctrl+I` into a key the core rejects. Accelerators are ASCII, so a fixed
 * locale is both correct and stable.
 */
function fold(value: string): string {
  return value.toLocaleLowerCase("en-US");
}

/** Whether a part is a key an accelerator can end on. Mirrors `is_key` in Rust. */
export function isBindableKey(part: string): boolean {
  if ([...part].length === 1) return true;
  if (NAMED_KEYS.includes(part)) return true;
  const digits = part.startsWith("f") ? part.slice(1) : null;
  if (digits === null || digits === "" || !/^\d+$/.test(digits)) return false;
  const number = Number(digits);
  return number >= 1 && number <= 24;
}

/** Splits an accelerator into modifiers and key, or `null` if it is not one. */
export function parseAccelerator(text: string): ParsedAccelerator | null {
  const modifiers: Modifier[] = [];
  let key: string | null = null;

  for (const raw of text.split("+")) {
    const part = fold(raw.trim());
    if (part === "") return null;
    const modifier = MODIFIER_ALIASES[part];
    if (modifier !== undefined) {
      if (!modifiers.includes(modifier)) modifiers.push(modifier);
      continue;
    }
    // Two keys is not a shortcut, it is a sequence, and nothing here plays one.
    if (key !== null) return null;
    if (!isBindableKey(part)) return null;
    key = part;
  }

  if (key === null) return null;
  return { modifiers: MODIFIER_ORDER.filter((m) => modifiers.includes(m)), key };
}

/** Renders a parsed accelerator back into its canonical string. */
export function formatCanonical(parsed: ParsedAccelerator): string {
  return [...parsed.modifiers, parsed.key].join("+");
}

/** Canonicalises an accelerator, or returns `null` when it is not one. */
export function normaliseAccelerator(text: string): string | null {
  const parsed = parseAccelerator(text);
  return parsed === null ? null : formatCanonical(parsed);
}

/**
 * Canonicalises the terminal prefix, which is modifiers and nothing else.
 *
 * A prefix with a key in it would take that key from the session for every
 * shortcut at once, which is the opposite of what a prefix is for.
 */
export function normalisePrefix(text: string): string | null {
  const modifiers: Modifier[] = [];
  for (const raw of text.split("+")) {
    const part = fold(raw.trim());
    const modifier = MODIFIER_ALIASES[part];
    if (modifier === undefined) return null;
    if (!modifiers.includes(modifier)) modifiers.push(modifier);
  }
  if (modifiers.length === 0) return null;
  return MODIFIER_ORDER.filter((m) => modifiers.includes(m)).join("+");
}

/**
 * The same accelerator as it must be typed inside a focused terminal.
 *
 * The prefix is added to the accelerator's own modifiers rather than replacing
 * them, so `Ctrl+N` becomes `Ctrl+Alt+N` under the default prefix — one extra
 * modifier, not a different key to remember.
 */
export function withPrefix(accelerator: string, prefix: string): string {
  const parsed = parseAccelerator(accelerator);
  if (parsed === null) return accelerator;
  const extra = prefix.split("+").flatMap((part) => {
    const modifier = MODIFIER_ALIASES[fold(part.trim())];
    return modifier === undefined ? [] : [modifier];
  });
  const merged = MODIFIER_ORDER.filter(
    (m) => parsed.modifiers.includes(m) || extra.includes(m),
  );
  return formatCanonical({ modifiers: merged, key: parsed.key });
}

/**
 * The keys a series binding covers.
 *
 * "Jump to tab 1–9" is one action and nine keys: the stored accelerator is the
 * first of them and the rest follow by incrementing the digit. Conflict
 * detection has to see all nine, or binding `Alt+4` to something else would
 * read as free when it is not.
 */
export function seriesAccelerators(accelerator: string, seriesLen: number): string[] {
  const parsed = parseAccelerator(accelerator);
  if (parsed === null) return [accelerator];
  const first = Number(parsed.key);
  if (seriesLen <= 1 || parsed.key.length !== 1 || !Number.isInteger(first)) {
    return [formatCanonical(parsed)];
  }
  const out: string[] = [];
  for (let i = 0; i < seriesLen && first + i <= 9; i += 1) {
    out.push(formatCanonical({ modifiers: parsed.modifiers, key: String(first + i) }));
  }
  return out;
}

/**
 * How `meta` is written on this machine.
 *
 * `navigator.platform` is deprecated and `userAgentData` is not in every
 * WebView this ships to, so the user agent string decides. Getting it wrong
 * costs a wrong word on a key cap, never a wrong binding — the stored value is
 * `meta` either way.
 */
function metaLabel(): string {
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;
  return /mac|iphone|ipad/i.test(ua) ? "Cmd" : "Super";
}

const MODIFIER_LABELS: Readonly<Record<Modifier, () => string>> = {
  ctrl: () => "Ctrl",
  alt: () => "Alt",
  shift: () => "Shift",
  meta: metaLabel,
};

/**
 * One key cap per element, in order, for rendering as `<kbd>`.
 *
 * A series binding reads as its span — `Alt` `1…9` — because nine rows of one
 * key each would be nine rows describing one action.
 */
export function acceleratorCaps(accelerator: string, seriesLen = 1): string[] {
  const parsed = parseAccelerator(accelerator);
  if (parsed === null) return [accelerator];

  const caps = parsed.modifiers.map((m) => MODIFIER_LABELS[m]());
  const last = Number(parsed.key);
  if (seriesLen > 1 && parsed.key.length === 1 && Number.isInteger(last)) {
    const end = Math.min(9, last + seriesLen - 1);
    caps.push(`${String(last)}…${String(end)}`);
    return caps;
  }
  caps.push(KEY_LABELS[parsed.key] ?? parsed.key.toUpperCase());
  return caps;
}

/** The same, as one string — for a `title`, an `aria-label` or a test. */
export function acceleratorLabel(accelerator: string, seriesLen = 1): string {
  return acceleratorCaps(accelerator, seriesLen).join("+");
}

/** True while only modifier keys are down — nothing to bind yet. */
export function isModifierKey(key: string): boolean {
  return (
    key === "Control" ||
    key === "Alt" ||
    key === "Shift" ||
    key === "Meta" ||
    key === "AltGraph" ||
    key === "CapsLock" ||
    key === "OS"
  );
}

/**
 * The key part of a keyboard event, in accelerator spelling.
 *
 * `event.key` first, because that is what the user sees on their own layout.
 * `event.code` is the fallback for the case `event.key` cannot express: on some
 * layouts `Alt+1` reports a symbol rather than "1", and "jump to tab 1" has to
 * keep working there.
 */
function keyFromEvent(event: KeyboardEvent): string | null {
  if (isModifierKey(event.key)) return null;

  const named = EVENT_KEY_NAMES[fold(event.key)];
  if (named !== undefined) return named;

  const folded = fold(event.key);
  if (/^f([1-9]|1\d|2[0-4])$/.test(folded)) return folded;

  // Printable ASCII is what the user has written on their key, whatever the
  // layout is, so it wins. `Alt+A` on an AZERTY keyboard must stay `Alt+A`.
  const single = [...event.key].length === 1;
  if (single && /^[\x20-\x7e]$/.test(folded)) return folded;

  // Anything else — `Alt+1` reporting "¡" on a Mac layout, a dead key — falls
  // back to the physical key, so "jump to tab 1" keeps working there.
  const digit = /^Digit([0-9])$/.exec(event.code);
  if (digit?.[1] !== undefined) return digit[1];
  const letter = /^Key([A-Z])$/.exec(event.code);
  if (letter?.[1] !== undefined) return fold(letter[1]);

  return single ? folded : null;
}

/**
 * The canonical accelerator a keyboard event stands for, or `null` for one
 * that cannot be a binding on its own (a bare modifier, a dead key).
 *
 * Shift is dropped when the key is a symbol the shift key itself produced —
 * `?` is `?`, not `Shift+?`. Keeping it would mean the cheat-sheet binding the
 * core ships as `?` could never be typed.
 */
export function acceleratorFromEvent(event: KeyboardEvent): string | null {
  const key = keyFromEvent(event);
  if (key === null) return null;

  const symbol = [...key].length === 1 && !/[a-z0-9]/.test(key);
  const modifiers = MODIFIER_ORDER.filter((m) => {
    switch (m) {
      case "ctrl":
        return event.ctrlKey;
      case "alt":
        return event.altKey;
      case "shift":
        return event.shiftKey && !symbol;
      case "meta":
        return event.metaKey;
    }
  });

  return formatCanonical({ modifiers, key });
}

/**
 * Whether a chord would be swallowed by ordinary typing.
 *
 * A single character with no `Ctrl`, `Alt` or `Meta` is a character someone may
 * be trying to type. The dispatcher lets those through whenever a text field
 * has the keyboard, rather than turning `?` into a shortcut that eats a
 * question mark out of a search box.
 */
export function isTypeableChord(accelerator: string): boolean {
  const parsed = parseAccelerator(accelerator);
  if (parsed === null) return false;
  if (parsed.modifiers.some((m) => m !== "shift")) return false;
  return [...parsed.key].length === 1 || parsed.key === "space";
}
