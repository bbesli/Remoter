/**
 * A browser key event, translated into what the two framebuffer protocols want.
 *
 * This is the file `remoter_proto::InputEvent`'s documentation is about, and
 * the one place in the application where the user's keyboard layout is known.
 *
 * RDP carries a **PS/2 Set 1 make code** and lets the *server* apply the layout
 * (MS-RDPBCGR §2.2.8.1.1.3.1.1.1). RFB carries an **X11 keysym** with the
 * layout already applied by the client (RFC 6143 §7.5.4). Neither can be
 * derived from the other without the layout, and the layout lives here — so
 * `InputEvent::Key` carries both and each adapter takes the one it needs.
 *
 * The three fields of a `KeyboardEvent`, and what each is worth:
 *
 * - **`code`** is the physical key, independent of layout. `"KeyI"` is the key
 *   where `I` sits on a US keyboard whatever the user's layout prints on it.
 *   This is the scancode. {@link scancodeFor}.
 * - **`key`** is the character the layout produced — `"a"`, `"ı"`, `"Dead"`.
 *   This is the keysym. {@link keysymFor}.
 * - **`keyCode`** is neither, despite the name. It is deprecated, it varies by
 *   browser and by layout, and an adapter that treats it as a scancode types
 *   correctly on a US keyboard and wrongly on every other. It is named here
 *   only so that nobody reaches for it. Nothing in this file reads it.
 *
 * # The Turkish Q keyboard is the test
 *
 * On a Turkish Q layout the physical key at the US `I` position produces `ı`
 * (U+0131, dotless i), the key at `;` produces `ş`, and the key at `.`
 * produces `ç`. Those three alone break every shortcut that is wired to a
 * character instead of a position, and every keysym that is derived from a
 * scancode instead of from the layout. `keymap.test.ts` walks that layout key
 * by key, because "it works on my keyboard" is how this class of bug ships.
 *
 * # What is deliberately not here
 *
 * **Keysyms for keys that produce no character.** A bare modifier, a function
 * key, an arrow: `keysymFor` returns null for all of them, because
 * `InputEvent::Key` documents `keysym` as optional for exactly that reason and
 * `crates/remoter-proto-vnc/src/keymap.rs` fills them in from the scancode
 * itself. Producing them twice is how the two tables drift apart.
 *
 * **A dead key mid-composition.** `key` is `"Dead"` and no character has been
 * produced yet; the composed character arrives on the next event. Null is the
 * honest answer, and it is what the contract asks for.
 */

/** Bit 8 of a scancode: the key was reported with an `E0` prefix. */
export const EXTENDED = 0x100;

/** One notch of a wheel, matching RDP's `rotationUnits` and `WHEEL_DELTA`. */
export const WHEEL_DELTA = 120;

/**
 * Modifier bits, matching `remoter_proto::Modifiers` exactly.
 *
 * The three lock states are in the set because RDP synchronises latches
 * explicitly with a Client Synchronize Event (MS-RDPBCGR §2.2.8.1.1.3.1.1.5).
 * A session that never sends one types in the wrong case until the user
 * notices and presses Caps Lock twice.
 */
export const MOD_SHIFT = 1 << 0;
export const MOD_CONTROL = 1 << 1;
export const MOD_ALT = 1 << 2;
export const MOD_META = 1 << 3;
export const MOD_ALT_GRAPH = 1 << 4;
export const MOD_CAPS_LOCK = 1 << 5;
export const MOD_NUM_LOCK = 1 << 6;
export const MOD_SCROLL_LOCK = 1 << 7;

/** Pointer button bits, matching `remoter_proto::PointerButtons` exactly. */
export const BUTTON_LEFT = 1 << 0;
export const BUTTON_RIGHT = 1 << 1;
export const BUTTON_MIDDLE = 1 << 2;
export const BUTTON_BACK = 1 << 3;
export const BUTTON_FORWARD = 1 << 4;

/**
 * `KeyboardEvent.code` to a PS/2 Set 1 make code.
 *
 * The `E0` prefix is bit 8, which is the convention `InputEvent::Key`
 * documents and the one MS-RDPBCGR encodes as `KBDFLAGS_EXTENDED` beside an
 * 8-bit code: right Control is `0x11d`, left Control is `0x1d`. A client that
 * drops the bit makes the right-hand modifiers behave as the left-hand ones.
 */
const SCANCODES: Readonly<Record<string, number>> = {
  Escape: 0x01,
  Digit1: 0x02,
  Digit2: 0x03,
  Digit3: 0x04,
  Digit4: 0x05,
  Digit5: 0x06,
  Digit6: 0x07,
  Digit7: 0x08,
  Digit8: 0x09,
  Digit9: 0x0a,
  Digit0: 0x0b,
  Minus: 0x0c,
  Equal: 0x0d,
  Backspace: 0x0e,
  Tab: 0x0f,
  KeyQ: 0x10,
  KeyW: 0x11,
  KeyE: 0x12,
  KeyR: 0x13,
  KeyT: 0x14,
  KeyY: 0x15,
  KeyU: 0x16,
  KeyI: 0x17,
  KeyO: 0x18,
  KeyP: 0x19,
  BracketLeft: 0x1a,
  BracketRight: 0x1b,
  Enter: 0x1c,
  ControlLeft: 0x1d,
  KeyA: 0x1e,
  KeyS: 0x1f,
  KeyD: 0x20,
  KeyF: 0x21,
  KeyG: 0x22,
  KeyH: 0x23,
  KeyJ: 0x24,
  KeyK: 0x25,
  KeyL: 0x26,
  Semicolon: 0x27,
  Quote: 0x28,
  Backquote: 0x29,
  ShiftLeft: 0x2a,
  Backslash: 0x2b,
  KeyZ: 0x2c,
  KeyX: 0x2d,
  KeyC: 0x2e,
  KeyV: 0x2f,
  KeyB: 0x30,
  KeyN: 0x31,
  KeyM: 0x32,
  Comma: 0x33,
  Period: 0x34,
  Slash: 0x35,
  ShiftRight: 0x36,
  NumpadMultiply: 0x37,
  AltLeft: 0x38,
  Space: 0x39,
  CapsLock: 0x3a,
  F1: 0x3b,
  F2: 0x3c,
  F3: 0x3d,
  F4: 0x3e,
  F5: 0x3f,
  F6: 0x40,
  F7: 0x41,
  F8: 0x42,
  F9: 0x43,
  F10: 0x44,
  NumLock: 0x45,
  ScrollLock: 0x46,
  // The keypad, in the order Set 1 lays it out: 7 8 9 - 4 5 6 + 1 2 3 0 .
  Numpad7: 0x47,
  Numpad8: 0x48,
  Numpad9: 0x49,
  NumpadSubtract: 0x4a,
  Numpad4: 0x4b,
  Numpad5: 0x4c,
  Numpad6: 0x4d,
  NumpadAdd: 0x4e,
  Numpad1: 0x4f,
  Numpad2: 0x50,
  Numpad3: 0x51,
  Numpad0: 0x52,
  NumpadDecimal: 0x53,
  // The 102nd key: the extra one between left Shift and Z on every European
  // keyboard, including the Turkish ones. It is not Backslash, and a table
  // that omits it drops a key that types `<` and `>`.
  IntlBackslash: 0x56,
  // F11 and F12 sit apart from F1..F10: they were added later.
  F11: 0x57,
  F12: 0x58,
  NumpadEqual: 0x59,
  F13: 0x64,
  F14: 0x65,
  F15: 0x66,
  F16: 0x67,
  F17: 0x68,
  F18: 0x69,
  F19: 0x6a,
  F20: 0x6b,
  F21: 0x6c,
  F22: 0x6d,
  F23: 0x6e,
  F24: 0x76,
  // Japanese and Korean keys. Present because a keyboard that has them sends
  // them, and an unmapped key is a key that does nothing.
  KanaMode: 0x70,
  IntlRo: 0x73,
  Convert: 0x79,
  NonConvert: 0x7b,
  IntlYen: 0x7d,
  Lang2: 0xf1,
  Lang1: 0xf2,

  // --- reported with an E0 prefix ---
  NumpadEnter: EXTENDED | 0x1c,
  ControlRight: EXTENDED | 0x1d,
  NumpadDivide: EXTENDED | 0x35,
  PrintScreen: EXTENDED | 0x37,
  AltRight: EXTENDED | 0x38,
  // Pause is the one key PS/2 sends with an `E1` prefix rather than `E0`, and
  // the scancode field has no way to say so. `0x146` is the value
  // `crates/remoter-proto-vnc/src/keymap.rs` maps to `XK_Pause`, so it is the
  // value this table produces — one convention, chosen in one place, rather
  // than two tables that disagree about the same key.
  Pause: EXTENDED | 0x46,
  Home: EXTENDED | 0x47,
  ArrowUp: EXTENDED | 0x48,
  PageUp: EXTENDED | 0x49,
  ArrowLeft: EXTENDED | 0x4b,
  ArrowRight: EXTENDED | 0x4d,
  End: EXTENDED | 0x4f,
  ArrowDown: EXTENDED | 0x50,
  PageDown: EXTENDED | 0x51,
  Insert: EXTENDED | 0x52,
  Delete: EXTENDED | 0x53,
  MetaLeft: EXTENDED | 0x5b,
  MetaRight: EXTENDED | 0x5c,
  ContextMenu: EXTENDED | 0x5d,
};

/**
 * The scancode for a physical key, or null for one this table does not name.
 *
 * Null rather than a guess. A vendor key, a multimedia key or a keyboard nobody
 * here has seen produces nothing, which is quieter than pressing whichever key
 * happens to sit at an invented code.
 */
export function scancodeFor(code: string): number | null {
  return SCANCODES[code] ?? null;
}

/** The largest keysym in the Unicode range X11 defines. */
const MAX_UNICODE_KEYSYM = 0x0100_0000 + 0x0010_ffff;

/** The offset the X keysym encoding puts a Unicode code point at. */
const UNICODE_KEYSYM_BASE = 0x0100_0000;

/**
 * The X11 keysym the user's layout produced, or null where it produced nothing.
 *
 * Latin-1 characters are their own keysym; everything else takes the
 * `0x01000000 + code point` form. That is the encoding `InputEvent::Key`
 * specifies, and it is what makes `ı` reach a VNC server as U+0131 rather than
 * as the `i` that sits at the same physical position.
 *
 * Null for anything that is not a single character: `"Shift"`, `"F5"`,
 * `"ArrowLeft"`, `"Dead"`, `"Unidentified"`, `"Process"`. Those are filled in
 * from the scancode by the VNC adapter's own table.
 */
export function keysymFor(key: string): number | null {
  // Not `key.length === 1`: an emoji or any astral character is two UTF-16
  // code units and is still one character the layout produced.
  const points = [...key];
  const only = points[0];
  if (points.length !== 1 || only === undefined) return null;

  const code = only.codePointAt(0);
  if (code === undefined) return null;

  // C0 controls are never what a layout produced: they are what a browser
  // reports for Enter, Tab and Escape on some platforms, and those have
  // keysyms of their own that come from the scancode.
  if (code < 0x20) return null;
  // Latin-1 is its own keysym; DEL and the C1 block are not printable.
  if (code <= 0xff) return code >= 0x7f && code <= 0x9f ? null : code;

  const keysym = UNICODE_KEYSYM_BASE + code;
  return keysym <= MAX_UNICODE_KEYSYM ? keysym : null;
}

/** What a key event needs to be asked about its modifiers. */
export interface ModifierSource {
  shiftKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  metaKey: boolean;
  getModifierState(key: string): boolean;
}

/**
 * Modifiers held and locks latched, as `remoter_proto::Modifiers` bits.
 *
 * AltGr is read through `getModifierState("AltGraph")` rather than inferred
 * from `altKey`, and the distinction is not cosmetic: on a Turkish, German or
 * French layout the right-hand Alt selects a third level of the layout. Sent as
 * plain Alt it arrives as a window-manager shortcut instead of the character
 * the user meant to type.
 *
 * Windows additionally reports AltGr as Ctrl+Alt, because that is literally how
 * it is implemented there. Those two bits are cleared when AltGraph is set, so
 * a remote host does not see a Ctrl+Alt chord the user never pressed.
 */
export function modifiersFrom(event: ModifierSource): number {
  const altGraph = event.getModifierState("AltGraph");
  let bits = 0;
  if (event.shiftKey) bits |= MOD_SHIFT;
  if (event.metaKey) bits |= MOD_META;
  if (altGraph) {
    bits |= MOD_ALT_GRAPH;
  } else {
    if (event.ctrlKey) bits |= MOD_CONTROL;
    if (event.altKey) bits |= MOD_ALT;
  }
  if (event.getModifierState("CapsLock")) bits |= MOD_CAPS_LOCK;
  if (event.getModifierState("NumLock")) bits |= MOD_NUM_LOCK;
  if (event.getModifierState("ScrollLock")) bits |= MOD_SCROLL_LOCK;
  return bits;
}

/**
 * One key transition, in the vocabulary `InputEvent::Key` carries.
 *
 * Both halves travel together, always. An event with a scancode and no keysym
 * is a modifier or a function key and is complete; an event with neither is not
 * sent at all.
 */
export interface KeyInput {
  scancode: number;
  keysym: number | null;
  modifiers: number;
  pressed: boolean;
}

/** What a key event needs to be translated. */
export interface KeySource extends ModifierSource {
  code: string;
  key: string;
  /** True while an IME is composing. Such an event is not a keystroke. */
  isComposing?: boolean;
}

/**
 * A key event as the core's input vocabulary, or null for one not worth
 * sending.
 *
 * Null in three cases, each of them deliberate:
 *
 * - **mid-composition.** `isComposing` means an IME owns the keystroke. The
 *   composed text arrives as a `compositionend`, and forwarding the raw keys as
 *   well types everything twice.
 * - **`key` is `"Process"`.** The other way a platform says an IME took it.
 * - **no scancode.** A key this table cannot place physically. See
 *   {@link scancodeFor}.
 */
export function keyInputFrom(event: KeySource, pressed: boolean): KeyInput | null {
  if (event.isComposing === true || event.key === "Process") return null;
  const scancode = scancodeFor(event.code);
  if (scancode === null) return null;
  return {
    scancode,
    keysym: keysymFor(event.key),
    modifiers: modifiersFrom(event),
    pressed,
  };
}

/**
 * The modifier each physical modifier key latches while it is held.
 *
 * Only used by {@link chordFor}: a real key event carries its modifiers in the
 * event itself, and {@link modifiersFrom} reads them from there rather than
 * inferring them from which keys this file thinks are down.
 *
 * The right-hand Alt is AltGr, not Alt. On a Turkish, German or French layout
 * it selects a third level of the layout, and a chord that claimed plain Alt
 * would arrive at the far end as a window-manager shortcut.
 */
const MODIFIER_OF: Readonly<Record<string, number>> = {
  ShiftLeft: MOD_SHIFT,
  ShiftRight: MOD_SHIFT,
  ControlLeft: MOD_CONTROL,
  ControlRight: MOD_CONTROL,
  AltLeft: MOD_ALT,
  AltRight: MOD_ALT_GRAPH,
  MetaLeft: MOD_META,
  MetaRight: MOD_META,
};

/**
 * A chord nobody can type, as the key transitions that produce it.
 *
 * Some combinations never reach a web page: the window manager takes Alt+Tab,
 * and on Windows and most Linux desktops Ctrl+Alt+Delete is intercepted by the
 * system before any application sees it. They are also the two combinations
 * people ask a remote desktop client for by name. A control that sends them
 * explicitly is the only way they can ever arrive — there is no keystroke for
 * this interface to capture.
 *
 * The keys go down in the order given and come up in the reverse order, which
 * is what a human hand does and what every far end expects: a Control released
 * before the key it modified produces a bare keypress at the other side.
 *
 * `keysym` is null throughout. These are physical positions, not characters,
 * and the VNC adapter's own table (`crates/remoter-proto-vnc/src/keymap.rs`)
 * fills in the keysym from the scancode. Guessing one here would be a second
 * table to drift from it.
 *
 * Null if any name is one {@link scancodeFor} cannot place: half a chord is
 * worse than none, because the half that arrives is a modifier that never comes
 * back up.
 */
/**
 * Whether a key press is a paste on the remote desktop.
 *
 * Ctrl+V and Shift+Insert, the two Windows answers to "paste", plus Cmd+V —
 * which reaches a remote Windows host as Win+V, but is what a Mac user's hand
 * does when it means paste, and offering the clipboard first costs nothing. A
 * held key's repeats are not new pastes.
 */
export function isPasteChord(
  event: Pick<KeyboardEvent, "code" | "ctrlKey" | "altKey" | "shiftKey" | "metaKey" | "repeat">,
): boolean {
  if (event.repeat) return false;
  if (event.code === "KeyV") return (event.ctrlKey || event.metaKey) && !event.altKey;
  if (event.code === "Insert") return event.shiftKey && !event.ctrlKey && !event.altKey;
  return false;
}

export function chordFor(codes: readonly string[]): KeyInput[] | null {
  if (codes.length === 0) return null;

  const scancodes: number[] = [];
  for (const code of codes) {
    const scancode = scancodeFor(code);
    if (scancode === null) return null;
    scancodes.push(scancode);
  }

  const events: KeyInput[] = [];
  let modifiers = 0;
  codes.forEach((code, index) => {
    // The modifiers a key carries are the ones already held when it goes down,
    // so the first key of a chord reports none — exactly as a real keydown
    // does.
    const scancode = scancodes[index] ?? 0;
    events.push({ scancode, keysym: null, modifiers, pressed: true });
    modifiers |= MODIFIER_OF[code] ?? 0;
  });
  for (let index = codes.length - 1; index >= 0; index -= 1) {
    const code = codes[index] ?? "";
    modifiers &= ~(MODIFIER_OF[code] ?? 0);
    events.push({ scancode: scancodes[index] ?? 0, keysym: null, modifiers, pressed: false });
  }
  return events;
}

/**
 * Which buttons are down, from `MouseEvent.buttons`.
 *
 * A full state rather than a transition, because that is what both protocols
 * put on the wire: RFB's `button-mask` (RFC 6143 §7.5.5) and RDP's pointer
 * events are each a snapshot, and the RDP adapter diffs them back into
 * transitions itself.
 *
 * The DOM's bit order is not the core's — 2 is the secondary button there and
 * the middle one here — so this is a translation and not a cast.
 */
export function buttonsFrom(buttons: number): number {
  let bits = 0;
  if ((buttons & 1) !== 0) bits |= BUTTON_LEFT;
  if ((buttons & 2) !== 0) bits |= BUTTON_RIGHT;
  if ((buttons & 4) !== 0) bits |= BUTTON_MIDDLE;
  if ((buttons & 8) !== 0) bits |= BUTTON_BACK;
  if ((buttons & 16) !== 0) bits |= BUTTON_FORWARD;
  return bits;
}

/** A wheel movement in the units `InputEvent::Pointer` carries. */
export interface WheelInput {
  /** Vertical; positive is away from the user. One notch is 120. */
  wheel: number;
  /** Horizontal; positive is to the right. Same units. */
  wheelX: number;
}

/** How many CSS pixels a `deltaMode` of lines and pages is taken to be. */
const PIXELS_PER_LINE = 16;
const PIXELS_PER_PAGE = 400;

/**
 * A wheel event in notches of 120.
 *
 * Three things have to be got right here.
 *
 * **Both axes.** A tilt wheel and a trackpad's horizontal swipe are a different
 * axis, not a different sign, and RDP encodes the horizontal one with its own
 * flag. Dropping `deltaX` is why horizontal scrolling does nothing in most
 * remote desktop clients.
 *
 * **The sign.** The DOM's `deltaY` is positive when the content scrolls down —
 * that is, when the wheel rolls *towards* the user — and `rotationUnits` is
 * positive away from the user. The two are opposite, so the vertical axis is
 * negated. The horizontal axis is not: both call rightwards positive.
 *
 * **`deltaMode`.** A mouse reports lines, a trackpad reports pixels, and a
 * page-mode event is rare but real. Each is converted to pixels first, so one
 * notch is one notch whatever the device claims to be measuring in.
 */
export function wheelFrom(event: {
  deltaX: number;
  deltaY: number;
  deltaMode: number;
}): WheelInput {
  const factor =
    event.deltaMode === 1 ? PIXELS_PER_LINE : event.deltaMode === 2 ? PIXELS_PER_PAGE : 1;
  const notches = (pixels: number) => {
    const units = Math.round((pixels * factor * WHEEL_DELTA) / (PIXELS_PER_LINE * 3));
    // i16 on the wire. A flung trackpad can exceed it, and a wrapped delta
    // scrolls the far end the wrong way.
    const clamped = Math.max(-32768, Math.min(32767, units));
    // Negating a zero delta produces -0, which is a different value from 0 to
    // everything that compares strictly. It encodes as zero either way, but it
    // makes "did this axis move?" answer wrongly for anyone who asks.
    return clamped === 0 ? 0 : clamped;
  };
  return { wheel: notches(-event.deltaY), wheelX: notches(event.deltaX) };
}
