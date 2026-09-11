/**
 * The keyboard mapping, and the layout it is most likely to be wrong on.
 *
 * The Turkish Q keyboard is the one the owner of this repository types on, and
 * it is the right test for a different reason too: it puts a *non-Latin-1*
 * character (`ı`, U+0131) and a *Latin-1* one (`ü`, U+00FC) on adjacent keys,
 * so a single layout exercises both branches of the keysym encoding. The rest
 * of the file covers the two things no layout can catch — the physical
 * scancode table, which must not move when the layout does, and the pointer.
 */

import { describe, expect, it } from "vitest";

import {
  BUTTON_BACK,
  BUTTON_FORWARD,
  BUTTON_LEFT,
  BUTTON_MIDDLE,
  BUTTON_RIGHT,
  buttonsFrom,
  EXTENDED,
  keyInputFrom,
  keysymFor,
  modifiersFrom,
  MOD_ALT,
  MOD_ALT_GRAPH,
  MOD_CAPS_LOCK,
  MOD_CONTROL,
  MOD_META,
  MOD_NUM_LOCK,
  MOD_SCROLL_LOCK,
  MOD_SHIFT,
  scancodeFor,
  wheelFrom,
  WHEEL_DELTA,
  type KeySource,
} from "./keymap";

/** A `KeyboardEvent`-shaped object, with nothing held unless asked for. */
function press(code: string, key: string, held: readonly string[] = []): KeySource {
  const set = new Set(held);
  return {
    code,
    key,
    shiftKey: set.has("Shift"),
    ctrlKey: set.has("Control"),
    altKey: set.has("Alt"),
    metaKey: set.has("Meta"),
    getModifierState: (name: string) => set.has(name),
  };
}

describe("a Turkish Q keyboard", () => {
  /**
   * The layout, as a browser reports it: the physical key on the left, the
   * character it produces on the right. Every `code` here is the US name of
   * that position — that is what `code` means — and every `key` is what a
   * Turkish Q layout actually types there.
   */
  const TURKISH_Q: readonly [code: string, key: string, scancode: number, keysym: number][] = [
    // The top row. `ı` is the one that breaks everything: it is at the position
    // a US keyboard calls `KeyI`, and it is not `i`.
    ["KeyQ", "q", 0x10, 0x71],
    ["KeyI", "ı", 0x17, 0x0100_0131],
    ["BracketLeft", "ğ", 0x1a, 0x0100_011f],
    // Latin-1, so its keysym is its own code point rather than the Unicode form.
    ["BracketRight", "ü", 0x1b, 0x00fc],
    // The home row. `ş` is where a US keyboard has the semicolon, and the key
    // where a US keyboard has the apostrophe types a dotted `i`.
    ["Semicolon", "ş", 0x27, 0x0100_015f],
    ["Quote", "i", 0x28, 0x0069],
    ["KeyA", "a", 0x1e, 0x0061],
    // The bottom row: `ö` and `ç` where the comma and the full stop are, and
    // the full stop itself pushed onto the slash.
    ["Comma", "ö", 0x33, 0x00f6],
    ["Period", "ç", 0x34, 0x00e7],
    ["Slash", ".", 0x35, 0x002e],
  ];

  it.each(TURKISH_Q)(
    "sends %s as scancode %d and the character it typed",
    (code, key, scancode, keysym) => {
      const input = keyInputFrom(press(code, key), true);
      expect(input).not.toBeNull();
      // The scancode is the physical position and is the same on every layout:
      // that is what makes the RDP server, which applies the layout itself,
      // type the right character.
      expect(input?.scancode).toBe(scancode);
      // The keysym is what this layout produced, and is what a VNC server —
      // which applies no layout — needs in order to type the same thing.
      expect(input?.keysym).toBe(keysym);
    },
  );

  it("does not confuse the dotted and dotless I", () => {
    // The pair that makes Turkish famous in bug trackers. Same physical keys as
    // a US `i` and `'`, four different characters between them, and every one
    // of them has to survive.
    expect(keysymFor("ı")).toBe(0x0100_0131);
    expect(keysymFor("i")).toBe(0x0069);
    expect(keysymFor("I")).toBe(0x0049);
    expect(keysymFor("İ")).toBe(0x0100_0130);
    expect(keysymFor("ı")).not.toBe(keysymFor("i"));
    expect(keysymFor("I")).not.toBe(keysymFor("İ"));
  });

  it("keeps the scancode when Shift changes the character", () => {
    const lower = keyInputFrom(press("KeyI", "ı"), true);
    const upper = keyInputFrom(press("KeyI", "I", ["Shift"]), true);
    expect(upper?.scancode).toBe(lower?.scancode);
    expect(upper?.keysym).not.toBe(lower?.keysym);
    expect(upper?.modifiers).toBe(MOD_SHIFT);
  });

  it("reads AltGr as a level shift and not as Ctrl+Alt", () => {
    // On this layout AltGr+Q is `@`. Windows reports AltGr as Ctrl+Alt because
    // that is how it is implemented there, and a client that forwards those
    // bits sends a window-manager chord instead of an `@`.
    const input = keyInputFrom(press("KeyQ", "@", ["AltGraph", "Control", "Alt"]), true);
    expect(input?.modifiers).toBe(MOD_ALT_GRAPH);
    expect(input?.modifiers).not.toBe(MOD_CONTROL | MOD_ALT);
    expect(input?.keysym).toBe(0x0040);
  });

  it("sends the 102nd key, which no US keyboard has", () => {
    expect(scancodeFor("IntlBackslash")).toBe(0x56);
    expect(scancodeFor("IntlBackslash")).not.toBe(scancodeFor("Backslash"));
  });
});

describe("scancodeFor", () => {
  it("marks the extended keys with bit 8", () => {
    // Right Control and left Control produce different Windows virtual keys. A
    // client that drops the bit makes the right-hand modifiers behave as the
    // left-hand ones.
    expect(scancodeFor("ControlLeft")).toBe(0x1d);
    expect(scancodeFor("ControlRight")).toBe(EXTENDED | 0x1d);
    expect(scancodeFor("Enter")).toBe(0x1c);
    expect(scancodeFor("NumpadEnter")).toBe(EXTENDED | 0x1c);
    expect(scancodeFor("AltLeft")).toBe(0x38);
    expect(scancodeFor("AltRight")).toBe(EXTENDED | 0x38);
  });

  it("lays the keypad out in the order Set 1 does", () => {
    expect(scancodeFor("Numpad7")).toBe(0x47);
    expect(scancodeFor("Numpad4")).toBe(0x4b);
    expect(scancodeFor("Numpad1")).toBe(0x4f);
    expect(scancodeFor("Numpad0")).toBe(0x52);
    expect(scancodeFor("NumpadDecimal")).toBe(0x53);
  });

  it("keeps the arrows, Home and Delete extended, not on the keypad", () => {
    expect(scancodeFor("ArrowUp")).toBe(EXTENDED | 0x48);
    expect(scancodeFor("Numpad8")).toBe(0x48);
    expect(scancodeFor("Delete")).toBe(EXTENDED | 0x53);
  });

  it("puts F11 and F12 apart from F1 to F10, as Set 1 does", () => {
    expect(scancodeFor("F1")).toBe(0x3b);
    expect(scancodeFor("F10")).toBe(0x44);
    expect(scancodeFor("F11")).toBe(0x57);
    expect(scancodeFor("F12")).toBe(0x58);
  });

  it("has nothing for a key it does not know", () => {
    expect(scancodeFor("AudioVolumeUp")).toBeNull();
    expect(scancodeFor("")).toBeNull();
  });
});

describe("keysymFor", () => {
  it("gives a Latin-1 character its own code point", () => {
    expect(keysymFor("a")).toBe(0x61);
    expect(keysymFor(" ")).toBe(0x20);
    expect(keysymFor("ä")).toBe(0xe4);
    expect(keysymFor("ÿ")).toBe(0xff);
  });

  it("gives everything above Latin-1 the Unicode form", () => {
    expect(keysymFor("Ā")).toBe(0x0100_0100);
    expect(keysymFor("€")).toBe(0x0100_20ac);
    expect(keysymFor("ж")).toBe(0x0100_0436);
  });

  it("has nothing for a key that produced no character", () => {
    // The contract: `keysym` is optional precisely for these, and the VNC
    // adapter fills them in from the scancode. Producing them here too is how
    // the two tables drift apart.
    for (const key of ["Shift", "Control", "AltGraph", "F5", "ArrowLeft", "Unidentified"]) {
      expect(keysymFor(key)).toBeNull();
    }
  });

  it("has nothing mid-composition", () => {
    // A dead key has produced no character yet; the composed one arrives next.
    expect(keysymFor("Dead")).toBeNull();
  });

  it("keeps an astral character whole", () => {
    // Two UTF-16 code units, one character the layout produced. A length check
    // of 1 would reject it.
    expect(keysymFor("😀")).toBe(0x0100_0000 + 0x1f600);
  });
});

describe("modifiersFrom", () => {
  it("carries the lock states, not only the held keys", () => {
    // RDP synchronises latches explicitly (MS-RDPBCGR §2.2.8.1.1.3.1.1.5). A
    // session that never sends one types in the wrong case until the user
    // notices and presses Caps Lock twice.
    const bits = modifiersFrom(press("KeyA", "A", ["CapsLock", "NumLock", "ScrollLock"]));
    expect(bits & MOD_CAPS_LOCK).toBe(MOD_CAPS_LOCK);
    expect(bits & MOD_NUM_LOCK).toBe(MOD_NUM_LOCK);
    expect(bits & MOD_SCROLL_LOCK).toBe(MOD_SCROLL_LOCK);
  });

  it("carries every held modifier separately", () => {
    const bits = modifiersFrom(press("KeyA", "a", ["Shift", "Control", "Alt", "Meta"]));
    expect(bits).toBe(MOD_SHIFT | MOD_CONTROL | MOD_ALT | MOD_META);
  });

  it("is empty when nothing is held", () => {
    expect(modifiersFrom(press("KeyA", "a"))).toBe(0);
  });
});

describe("keyInputFrom", () => {
  it("sends nothing while an IME is composing", () => {
    // The composed text arrives as its own event. Forwarding the raw keys as
    // well types everything twice.
    expect(keyInputFrom({ ...press("KeyA", "a"), isComposing: true }, true)).toBeNull();
    expect(keyInputFrom(press("KeyA", "Process"), true)).toBeNull();
  });

  it("sends nothing for a key it cannot place physically", () => {
    expect(keyInputFrom(press("MediaPlayPause", "MediaPlayPause"), true)).toBeNull();
  });

  it("carries the transition", () => {
    expect(keyInputFrom(press("KeyA", "a"), true)?.pressed).toBe(true);
    expect(keyInputFrom(press("KeyA", "a"), false)?.pressed).toBe(false);
  });
});

describe("buttonsFrom", () => {
  it("translates the DOM's bit order into the core's", () => {
    // Not a cast: 2 is the secondary button in the DOM and the middle one here.
    expect(buttonsFrom(1)).toBe(BUTTON_LEFT);
    expect(buttonsFrom(2)).toBe(BUTTON_RIGHT);
    expect(buttonsFrom(4)).toBe(BUTTON_MIDDLE);
    expect(buttonsFrom(8)).toBe(BUTTON_BACK);
    expect(buttonsFrom(16)).toBe(BUTTON_FORWARD);
  });

  it("carries several buttons at once", () => {
    expect(buttonsFrom(1 | 4)).toBe(BUTTON_LEFT | BUTTON_MIDDLE);
    expect(buttonsFrom(0)).toBe(0);
  });
});

describe("wheelFrom", () => {
  it("turns one line-mode notch into 120 units, away from the user positive", () => {
    // The DOM's deltaY is positive when the wheel rolls towards the user;
    // rotationUnits is positive away from it. The axis is inverted, and a
    // client that forgets scrolls every remote window the wrong way.
    expect(wheelFrom({ deltaX: 0, deltaY: -3, deltaMode: 1 })).toEqual({
      wheel: WHEEL_DELTA,
      wheelX: 0,
    });
    expect(wheelFrom({ deltaX: 0, deltaY: 3, deltaMode: 1 }).wheel).toBe(-WHEEL_DELTA);
  });

  it("keeps the horizontal axis separate and un-inverted", () => {
    // A tilt wheel is a different axis, not a different sign, and RDP encodes
    // it with its own flag. Both call rightwards positive.
    const wheel = wheelFrom({ deltaX: 3, deltaY: 0, deltaMode: 1 });
    expect(wheel.wheelX).toBe(WHEEL_DELTA);
    expect(wheel.wheel).toBe(0);
  });

  it("converts pixel and page modes to the same units", () => {
    // A trackpad reports pixels, a mouse reports lines. One notch has to mean
    // one notch whatever the device claims to be measuring in.
    expect(wheelFrom({ deltaX: 0, deltaY: -48, deltaMode: 0 }).wheel).toBe(WHEEL_DELTA);
    expect(wheelFrom({ deltaX: 0, deltaY: -1, deltaMode: 2 }).wheel).toBeGreaterThan(WHEEL_DELTA);
  });

  it("clamps to what the wire can carry", () => {
    // i16 on the wire. A flung trackpad exceeds it, and a wrapped delta scrolls
    // the far end the wrong way.
    const flung = wheelFrom({ deltaX: 0, deltaY: -100_000, deltaMode: 1 });
    expect(flung.wheel).toBeLessThanOrEqual(32767);
    expect(flung.wheel).toBeGreaterThan(0);
  });
});
