/**
 * The clipboard and mouse rules each platform's own terminal follows.
 *
 * Every rule is checked on every platform from whatever machine runs the suite,
 * because the one that was wrong before this file existed — Ctrl+V sending a
 * literal ^V to a Windows shell — could not be seen from the Linux machine it
 * was written on.
 */

import { describe, expect, it } from "vitest";

import { platformFromUserAgent } from "@/lib/platform";

import { behaviourFor, keyAction, menuShortcut, type KeyChord } from "./terminalInput";

function press(key: string, mods: Partial<KeyChord> = {}): KeyChord {
  return {
    type: "keydown",
    key,
    code: mods.code ?? "",
    ctrlKey: false,
    shiftKey: false,
    altKey: false,
    metaKey: false,
    ...mods,
  };
}

describe("platformFromUserAgent", () => {
  it("recognises the three WebViews this ships in by the operating system they name", () => {
    expect(
      platformFromUserAgent(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36 Edg/140.0",
      ),
    ).toBe("windows");
    expect(
      platformFromUserAgent(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
      ),
    ).toBe("macos");
    expect(
      platformFromUserAgent(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
      ),
    ).toBe("linux");
  });
});

describe("Windows, as Windows Terminal does it", () => {
  it("copies on Ctrl+C only when something is selected, and otherwise leaves the interrupt alone", () => {
    expect(keyAction("windows", press("c", { ctrlKey: true }), true)).toBe("copy");
    expect(keyAction("windows", press("c", { ctrlKey: true }), false)).toBeNull();
  });

  it("pastes on Ctrl+V instead of sending ^V to the shell", () => {
    expect(keyAction("windows", press("v", { ctrlKey: true }), false)).toBe("paste");
  });

  it("keeps the older clipboard keys working", () => {
    expect(keyAction("windows", press("Insert", { code: "Insert", shiftKey: true }), false)).toBe("paste");
    expect(keyAction("windows", press("Insert", { code: "Insert", ctrlKey: true }), true)).toBe("copy");
    expect(keyAction("windows", press("C", { ctrlKey: true, shiftKey: true }), false)).toBe("copy");
    expect(keyAction("windows", press("V", { ctrlKey: true, shiftKey: true }), false)).toBe("paste");
  });

  it("answers the right button by copying or pasting, not with a menu", () => {
    expect(behaviourFor("windows").rightClick).toBe("copyOrPaste");
    expect(behaviourFor("windows").middleClickPastes).toBe(false);
  });
});

describe("macOS, as Terminal.app does it", () => {
  it("uses Cmd for the clipboard, and never takes Ctrl+C from the shell", () => {
    expect(keyAction("macos", press("c", { metaKey: true }), true)).toBe("copy");
    expect(keyAction("macos", press("v", { metaKey: true }), false)).toBe("paste");
    expect(keyAction("macos", press("a", { metaKey: true }), false)).toBe("selectAll");
    expect(keyAction("macos", press("k", { metaKey: true }), false)).toBe("clearScrollback");
    expect(keyAction("macos", press("c", { ctrlKey: true }), true)).toBeNull();
    expect(keyAction("macos", press("v", { ctrlKey: true }), false)).toBeNull();
  });

  it("opens a menu on the right button and holds a steady block cursor", () => {
    const mac = behaviourFor("macos");
    expect(mac.rightClick).toBe("menu");
    expect(mac.cursorStyle).toBe("block");
    expect(mac.cursorBlink).toBe(false);
  });
});

describe("Linux, as GNOME Terminal and Konsole do it", () => {
  it("uses Ctrl+Shift for the clipboard, and leaves plain Ctrl to the shell", () => {
    expect(keyAction("linux", press("C", { ctrlKey: true, shiftKey: true }), true)).toBe("copy");
    expect(keyAction("linux", press("V", { ctrlKey: true, shiftKey: true }), false)).toBe("paste");
    expect(keyAction("linux", press("A", { ctrlKey: true, shiftKey: true }), false)).toBe("selectAll");
    expect(keyAction("linux", press("c", { ctrlKey: true }), true)).toBeNull();
    expect(keyAction("linux", press("v", { ctrlKey: true }), false)).toBeNull();
  });

  it("pastes the PRIMARY selection on Shift+Insert, as xterm always has", () => {
    expect(keyAction("linux", press("Insert", { code: "Insert", shiftKey: true }), false)).toBe(
      "pastePrimary",
    );
  });

  it("makes a selection the PRIMARY selection and pastes it with the middle button", () => {
    const linux = behaviourFor("linux");
    expect(linux.selectionIsPrimary).toBe(true);
    expect(linux.middleClickPastes).toBe(true);
    expect(linux.rightClick).toBe("menu");
  });

  it("keeps a path or a URL whole on a double click", () => {
    const separators = behaviourFor("linux").wordSeparator;
    for (const inside of ["/", ".", "-", ":", "@", "_", "~", "="]) {
      expect(separators).not.toContain(inside);
    }
  });

  it("defers the font to the desktop's own monospace setting", () => {
    expect(behaviourFor("linux").fontFamily.startsWith("monospace")).toBe(true);
  });
});

describe("everywhere", () => {
  it("zooms the font on the keys every native terminal binds", () => {
    expect(keyAction("linux", press("+", { ctrlKey: true, shiftKey: true }), false)).toBe("zoomIn");
    expect(keyAction("windows", press("-", { ctrlKey: true, code: "Minus" }), false)).toBe("zoomOut");
    expect(keyAction("macos", press("0", { metaKey: true, code: "Digit0" }), false)).toBe("zoomReset");
  });

  it("ignores key releases and ordinary typing", () => {
    expect(keyAction("windows", { ...press("v", { ctrlKey: true }), type: "keyup" }, false)).toBeNull();
    for (const platform of ["windows", "macos", "linux"] as const) {
      expect(keyAction(platform, press("a"), false)).toBeNull();
      expect(keyAction(platform, press("r", { ctrlKey: true }), false)).toBeNull();
    }
  });

  it("writes menu shortcuts the way each platform's menus write them", () => {
    expect(menuShortcut("macos", "copy")).toBe("⌘C");
    expect(menuShortcut("linux", "paste")).toBe("Ctrl+Shift+V");
    expect(menuShortcut("windows", "copy")).toBe("Ctrl+C");
  });
});
