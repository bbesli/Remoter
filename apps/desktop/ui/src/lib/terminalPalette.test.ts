/**
 * The contrast arithmetic and the palette round trip.
 *
 * Both are tested because both are load-bearing in a way that is invisible
 * until it is wrong: a contrast ratio that is off by a factor tells a user
 * their theme is fine when it is unreadable, and an override that does not
 * survive a save-and-reload silently reverts a colour someone chose on
 * purpose.
 */

import { describe, expect, it } from "vitest";

import englishSettings from "../../../../../locales/en/settings.json";

import type { TerminalAppearance } from "./ipc";
import {
  DEFAULT_TERMINAL_APPEARANCE,
  TERMINAL_ANSI_KEYS,
  TERMINAL_COLOR_KEYS,
  TERMINAL_PALETTES,
  baseTerminalColors,
  contrastRatio,
  contrastReport,
  failingColors,
  gradeContrast,
  isTerminalPaletteId,
  normaliseHex,
  opaqueHex,
  paletteById,
  paletteCreditKey,
  paletteNameKey,
  parseHexColor,
  pruneOverrides,
  resolvePaletteId,
  resolveTerminalColors,
} from "./terminalPalette";

/**
 * Follows a dotted catalogue key into the English `settings` catalogue, the way
 * `t()` does. Resolving the key the screen actually passes is the point: a
 * helper that returns a well-formed key naming nothing would pass a comparison
 * against itself and render a humanised key on the card.
 */
function lookupEnglish(key: string): unknown {
  let current: unknown = englishSettings;
  for (const segment of key.split(".")) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

describe("hex parsing", () => {
  it("accepts the forms people actually paste", () => {
    expect(parseHexColor("#fff")).toEqual({ r: 255, g: 255, b: 255, a: 1 });
    expect(parseHexColor("#FFFFFF")).toEqual({ r: 255, g: 255, b: 255, a: 1 });
    expect(parseHexColor("  #1a1c20  ")).toEqual({ r: 26, g: 28, b: 32, a: 1 });
  });

  it("carries alpha through, because a selection colour has one", () => {
    const parsed = parseHexColor("#00000080");
    expect(parsed?.a).toBeCloseTo(128 / 255, 5);
  });

  it("refuses anything that is not a colour rather than guessing", () => {
    expect(parseHexColor("crimson")).toBeNull();
    expect(parseHexColor("#12345")).toBeNull();
    expect(parseHexColor("#gggggg")).toBeNull();
    expect(parseHexColor("")).toBeNull();
  });

  it("canonicalises to one spelling, so a comparison can be a string one", () => {
    expect(normaliseHex("#F00")).toBe("#ff0000");
    expect(normaliseHex("#FF0000")).toBe("#ff0000");
    expect(normaliseHex("#ff0000ff")).toBe("#ff0000");
    expect(normaliseHex("#88C0D04D")).toBe("#88c0d04d");
  });

  it("strips alpha for the platform colour control, which cannot hold it", () => {
    expect(opaqueHex("#88c0d04d")).toBe("#88c0d0");
    expect(opaqueHex("not a colour")).toBe("#000000");
  });
});

describe("the contrast ratio", () => {
  it("is 21 between black and white and 1 between a colour and itself", () => {
    expect(contrastRatio("#ffffff", "#000000")).toBeCloseTo(21, 5);
    expect(contrastRatio("#000000", "#ffffff")).toBeCloseTo(21, 5);
    expect(contrastRatio("#3bb6c4", "#3bb6c4")).toBeCloseTo(1, 5);
  });

  it("matches the published value for the classic AA boundary grey", () => {
    // #767676 on white is the grey WCAG examples use for "just passes 4.5:1".
    expect(contrastRatio("#767676", "#ffffff")).toBeCloseTo(4.54, 2);
  });

  it("is the same either way round: it is a ratio, not a direction", () => {
    expect(contrastRatio("#e05252", "#131417")).toBeCloseTo(
      contrastRatio("#131417", "#e05252"),
      5,
    );
  });

  it("composites a translucent colour over its background first", () => {
    // Half-opacity white over black is mid grey, which is nowhere near 21:1.
    const composited = contrastRatio("#ffffff80", "#000000");
    expect(composited).toBeGreaterThan(1);
    expect(composited).toBeLessThan(21);
    expect(composited).toBeCloseTo(contrastRatio("#808080", "#000000"), 1);
  });

  it("reports the worst case for a value it cannot read", () => {
    // Silence would be the wrong failure mode for an accessibility check.
    expect(contrastRatio("nonsense", "#000000")).toBe(1);
  });

  it("catches the classic unusable pairing", () => {
    // Red on dark blue: the way a hand-made theme becomes unreadable.
    expect(gradeContrast(contrastRatio("#c00000", "#001a4d"))).toBe("fail");
  });
});

describe("the grades", () => {
  it("treats terminal output as body text, so 3:1 is a warning and not a pass", () => {
    expect(gradeContrast(2.99)).toBe("fail");
    expect(gradeContrast(3)).toBe("large");
    expect(gradeContrast(4.49)).toBe("large");
    expect(gradeContrast(4.5)).toBe("aa");
    expect(gradeContrast(6.99)).toBe("aa");
    expect(gradeContrast(7)).toBe("aaa");
  });
});

describe("the shipped palettes", () => {
  it("all define every colour, as a real hex value", () => {
    for (const palette of TERMINAL_PALETTES) {
      for (const key of TERMINAL_COLOR_KEYS) {
        const value = palette.colors[key];
        expect(parseHexColor(value), `${palette.id}.${key} = ${value}`).not.toBeNull();
        expect(normaliseHex(value)).toBe(value);
      }
    }
  });

  it("name themselves and their author through the catalogue", () => {
    // The name and the credit were two string fields here until the
    // localisation pass: "Remoter — the palette this application shipped with"
    // is a sentence on screen, and a sentence on screen comes from a catalogue
    // (CLAUDE.md §6). What can go wrong now is a palette added to the table
    // with no catalogue entry behind it — which renders a humanised key on the
    // card and looks, at a glance, deliberate. So the keys are resolved rather
    // than merely constructed.
    for (const palette of TERMINAL_PALETTES) {
      const name = lookupEnglish(paletteNameKey(palette.id));
      const credit = lookupEnglish(paletteCreditKey(palette.id));
      expect(typeof name, `${palette.id} name`).toBe("string");
      expect(typeof credit, `${palette.id} credit`).toBe("string");
      expect(String(name).trim().length, `${palette.id} name`).toBeGreaterThan(0);
      expect(String(credit).trim().length, `${palette.id} credit`).toBeGreaterThan(0);
    }
  });

  it("carry no English of their own any more", () => {
    // The regression this stops is the easy one: someone adds a palette by
    // copying the entry above it, and puts `name: "Ayu Mirage"` back on it
    // because that is where a name obviously goes. The lint rule cannot see a
    // string in a data table that never reaches JSX as a literal.
    for (const palette of TERMINAL_PALETTES) {
      // Sorted, so reordering the declaration is not a failure. Only a new
      // field is.
      expect([...Object.keys(palette)].sort(), palette.id).toEqual(["colors", "ground", "id"]);
    }
  });

  it("rate every colour they carry against their own background", () => {
    for (const palette of TERMINAL_PALETTES) {
      const report = contrastReport(palette.colors);
      expect(report).toHaveLength(TERMINAL_ANSI_KEYS.length + 1);
      expect(report.every((entry) => entry.ratio >= 1 && entry.ratio <= 21)).toBe(true);
    }
  });

  it("keep the two Remoter sets readable: only the ANSI blacks fall short", () => {
    // Colour 0 is the background's own colour in every palette ever written,
    // and colour 8 is the dim one. Everything a program prints as text has to
    // clear AA, or the default the application ships would be the first thing
    // the contrast warnings complained about.
    for (const id of ["remoter-dark", "remoter-light"] as const) {
      const palette = paletteById(id);
      expect(palette, id).toBeDefined();
      if (palette === undefined) continue;
      const failing = failingColors(palette.colors).map((entry) => entry.key);
      expect(failing.filter((key) => key !== "black" && key !== "brightBlack")).toEqual([]);
    }
  });
});

describe("resolving an appearance", () => {
  it("defaults to following the interface theme, as the stylesheet used to", () => {
    expect(DEFAULT_TERMINAL_APPEARANCE.palette).toBe("auto");
    expect(resolvePaletteId("auto", "dark")).toBe("remoter-dark");
    expect(resolvePaletteId("auto", "light")).toBe("remoter-light");
    // High contrast reaches the terminal: asking for maximum contrast asks for
    // it everywhere.
    expect(resolvePaletteId("auto", "hc-dark")).toBe("high-contrast");
    expect(resolvePaletteId("auto", "hc-light")).toBe("high-contrast");
  });

  it("ignores the interface theme once a palette has been chosen", () => {
    expect(resolvePaletteId("nord", "light")).toBe("nord");
    expect(resolvePaletteId("nord", "hc-dark")).toBe("nord");
  });

  it("knows which ids it has", () => {
    expect(isTerminalPaletteId("auto")).toBe(true);
    expect(isTerminalPaletteId("gruvbox-dark")).toBe(true);
    expect(isTerminalPaletteId("dracula")).toBe(false);
  });

  it("falls back to a complete palette when the stored id names nothing", () => {
    // A settings file from a newer build, or one edited by hand. It must cost
    // the user their palette choice, never a terminal with no foreground.
    const stored: TerminalAppearance = {
      palette: "a-palette-from-the-future",
      overrides: {},
      fontFamily: "",
      fontSize: 13,
    };
    const colors = resolveTerminalColors(stored, "dark");
    for (const key of TERMINAL_COLOR_KEYS) {
      expect(parseHexColor(colors[key]), key).not.toBeNull();
    }
  });
});

describe("the palette round trip", () => {
  const nord = paletteById("nord");

  it("returns the palette untouched when nothing is overridden", () => {
    expect(nord).toBeDefined();
    if (nord === undefined) return;
    const colors = resolveTerminalColors(
      { palette: "nord", overrides: {}, fontFamily: "", fontSize: 13 },
      "dark",
    );
    expect(colors).toEqual(nord.colors);
  });

  it("survives a save and a reload for every colour, one at a time", () => {
    // The shape a save actually takes: edit a colour, prune what now matches
    // the palette, store, read back, resolve. Every key has to come out of
    // that the way it went in.
    for (const key of TERMINAL_COLOR_KEYS) {
      const edited: TerminalAppearance = {
        palette: "nord",
        overrides: { [key]: "#AbCdEf" },
        fontFamily: "",
        fontSize: 13,
      };
      const stored = { ...edited, overrides: pruneOverrides(edited, "dark") };
      const colors = resolveTerminalColors(stored, "dark");
      expect(colors[key], key).toBe("#abcdef");
    }
  });

  it("drops an override that has been set back to the palette's own colour", () => {
    expect(nord).toBeDefined();
    if (nord === undefined) return;
    const appearance: TerminalAppearance = {
      palette: "nord",
      overrides: { red: nord.colors.red, green: "#00ff00" },
      fontFamily: "",
      fontSize: 13,
    };
    // Otherwise `red` would look changed in the interface, and would stop
    // following the palette the next time one was chosen.
    expect(pruneOverrides(appearance, "dark")).toEqual({ green: "#00ff00" });
  });

  it("drops an override that names a colour this build does not have", () => {
    const appearance: TerminalAppearance = {
      palette: "nord",
      overrides: { puce: "#ff0000", red: "#00ff00" },
      fontFamily: "",
      fontSize: 13,
    };
    expect(pruneOverrides(appearance, "dark")).toEqual({ red: "#00ff00" });
    expect(resolveTerminalColors(appearance, "dark").red).toBe("#00ff00");
  });

  it("drops an override that is not a colour rather than blanking the slot", () => {
    expect(nord).toBeDefined();
    if (nord === undefined) return;
    const appearance: TerminalAppearance = {
      palette: "nord",
      overrides: { red: "rgb(255,0,0)" },
      fontFamily: "",
      fontSize: 13,
    };
    expect(resolveTerminalColors(appearance, "dark").red).toBe(nord.colors.red);
  });

  it("keeps overrides when the palette changes underneath them", () => {
    // Choosing a new palette moves every colour that was left alone, and keeps
    // the ones that were not. That is why only the differences are stored.
    const appearance: TerminalAppearance = {
      palette: "nord",
      overrides: { red: "#ff0000" },
      fontFamily: "",
      fontSize: 13,
    };
    const moved = { ...appearance, palette: "gruvbox-dark" };
    const gruvbox = paletteById("gruvbox-dark");
    expect(gruvbox).toBeDefined();
    if (gruvbox === undefined) return;

    const colors = resolveTerminalColors(moved, "dark");
    expect(colors.red).toBe("#ff0000");
    expect(colors.background).toBe(gruvbox.colors.background);
    expect(baseTerminalColors(moved, "dark")).toEqual(gruvbox.colors);
  });
});
