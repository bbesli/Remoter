/**
 * The terminal's palettes, and the contrast arithmetic that judges them.
 *
 * This module is the single source of truth for what colour a terminal draws
 * with. It used to be `features/sessions/terminalTokens.css`, read back with
 * `getComputedStyle` — which was fine while the palette was fixed, and became
 * a dead end the moment a user was allowed to change one colour: CSS custom
 * properties cannot be edited per user, per colour, and read back reliably in
 * one place. So the values moved here, `terminals.ts` writes them out as
 * `--term-*` on the document element for anything CSS-side that wants them,
 * and there is still exactly one copy of each number.
 *
 * It is deliberately pure: no DOM, no xterm, no IPC. That is what lets the
 * settings screen preview a palette it has not applied, and what lets the
 * contrast rules be tested without a browser.
 *
 * Contrast matters here more than anywhere else in the application.
 * `docs/ui/design-system.md` requires WCAG 2.2 AA, and a terminal is the one
 * surface where the user picks the colours themselves. Red on dark blue is the
 * classic way a theme becomes unusable, and it is unusable in a way nobody
 * notices until they are reading a stack trace on a production box. So the
 * ratios are computed and reported. They are never enforced: it is the user's
 * terminal, and an accessibility check that overrules a deliberate choice is
 * just a bug with a certificate.
 */

import type { TerminalAppearance, ThemeName } from "./ipc";

/** The interface theme actually in effect — "system" already resolved. */
export type InterfaceTheme = Exclude<ThemeName, "system">;

// ------------------------------------------------------------- the keys ----

/** The 16 ANSI colours, in the order a terminal numbers them (0–15). */
export const TERMINAL_ANSI_KEYS = [
  "black",
  "red",
  "green",
  "yellow",
  "blue",
  "magenta",
  "cyan",
  "white",
  "brightBlack",
  "brightRed",
  "brightGreen",
  "brightYellow",
  "brightBlue",
  "brightMagenta",
  "brightCyan",
  "brightWhite",
] as const;

/** Everything that is not one of the numbered colours. */
export const TERMINAL_SURFACE_KEYS = [
  "background",
  "foreground",
  "cursor",
  "cursorAccent",
  "selection",
] as const;

export const TERMINAL_COLOR_KEYS = [
  ...TERMINAL_SURFACE_KEYS,
  ...TERMINAL_ANSI_KEYS,
] as const;

export type TerminalAnsiKey = (typeof TERMINAL_ANSI_KEYS)[number];
export type TerminalColorKey = (typeof TERMINAL_COLOR_KEYS)[number];

/** A complete palette: every key has a value, always. */
export type TerminalColors = Record<TerminalColorKey, string>;

/** The custom property each colour is published as, for CSS that wants it. */
export const TERMINAL_TOKEN_NAMES: Record<TerminalColorKey, string> = {
  background: "--term-bg",
  foreground: "--term-fg",
  cursor: "--term-cursor",
  cursorAccent: "--term-cursor-accent",
  selection: "--term-selection",
  black: "--term-black",
  red: "--term-red",
  green: "--term-green",
  yellow: "--term-yellow",
  blue: "--term-blue",
  magenta: "--term-magenta",
  cyan: "--term-cyan",
  white: "--term-white",
  brightBlack: "--term-bright-black",
  brightRed: "--term-bright-red",
  brightGreen: "--term-bright-green",
  brightYellow: "--term-bright-yellow",
  brightBlue: "--term-bright-blue",
  brightMagenta: "--term-bright-magenta",
  brightCyan: "--term-bright-cyan",
  brightWhite: "--term-bright-white",
};

// ---------------------------------------------------------- the palettes ----

export type BuiltInPaletteId =
  | "remoter-dark"
  | "remoter-light"
  | "solarized-dark"
  | "solarized-light"
  | "gruvbox-dark"
  | "nord"
  | "tomorrow-night"
  | "high-contrast";

/**
 * `"auto"` is not a palette. It is the instruction "use the one that goes with
 * the interface theme", which is what the application did before any of this
 * was configurable — including switching to the high-contrast palette under a
 * high-contrast theme. Keeping it as the default means an existing
 * installation sees exactly the colours it saw yesterday.
 */
export type TerminalPaletteId = "auto" | BuiltInPaletteId;

export interface TerminalPalette {
  id: BuiltInPaletteId;
  /** The interface theme it is built to sit beside. */
  ground: "dark" | "light";
  colors: TerminalColors;
}

/**
 * Where the palette's visible name and its credit live: the `settings`
 * catalogue, under the palette's own id.
 *
 * They used to be two string fields on the palette above, and they were the
 * last hardcoded English on this screen — "Remoter — the palette this
 * application shipped with" is a sentence, and CLAUDE.md §6 has no exception
 * for a sentence that happens to sit in a data table. Moving the strings out
 * rather than adding a `nameKey` field keeps the palette a pure description of
 * colours, and makes a palette whose catalogue entry is missing a *compile*
 * error: the return type below is a union of the eight keys, and `t()` only
 * accepts keys the English catalogue actually declares.
 *
 * The credit is translated copy for a reason that is easy to get backwards. The
 * author names and licence abbreviations inside it are not translated — "Ethan
 * Schoonover, MIT" is the same in every language — but the words around them
 * are, and so is the whole of the two Remoter credits, which are descriptions
 * rather than attributions. The catalogue note says which is which.
 */
export function paletteNameKey(
  id: BuiltInPaletteId,
): `terminal.palettes.${BuiltInPaletteId}.name` {
  return `terminal.palettes.${id}.name`;
}

export function paletteCreditKey(
  id: BuiltInPaletteId,
): `terminal.palettes.${BuiltInPaletteId}.credit` {
  return `terminal.palettes.${id}.credit`;
}

/**
 * The set `terminalTokens.css` held from the beginning, and the one an unknown
 * palette id falls back to.
 *
 * It is named rather than indexed out of the array below because
 * `noUncheckedIndexedAccess` makes `TERMINAL_PALETTES[0]` a "palette or
 * undefined", and a `!` there would be an assertion standing in for a
 * guarantee this const actually provides.
 */
const REMOTER_DARK: TerminalPalette = {
  id: "remoter-dark",
  ground: "dark",
  colors: {
    background: "#131417",
    foreground: "#d7dbe0",
    cursor: "#3bb6c4",
    cursorAccent: "#131417",
    selection: "#3bb6c44d",
    black: "#1a1c20",
    red: "#e05252",
    green: "#4bb47b",
    yellow: "#e0a33d",
    blue: "#7f9df0",
    magenta: "#c88fd8",
    cyan: "#3bb6c4",
    white: "#c8ced4",
    brightBlack: "#6d757d",
    brightRed: "#f07b78",
    brightGreen: "#6dd39c",
    brightYellow: "#f2c065",
    brightBlue: "#9db4ff",
    brightMagenta: "#dfaced",
    brightCyan: "#4fd0de",
    brightWhite: "#f2f4f6",
  },
};

/**
 * The palettes this build ships.
 *
 * Every one is published under a permissive licence and reproduced by its
 * documented hex values. `remoter-dark` is the set that was in
 * `terminalTokens.css` from the beginning; `remoter-light` is its counterpart,
 * chosen so that every one of the sixteen clears 4.5:1 on its own background
 * except the two greys that programs use as backgrounds rather than as text.
 */
export const TERMINAL_PALETTES: readonly TerminalPalette[] = [
  REMOTER_DARK,
  {
    id: "remoter-light",
    ground: "light",
    colors: {
      background: "#fbfbfc",
      foreground: "#1f2328",
      cursor: "#0f6f7c",
      cursorAccent: "#ffffff",
      selection: "#17808f3d",
      black: "#1f2328",
      red: "#a32222",
      green: "#146b42",
      yellow: "#7a5205",
      blue: "#2a44b8",
      magenta: "#8b3fa8",
      cyan: "#0f6f7c",
      white: "#5b636b",
      brightBlack: "#6d757d",
      brightRed: "#8f1f1f",
      brightGreen: "#0f5433",
      brightYellow: "#63430a",
      brightBlue: "#1f3596",
      brightMagenta: "#6f2f8a",
      brightCyan: "#0c5f6b",
      brightWhite: "#2a2e34",
    },
  },
  {
    id: "solarized-dark",
    ground: "dark",
    colors: {
      background: "#002b36",
      foreground: "#93a1a1",
      cursor: "#93a1a1",
      cursorAccent: "#002b36",
      selection: "#268bd24d",
      black: "#073642",
      red: "#dc322f",
      green: "#859900",
      yellow: "#b58900",
      blue: "#268bd2",
      magenta: "#d33682",
      cyan: "#2aa198",
      white: "#eee8d5",
      brightBlack: "#586e75",
      brightRed: "#cb4b16",
      brightGreen: "#586e75",
      brightYellow: "#657b83",
      brightBlue: "#839496",
      brightMagenta: "#6c71c4",
      brightCyan: "#93a1a1",
      brightWhite: "#fdf6e3",
    },
  },
  {
    id: "solarized-light",
    ground: "light",
    colors: {
      background: "#fdf6e3",
      foreground: "#657b83",
      cursor: "#586e75",
      cursorAccent: "#fdf6e3",
      selection: "#268bd23d",
      black: "#073642",
      red: "#dc322f",
      green: "#859900",
      yellow: "#b58900",
      blue: "#268bd2",
      magenta: "#d33682",
      cyan: "#2aa198",
      white: "#eee8d5",
      brightBlack: "#002b36",
      brightRed: "#cb4b16",
      brightGreen: "#586e75",
      brightYellow: "#657b83",
      brightBlue: "#839496",
      brightMagenta: "#6c71c4",
      brightCyan: "#93a1a1",
      brightWhite: "#fdf6e3",
    },
  },
  {
    id: "gruvbox-dark",
    ground: "dark",
    colors: {
      background: "#282828",
      foreground: "#ebdbb2",
      cursor: "#ebdbb2",
      cursorAccent: "#282828",
      selection: "#83a5984d",
      black: "#282828",
      red: "#cc241d",
      green: "#98971a",
      yellow: "#d79921",
      blue: "#458588",
      magenta: "#b16286",
      cyan: "#689d6a",
      white: "#a89984",
      brightBlack: "#928374",
      brightRed: "#fb4934",
      brightGreen: "#b8bb26",
      brightYellow: "#fabd2f",
      brightBlue: "#83a598",
      brightMagenta: "#d3869b",
      brightCyan: "#8ec07c",
      brightWhite: "#ebdbb2",
    },
  },
  {
    id: "nord",
    ground: "dark",
    colors: {
      background: "#2e3440",
      foreground: "#d8dee9",
      cursor: "#d8dee9",
      cursorAccent: "#2e3440",
      selection: "#88c0d04d",
      black: "#3b4252",
      red: "#bf616a",
      green: "#a3be8c",
      yellow: "#ebcb8b",
      blue: "#81a1c1",
      magenta: "#b48ead",
      cyan: "#88c0d0",
      white: "#e5e9f0",
      brightBlack: "#4c566a",
      brightRed: "#bf616a",
      brightGreen: "#a3be8c",
      brightYellow: "#ebcb8b",
      brightBlue: "#81a1c1",
      brightMagenta: "#b48ead",
      brightCyan: "#8fbcbb",
      brightWhite: "#eceff4",
    },
  },
  {
    id: "tomorrow-night",
    ground: "dark",
    colors: {
      background: "#1d1f21",
      foreground: "#c5c8c6",
      cursor: "#c5c8c6",
      cursorAccent: "#1d1f21",
      selection: "#81a2be4d",
      black: "#1d1f21",
      red: "#cc6666",
      green: "#b5bd68",
      yellow: "#f0c674",
      blue: "#81a2be",
      magenta: "#b294bb",
      cyan: "#8abeb7",
      white: "#c5c8c6",
      brightBlack: "#969896",
      brightRed: "#cc6666",
      brightGreen: "#b5bd68",
      brightYellow: "#f0c674",
      brightBlue: "#81a2be",
      brightMagenta: "#b294bb",
      brightCyan: "#8abeb7",
      brightWhite: "#ffffff",
    },
  },
  {
    id: "high-contrast",
    ground: "dark",
    colors: {
      background: "#000000",
      foreground: "#ffffff",
      cursor: "#ffff00",
      cursorAccent: "#000000",
      selection: "#ffff0059",
      black: "#000000",
      red: "#ff7b7b",
      green: "#5ee08f",
      yellow: "#ffc24d",
      blue: "#9db4ff",
      magenta: "#e9b6ff",
      cyan: "#63d8e6",
      white: "#ffffff",
      brightBlack: "#c3c9d0",
      brightRed: "#ff9b9b",
      brightGreen: "#8affb5",
      brightYellow: "#ffd782",
      brightBlue: "#b6c6ff",
      brightMagenta: "#f3d0ff",
      brightCyan: "#8af1ff",
      brightWhite: "#ffffff",
    },
  },
];

/** The appearance a fresh installation starts with. Mirrors `default_terminal()`. */
export const DEFAULT_TERMINAL_APPEARANCE: TerminalAppearance = {
  palette: "auto",
  overrides: {},
  fontFamily: "",
  fontSize: 13,
};

/** Bounds the core also enforces, repeated here so the control can say them. */
export const MIN_TERMINAL_FONT_SIZE = 8;
export const MAX_TERMINAL_FONT_SIZE = 32;

export function paletteById(id: string): TerminalPalette | undefined {
  return TERMINAL_PALETTES.find((palette) => palette.id === id);
}

/** Whether a string names a palette this build has, `"auto"` included. */
export function isTerminalPaletteId(id: string): id is TerminalPaletteId {
  return id === "auto" || paletteById(id) !== undefined;
}

/**
 * Which concrete palette `"auto"` means right now.
 *
 * The high-contrast pair maps to the high-contrast palette because a user who
 * asked for maximum contrast asked for it everywhere — a "tasteful" palette
 * inside the session would be the application quietly overruling an
 * accessibility setting. That was already the behaviour in CSS; it survives
 * the move here unchanged.
 */
export function resolvePaletteId(
  id: TerminalPaletteId,
  theme: InterfaceTheme,
): BuiltInPaletteId {
  if (id !== "auto") return id;
  if (theme === "hc-dark" || theme === "hc-light") return "high-contrast";
  return theme === "light" ? "remoter-light" : "remoter-dark";
}

// ------------------------------------------------------------ hex colour ----

export interface Rgba {
  r: number;
  g: number;
  b: number;
  /** 0–1. Only `selection` normally carries one. */
  a: number;
}

const HEX = /^#(?:[0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;

/**
 * Parses `#rgb`, `#rgba`, `#rrggbb` or `#rrggbbaa`, or returns null.
 *
 * People paste hex from anywhere — a theme gallery, a colleague's dotfiles, a
 * screenshot tool — so the short forms are accepted as written rather than
 * rejected for not being six digits.
 */
export function parseHexColor(text: string): Rgba | null {
  const trimmed = text.trim();
  if (!HEX.test(trimmed)) return null;

  const body = trimmed.slice(1);
  const short = body.length <= 4;
  const size = short ? 1 : 2;
  const channel = (index: number): number => {
    const part = body.slice(index * size, index * size + size);
    const value = Number.parseInt(short ? part + part : part, 16);
    return Number.isNaN(value) ? 0 : value;
  };

  const hasAlpha = body.length === 4 || body.length === 8;
  return {
    r: channel(0),
    g: channel(1),
    b: channel(2),
    a: hasAlpha ? channel(3) / 255 : 1,
  };
}

/**
 * The canonical form: lower case, `#rrggbb`, or `#rrggbbaa` when it is not
 * opaque. One form is what makes "did the user change this colour?" a string
 * comparison rather than a colour comparison.
 */
export function normaliseHex(text: string): string | null {
  const rgba = parseHexColor(text);
  if (rgba === null) return null;

  const pair = (value: number) => Math.round(value).toString(16).padStart(2, "0");
  const base = `#${pair(rgba.r)}${pair(rgba.g)}${pair(rgba.b)}`;
  return rgba.a >= 1 ? base : `${base}${pair(rgba.a * 255)}`;
}

/** The opaque part, for a `<input type="color">` — which cannot hold alpha. */
export function opaqueHex(text: string): string {
  const rgba = parseHexColor(text);
  if (rgba === null) return "#000000";
  const pair = (value: number) => Math.round(value).toString(16).padStart(2, "0");
  return `#${pair(rgba.r)}${pair(rgba.g)}${pair(rgba.b)}`;
}

// -------------------------------------------------------------- contrast ----

/** sRGB relative luminance. WCAG 2.2, §"relative luminance". */
export function relativeLuminance(rgba: Rgba): number {
  const linear = (value: number): number => {
    const channel = value / 255;
    return channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * linear(rgba.r) + 0.7152 * linear(rgba.g) + 0.0722 * linear(rgba.b);
}

/** Lays a translucent colour over an opaque one, so a ratio can be computed. */
export function compositeOver(top: Rgba, bottom: Rgba): Rgba {
  if (top.a >= 1) return top;
  const mix = (a: number, b: number) => a * top.a + b * (1 - top.a);
  return { r: mix(top.r, bottom.r), g: mix(top.g, bottom.g), b: mix(top.b, bottom.b), a: 1 };
}

/**
 * The WCAG contrast ratio between two colours, 1 to 21.
 *
 * Either may be translucent; it is composited over the other first, because a
 * ratio against a colour that is partly the colour behind it is meaningless
 * otherwise. Returns 1 — "indistinguishable" — for anything unparseable, which
 * is the safe answer: it warns rather than staying quiet.
 */
export function contrastRatio(foreground: string, background: string): number {
  const back = parseHexColor(background);
  const front = parseHexColor(foreground);
  if (back === null || front === null) return 1;

  const solidBack = back.a >= 1 ? back : compositeOver(back, { r: 0, g: 0, b: 0, a: 1 });
  const solidFront = compositeOver(front, solidBack);

  const a = relativeLuminance(solidFront);
  const b = relativeLuminance(solidBack);
  const lighter = Math.max(a, b);
  const darker = Math.min(a, b);
  return (lighter + 0.05) / (darker + 0.05);
}

/**
 * How a ratio rates for terminal text.
 *
 * Terminal output is body text at any size the user picks, so AA is 4.5:1 and
 * the 3:1 large-text allowance is a warning rather than a pass — it applies to
 * 18pt, and nobody runs a shell at 18pt.
 */
export type ContrastGrade = "aaa" | "aa" | "large" | "fail";

export function gradeContrast(ratio: number): ContrastGrade {
  if (ratio >= 7) return "aaa";
  if (ratio >= 4.5) return "aa";
  if (ratio >= 3) return "large";
  return "fail";
}

export interface ContrastEntry {
  key: TerminalColorKey;
  ratio: number;
  grade: ContrastGrade;
}

/**
 * Every colour a program prints text in, rated against the background.
 *
 * Cursor, cursor accent, selection and the background itself are not in the
 * list: they are not text, and rating them would bury the seventeen that are.
 */
export function contrastReport(colors: TerminalColors): ContrastEntry[] {
  const graded: TerminalColorKey[] = ["foreground", ...TERMINAL_ANSI_KEYS];
  return graded.map((key) => {
    const ratio = contrastRatio(colors[key], colors.background);
    return { key, ratio, grade: gradeContrast(ratio) };
  });
}

/** Just the ones that will be hard to read. */
export function failingColors(colors: TerminalColors): ContrastEntry[] {
  return contrastReport(colors).filter((entry) => entry.grade === "large" || entry.grade === "fail");
}

// ------------------------------------------------------------ resolution ----

function isColorKey(key: string): key is TerminalColorKey {
  return (TERMINAL_COLOR_KEYS as readonly string[]).includes(key);
}

/**
 * The colours a terminal actually draws with: the palette, then the user's
 * overrides on top.
 *
 * An override that names a colour this build does not have, or that is not a
 * colour, is dropped rather than allowed to blank a slot. A settings file
 * hand-edited into nonsense should cost the user the one line they broke, not
 * a terminal with no foreground.
 */
export function resolveTerminalColors(
  appearance: TerminalAppearance,
  theme: InterfaceTheme,
): TerminalColors {
  const id = isTerminalPaletteId(appearance.palette) ? appearance.palette : "auto";
  // `resolvePaletteId` only ever names a palette in the table, but the lookup
  // is fallible by type, and a missing palette must not take the session area
  // down with it — so an unknown id falls back to the shipped dark set.
  const base = paletteById(resolvePaletteId(id, theme)) ?? REMOTER_DARK;
  const colors: TerminalColors = { ...base.colors };

  for (const [key, value] of Object.entries(appearance.overrides ?? {})) {
    if (!isColorKey(key)) continue;
    const hex = normaliseHex(value);
    if (hex !== null) colors[key] = hex;
  }

  return colors;
}

/** The palette a reset goes back to, with no overrides applied. */
export function baseTerminalColors(
  appearance: TerminalAppearance,
  theme: InterfaceTheme,
): TerminalColors {
  return resolveTerminalColors(
    { ...appearance, overrides: {} },
    theme,
  );
}

/**
 * Drops overrides that now equal the palette they sit on.
 *
 * Without this, setting a colour back to its palette value by hand would leave
 * an override that looks changed, and would then stop following the palette
 * when the user switched to a different one.
 */
export function pruneOverrides(
  appearance: TerminalAppearance,
  theme: InterfaceTheme,
): Record<string, string> {
  const base = baseTerminalColors(appearance, theme);
  const kept: Record<string, string> = {};

  for (const [key, value] of Object.entries(appearance.overrides ?? {})) {
    if (!isColorKey(key)) continue;
    const hex = normaliseHex(value);
    if (hex === null || hex === base[key]) continue;
    kept[key] = hex;
  }

  return kept;
}
