/**
 * The four themes' colour tokens, read back from the stylesheet that defines
 * them.
 *
 * A theme preview has to paint a theme that is not the one currently applied.
 * The token blocks in `styles/tokens.css` are bound to `:root[data-theme=…]`,
 * and `:root` matches the document element only — the same attribute on a
 * nested wrapper inherits nothing. The alternative to reading the rules back is
 * a second copy of the palettes inside this feature, which would drift from the
 * originals the first time either side is edited. So the values are looked up
 * once at runtime and handed to the preview as local variable overrides.
 */

import type { CSSProperties } from "react";

import type { ThemeName } from "@/lib/ipc";

/** Every theme that has a palette of its own. "system" resolves to one of these. */
export type PreviewTheme = Exclude<ThemeName, "system">;

export const PREVIEW_THEMES: readonly PreviewTheme[] = [
  "light",
  "dark",
  "hc-light",
  "hc-dark",
];

/** Only what the miniature paints. Copying a whole block would be waste. */
const PREVIEW_TOKENS = [
  "--bg-canvas",
  "--bg-surface",
  "--bg-inset",
  "--border-default",
  "--border-strong",
  "--accent",
  "--fg-muted",
] as const;

type PreviewToken = (typeof PREVIEW_TOKENS)[number];

export type ThemePalette = Record<PreviewToken, string>;

/** Same-origin sheets only; a cross-origin one throws on `cssRules`. */
function styleRules(): CSSStyleRule[] {
  const rules: CSSStyleRule[] = [];

  for (const sheet of Array.from(document.styleSheets)) {
    let list: CSSRuleList;
    try {
      list = sheet.cssRules;
    } catch {
      continue;
    }
    for (const rule of Array.from(list)) {
      if (rule instanceof CSSStyleRule) rules.push(rule);
    }
  }

  return rules;
}

/**
 * Reads each theme's preview tokens. A theme whose block is not found is
 * omitted rather than half-filled, so the caller can fall back to a preview
 * that claims no colours at all instead of showing wrong ones.
 */
export function readThemePalettes(): Map<PreviewTheme, ThemePalette> {
  const palettes = new Map<PreviewTheme, ThemePalette>();
  const rules = styleRules();

  for (const theme of PREVIEW_THEMES) {
    // `[data-theme="light"]` does not match `[data-theme="hc-light"]`: the
    // quote is part of the needle.
    const marker = `[data-theme="${theme}"]`;
    const found: Partial<Record<PreviewToken, string>> = {};

    for (const rule of rules) {
      if (!rule.selectorText.includes(marker)) continue;
      for (const token of PREVIEW_TOKENS) {
        const value = rule.style.getPropertyValue(token).trim();
        if (value !== "") found[token] = value;
      }
    }

    const complete = PREVIEW_TOKENS.every((token) => found[token] !== undefined);
    if (complete) palettes.set(theme, found as ThemePalette);
  }

  return palettes;
}

/**
 * The palette as inline custom properties.
 *
 * They carry the token names themselves, so the preview's stylesheet reads like
 * any other component's — `var(--bg-surface)` — and simply resolves against the
 * theme being previewed.
 */
export function paletteStyle(palette: ThemePalette): CSSProperties {
  return palette as CSSProperties;
}
