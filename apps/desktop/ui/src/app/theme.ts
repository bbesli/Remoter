/**
 * Which theme the window is drawn in, from the first frame on.
 *
 * The user's choice is stored by the core, in the settings file, and it used to
 * be read back only when the Settings screen was opened. Everywhere else the
 * application started on the store's default, `system`, and stayed there until
 * someone happened to open Settings — so a person who had chosen dark opened
 * the application to a light window, while the native window background and
 * anything drawn from the core's own copy of the settings came up dark. Part
 * light and part dark, on every start.
 *
 * Two things fix it, and both are needed:
 *
 * - **The core's value is applied at start-up**, from the same settings read
 *   the language already uses, without waiting for any screen. The core is the
 *   authority: a settings file edited between runs wins.
 * - **The last theme the window showed is remembered in the WebView's own
 *   storage** and put on `<html>` before React renders. The settings read is a
 *   round trip, and without this the first frames of every start would still be
 *   drawn in the default and then change under the user's eyes. It is a cache,
 *   nothing more: when it is missing or wrong, the core's answer replaces it a
 *   moment later.
 */

import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";

import { useSystemTheme } from "@/hooks/useSystemTheme";
import { ipc, type ThemeName } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

/** A theme the stylesheet has a token block for: `system` resolved. */
export type ResolvedTheme = Exclude<ThemeName, "system">;

const CHOICE_KEY = "remoter.theme.choice";
const RESOLVED_KEY = "remoter.theme.resolved";

const CHOICES: readonly ThemeName[] = ["system", "light", "dark", "hc-light", "hc-dark"];

function isChoice(value: string | null): value is ThemeName {
  return value !== null && (CHOICES as readonly string[]).includes(value);
}

function isResolved(value: string | null): value is ResolvedTheme {
  return isChoice(value) && value !== "system";
}

/**
 * The theme the window showed when it last closed, if the WebView kept it.
 *
 * Storage can be unavailable — a private profile, a sandbox that refuses it —
 * and then there is simply nothing remembered.
 */
export function recallTheme(): { choice: ThemeName; resolved: ResolvedTheme } | null {
  try {
    const choice = globalThis.localStorage.getItem(CHOICE_KEY);
    const resolved = globalThis.localStorage.getItem(RESOLVED_KEY);
    if (!isChoice(choice) || !isResolved(resolved)) return null;
    return { choice, resolved };
  } catch {
    return null;
  }
}

function rememberTheme(choice: ThemeName, resolved: ResolvedTheme): void {
  try {
    globalThis.localStorage.setItem(CHOICE_KEY, choice);
    globalThis.localStorage.setItem(RESOLVED_KEY, resolved);
  } catch {
    // Nothing remembered; the next start reads the core's value a moment later.
  }
}

/**
 * Before the first render: put the remembered theme on the document and in the
 * store, so the first frame is already the right one.
 */
export function applyRememberedTheme(): void {
  const remembered = recallTheme();
  if (remembered === null) return;
  document.documentElement.dataset["theme"] = remembered.resolved;
  useApp.getState().setTheme(remembered.choice);
}

/**
 * Keeps `<html data-theme>` in step with the user's choice, the stored setting
 * and the operating system. Mounted once, by `App`.
 */
export function useAppliedTheme(): void {
  const theme = useApp((state) => state.theme);
  const setTheme = useApp((state) => state.setTheme);
  const systemTheme = useSystemTheme();

  // The same query the language is read from, so start-up makes one settings
  // call and not two. `staleTime: Infinity` matches it: later changes arrive
  // through the Settings screen writing this cache, not through refetching.
  const stored = useQuery({
    queryKey: qk.settings(),
    queryFn: ipc.getSettings,
    staleTime: Infinity,
  }).data?.theme;

  useEffect(() => {
    if (stored !== undefined) setTheme(stored);
  }, [stored, setTheme]);

  useEffect(() => {
    const resolved: ResolvedTheme = theme === "system" ? systemTheme : theme;
    document.documentElement.dataset["theme"] = resolved;
    rememberTheme(theme, resolved);
    void paintWindowBackground();
  }, [theme, systemTheme]);
}

/**
 * The native window's own background, to the theme's canvas colour.
 *
 * `tauri.conf.json` fixes it at the dark canvas so a dark start does not flash
 * white. Under a light theme that same colour showed through wherever the
 * WebView had not painted yet — the strip a resize uncovers, the first frame —
 * as dark bands around a light window. Best effort: outside Tauri, or on an
 * engine that ignores it, the window keeps the configured colour.
 */
async function paintWindowBackground(): Promise<void> {
  const canvas = getComputedStyle(document.documentElement).getPropertyValue("--bg-canvas").trim();
  const rgb = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(canvas);
  if (rgb === null) return;
  const [r, g, b] = [rgb[1], rgb[2], rgb[3]].map((hex) => Number.parseInt(hex ?? "0", 16));
  try {
    const { getCurrentWindow } = await import("@tauri-apps/api/window");
    await getCurrentWindow().setBackgroundColor([r ?? 0, g ?? 0, b ?? 0, 255]);
  } catch {
    // Not inside Tauri, or the platform does not support it.
  }
}
