/**
 * "Ctrl+Alt — prefix active in terminal", at the end of the status bar.
 *
 * `ui_parts/project_ui_design/03 Main Window` puts this line at the inline end
 * of the bar under the session, and it earns the pixels: while a terminal has
 * the keyboard the application's own shortcuts are a different chord from the
 * one the settings screen shows, and nothing else on screen says so. It
 * appears only while that is true, because a hint that is always on screen is
 * a hint nobody reads.
 */

import type { ReactNode } from "react";

import { useT } from "@/i18n";

import { acceleratorCaps } from "./accelerator";
import { useKeyboardSettings, useTerminalFocused } from "./registry";

import s from "./PrefixIndicator.module.css";

interface PrefixProps {
  /** Passed in so this module stays below the session feature. */
  isTerminalFocused: () => boolean;
}

export function TerminalPrefixIndicator({ isTerminalFocused }: PrefixProps) {
  const t = useT("common");
  const focused = useTerminalFocused(isTerminalFocused);
  const { prefix } = useKeyboardSettings();

  if (!focused) return null;

  // The prefix is modifiers only, so every cap it produces is a modifier name.
  const caps = acceleratorCaps(`${prefix}+space`).slice(0, -1);

  return (
    <div className={s.indicator} title={t("terminalPrefix.explained")}>
      <span className={s.keys}>
        {caps.map((cap) => (
          // Key caps — Ctrl, Alt, Shift — are key names and are never
          // translated (docs/features/i18n.md).
          <kbd key={cap} className={s.key}>
            {cap}
          </kbd>
        ))}
      </span>
      <span>{t("terminalPrefix.active")}</span>
    </div>
  );
}

/**
 * The status bar with the prefix hint pinned to its inline end.
 *
 * A wrapper rather than a change to `StatusBar` itself: the bar describes the
 * session, and this describes the keyboard. They share a row, not a
 * responsibility.
 */
export function StatusBarPrefixRow({
  isTerminalFocused,
  children,
}: PrefixProps & { children: ReactNode }) {
  return (
    <div className={s.row}>
      {children}
      <TerminalPrefixIndicator isTerminalFocused={isTerminalFocused} />
    </div>
  );
}
