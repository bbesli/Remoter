/**
 * Theme selection.
 *
 * Each option is a miniature of the real window painted in the theme it
 * offers, so "high contrast dark" is a picture rather than a promise. The
 * miniatures are built from the same tokens the application uses — see
 * `themePalette.ts` for why they are read back from the stylesheet.
 *
 * "Follow the system" is a fifth radio rather than a separate switch: it is one
 * value of one setting, and a switch beside a radio group invites the question
 * of which one wins.
 *
 * A choice applies before it is persisted. The store drives what is on screen
 * and the write to the core follows; if the write fails the screen hosting this
 * section puts the applied theme back to the stored one, so the interface never
 * shows a theme the vault does not hold.
 */

import { useState } from "react";

import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { useSystemTheme } from "@/hooks/useSystemTheme";
import type { ThemeName } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import { SettingsSection } from "./SettingsSection";
import { useT } from "@/i18n";
import {
  PREVIEW_THEMES,
  paletteStyle,
  readThemePalettes,
  type PreviewTheme,
  type ThemePalette,
} from "./themePalette";
import type { SectionProps } from "./types";
import s from "./AppearanceSection.module.css";


/**
 * Catalogue keys rather than labels: this map is module-level, and a label
 * resolved at import would keep the language the application started in.
 */
const THEME_LABEL_KEYS = {
  light: "appearance.light",
  dark: "appearance.dark",
  "hc-light": "appearance.hcLight",
  "hc-dark": "appearance.hcDark",
} as const satisfies Record<PreviewTheme, string>;

/** The miniature: a title bar, a sidebar and a content pane, as in the design. */
function ThemePreview({ palette }: { palette: ThemePalette | undefined }) {
  const t = useT("settings");

  if (palette === undefined) {
    return (
      <div className={s.previewMissing}>
        <span>{t("appearance.previewUnavailable")}</span>
      </div>
    );
  }

  return (
    <div className={s.preview} style={paletteStyle(palette)} aria-hidden="true">
      <div className={s.previewBar}>
        <span className={s.previewDot} />
        <span className={s.previewBarLine} />
      </div>
      <div className={s.previewBody}>
        {/* Widths come from the stylesheet by position: these are shapes, not data. */}
        <div className={s.previewSidebar}>
          <span className={s.previewLine} />
          <span className={s.previewLine} />
          <span className={s.previewLineAccent} />
        </div>
        <div className={s.previewContent}>
          <span className={s.previewLineStrong} />
          <span className={s.previewLine} />
          <span className={s.previewLine} />
        </div>
      </div>
    </div>
  );
}

export function AppearanceSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: SectionProps) {
  const t = useT("settings");
  const tCommon = useT("common");
  const setTheme = useApp((state) => state.setTheme);
  const systemTheme = useSystemTheme();

  // Read on first render. The stylesheet is in the document before React
  // mounts and does not change while the window is open, so this is a lazy
  // initial value rather than an effect.
  const [palettes] = useState<Map<PreviewTheme, ThemePalette>>(readThemePalettes);

  const saving = savingField === "theme";
  const themeFailure = failure !== null && failure.field === "theme" ? failure.failure : null;

  function choose(theme: ThemeName) {
    if (theme === settings.theme) return;
    setTheme(theme);
    onSave("theme", { theme });
  }

  return (
    <SettingsSection title={t("appearance.title")} description={t("appearance.description")}>
      <div className={s.group} role="radiogroup" aria-label={t("appearance.title")}>
        <div className={s.grid}>
          {PREVIEW_THEMES.map((theme) => (
            <label key={theme} className={s.card}>
              <input
                className={s.radio}
                type="radio"
                name="remoter-theme"
                value={theme}
                checked={settings.theme === theme}
                onChange={() => choose(theme)}
                // The label's own text is a miniature plus a name; naming the
                // control here keeps what is announced short and exact.
                aria-label={t(THEME_LABEL_KEYS[theme])}
              />
              <ThemePreview palette={palettes.get(theme)} />
              <span className={s.cardLabel}>
                <span className={s.mark} aria-hidden="true" />
                <span className={s.cardName}>{t(THEME_LABEL_KEYS[theme])}</span>
              </span>
            </label>
          ))}
        </div>

        <label className={s.systemRow}>
          <input
            className={s.radio}
            type="radio"
            name="remoter-theme"
            value="system"
            checked={settings.theme === "system"}
            onChange={() => choose("system")}
            aria-label={t("appearance.system")}
          />
          <span className={s.mark} aria-hidden="true" />
          <span className={s.systemName}>{t("appearance.system")}</span>
          <span className={s.systemHint}>
            {t("appearance.systemNow", {
              resolved:
                systemTheme === "light"
                  ? t("appearance.systemLight")
                  : t("appearance.systemDark"),
            })}
          </span>
        </label>
      </div>

      {saving && (
        <p className={s.saving}>
          <Spinner size={14} label={t("appearance.saving")} />
          {t("appearance.saving")}
        </p>
      )}

      {themeFailure !== null && (
        <FailureNotice
          failure={themeFailure}
          title={t("appearance.saveFailed")}
          onRetry={onRetrySave}
          retryLabel={tCommon("action.saveAgain")}
        />
      )}

      {/* The terminal is configurable, on the next tab along, so this line is a
          pointer rather than a limitation. The second half is load-bearing:
          the palette ships as "follow the interface theme", so a choice made
          here does change the terminal until somebody picks a palette over
          there — saying only "they are separate" would be the same kind of
          wrong sentence this line replaced. */}
      <p className={s.note}>{t("appearance.terminalNote")}</p>
    </SettingsSection>
  );
}
