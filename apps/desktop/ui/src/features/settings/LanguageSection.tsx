/**
 * Language selection.
 *
 * Remoter is specified to ship in ten languages (docs/features/i18n.md) and
 * exactly one of them is translated today. Listing the other nine as if they
 * were choices would produce a control that changes nothing — the worst
 * outcome available here, because the user cannot tell a broken setting from a
 * language that simply reuses English strings. So the nine are shown, disabled,
 * each saying what it is waiting for.
 *
 * Every name is written in its own script and carries `lang` so a screen reader
 * pronounces it and the browser picks the right font. Arabic additionally
 * carries `dir`, since the surrounding paragraph is left-to-right.
 */

import { Badge } from "@/components/Badge";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { useApp } from "@/stores/app";

import { SettingsSection } from "./SettingsSection";
import type { SectionProps } from "./types";
import s from "./LanguageSection.module.css";

const TEXT = {
  title: "Language",
  description:
    "Ten languages are planned for 1.0. Right-to-left languages mirror the whole layout, not just the text.",

  progress:
    "Only English is translated so far. The other nine are listed because translation is under way; each becomes selectable when its catalogue is complete, and until then choosing it would change nothing.",

  notReady: "Not yet available",
  unavailableLabel: (name: string) => `${name} — not yet available`,
  rtl: "RTL",
  saving: "Saving the language…",
  saveFailed: "The language was not saved.",
  retry: "Save again",

  storedUnavailable: (locale: string) =>
    `Your settings ask for ${locale}, which has no catalogue yet, so the interface stays in English.`,
} as const;

interface Locale {
  /** The BCP 47 tag stored in settings and used for the catalogue directory. */
  code: string;
  /** The language's own name, in its own script. Never translated. */
  name: string;
  rtl: boolean;
  /** True once `locales/<code>/` is complete enough to select. */
  available: boolean;
}

/** The ten from docs/features/i18n.md, in that document's order. */
const LOCALES: readonly Locale[] = [
  { code: "en", name: "English", rtl: false, available: true },
  { code: "zh-Hans", name: "简体中文", rtl: false, available: false },
  { code: "es", name: "Español", rtl: false, available: false },
  { code: "hi", name: "हिन्दी", rtl: false, available: false },
  { code: "ar", name: "العربية", rtl: true, available: false },
  { code: "pt-BR", name: "Português (Brasil)", rtl: false, available: false },
  { code: "ru", name: "Русский", rtl: false, available: false },
  { code: "fr", name: "Français", rtl: false, available: false },
  { code: "de", name: "Deutsch", rtl: false, available: false },
  { code: "tr", name: "Türkçe", rtl: false, available: false },
];

export function LanguageSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: SectionProps) {
  const setLocale = useApp((state) => state.setLocale);

  const saving = savingField === "locale";
  const localeFailure = failure !== null && failure.field === "locale" ? failure.failure : null;
  const storedIsAvailable = LOCALES.some(
    (locale) => locale.code === settings.locale && locale.available,
  );

  function choose(code: string) {
    if (code === settings.locale) return;
    setLocale(code);
    onSave("locale", { locale: code });
  }

  return (
    <SettingsSection title={TEXT.title} description={TEXT.description}>
      <p className={s.progress}>{TEXT.progress}</p>

      {!storedIsAvailable && <p className={s.mismatch}>{TEXT.storedUnavailable(settings.locale)}</p>}

      <div className={s.grid} role="radiogroup" aria-label={TEXT.title}>
        {LOCALES.map((locale) => (
          <label
            key={locale.code}
            className={locale.available ? s.row : [s.row, s.unavailable].join(" ")}
          >
            <input
              className={s.radio}
              type="radio"
              name="remoter-locale"
              value={locale.code}
              checked={settings.locale === locale.code}
              disabled={!locale.available}
              onChange={() => choose(locale.code)}
              // The row carries a badge and a status beside the name; the
              // control is named on its own so the announcement stays exact.
              aria-label={locale.available ? locale.name : TEXT.unavailableLabel(locale.name)}
            />
            <span className={s.mark} aria-hidden="true" />
            <span
              className={s.name}
              lang={locale.code}
              {...(locale.rtl ? { dir: "rtl" as const } : {})}
            >
              {locale.name}
            </span>
            {locale.rtl && <Badge tone="info">{TEXT.rtl}</Badge>}
            <span className={s.spacer} />
            {!locale.available && <span className={s.status}>{TEXT.notReady}</span>}
          </label>
        ))}
      </div>

      {saving && (
        <p className={s.saving}>
          <Spinner size={14} label={TEXT.saving} />
          {TEXT.saving}
        </p>
      )}

      {localeFailure !== null && (
        <FailureNotice
          failure={localeFailure}
          title={TEXT.saveFailed}
          onRetry={onRetrySave}
          retryLabel={TEXT.retry}
        />
      )}
    </SettingsSection>
  );
}
