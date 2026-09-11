/**
 * Language selection.
 *
 * This screen used to list ten languages and mark nine of them "Not yet
 * available", from a hardcoded `available` flag. That was honest at the time
 * and is exactly the wrong shape now: the flag has to be edited by hand when a
 * catalogue lands, so the first thing that happens after a translation ships is
 * that the screen keeps calling it unavailable. Availability is measured from
 * the catalogue directory instead (`isLocaleAvailable`), so a language becomes
 * selectable the moment `locales/<code>/` is complete and this file needs no
 * change at all.
 *
 * Choosing one takes effect immediately: `setLocale` moves the store, the
 * provider above the whole application loads the catalogues and writes `lang`
 * and `dir` onto the document, and `onSave` persists it. No restart, and no
 * remount — every component reads its copy through `useT`, which re-renders on
 * a language change.
 *
 * Every name is written in its own script and carries `lang` so a screen reader
 * pronounces it and the browser picks the right font. A right-to-left name
 * additionally carries `dir`, because the row around it is in the interface's
 * direction, not the language's.
 */

import { Badge } from "@/components/Badge";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { SUPPORTED_LOCALES, isLocaleAvailable, useT } from "@/i18n";
import { useApp } from "@/stores/app";

import { SettingsSection } from "./SettingsSection";
import type { SectionProps } from "./types";
import s from "./LanguageSection.module.css";

export function LanguageSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: SectionProps) {
  const t = useT("settings");
  const tCommon = useT("common");
  const setLocale = useApp((state) => state.setLocale);

  const saving = savingField === "locale";
  const localeFailure = failure !== null && failure.field === "locale" ? failure.failure : null;

  // Measured, not declared. Both of these were constants until the catalogues
  // existed, and a constant is what let the screen go stale.
  const locales = SUPPORTED_LOCALES.map((locale) => ({
    ...locale,
    available: isLocaleAvailable(locale.code),
  }));
  const availableCount = locales.filter((locale) => locale.available).length;
  const storedIsAvailable = isLocaleAvailable(settings.locale);

  function choose(code: string) {
    if (code === settings.locale) return;
    setLocale(code);
    onSave("locale", { locale: code });
  }

  return (
    <SettingsSection title={t("language.title")} description={t("language.description")}>
      <p className={s.progress}>{t("language.progress", { available: availableCount })}</p>

      {!storedIsAvailable && (
        <p className={s.mismatch}>
          {t("language.storedUnavailable", { locale: settings.locale })}
        </p>
      )}

      <div className={s.grid} role="radiogroup" aria-label={t("language.title")}>
        {locales.map((locale) => (
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
              // The endonym is not translated in either case.
              aria-label={
                locale.available
                  ? locale.endonym
                  : t("language.unavailableLabel", { name: locale.endonym })
              }
            />
            <span className={s.mark} aria-hidden="true" />
            <span
              className={s.name}
              lang={locale.code}
              {...(locale.dir === "rtl" ? { dir: "rtl" as const } : {})}
            >
              {locale.endonym}
            </span>
            {locale.dir === "rtl" && <Badge tone="info">{t("language.rtl")}</Badge>}
            <span className={s.spacer} />
            {!locale.available && <span className={s.status}>{t("language.notReady")}</span>}
          </label>
        ))}
      </div>

      {saving && (
        <p className={s.saving}>
          <Spinner size={14} label={t("language.saving")} />
          {t("language.saving")}
        </p>
      )}

      {localeFailure !== null && (
        <FailureNotice
          failure={localeFailure}
          title={t("language.saveFailed")}
          onRetry={onRetrySave}
          retryLabel={tCommon("action.saveAgain")}
        />
      )}
    </SettingsSection>
  );
}
