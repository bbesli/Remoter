/**
 * The rolling backups kept beside the vault file.
 *
 * This number does not mean what it used to, and the change is invisible from
 * the control, so the panel explains it. Rotation happens on the **first save
 * of a session**, not on every save: every node edit is a save, so with three
 * backups the image from before an editing mistake used to be gone after four
 * ordinary clicks. Rotating once a session makes `.bak.1` the vault as it stood
 * when you opened it — see docs/security/vault-format.md, which is where the
 * reasoning lives.
 *
 * Zero is a legitimate answer, not a warning to talk someone out of. A vault in
 * a synced folder already has the provider keeping historical copies of the
 * ciphertext, and some people would rather not add three more.
 *
 * The count is stored in the header, which is readable before the body is
 * decrypted — which is exactly the situation the backups exist for.
 */

import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { formatNumber, useLocale, useT } from "@/i18n";

import { BACKUP_MAX } from "./slots";
import type { VaultSectionProps } from "./types";
import c from "./controls.module.css";
import s from "./BackupsSection.module.css";

interface BackupsSectionProps extends VaultSectionProps {
  /** How many backup files are beside the vault now, from the slot read. */
  backupsPresent: number;
}

export function BackupsSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
  backupsPresent,
}: BackupsSectionProps) {
  const t = useT("vaultsettings");
  const { code: locale } = useLocale();
  const saving = savingField === "backupCount";
  const problem = failure !== null && failure.field === "backupCount" ? failure.failure : null;
  const choices = Array.from({ length: BACKUP_MAX + 1 }, (_unused, n) => n);

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{t("backups.title")}</h2>
        <p className={s.description}>{t("backups.description")}</p>
      </div>

      <fieldset className={c.chips} disabled={saving}>
        <legend className={c.legend}>{t("backups.legend")}</legend>
        {choices.map((count) => (
          <label
            key={count}
            className={count === settings.backupCount ? [c.chip, c.chipOn].join(" ") : c.chip}
          >
            <input
              className={c.radio}
              type="radio"
              name="vault-backup-count"
              value={count}
              checked={count === settings.backupCount}
              onChange={() => onSave("backupCount", { backupCount: count })}
            />
            {/* A bare numeral, but still a number: Intl draws it in the
                digits this locale uses. */}
            {count === 0 ? t("backups.none") : formatNumber(locale, count)}
          </label>
        ))}
      </fieldset>

      {saving && (
        <p className={c.saving}>
          <Spinner size={14} label={t("status.saving")} />
          {t("status.saving")}
        </p>
      )}
      {problem !== null && (
        <FailureNotice failure={problem} title={t("backups.failed")} onRetry={onRetrySave} />
      )}

      <div className={s.explainer}>
        <h3 className={s.explainerTitle}>{t("backups.onceASession")}</h3>
        <p className={s.explainerBody}>{t("backups.onceASessionBody")}</p>
      </div>

      <div className={s.explainer}>
        <h3 className={s.explainerTitle}>{t("backups.zeroTitle")}</h3>
        <p className={s.explainerBody}>{t("backups.zeroBody")}</p>
      </div>

      <p className={c.note}>
        {t("backups.present", { count: backupsPresent })} {t("backups.presentPrune")}
      </p>
    </section>
  );
}
