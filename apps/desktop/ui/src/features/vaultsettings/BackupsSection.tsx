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

import { BACKUP_MAX } from "./slots";
import type { VaultSectionProps } from "./types";
import c from "./controls.module.css";
import s from "./BackupsSection.module.css";

const TEXT = {
  title: "Backups",
  description:
    "Before the vault is overwritten, the previous file is rotated into a rolling backup beside it: vault.rvault.bak.1 through .bak.N.",

  legend: "How many to keep",
  none: "None",
  count: (n: number) => `${n}`,

  onceASession: "Rotated once per session, not once per save",
  onceASessionBody:
    "Every edit to a node is a save. If a backup were taken on each one, three backups would be four clicks deep and the file from before a mistake would already be gone. Rotating on the first save of a session makes .bak.1 the vault exactly as it stood when you opened it.",

  zeroTitle: "Keeping none is a real choice",
  zeroBody:
    "If this vault lives in a synced folder, the provider already keeps historical copies of the ciphertext, and you may not want extra copies of it lying around the disk as well.",

  present: (n: number) =>
    n === 0
      ? "There are no backups beside this vault right now."
      : n === 1
        ? "One backup sits beside this vault right now."
        : `${n} backups sit beside this vault right now.`,
  presentPrune:
    "Lowering the number does not delete the files already written; the next rotation stops at the new limit.",

  saving: "Saving…",
  failed: "The backup count was not saved.",
} as const;

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
  const saving = savingField === "backupCount";
  const problem = failure !== null && failure.field === "backupCount" ? failure.failure : null;
  const choices = Array.from({ length: BACKUP_MAX + 1 }, (_unused, n) => n);

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{TEXT.title}</h2>
        <p className={s.description}>{TEXT.description}</p>
      </div>

      <fieldset className={c.chips} disabled={saving}>
        <legend className={c.legend}>{TEXT.legend}</legend>
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
            {count === 0 ? TEXT.none : TEXT.count(count)}
          </label>
        ))}
      </fieldset>

      {saving && (
        <p className={c.saving}>
          <Spinner size={14} label={TEXT.saving} />
          {TEXT.saving}
        </p>
      )}
      {problem !== null && (
        <FailureNotice failure={problem} title={TEXT.failed} onRetry={onRetrySave} />
      )}

      <div className={s.explainer}>
        <h3 className={s.explainerTitle}>{TEXT.onceASession}</h3>
        <p className={s.explainerBody}>{TEXT.onceASessionBody}</p>
      </div>

      <div className={s.explainer}>
        <h3 className={s.explainerTitle}>{TEXT.zeroTitle}</h3>
        <p className={s.explainerBody}>{TEXT.zeroBody}</p>
      </div>

      <p className={c.note}>
        {TEXT.present(backupsPresent)} {TEXT.presentPrune}
      </p>
    </section>
  );
}
