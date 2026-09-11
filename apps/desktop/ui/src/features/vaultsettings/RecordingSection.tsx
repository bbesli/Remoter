/**
 * The vault's recording policy.
 *
 * Inheritable: this is the value everything in the vault uses unless a folder
 * or a connection sets its own, which is how an organisation sets it once.
 *
 * **This build has no recorder.** `docs/roadmap.md` puts session recording at
 * v0.4, and the whole of `docs/features/recording-audit.md` describes something
 * that does not exist yet. The cards stay, because the vault already carries
 * the field and storing the intent now is what makes the policy available the
 * day the recorder lands — but the screen says so above the cards, in the
 * warning callout, rather than in a note underneath them. A user who reads
 * "every session is recorded" and believes it will behave as though they have
 * a compliance record they do not have, which is the one failure mode of this
 * screen that costs something. Hence also the tense: every line here that
 * describes recording behaviour is written in the future, so no sentence on
 * this screen is a claim about what is happening today.
 *
 * `docs/features/recording-audit.md` names four policies. The vault file holds
 * three — never, ask, always — and `Required`, the compliance one that will
 * refuse to connect when recording cannot start, has no field behind it. It is
 * described here rather than offered, because a fourth card that silently
 * stored "always" would be the difference between a session that is refused
 * and a session that is recorded on a best-effort basis.
 */

import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { useT } from "@/i18n";
import type { RecordingPolicy } from "@/lib/ipc";

import type { VaultSectionProps } from "./types";
import c from "./controls.module.css";
import s from "./RecordingSection.module.css";

/**
 * The three policies the vault file can hold, as catalogue keys: this array is
 * module-level, and a resolved label here would not follow a language change.
 */
const CHOICES = [
  { value: "never", labelKey: "recording.never", helpKey: "recording.neverHelp" },
  { value: "on_request", labelKey: "recording.ask", helpKey: "recording.askHelp" },
  { value: "always", labelKey: "recording.always", helpKey: "recording.alwaysHelp" },
] as const satisfies readonly { value: RecordingPolicy; labelKey: string; helpKey: string }[];

export function RecordingSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: VaultSectionProps) {
  const t = useT("vaultsettings");
  const saving = savingField === "recording";
  const problem = failure !== null && failure.field === "recording" ? failure.failure : null;

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{t("recording.title")}</h2>
        <p className={s.description}>{t("recording.description")}</p>
      </div>

      {/* Above the cards, not below them: this is the fact that decides what
          the cards mean, and a reader who stops after the first control has
          still read it. */}
      <Callout tone="warning" title={t("recording.notYetTitle")}>
        {t("recording.notYetBody")}
      </Callout>

      <fieldset className={c.choices} disabled={saving}>
        <legend className={s.hiddenLegend}>{t("recording.title")}</legend>
        {CHOICES.map((choice) => (
          <label
            key={choice.value}
            className={
              choice.value === settings.recording ? [c.choice, c.choiceOn].join(" ") : c.choice
            }
          >
            <input
              className={c.radio}
              type="radio"
              name="vault-recording"
              value={choice.value}
              checked={choice.value === settings.recording}
              onChange={() => onSave("recording", { recording: choice.value })}
            />
            <span className={c.mark} aria-hidden="true" />
            <span className={c.choiceText}>
              <span className={c.choiceName}>{t(choice.labelKey)}</span>
              <span className={c.choiceHelp}>{t(choice.helpKey)}</span>
            </span>
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
        <FailureNotice failure={problem} title={t("recording.failed")} onRetry={onRetrySave} />
      )}

      <div className={s.notes}>
        <p className={c.note}>{t("recording.required")}</p>
        <p className={c.note}>{t("recording.storage")}</p>
      </div>
    </section>
  );
}
