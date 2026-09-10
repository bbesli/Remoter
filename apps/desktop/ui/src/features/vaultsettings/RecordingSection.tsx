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
import type { RecordingPolicy } from "@/lib/ipc";

import type { VaultSectionProps } from "./types";
import c from "./controls.module.css";
import s from "./RecordingSection.module.css";

const TEXT = {
  title: "Recording policy",
  description:
    "Inherited by everything in this vault that does not set its own, so it is set once for the whole tree.",

  notYetTitle: "Nothing is recorded in this version",
  notYetBody:
    "Remoter has no recorder yet: whichever card is selected, every session in this vault opens unrecorded. The choice below is stored in the vault now and takes effect when session recording is built.",

  never: "Never",
  neverHelp:
    "Nothing in this vault will be recorded, unless a folder or a connection below it sets its own policy.",
  ask: "Ask at session start",
  askHelp: "A prompt before the session opens. Declining will open the session unrecorded.",
  always: "Always",
  alwaysHelp:
    "Every session will be recorded, after a notice before it opens. If the recorder cannot start the session will still open — recording will be best-effort at this policy.",

  required:
    'A fourth policy, "required" — record, and refuse to connect if recording cannot start — is not offered here. The vault file has no field for it, so a fourth card would store one of the three above and mean something weaker than its name.',

  storage:
    "Recordings will live outside the vault, in a directory you choose, each encrypted with a key derived from the vault's master key and so readable only while the vault is unlocked. Nothing is uploaded anywhere.",

  saving: "Saving…",
  failed: "The recording policy was not saved.",
} as const;

const CHOICES: readonly { value: RecordingPolicy; label: string; help: string }[] = [
  { value: "never", label: TEXT.never, help: TEXT.neverHelp },
  { value: "on_request", label: TEXT.ask, help: TEXT.askHelp },
  { value: "always", label: TEXT.always, help: TEXT.alwaysHelp },
];

export function RecordingSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: VaultSectionProps) {
  const saving = savingField === "recording";
  const problem = failure !== null && failure.field === "recording" ? failure.failure : null;

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{TEXT.title}</h2>
        <p className={s.description}>{TEXT.description}</p>
      </div>

      {/* Above the cards, not below them: this is the fact that decides what
          the cards mean, and a reader who stops after the first control has
          still read it. */}
      <Callout tone="warning" title={TEXT.notYetTitle}>
        {TEXT.notYetBody}
      </Callout>

      <fieldset className={c.choices} disabled={saving}>
        <legend className={s.hiddenLegend}>{TEXT.title}</legend>
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
              <span className={c.choiceName}>{choice.label}</span>
              <span className={c.choiceHelp}>{choice.help}</span>
            </span>
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

      <div className={s.notes}>
        <p className={c.note}>{TEXT.required}</p>
        <p className={c.note}>{TEXT.storage}</p>
      </div>
    </section>
  );
}
