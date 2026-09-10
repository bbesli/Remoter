/**
 * Auto-lock.
 *
 * Locking is real: it zeroizes the vault master key, the content and secret
 * keys and every cached plaintext, then drops the in-memory database. That is
 * why what happens to a running session has to be a separate decision, and why
 * the default is the one it is.
 *
 * Sessions keep running by default because an administrator watching a long
 * deployment does not want it killed because they went for coffee — the
 * sentence is from docs/security/key-management.md and it is the reason, so it
 * is on the screen rather than in the document only.
 *
 * The idle ladder replaces the design's slider. On a slider, "never" is a
 * pixel away from "one minute", and the two are not neighbouring values of the
 * same kind of decision.
 *
 * # Every control on this screen has to do what it says
 *
 * Two things were wrong here and both were the same mistake.
 *
 * The timeout above wrote `vault.settings.auto_lock_minutes` while the
 * countdown read the application-level setting of the same name, so choosing
 * "1 min" or "Never" changed nothing at all. The vault's value is now the one
 * the core counts down.
 *
 * The three switches below persisted values nothing observed. Rather than
 * leave them looking as though they work, the core reports how well this build
 * can see each event on this machine, and a switch it cannot honour is
 * disabled and says so. The stored value is still shown, because it travels
 * with the vault file and a trigger this machine cannot see is one another
 * machine may.
 */

import { Spinner } from "@/components/Spinner";
import { FailureNotice } from "@/components/FailureNotice";
import type { LockTriggerObservation, LockTriggerSupport, SessionOnLock } from "@/lib/ipc";

import { AUTO_LOCK_CHOICES } from "./slots";
import type { VaultSectionProps, VaultSettingsField } from "./types";
import c from "./controls.module.css";
import s from "./AutoLockSection.module.css";

const TEXT = {
  title: "Auto-lock",
  description:
    "Locking zeroizes every key and cached secret and drops the in-memory database. Reopening needs a full unlock.",

  idleLegend: "Lock after idle for",
  /*
   * This sentence used to say idle was measured from the desktop's own input
   * idle time. It was not, and the difference cost the user real work: idle was
   * measured from the last call that touched the vault, so typing in a terminal
   * was not activity and the vault locked while it was being used. The
   * measurement is fixed — session input and session output both count now —
   * and so is the sentence, which says what is measured rather than what would
   * be nicer to measure.
   */
  idleHelp:
    "Idle means nothing has touched the vault and no session has carried traffic. Keystrokes you send and output a host sends both count, so a session you are watching but not typing into does not go idle while output keeps arriving.",
  idleScope:
    "Remoter does not read the desktop's own input idle time, so time spent in another application counts as idle even though you are at the keyboard.",
  idleNever:
    "Never means the vault stays open until you lock it or quit. That is a defensible choice on a machine only you can reach, and a bad one on a shared desk.",

  screenLock: "When the screen locks",
  suspend: "On suspend or hibernate",
  minimise: "When the window is minimised",
  minimiseHelp: "Off by default. Most people minimise far more often than they walk away.",

  on: "On",
  off: "Off",
  unavailable: "N/A",

  /*
   * One sentence per unobservable trigger, naming what is missing rather than
   * saying "not supported". A user who knows *why* can tell whether it will
   * ever change.
   */
  noScreenLock:
    "This build cannot see the screen lock on this system, so this switch would not lock anything. Watching it means the desktop's screen-lock signal, which Remoter does not yet listen for.",
  noSuspend:
    "This build cannot see this machine suspend, so this switch would not lock anything here.",
  noMinimise:
    "This build cannot see the window being minimised, so this switch would not lock anything. The window toolkit does not report it under this desktop, and a switch that worked on some desktops and silently did nothing on others would be worse than one that is honest.",
  onResumeSuspend:
    "Remoter cannot ask this system for advance notice of a suspend, so it locks when the machine comes back rather than before it sleeps. The keys are in memory while it sleeps, and in the hibernation image if it hibernates.",
  keptForOtherMachines:
    "The setting is kept in the vault, so it still applies on a computer where Remoter can see the event.",

  sessionsLegend: "What happens to running sessions",
  keepRunning: "Keep them running",
  keepRunningHelp:
    "The default, and the reason for it: an administrator watching a long deployment does not want their session killed because they went for coffee. Output keeps arriving and you can watch it.",
  freezeInput: "Keep them running, freeze input",
  freezeInputHelp:
    "Sessions stay alive but nothing can be typed into them until you unlock. Tabs show a locked badge.",
  disconnectAll: "Disconnect everything",
  disconnectAllHelp:
    "Strictest. Unsaved work in a session is lost, including transfers in progress.",
  audited: "Changing this is written to the vault's audit log.",

  saving: "Saving…",
  failed: "That setting was not saved.",
} as const;

const SESSION_CHOICES: readonly { value: SessionOnLock; label: string; help: string }[] = [
  { value: "keep_running", label: TEXT.keepRunning, help: TEXT.keepRunningHelp },
  { value: "freeze_input", label: TEXT.freezeInput, help: TEXT.freezeInputHelp },
  { value: "disconnect_all", label: TEXT.disconnectAll, help: TEXT.disconnectAllHelp },
];

type TriggerField = "lockOnScreenLock" | "lockOnSuspend" | "lockOnMinimise";

/**
 * What this build cannot see, when the core did not say.
 *
 * Only reachable from a fixture: the core sends `lockTriggers` with every read.
 * Assuming the switches work is the right fallback for a screen that has not
 * been told otherwise — claiming a control is broken on no evidence is its own
 * kind of lie.
 */
const ASSUME_OBSERVED: LockTriggerSupport = {
  screenLock: "observed",
  suspend: "observed",
  minimise: "observed",
};

export function AutoLockSection({
  settings,
  onSave,
  savingField,
  failure,
  onRetrySave,
}: VaultSectionProps) {
  const failureFor = (field: VaultSettingsField) =>
    failure !== null && failure.field === field ? failure.failure : null;

  const support = settings.lockTriggers ?? ASSUME_OBSERVED;

  const toggle = (
    field: TriggerField,
    label: string,
    help: string | null,
    observation: LockTriggerObservation,
    unobservedNote: string,
  ) => {
    const value = settings[field];
    const saving = savingField === field;
    const problem = failureFor(field);
    const honoured = observation !== "unobserved";
    // The caveat sits under the label, in the same place the help does, so it
    // is read with the switch rather than after it.
    const caveat =
      observation === "on_resume" && field === "lockOnSuspend" ? TEXT.onResumeSuspend : null;

    // The word, not only the switch position — and a third word, because a
    // switch this build cannot honour is neither on nor off in any sense the
    // user cares about.
    let stateWord: string = TEXT.unavailable;
    if (honoured) stateWord = value ? TEXT.on : TEXT.off;

    return (
      // `display: contents`, so the failure below is a sibling row rather than
      // a nested box — and so the retry button is outside the label, where a
      // click on it cannot also flip the switch.
      <div className={s.rowGroup}>
        <div className={c.row}>
          <label className={c.switchRow}>
            <input
              className={c.checkbox}
              type="checkbox"
              role="switch"
              checked={value}
              // Disabled rather than merely annotated: a switch that can be
              // flipped is a switch that claims to do something.
              disabled={saving || !honoured}
              onChange={(event) => {
                if (!honoured) return;
                onSave(field, { [field]: event.target.checked });
              }}
            />
            <span className={c.track} aria-hidden="true">
              <span className={c.thumb} />
            </span>
            <span className={c.rowText}>
              <span className={c.rowLabel}>{label}</span>
              {help !== null && <span className={c.rowHelp}>{help}</span>}
              {caveat !== null && <span className={c.rowHelp}>{caveat}</span>}
              {!honoured && (
                <span className={s.unavailable}>
                  {unobservedNote} {TEXT.keptForOtherMachines}
                </span>
              )}
            </span>
            {saving ? (
              <span className={c.switchState}>
                <Spinner size={13} label={TEXT.saving} />
              </span>
            ) : (
              <span className={c.switchState}>{stateWord}</span>
            )}
          </label>
        </div>
        {problem !== null && (
          <div className={c.row}>
            <FailureNotice failure={problem} title={TEXT.failed} onRetry={onRetrySave} />
          </div>
        )}
      </div>
    );
  };

  const idleSaving = savingField === "autoLockMinutes";
  const idleFailure = failureFor("autoLockMinutes");
  const sessionSaving = savingField === "sessionOnLock";
  const sessionFailure = failureFor("sessionOnLock");

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{TEXT.title}</h2>
        <p className={s.description}>{TEXT.description}</p>
      </div>

      <fieldset className={c.chips} disabled={idleSaving}>
        <legend className={c.legend}>{TEXT.idleLegend}</legend>
        {AUTO_LOCK_CHOICES.map((choice) => (
          <label
            key={choice.minutes}
            className={
              choice.minutes === settings.autoLockMinutes ? [c.chip, c.chipOn].join(" ") : c.chip
            }
          >
            <input
              className={c.radio}
              type="radio"
              name="vault-auto-lock"
              value={choice.minutes}
              checked={choice.minutes === settings.autoLockMinutes}
              onChange={() => onSave("autoLockMinutes", { autoLockMinutes: choice.minutes })}
            />
            {choice.label}
          </label>
        ))}
      </fieldset>

      <p className={c.note}>{TEXT.idleHelp}</p>
      <p className={c.note}>{TEXT.idleScope}</p>
      {settings.autoLockMinutes === 0 && <p className={s.warn}>{TEXT.idleNever}</p>}

      {idleSaving && (
        <p className={c.saving}>
          <Spinner size={14} label={TEXT.saving} />
          {TEXT.saving}
        </p>
      )}
      {idleFailure !== null && (
        <FailureNotice failure={idleFailure} title={TEXT.failed} onRetry={onRetrySave} />
      )}

      <div className={c.rows}>
        {toggle("lockOnScreenLock", TEXT.screenLock, null, support.screenLock, TEXT.noScreenLock)}
        {toggle("lockOnSuspend", TEXT.suspend, null, support.suspend, TEXT.noSuspend)}
        {toggle(
          "lockOnMinimise",
          TEXT.minimise,
          TEXT.minimiseHelp,
          support.minimise,
          TEXT.noMinimise,
        )}
      </div>

      <fieldset className={c.choices} disabled={sessionSaving}>
        <legend className={c.legend}>{TEXT.sessionsLegend}</legend>
        {SESSION_CHOICES.map((choice) => (
          <label
            key={choice.value}
            className={
              choice.value === settings.sessionOnLock
                ? [c.choice, c.choiceOn].join(" ")
                : c.choice
            }
          >
            <input
              className={c.radio}
              type="radio"
              name="vault-session-on-lock"
              value={choice.value}
              checked={choice.value === settings.sessionOnLock}
              onChange={() => onSave("sessionOnLock", { sessionOnLock: choice.value })}
            />
            <span className={c.mark} aria-hidden="true" />
            <span className={c.choiceText}>
              <span className={c.choiceName}>{choice.label}</span>
              <span className={c.choiceHelp}>{choice.help}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {sessionSaving && (
        <p className={c.saving}>
          <Spinner size={14} label={TEXT.saving} />
          {TEXT.saving}
        </p>
      )}
      {sessionFailure !== null && (
        <FailureNotice failure={sessionFailure} title={TEXT.failed} onRetry={onRetrySave} />
      )}

      <p className={c.note}>{TEXT.audited}</p>
    </section>
  );
}
