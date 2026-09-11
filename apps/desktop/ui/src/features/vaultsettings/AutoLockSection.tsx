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
import { useT } from "@/i18n";
import type { LockTriggerObservation, LockTriggerSupport, SessionOnLock } from "@/lib/ipc";

import { AUTO_LOCK_MINUTES, autoLockLabel } from "./slots";
import type { VaultSectionProps, VaultSettingsField } from "./types";
import c from "./controls.module.css";
import s from "./AutoLockSection.module.css";

/**
 * The three answers, as catalogue keys: this array is module-level, so a
 * resolved label would be frozen in the language the application started in.
 */
const SESSION_CHOICES = [
  { value: "keep_running", labelKey: "autoLock.keepRunning", helpKey: "autoLock.keepRunningHelp" },
  { value: "freeze_input", labelKey: "autoLock.freezeInput", helpKey: "autoLock.freezeInputHelp" },
  {
    value: "disconnect_all",
    labelKey: "autoLock.disconnectAll",
    helpKey: "autoLock.disconnectAllHelp",
  },
] as const satisfies readonly { value: SessionOnLock; labelKey: string; helpKey: string }[];

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
  const t = useT("vaultsettings");
  const tCommon = useT("common");

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
      observation === "on_resume" && field === "lockOnSuspend"
        ? t("autoLock.onResumeSuspend")
        : null;

    // The word, not only the switch position — and a third word, because a
    // switch this build cannot honour is neither on nor off in any sense the
    // user cares about.
    let stateWord: string = t("autoLock.unavailable");
    if (honoured) stateWord = value ? tCommon("toggle.on") : tCommon("toggle.off");

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
                  {unobservedNote} {t("autoLock.keptForOtherMachines")}
                </span>
              )}
            </span>
            {saving ? (
              <span className={c.switchState}>
                <Spinner size={13} label={t("status.saving")} />
              </span>
            ) : (
              <span className={c.switchState}>{stateWord}</span>
            )}
          </label>
        </div>
        {problem !== null && (
          <div className={c.row}>
            <FailureNotice failure={problem} title={t("autoLock.failed")} onRetry={onRetrySave} />
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
        <h2 className={s.title}>{t("autoLock.title")}</h2>
        <p className={s.description}>{t("autoLock.description")}</p>
      </div>

      <fieldset className={c.chips} disabled={idleSaving}>
        <legend className={c.legend}>{t("autoLock.idleLegend")}</legend>
        {AUTO_LOCK_MINUTES.map((minutes) => (
          <label
            key={minutes}
            className={
              minutes === settings.autoLockMinutes ? [c.chip, c.chipOn].join(" ") : c.chip
            }
          >
            <input
              className={c.radio}
              type="radio"
              name="vault-auto-lock"
              value={minutes}
              checked={minutes === settings.autoLockMinutes}
              onChange={() => onSave("autoLockMinutes", { autoLockMinutes: minutes })}
            />
            {autoLockLabel(minutes, t)}
          </label>
        ))}
      </fieldset>

      <p className={c.note}>{t("autoLock.idleHelp")}</p>
      <p className={c.note}>{t("autoLock.idleScope")}</p>
      {settings.autoLockMinutes === 0 && <p className={s.warn}>{t("autoLock.idleNever")}</p>}

      {idleSaving && (
        <p className={c.saving}>
          <Spinner size={14} label={t("status.saving")} />
          {t("status.saving")}
        </p>
      )}
      {idleFailure !== null && (
        <FailureNotice failure={idleFailure} title={t("autoLock.failed")} onRetry={onRetrySave} />
      )}

      <div className={c.rows}>
        {toggle(
          "lockOnScreenLock",
          t("autoLock.screenLock"),
          null,
          support.screenLock,
          t("autoLock.noScreenLock"),
        )}
        {toggle(
          "lockOnSuspend",
          t("autoLock.suspend"),
          null,
          support.suspend,
          t("autoLock.noSuspend"),
        )}
        {toggle(
          "lockOnMinimise",
          t("autoLock.minimise"),
          t("autoLock.minimiseHelp"),
          support.minimise,
          t("autoLock.noMinimise"),
        )}
      </div>

      <fieldset className={c.choices} disabled={sessionSaving}>
        <legend className={c.legend}>{t("autoLock.sessionsLegend")}</legend>
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
              <span className={c.choiceName}>{t(choice.labelKey)}</span>
              <span className={c.choiceHelp}>{t(choice.helpKey)}</span>
            </span>
          </label>
        ))}
      </fieldset>

      {sessionSaving && (
        <p className={c.saving}>
          <Spinner size={14} label={t("status.saving")} />
          {t("status.saving")}
        </p>
      )}
      {sessionFailure !== null && (
        <FailureNotice
          failure={sessionFailure}
          title={t("autoLock.failed")}
          onRetry={onRetrySave}
        />
      )}

      <p className={c.note}>{t("autoLock.audited")}</p>
    </section>
  );
}
