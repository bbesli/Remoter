/**
 * Rotating the vault master key, and what it did.
 *
 * Framed by the situation that calls for it, as docs/security/key-management.md
 * asks: this is the answer to "a copy of this file may have leaked while one of
 * my keys was compromised". It is the only operation on this screen that
 * re-encrypts the body — a new master key, every slot re-wrapped, every stored
 * secret resealed.
 *
 * Two things the user has to know before pressing it, and both are said here
 * rather than discovered afterwards:
 *
 *   - It does not make the leaked copy unreadable. That file still opens with
 *     the old keys, and so do the rolling backups beside the vault, which this
 *     save rotates.
 *   - Every slot must be accounted for. A password slot needs its password; a
 *     slot the plan neither opens nor discards is a refusal, not a silent
 *     deletion. `rotationRefusals` names each one on the form, because the
 *     core's version of the same refusal arrives after the wait.
 *
 * The passwords live in this component's state until the command takes them,
 * which is the same arrangement the connection editor uses for a credential:
 * never in a query, never in the store, never logged.
 */

import { useState } from "react";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { TextInput } from "@/components/TextInput";
import { kdfNote } from "@/features/vault/UnlockScreen";
import { isolate, useLocale, useT } from "@/i18n";
import type { IpcFailure, RotateMasterKey, RotationOutcome, Slot } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import { rotationRefusals, slotKindLabel, type RotationSlotPlan } from "./slots";
import s from "./RotateMasterKeyDialog.module.css";

interface Credential {
  password: string;
  keyfilePath: string | null;
}

interface RotateMasterKeyDialogProps {
  slots: readonly Slot[];
  vaultPath: string;
  busy: boolean;
  failure: IpcFailure | null;
  onConfirm: (req: RotateMasterKey) => void;
  onRetry: () => void;
  onClose: () => void;
}

export function RotateMasterKeyDialog({
  slots,
  vaultPath,
  busy,
  failure,
  onConfirm,
  onRetry,
  onClose,
}: RotateMasterKeyDialogProps) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const [credentials, setCredentials] = useState<Record<number, Credential>>({});
  const [drops, setDrops] = useState<readonly number[]>([]);

  const credentialFor = (index: number): Credential =>
    credentials[index] ?? { password: "", keyfilePath: null };

  function setCredential(index: number, patch: Partial<Credential>) {
    setCredentials((held) => ({ ...held, [index]: { ...credentialFor(index), ...patch } }));
  }

  function toggleDrop(index: number, drop: boolean) {
    setDrops((held) => (drop ? [...held, index] : held.filter((i) => i !== index)));
  }

  const plan: RotationSlotPlan[] = slots.map((slot) => ({
    index: slot.index,
    kind: slot.kind,
    label: slot.label,
    hasCredential: credentialFor(slot.index).password !== "",
    drop: drops.includes(slot.index),
  }));

  const problems = rotationRefusals(plan, t);
  const keyfileProblem = slots.some(
    (slot) =>
      !drops.includes(slot.index) &&
      keyfileBlocked(credentialFor(slot.index).keyfilePath, vaultPath),
  );
  const blocked = problems.length > 0 || keyfileProblem;
  const passwordSlots = slots.filter(
    (slot) => slot.kind === "password" && !drops.includes(slot.index),
  ).length;

  function submit() {
    if (busy || blocked) return;
    onConfirm({
      credentials: slots
        .filter((slot) => slot.kind === "password" && !drops.includes(slot.index))
        .map((slot) => ({
          index: slot.index,
          password: credentialFor(slot.index).password,
          keyfilePath: credentialFor(slot.index).keyfilePath,
        })),
      dropSlots: [...drops],
    });
  }

  return (
    <Dialog
      id="vault-rotate-master-key"
      title={t("rotateMaster.title")}
      lead={t("rotateMaster.lead")}
      wide
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={t("rotateMaster.blocked")}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {tCommon("action.cancel")}
          </Button>
          <BusyButton
            variant="danger"
            busy={busy}
            busyLabel={t("rotateMaster.busy")}
            disabled={blocked}
            onClick={submit}
            {...(problems[0] === undefined ? {} : { title: problems[0] })}
          >
            {t("rotateMaster.confirm")}
          </BusyButton>
        </>
      }
    >
      <Callout tone="info" title={t("rotateMaster.whenTitle")}>
        {t("rotateMaster.whenBody")}
      </Callout>

      <Callout tone="warning" title={t("rotateMaster.limitTitle")}>
        {t("rotateMaster.limitBody")}
      </Callout>

      <p className={s.cost}>
        <strong className={s.costTitle}>{t("rotateMaster.costTitle")}</strong>{" "}
        {t("rotateMaster.costBody", { count: passwordSlots })}
      </p>

      <fieldset className={s.slots} disabled={busy}>
        <legend className={s.legend}>{t("rotateMaster.slotsLegend")}</legend>

        {slots.map((slot) => {
          const dropped = drops.includes(slot.index);
          const credential = credentialFor(slot.index);
          return (
            <div key={slot.index} className={dropped ? [s.slot, s.slotOff].join(" ") : s.slot}>
              <div className={s.slotHead}>
                {/* The slot's own name, isolated: it is the user's text. */}
                <span className={s.slotName}>{isolate(slot.label)}</span>
                <span className={s.slotKind}>{slotKindLabel(slot.kind, t)}</span>
                <span className={s.slotIndex}>
                  {t("slot.indexBadge", { index: slot.index })}
                </span>
              </div>

              {!dropped && slot.kind === "password" && (
                <>
                  <Field
                    label={t("rotateMaster.password")}
                    htmlFor={`vault-rotate-password-${slot.index}`}
                  >
                    <TextInput
                      id={`vault-rotate-password-${slot.index}`}
                      type="password"
                      value={credential.password}
                      onChange={(value) => setCredential(slot.index, { password: value })}
                      disabled={busy}
                    />
                  </Field>
                  {slot.requiresKeyfile && (
                    <KeyfileField
                      label={t("rotateMaster.keyfile")}
                      help={t("rotateMaster.keyfileHelp")}
                      path={credential.keyfilePath}
                      onChange={(value) => setCredential(slot.index, { keyfilePath: value })}
                      vaultPath={vaultPath}
                      disabled={busy}
                    />
                  )}
                </>
              )}

              {!dropped && slot.kind === "recovery" && (
                <p className={s.slotNote}>{t("rotateMaster.recoveryNote")}</p>
              )}
              {!dropped && slot.kind === "keychain" && (
                <p className={s.slotNote}>{t("rotateMaster.keychainNote")}</p>
              )}
              {!dropped && slot.kind === "fido2" && (
                <p className={s.slotNote}>{t("rotateMaster.fido2Note")}</p>
              )}

              <label className={s.dropRow}>
                <input
                  type="checkbox"
                  checked={dropped}
                  disabled={busy}
                  onChange={(event) => toggleDrop(slot.index, event.target.checked)}
                />
                <span>{dropped ? t("rotateMaster.dropped") : t("rotateMaster.drop")}</span>
              </label>
            </div>
          );
        })}
      </fieldset>

      {problems.length > 0 && (
        <Callout tone="warning" title={t("rotateMaster.problemsTitle")}>
          <ul className={s.problems}>
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Callout>
      )}

      {busy && (
        <div className={s.busy}>
          <BusyStatus label={t("rotateMaster.stage")} note={kdfNote(locale, null)} size={16} />
        </div>
      )}

      {failure !== null && (
        <FailureNotice failure={failure} title={t("rotateMaster.failed")} onRetry={onRetry}>
          <span className={s.unchanged}>{t("rotateMaster.unchanged")}</span>
        </FailureNotice>
      )}
    </Dialog>
  );
}

/**
 * What the rotation did, after the last recovery key has been transcribed.
 *
 * Counts, not reassurance: which slots survived, which were discarded, and how
 * many secrets were resealed are the three facts that say the operation was
 * the one intended.
 */
export function RotationSummaryDialog({
  outcome,
  onClose,
}: {
  outcome: RotationOutcome;
  onClose: () => void;
}) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");

  return (
    <Dialog
      id="vault-rotation-summary"
      title={t("rotationSummary.title")}
      lead={t("rotationSummary.lead")}
      onDismiss={onClose}
      footer={
        <Button variant="primary" onClick={onClose}>
          {tCommon("action.close")}
        </Button>
      }
    >
      <ul className={s.counts}>
        <li>{t("rotationSummary.rewrapped", { count: outcome.rewrapped.length })}</li>
        <li>{t("rotationSummary.dropped", { count: outcome.dropped.length })}</li>
        <li>{t("rotationSummary.resealed", { count: outcome.secretsResealed })}</li>
      </ul>
      <Callout tone="warning" title={t("rotateMaster.limitTitle")}>
        {t("rotateMaster.limitBody")}
      </Callout>
    </Dialog>
  );
}
