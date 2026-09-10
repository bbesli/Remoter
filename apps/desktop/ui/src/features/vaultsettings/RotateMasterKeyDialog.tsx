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
import type { IpcFailure, RotateMasterKey, RotationOutcome, Slot } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import { SLOT_KIND_LABEL, rotationRefusals, type RotationSlotPlan } from "./slots";
import s from "./RotateMasterKeyDialog.module.css";

const TEXT = {
  title: "Rotate the vault master key",
  lead: "A new master key is generated, every slot is re-wrapped around it, and every secret in the vault is resealed.",

  whenTitle: "When this is the right answer",
  whenBody:
    "A copy of this file may have leaked while one of your keys was compromised. Changing a password re-wraps one slot; this replaces the key the whole body is encrypted under.",

  limitTitle: "What it cannot do",
  limitBody:
    "The copy that leaked still opens with the old keys, and so do the rolling backups beside this vault, which this save rotates. Delete the copies you know about; rotation protects what happens next, not what already left.",

  costTitle: "It takes real time",
  costBody: (passwordSlots: number) =>
    passwordSlots === 1
      ? "Argon2id runs once, for the one password slot, and every stored secret is resealed."
      : `Argon2id runs once per password slot — ${passwordSlots} here — and every stored secret is resealed.`,

  slotsLegend: "Every slot has to be accounted for",
  password: "Password",
  keyfile: "Key file",
  keyfileHelp: "The file this slot requires today.",
  drop: "I do not have this one. Discard the slot.",
  dropped: "Will be discarded",

  recoveryNote: "A new recovery key is issued for this slot, and shown once when the rotation ends.",
  keychainNote:
    "Re-wrapped from the token in this machine's keyring. If the token is gone, discard the slot and enrol this machine again afterwards.",
  fido2Note: "This version cannot re-wrap a security key slot.",

  problemsTitle: "Not ready to rotate",

  cancel: "Cancel",
  rotate: "Rotate the master key",
  rotating: "Re-keying…",
  rotatingBlocked:
    "The vault is being re-keyed. Closing now would leave the new recovery keys, which are shown once, nowhere to appear.",
  rotatingStage: "Deriving a key for each slot, then re-encrypting the vault…",
  failed: "The vault was not rotated.",
  unchanged: "Nothing changed: the vault is exactly as it was before you pressed the button.",

  summaryTitle: "The vault has been re-keyed",
  summaryLead: "Everything below is already written to the file.",
  rewrapped: (n: number) => (n === 1 ? "1 slot re-wrapped" : `${n} slots re-wrapped`),
  droppedCount: (n: number) => (n === 1 ? "1 slot discarded" : `${n} slots discarded`),
  resealed: (n: number) => (n === 1 ? "1 secret resealed" : `${n} secrets resealed`),
  summaryDone: "Close",
} as const;

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

  const problems = rotationRefusals(plan);
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
      title={TEXT.title}
      lead={TEXT.lead}
      wide
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={TEXT.rotatingBlocked}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {TEXT.cancel}
          </Button>
          <BusyButton
            variant="danger"
            busy={busy}
            busyLabel={TEXT.rotating}
            disabled={blocked}
            onClick={submit}
            {...(problems[0] === undefined ? {} : { title: problems[0] })}
          >
            {TEXT.rotate}
          </BusyButton>
        </>
      }
    >
      <Callout tone="info" title={TEXT.whenTitle}>
        {TEXT.whenBody}
      </Callout>

      <Callout tone="warning" title={TEXT.limitTitle}>
        {TEXT.limitBody}
      </Callout>

      <p className={s.cost}>
        <strong className={s.costTitle}>{TEXT.costTitle}</strong> {TEXT.costBody(passwordSlots)}
      </p>

      <fieldset className={s.slots} disabled={busy}>
        <legend className={s.legend}>{TEXT.slotsLegend}</legend>

        {slots.map((slot) => {
          const dropped = drops.includes(slot.index);
          const credential = credentialFor(slot.index);
          return (
            <div key={slot.index} className={dropped ? [s.slot, s.slotOff].join(" ") : s.slot}>
              <div className={s.slotHead}>
                <span className={s.slotName}>{slot.label}</span>
                <span className={s.slotKind}>{SLOT_KIND_LABEL[slot.kind]}</span>
                <span className={s.slotIndex}>slot {slot.index}</span>
              </div>

              {!dropped && slot.kind === "password" && (
                <>
                  <Field label={TEXT.password} htmlFor={`vault-rotate-password-${slot.index}`}>
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
                      label={TEXT.keyfile}
                      help={TEXT.keyfileHelp}
                      path={credential.keyfilePath}
                      onChange={(value) => setCredential(slot.index, { keyfilePath: value })}
                      vaultPath={vaultPath}
                      disabled={busy}
                    />
                  )}
                </>
              )}

              {!dropped && slot.kind === "recovery" && (
                <p className={s.slotNote}>{TEXT.recoveryNote}</p>
              )}
              {!dropped && slot.kind === "keychain" && (
                <p className={s.slotNote}>{TEXT.keychainNote}</p>
              )}
              {!dropped && slot.kind === "fido2" && <p className={s.slotNote}>{TEXT.fido2Note}</p>}

              <label className={s.dropRow}>
                <input
                  type="checkbox"
                  checked={dropped}
                  disabled={busy}
                  onChange={(event) => toggleDrop(slot.index, event.target.checked)}
                />
                <span>{dropped ? TEXT.dropped : TEXT.drop}</span>
              </label>
            </div>
          );
        })}
      </fieldset>

      {problems.length > 0 && (
        <Callout tone="warning" title={TEXT.problemsTitle}>
          <ul className={s.problems}>
            {problems.map((problem) => (
              <li key={problem}>{problem}</li>
            ))}
          </ul>
        </Callout>
      )}

      {busy && (
        <div className={s.busy}>
          <BusyStatus label={TEXT.rotatingStage} note={kdfNote(null)} size={16} />
        </div>
      )}

      {failure !== null && (
        <FailureNotice failure={failure} title={TEXT.failed} onRetry={onRetry}>
          <span className={s.unchanged}>{TEXT.unchanged}</span>
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
  return (
    <Dialog
      id="vault-rotation-summary"
      title={TEXT.summaryTitle}
      lead={TEXT.summaryLead}
      onDismiss={onClose}
      footer={
        <Button variant="primary" onClick={onClose}>
          {TEXT.summaryDone}
        </Button>
      }
    >
      <ul className={s.counts}>
        <li>{TEXT.rewrapped(outcome.rewrapped.length)}</li>
        <li>{TEXT.droppedCount(outcome.dropped.length)}</li>
        <li>{TEXT.resealed(outcome.secretsResealed)}</li>
      </ul>
      <Callout tone="warning" title={TEXT.limitTitle}>
        {TEXT.limitBody}
      </Callout>
    </Dialog>
  );
}
