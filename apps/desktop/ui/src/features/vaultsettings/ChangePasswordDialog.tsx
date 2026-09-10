/**
 * Changing the password on one slot.
 *
 * What this is not is a rotation. The master key does not change: nothing is
 * re-encrypted, every other slot keeps working and the recovery keys stay
 * valid. That distinction is the first thing the dialog says, because a user
 * who believes this repairs a leak will not then do the thing that does — the
 * master key rotation, further down the same screen.
 *
 * The current credential is verified by the core before anything is replaced,
 * so a typo cannot lock the slot. Both passwords are held here only until the
 * command takes them.
 *
 * The new key file is chosen explicitly, including "none". The core does not
 * carry the current one over silently, and a form that implied it did would be
 * the difference between a slot that opens tomorrow and one that does not.
 */

import { useState } from "react";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { TextInput } from "@/components/TextInput";
import { kdfNote } from "@/features/vault/UnlockScreen";
import type { ChangePassword, IpcFailure, Slot } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import s from "./ChangePasswordDialog.module.css";

const TEXT = {
  title: "Change this slot's password",
  lead: "The slot is re-wrapped around the new password. The master key does not change, so nothing is re-encrypted, every other slot keeps working and the recovery keys stay valid.",

  notARotation: "This does not help if the file itself leaked",
  notARotationBody:
    "A copy taken while the old password was in use still opens with the old password. Rotating the vault master key is the answer to that, and it is on this screen.",

  current: "Current password",
  currentHelp: "Verified before anything is replaced, so a typo here cannot lock the slot.",
  currentKeyfile: "Current key file",
  currentKeyfileHelp: "This slot requires one, so the change needs it as well.",

  next: "New password",
  confirm: "Repeat the new password",
  confirmMismatch: "The two passwords are not the same.",

  newKeyfile: "Key file from now on",
  newKeyfileHelp:
    "Chosen explicitly, including leaving it empty: the current key file is not carried over. Empty means this slot needs only a password.",

  blockedCurrent: "Type the slot's current password.",
  blockedCurrentKeyfile: "Choose the key file this slot currently requires.",
  blockedNew: "Type the new password twice, the same way.",
  blockedKeyfile: "That file cannot be a key file.",

  cancel: "Cancel",
  save: "Change the password",
  saving: "Deriving the key…",
  savingBlocked:
    "The change is already with the core. This closes when it answers, so a rejected password has somewhere to be reported.",
  savingStage: "Verifying the current password, then deriving the new key…",
  failed: "The password was not changed.",
} as const;

interface ChangePasswordDialogProps {
  slot: Slot;
  vaultPath: string;
  busy: boolean;
  failure: IpcFailure | null;
  onConfirm: (req: ChangePassword) => void;
  onRetry: () => void;
  onClose: () => void;
}

export function ChangePasswordDialog({
  slot,
  vaultPath,
  busy,
  failure,
  onConfirm,
  onRetry,
  onClose,
}: ChangePasswordDialogProps) {
  const [current, setCurrent] = useState("");
  const [currentKeyfile, setCurrentKeyfile] = useState<string | null>(null);
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [newKeyfile, setNewKeyfile] = useState<string | null>(null);

  const matches = next !== "" && next === confirm;
  const blocked =
    current === ""
      ? TEXT.blockedCurrent
      : slot.requiresKeyfile && currentKeyfile === null
        ? TEXT.blockedCurrentKeyfile
        : !matches
          ? TEXT.blockedNew
          : keyfileBlocked(currentKeyfile, vaultPath) || keyfileBlocked(newKeyfile, vaultPath)
            ? TEXT.blockedKeyfile
            : null;

  function submit() {
    if (busy || blocked !== null) return;
    onConfirm({
      slotIndex: slot.index,
      currentPassword: current,
      currentKeyfilePath: currentKeyfile,
      newPassword: next,
      newKeyfilePath: newKeyfile,
    });
  }

  return (
    <Dialog
      id="vault-change-password"
      title={TEXT.title}
      lead={TEXT.lead}
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={TEXT.savingBlocked}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {TEXT.cancel}
          </Button>
          <BusyButton
            variant="primary"
            busy={busy}
            busyLabel={TEXT.saving}
            disabled={blocked !== null}
            onClick={submit}
            {...(blocked === null ? {} : { title: blocked })}
          >
            {TEXT.save}
          </BusyButton>
        </>
      }
    >
      <div className={s.subject}>
        <span className={s.label}>{slot.label}</span>
        <span className={s.index}>slot {slot.index}</span>
      </div>

      <Field label={TEXT.current} help={TEXT.currentHelp} htmlFor="vault-change-current">
        <TextInput
          id="vault-change-current"
          type="password"
          value={current}
          onChange={setCurrent}
          disabled={busy}
          autoFocus
        />
      </Field>

      {slot.requiresKeyfile && (
        <KeyfileField
          label={TEXT.currentKeyfile}
          help={TEXT.currentKeyfileHelp}
          path={currentKeyfile}
          onChange={setCurrentKeyfile}
          vaultPath={vaultPath}
          disabled={busy}
        />
      )}

      <Field label={TEXT.next} htmlFor="vault-change-new">
        <TextInput
          id="vault-change-new"
          type="password"
          value={next}
          onChange={setNext}
          disabled={busy}
        />
      </Field>

      <Field
        label={TEXT.confirm}
        htmlFor="vault-change-confirm"
        {...(confirm !== "" && !matches ? { error: TEXT.confirmMismatch } : {})}
      >
        <TextInput
          id="vault-change-confirm"
          type="password"
          value={confirm}
          onChange={setConfirm}
          disabled={busy}
          invalid={confirm !== "" && !matches}
        />
      </Field>

      <KeyfileField
        label={TEXT.newKeyfile}
        help={TEXT.newKeyfileHelp}
        path={newKeyfile}
        onChange={setNewKeyfile}
        vaultPath={vaultPath}
        disabled={busy}
      />

      {busy && (
        <div className={s.busy}>
          <BusyStatus
            label={TEXT.savingStage}
            note={kdfNote(slot.kdfSummary)}
            size={16}
          />
        </div>
      )}

      <Callout tone="info" title={TEXT.notARotation}>
        {TEXT.notARotationBody}
      </Callout>

      {failure !== null && <FailureNotice failure={failure} title={TEXT.failed} onRetry={onRetry} />}
    </Dialog>
  );
}
