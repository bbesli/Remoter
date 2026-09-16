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
import { isolate, useLocale, useT } from "@/i18n";
import type { ChangePassword, IpcFailure, Slot } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import s from "./ChangePasswordDialog.module.css";

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
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const [current, setCurrent] = useState("");
  const [currentKeyfile, setCurrentKeyfile] = useState<string | null>(null);
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [newKeyfile, setNewKeyfile] = useState<string | null>(null);

  const matches = next !== "" && next === confirm;
  const blocked =
    current === ""
      ? t("changePassword.blockedCurrent")
      : slot.requiresKeyfile && currentKeyfile === null
        ? t("changePassword.blockedCurrentKeyfile")
        : !matches
          ? t("changePassword.blockedNew")
          : keyfileBlocked(currentKeyfile, vaultPath) || keyfileBlocked(newKeyfile, vaultPath)
            ? t("changePassword.blockedKeyfile")
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
      title={t("changePassword.title")}
      lead={t("changePassword.lead")}
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={t("changePassword.savingBlocked")}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {tCommon("action.cancel")}
          </Button>
          <BusyButton
            variant="primary"
            busy={busy}
            busyLabel={t("changePassword.saving")}
            disabled={blocked !== null}
            onClick={submit}
            {...(blocked === null ? {} : { title: blocked })}
          >
            {t("changePassword.save")}
          </BusyButton>
        </>
      }
    >
      <div className={s.subject}>
        {/* The slot's own name, isolated: it is the user's text, not ours. */}
        <span className={s.label}>{isolate(slot.label)}</span>
        <span className={s.index}>{t("slot.indexBadge", { index: slot.index })}</span>
      </div>

      <Field
        label={t("changePassword.current")}
        help={t("changePassword.currentHelp")}
        htmlFor="vault-change-current"
      >
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
          label={t("changePassword.currentKeyfile")}
          help={t("changePassword.currentKeyfileHelp")}
          path={currentKeyfile}
          onChange={setCurrentKeyfile}
          vaultPath={vaultPath}
          disabled={busy}
        />
      )}

      <Field label={t("changePassword.next")} htmlFor="vault-change-new">
        <TextInput
          id="vault-change-new"
          type="password"
          value={next}
          onChange={setNext}
          disabled={busy}
        />
      </Field>

      <Field
        label={t("changePassword.confirm")}
        htmlFor="vault-change-confirm"
        {...(confirm !== "" && !matches ? { error: t("changePassword.confirmMismatch") } : {})}
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
        label={t("changePassword.newKeyfile")}
        help={t("changePassword.newKeyfileHelp")}
        path={newKeyfile}
        onChange={setNewKeyfile}
        vaultPath={vaultPath}
        disabled={busy}
        canGenerate
      />

      {busy && (
        <div className={s.busy}>
          <BusyStatus
            label={t("changePassword.savingStage")}
            note={kdfNote(locale, slot.kdf)}
            size={16}
          />
        </div>
      )}

      <Callout tone="info" title={t("changePassword.notARotation")}>
        {t("changePassword.notARotationBody")}
      </Callout>

      {failure !== null && (
        <FailureNotice failure={failure} title={t("changePassword.failed")} onRetry={onRetry} />
      )}
    </Dialog>
  );
}
