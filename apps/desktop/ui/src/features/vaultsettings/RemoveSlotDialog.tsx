/**
 * Revoking a key slot.
 *
 * Presentational on purpose: the mutation belongs to the section that owns the
 * slot list, so this file is the confirmation and nothing else, and a test can
 * hold it without a query client.
 *
 * Two guards, both from docs/security/key-management.md. The last slot cannot
 * be removed at all, and the row that opens this dialog already says so — the
 * refusal is repeated here because a screen that disables a button in one
 * place and allows it in another is worse than one that never disabled it.
 * And the recovery slot needs the sentence typed, not a box ticked.
 */

import { useState } from "react";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { TextInput } from "@/components/TextInput";
import type { IpcFailure, Slot } from "@/lib/ipc";

import {
  LAST_RESORT_PHRASE,
  SLOT_KIND_LABEL,
  lastResortSatisfied,
  needsLastResort,
  slotDetail,
} from "./slots";
import s from "./RemoveSlotDialog.module.css";
import { Dialog } from "./Dialog";

const TEXT = {
  title: "Remove this slot",
  lead: "The slot entry is deleted from the header. Nothing is re-encrypted and every other slot keeps working — this is not a rotation.",

  refusedTitle: "This slot cannot be removed",

  warningTitle: "Before you do",

  phrasePrompt: "Type this sentence to confirm:",
  phraseLabel: "Confirmation sentence",
  phraseHint: "The words as written above. Capitals do not matter.",
  phraseBlocked: "Type the sentence above to remove this slot.",

  lostKey:
    "Revocation deletes the slot entry, so a key you have lost can still be revoked — you do not need it to hand.",

  cancel: "Cancel",
  remove: "Remove the slot",
  removing: "Removing…",
  removingBlocked:
    "The removal is already with the core. This closes when it answers, so its result has somewhere to appear.",
  failed: "The slot was not removed.",
} as const;

interface RemoveSlotDialogProps {
  slot: Slot;
  /** Non-null when the core would refuse: the last slot in the table. */
  refusal: string | null;
  /** Shown but not blocking: the last recovery key, or this session's own slot. */
  warning: string | null;
  busy: boolean;
  failure: IpcFailure | null;
  onConfirm: () => void;
  onRetry: () => void;
  onClose: () => void;
}

export function RemoveSlotDialog({
  slot,
  refusal,
  warning,
  busy,
  failure,
  onConfirm,
  onRetry,
  onClose,
}: RemoveSlotDialogProps) {
  const [phrase, setPhrase] = useState("");

  const needsPhrase = needsLastResort(slot.kind);
  const phraseOk = lastResortSatisfied(slot.kind, phrase);
  const blocked = refusal !== null || !phraseOk;

  return (
    <Dialog
      id="vault-remove-slot"
      title={TEXT.title}
      lead={TEXT.lead}
      // A removal in flight owns the dialog: the command is already at the
      // core and closing here would leave its failure nowhere to appear.
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={TEXT.removingBlocked}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {TEXT.cancel}
          </Button>
          <BusyButton
            variant="danger"
            busy={busy}
            busyLabel={TEXT.removing}
            disabled={blocked}
            onClick={onConfirm}
            title={refusal ?? (phraseOk ? undefined : TEXT.phraseBlocked)}
          >
            {TEXT.remove}
          </BusyButton>
        </>
      }
    >
      <div className={s.subject}>
        <span className={s.kind}>{SLOT_KIND_LABEL[slot.kind]}</span>
        <span className={s.label}>{slot.label}</span>
        <span className={s.detail}>{slotDetail(slot)}</span>
        <span className={s.index}>slot {slot.index}</span>
      </div>

      {refusal !== null && (
        <Callout tone="danger" title={TEXT.refusedTitle}>
          {refusal}
        </Callout>
      )}

      {refusal === null && warning !== null && (
        <Callout tone="warning" title={TEXT.warningTitle}>
          {warning}
        </Callout>
      )}

      {refusal === null && <p className={s.note}>{TEXT.lostKey}</p>}

      {refusal === null && needsPhrase && (
        <div className={s.phraseBlock}>
          <p className={s.phrasePrompt}>{TEXT.phrasePrompt}</p>
          <p className={s.phrase}>{LAST_RESORT_PHRASE}</p>
          <TextInput
            value={phrase}
            onChange={setPhrase}
            ariaLabel={TEXT.phraseLabel}
            disabled={busy}
            autoFocus
          />
          <p className={s.phraseHint}>{TEXT.phraseHint}</p>
        </div>
      )}

      {failure !== null && (
        <FailureNotice failure={failure} title={TEXT.failed} onRetry={onRetry} />
      )}
    </Dialog>
  );
}
