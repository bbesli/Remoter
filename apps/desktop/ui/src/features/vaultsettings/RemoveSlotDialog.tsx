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
import { isolate, useLocale, useT } from "@/i18n";
import type { IpcFailure, Slot } from "@/lib/ipc";

import {
  lastResortPhrase,
  lastResortSatisfied,
  needsLastResort,
  slotDetail,
  slotKindLabel,
} from "./slots";
import s from "./RemoveSlotDialog.module.css";
import { Dialog } from "./Dialog";

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
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const [phrase, setPhrase] = useState("");

  const needsPhrase = needsLastResort(slot.kind);
  // Compared against the sentence in the language it was shown in, which is
  // why the phrase is read here rather than baked into the comparison.
  const required = lastResortPhrase(t);
  // The locale travels with the phrase: case is forgiven by this language's
  // rules, which is the only way a Turkish reader can type the sentence they
  // were shown in capitals and be believed. See `lastResortSatisfied`.
  const phraseOk = lastResortSatisfied(slot.kind, phrase, required, locale);
  const blocked = refusal !== null || !phraseOk;

  return (
    <Dialog
      id="vault-remove-slot"
      title={t("removeSlot.title")}
      lead={t("removeSlot.lead")}
      // A removal in flight owns the dialog: the command is already at the
      // core and closing here would leave its failure nowhere to appear.
      onDismiss={busy ? null : onClose}
      dismissBlockedReason={t("removeSlot.removingBlocked")}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            {tCommon("action.cancel")}
          </Button>
          <BusyButton
            variant="danger"
            busy={busy}
            busyLabel={t("removeSlot.removing")}
            disabled={blocked}
            onClick={onConfirm}
            title={refusal ?? (phraseOk ? undefined : t("removeSlot.phraseBlocked"))}
          >
            {t("removeSlot.remove")}
          </BusyButton>
        </>
      }
    >
      <div className={s.subject}>
        <span className={s.kind}>{slotKindLabel(slot.kind, t)}</span>
        {/* The slot's own name, isolated: it is the user's text, not ours. */}
        <span className={s.label}>{isolate(slot.label)}</span>
        <span className={s.detail}>{slotDetail(slot, { t, tCommon, locale })}</span>
        <span className={s.index}>{t("slot.indexBadge", { index: slot.index })}</span>
      </div>

      {refusal !== null && (
        <Callout tone="danger" title={t("removeSlot.refusedTitle")}>
          {refusal}
        </Callout>
      )}

      {refusal === null && warning !== null && (
        <Callout tone="warning" title={t("removeSlot.warningTitle")}>
          {warning}
        </Callout>
      )}

      {refusal === null && <p className={s.note}>{t("removeSlot.lostKey")}</p>}

      {refusal === null && needsPhrase && (
        <div className={s.phraseBlock}>
          <p className={s.phrasePrompt}>{t("removeSlot.phrasePrompt")}</p>
          <p className={s.phrase}>{required}</p>
          <TextInput
            value={phrase}
            onChange={setPhrase}
            ariaLabel={t("removeSlot.phraseLabel")}
            disabled={busy}
            autoFocus
          />
          <p className={s.phraseHint}>{t("removeSlot.phraseHint")}</p>
        </div>
      )}

      {failure !== null && (
        <FailureNotice failure={failure} title={t("removeSlot.failed")} onRetry={onRetry} />
      )}
    </Dialog>
  );
}
