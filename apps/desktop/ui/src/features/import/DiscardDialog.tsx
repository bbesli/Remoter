/**
 * Leaving the wizard with a parsed preview still in the core.
 *
 * The preview is not a screenful of data — it is the parsed file, held in the
 * core with the passwords it recovered in plaintext. Leaving must drop it, and
 * dropping it is worth confirming, because the parse of a large confCons.xml
 * is not free to repeat.
 *
 * `aria-modal` is a promise: focus enters on open, Tab is trapped, Escape
 * cancels, focus returns to what had it, and the wizard's own Escape handler
 * stands down while this is registered. All five, or the attribute comes off.
 */

import { useEffect, useRef } from "react";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import type { IpcFailure } from "@/lib/ipc";

import s from "./ImportWizard.module.css";

export const DISCARD_MODAL_ID = "import-discard";

const TEXT = {
  title: "Discard this import?",
  body: "The parsed file is held in the core, along with every password it recovered. Leaving now drops it and wipes them. Nothing has been written to your vault, so there is nothing to undo — but the file would have to be read again.",
  keep: "Keep working",
  discard: "Discard and leave",
  discarding: "Dropping the preview…",
  failed: "The preview could not be dropped.",
  leaveAnyway: "Leave anyway",
  leaveAnywayHint:
    "The core drops a preview when the vault locks, so leaving does not keep it open indefinitely.",
} as const;

interface DiscardDialogProps {
  busy: boolean;
  failure: IpcFailure | null;
  onConfirm: () => void;
  onCancel: () => void;
  /** Used only after a failed cancel, so a broken core cannot trap the user. */
  onLeaveAnyway: () => void;
}

export function DiscardDialog({
  busy,
  failure,
  onConfirm,
  onCancel,
  onLeaveAnyway,
}: DiscardDialogProps) {
  const dialog = useRef<HTMLDivElement>(null);
  useModalRegistration(DISCARD_MODAL_ID, true);
  useFocusTrap(true, dialog);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // Capture, and stopped here: the wizard behind this listens for Escape
      // too, and both firing would close the dialog and the wizard at once.
      e.preventDefault();
      e.stopPropagation();
      onCancel();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [onCancel]);

  return (
    <div className={s.overlay}>
      <div
        ref={dialog}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby="import-discard-title"
        tabIndex={-1}
      >
        <h2 className={s.dialogTitle} id="import-discard-title">
          {TEXT.title}
        </h2>
        <p className={s.dialogText}>{TEXT.body}</p>

        {failure !== null && (
          <FailureNotice failure={failure} title={TEXT.failed}>
            <Button variant="ghost" size="sm" onClick={onLeaveAnyway} title={TEXT.leaveAnywayHint}>
              {TEXT.leaveAnyway}
            </Button>
          </FailureNotice>
        )}

        <div className={s.dialogButtons}>
          <Button onClick={onCancel}>{TEXT.keep}</Button>
          <BusyButton
            variant="danger"
            busy={busy}
            busyLabel={TEXT.discarding}
            onClick={onConfirm}
          >
            {TEXT.discard}
          </BusyButton>
        </div>
      </div>
    </div>
  );
}
