/**
 * A recovery key, shown exactly once.
 *
 * Reached three ways: a recovery slot added, a recovery slot rotated, and a
 * master key rotation, which issues a fresh key for every recovery slot it
 * re-wraps. Nothing in the vault file can reproduce any of them and no command
 * asks for one again, so this dialog is the only moment the key exists outside
 * the core.
 *
 * The panel is the create wizard's, not a copy of it. That screen already
 * proved the pattern the documentation asks for — the user retypes the group
 * the core nominates before the way out unlocks — and a second implementation
 * of a transcription check would be a second chance to get it subtly wrong.
 * The panel wants a `CreateVaultResult` because that is the shape it was born
 * with; the fields it reads are the groups, the nominated index, and the vault
 * path and KDF summary it prints on the paper sheet, all of which are true
 * here as well.
 *
 * Escape does not close this. Everywhere else in the application a modal
 * cancels on Escape; here cancelling destroys the only copy of a key that
 * cannot be reissued, so the press is caught and answered instead.
 */

import { useMemo, useState } from "react";

import { Button } from "@/components/Button";
import { RecoveryKeyPanel } from "@/features/vault/RecoveryKeyScreen";
import { useT } from "@/i18n";
import type { CreateVaultResult, KdfParams, RecoveryKey } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import s from "./RecoveryKeyDialog.module.css";

interface RecoveryKeyDialogProps {
  recoveryKey: RecoveryKey;
  /** Printed on the paper sheet, so the page says which vault it opens. */
  vaultPath: string;
  /** What the vault's password slot cost to derive, for the same sheet. */
  kdf: KdfParams | null;
  /** Set when more than one key is being handed over, as after a rotation. */
  sequence?: { position: number; total: number } | undefined;
  onDone: () => void;
}

export function RecoveryKeyDialog({
  recoveryKey,
  vaultPath,
  kdf,
  sequence,
  onDone,
}: RecoveryKeyDialogProps) {
  const t = useT("vaultsettings");
  const [confirmed, setConfirmed] = useState(false);

  const sheet = useMemo<CreateVaultResult>(
    () => ({
      path: vaultPath,
      recoveryKeyGroups: recoveryKey.recoveryKeyGroups,
      confirmGroupIndex: recoveryKey.confirmGroupIndex,
      kdf,
    }),
    [vaultPath, recoveryKey, kdf],
  );

  const last = sequence === undefined || sequence.position === sequence.total;

  return (
    <Dialog
      id={`vault-recovery-key-${recoveryKey.slotIndex}`}
      title={
        sequence === undefined
          ? t("recoveryKey.title")
          : t("recoveryKey.titleSequence", {
              position: sequence.position,
              total: sequence.total,
            })
      }
      lead={t("recoveryKey.lead", { index: recoveryKey.slotIndex })}
      onDismiss={null}
      dismissBlockedReason={t("recoveryKey.escapeBlocked")}
      wide
      footer={
        <>
          {!confirmed && <span className={s.blocked}>{t("recoveryKey.blocked")}</span>}
          <Button
            variant="primary"
            onClick={onDone}
            disabled={!confirmed}
            title={confirmed ? undefined : t("recoveryKey.blocked")}
          >
            {last ? t("recoveryKey.doneLast") : t("recoveryKey.done")}
          </Button>
        </>
      }
    >
      <RecoveryKeyPanel result={sheet} onConfirmedChange={setConfirmed} />
    </Dialog>
  );
}
