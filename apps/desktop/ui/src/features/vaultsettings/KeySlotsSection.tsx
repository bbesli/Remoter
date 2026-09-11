/**
 * The key slots, as objects rather than checkboxes.
 *
 * Each slot is a row with its own identity: what kind of key it is, what it is
 * called, when it was enrolled, when it last opened this vault, whether it also
 * needs a key file, and the Argon2id parameters it was wrapped with. That is
 * what makes "which keys can open this vault" a question with a visual answer,
 * which is the whole point of the design.
 *
 * Every mutation on this screen lives here rather than inside the dialogs. The
 * dialogs are then presentation with an `onConfirm`, which is what lets a test
 * hold the confirmation without a query client, and it keeps one place that
 * knows a slot change invalidates the slot table, the vault settings and the
 * vault state together.
 *
 * A recovery key returned by any of these commands is queued and shown once,
 * transcription check and all. Nothing here caches one: `keyQueue` holds it
 * only between the command returning and the user confirming they have written
 * it down, and the dialog cannot be dismissed in between.
 */

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { useStagedSecret } from "@/hooks/useStagedSecret";

import { Badge } from "@/components/Badge";
import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { isolate, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type {
  AddPasswordSlot,
  ChangePassword,
  IpcFailure,
  KdfParams,
  RecoveryKey,
  RotateMasterKey,
  RotationOutcome,
  Slot,
  VaultSlots,
} from "@/lib/ipc";

import { AddSlotDialog } from "./AddSlotDialog";
import { ChangePasswordDialog } from "./ChangePasswordDialog";
import { Dialog } from "./Dialog";
import { RecoveryKeyDialog } from "./RecoveryKeyDialog";
import { RemoveSlotDialog } from "./RemoveSlotDialog";
import { RotateMasterKeyDialog, RotationSummaryDialog } from "./RotateMasterKeyDialog";
import { invalidateAfterSlotChange } from "./keys";
import {
  SLOT_KIND_ICON,
  removalRefusal,
  removalWarning,
  slotDetail,
  slotKindLabel,
} from "./slots";
import s from "./KeySlotsSection.module.css";

interface KeySlotsSectionProps {
  vaultSlots: VaultSlots;
  vaultPath: string;
  /** What the vault's password slot cost to derive, for a recovery key sheet. */
  kdf: KdfParams | null;
}

type AddKind = "password" | "recovery" | "keychain";

export function KeySlotsSection({ vaultSlots, vaultPath, kdf }: KeySlotsSectionProps) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const queryClient = useQueryClient();
  const slots = vaultSlots.slots;

  const [adding, setAdding] = useState(false);
  const [changing, setChanging] = useState<Slot | null>(null);
  const [removing, setRemoving] = useState<Slot | null>(null);
  const [rotatingRecovery, setRotatingRecovery] = useState<Slot | null>(null);
  const [rotatingMaster, setRotatingMaster] = useState(false);

  /**
   * Recovery keys waiting to be written down, oldest first. A master key
   * rotation returns one per recovery slot, and each is shown on its own.
   */
  const [keyQueue, setKeyQueue] = useState<readonly RecoveryKey[]>([]);
  const [rotationOutcome, setRotationOutcome] = useState<RotationOutcome | null>(null);

  const refresh = () => void invalidateAfterSlotChange(queryClient);

  // These three carry a master password. It is staged in a ref rather than
  // passed as a mutation variable, because TanStack retains variables in its
  // cache after the call settles — see useStagedSecret.
  const stagedAdd = useStagedSecret<AddPasswordSlot>();
  const stagedChange = useStagedSecret<ChangePassword>();
  const stagedRotate = useStagedSecret<RotateMasterKey>();

  const addPassword = useMutation({
    mutationFn: () => {
      const req = stagedAdd.read();
      if (req === null) return Promise.reject(new Error("nothing staged"));
      return ipc.addPasswordSlot(req);
    },
    onSuccess: () => {
      stagedAdd.clear();
      setAdding(false);
      refresh();
    },
  });

  const addRecovery = useMutation({
    mutationFn: (label: string) => ipc.addRecoverySlot(label),
    onSuccess: (key) => {
      setAdding(false);
      setKeyQueue([key]);
      refresh();
    },
  });

  const addKeychain = useMutation({
    mutationFn: (label: string) => ipc.addKeychainSlot(label),
    onSuccess: () => {
      setAdding(false);
      refresh();
    },
  });

  const changePassword = useMutation({
    mutationFn: () => {
      const req = stagedChange.read();
      if (req === null) return Promise.reject(new Error("nothing staged"));
      return ipc.changeMasterPassword(req);
    },
    onSuccess: () => {
      stagedChange.clear();
      setChanging(null);
      refresh();
    },
  });

  const removeSlot = useMutation({
    mutationFn: (index: number) => ipc.removeSlot(index),
    onSuccess: () => {
      setRemoving(null);
      refresh();
    },
  });

  const rotateRecovery = useMutation({
    mutationFn: (index: number) => ipc.rotateRecoveryKey(index),
    onSuccess: (key) => {
      setRotatingRecovery(null);
      setKeyQueue([key]);
      refresh();
    },
  });

  const rotateMaster = useMutation({
    mutationFn: () => {
      const req = stagedRotate.read();
      if (req === null) return Promise.reject(new Error("nothing staged"));
      return ipc.rotateMasterKey(req);
    },
    onSuccess: (outcome) => {
      stagedRotate.clear();
      setRotatingMaster(false);
      setKeyQueue(outcome.recoveryKeys);
      setRotationOutcome(outcome);
      refresh();
    },
  });

  const addBusy: AddKind | null = addPassword.isPending
    ? "password"
    : addRecovery.isPending
      ? "recovery"
      : addKeychain.isPending
        ? "keychain"
        : null;

  const addFailure: IpcFailure | null =
    addPassword.error !== null
      ? asFailure(addPassword.error)
      : addRecovery.error !== null
        ? asFailure(addRecovery.error)
        : addKeychain.error !== null
          ? asFailure(addKeychain.error)
          : null;

  const refusal = removalRefusal(slots, t);
  const pendingKey = keyQueue[0];

  function closeAdd() {
    if (addBusy !== null) return;
    addPassword.reset();
    addRecovery.reset();
    addKeychain.reset();
    setAdding(false);
  }

  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{t("slots.title")}</h2>
        <p className={s.description}>{t("slots.description")}</p>
      </div>

      <div className={s.list}>
        {slots.map((slot) => {
          const unusedRecovery = slot.kind === "recovery" && slot.lastUsed === null;
          return (
            <div
              key={slot.index}
              className={unusedRecovery ? [s.row, s.rowAlert].join(" ") : s.row}
            >
              <span className={unusedRecovery ? [s.glyph, s.glyphAlert].join(" ") : s.glyph}>
                <Icon name={SLOT_KIND_ICON[slot.kind]} size={17} />
              </span>

              <div className={s.rowBody}>
                <div className={s.rowHead}>
                  {/* The name the user gave this slot, isolated so its script
                      cannot reorder the badges beside it. */}
                  <span className={s.rowName}>{isolate(slot.label)}</span>
                  <Badge mono>{t("slot.indexBadge", { index: slot.index })}</Badge>
                  <Badge tone="neutral">{slotKindLabel(slot.kind, t)}</Badge>
                  {vaultSlots.openedWith === slot.index && (
                    <Badge tone="success">{t("slots.openedWithBadge")}</Badge>
                  )}
                  {unusedRecovery && <Badge tone="warning">{t("slots.neverUsedBadge")}</Badge>}
                </div>
                <p className={s.rowDetail}>{slotDetail(slot, { t, tCommon, locale })}</p>
                {unusedRecovery && (
                  <p className={s.rowAlertNote}>{t("slots.unusedRecoveryBody")}</p>
                )}
                {refusal !== null && <p className={s.rowRefusal}>{refusal}</p>}
              </div>

              <div className={s.rowActions}>
                {slot.kind === "password" && (
                  <Button size="sm" onClick={() => setChanging(slot)}>
                    {t("slots.change")}
                  </Button>
                )}
                {slot.kind === "recovery" && (
                  <Button size="sm" onClick={() => setRotatingRecovery(slot)}>
                    {t("slots.rotate")}
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="danger"
                  disabled={refusal !== null}
                  title={refusal ?? undefined}
                  onClick={() => setRemoving(slot)}
                >
                  {t("slots.remove")}
                </Button>
              </div>
            </div>
          );
        })}

        <button type="button" className={s.addRow} onClick={() => setAdding(true)}>
          <Icon name="plus" size={15} />
          <span className={s.addLabel}>{t("slots.add")}</span>
          <span className={s.addHint}>{t("slots.addHint")}</span>
        </button>
      </div>

      {/* A removal that failed after its dialog closed still has to be seen. */}
      {removeSlot.error !== null && removing === null && (
        <FailureNotice
          failure={asFailure(removeSlot.error)}
          title={t("slots.removeFailed")}
          onRetry={() => removeSlot.reset()}
          retryLabel={tCommon("action.cancel")}
        />
      )}

      <div className={s.divider} />

      <div className={s.expensive}>
        <span className={s.expensiveLabel}>{t("expensive.label")}</span>
        <div className={s.rotateCard}>
          <h3 className={s.rotateTitle}>{t("rotateMaster.cardTitle")}</h3>
          <p className={s.rotateBody}>{t("rotateMaster.cardBody")}</p>
          <div className={s.rotateActions}>
            <Button variant="danger" onClick={() => setRotatingMaster(true)}>
              {t("rotateMaster.cardButton")}
            </Button>
            <span className={s.rotateAside}>{t("rotateMaster.cardAside")}</span>
          </div>
        </div>
      </div>

      <Callout tone="info" title={t("slots.invariantTitle")}>
        {t("slots.invariantBody")}
      </Callout>

      {adding && (
        <AddSlotDialog
          vaultPath={vaultPath}
          busy={addBusy}
          failure={addFailure}
          onAddPassword={(req) => {
            stagedAdd.stage(req);
            addPassword.mutate();
          }}
          onAddRecovery={(label) => addRecovery.mutate(label)}
          onAddKeychain={(label) => addKeychain.mutate(label)}
          onRetry={() => {
            if (stagedAdd.has() && addPassword.error !== null) {
              addPassword.mutate();
              return;
            }
            if (addRecovery.variables !== undefined && addRecovery.error !== null) {
              addRecovery.mutate(addRecovery.variables);
              return;
            }
            if (addKeychain.variables !== undefined) addKeychain.mutate(addKeychain.variables);
          }}
          onClose={closeAdd}
        />
      )}

      {changing !== null && (
        <ChangePasswordDialog
          slot={changing}
          vaultPath={vaultPath}
          busy={changePassword.isPending}
          failure={changePassword.error === null ? null : asFailure(changePassword.error)}
          onConfirm={(req) => {
            stagedChange.stage(req);
            changePassword.mutate();
          }}
          onRetry={() => {
            if (stagedChange.has()) changePassword.mutate();
          }}
          onClose={() => {
            if (changePassword.isPending) return;
            changePassword.reset();
            stagedChange.clear();
            setChanging(null);
          }}
        />
      )}

      {removing !== null && (
        <RemoveSlotDialog
          slot={removing}
          refusal={refusal}
          warning={removalWarning(slots, removing, vaultSlots.openedWith, t)}
          busy={removeSlot.isPending}
          failure={removeSlot.error === null ? null : asFailure(removeSlot.error)}
          onConfirm={() => removeSlot.mutate(removing.index)}
          onRetry={() => removeSlot.mutate(removing.index)}
          onClose={() => {
            if (removeSlot.isPending) return;
            removeSlot.reset();
            setRemoving(null);
          }}
        />
      )}

      {rotatingRecovery !== null && (
        <Dialog
          id="vault-rotate-recovery"
          title={t("rotateRecovery.title")}
          lead={t("rotateRecovery.lead")}
          onDismiss={
            rotateRecovery.isPending
              ? null
              : () => {
                  rotateRecovery.reset();
                  setRotatingRecovery(null);
                }
          }
          dismissBlockedReason={t("rotateRecovery.blocked")}
          footer={
            <>
              <Button
                variant="secondary"
                disabled={rotateRecovery.isPending}
                onClick={() => {
                  rotateRecovery.reset();
                  setRotatingRecovery(null);
                }}
              >
                {tCommon("action.cancel")}
              </Button>
              <BusyButton
                variant="danger"
                busy={rotateRecovery.isPending}
                busyLabel={t("rotateRecovery.busy")}
                onClick={() => rotateRecovery.mutate(rotatingRecovery.index)}
              >
                {t("rotateRecovery.confirm")}
              </BusyButton>
            </>
          }
        >
          <p className={s.dialogBody}>{t("rotateRecovery.body")}</p>
          {rotateRecovery.error !== null && (
            <FailureNotice
              failure={asFailure(rotateRecovery.error)}
              title={t("rotateRecovery.failed")}
              onRetry={() => rotateRecovery.mutate(rotatingRecovery.index)}
            />
          )}
        </Dialog>
      )}

      {rotatingMaster && (
        <RotateMasterKeyDialog
          slots={slots}
          vaultPath={vaultPath}
          busy={rotateMaster.isPending}
          failure={rotateMaster.error === null ? null : asFailure(rotateMaster.error)}
          onConfirm={(req) => {
            stagedRotate.stage(req);
            rotateMaster.mutate();
          }}
          onRetry={() => {
            if (stagedRotate.has()) rotateMaster.mutate();
          }}
          onClose={() => {
            if (rotateMaster.isPending) return;
            rotateMaster.reset();
            stagedRotate.clear();
            setRotatingMaster(false);
          }}
        />
      )}

      {/* Ahead of the summary: the keys are the perishable part. */}
      {pendingKey !== undefined && (
        <RecoveryKeyDialog
          key={`${pendingKey.slotIndex}-${keyQueue.length}`}
          recoveryKey={pendingKey}
          vaultPath={vaultPath}
          kdf={kdf}
          {...(keyQueue.length > 1 || rotationOutcome !== null
            ? {
                sequence: {
                  position:
                    (rotationOutcome?.recoveryKeys.length ?? keyQueue.length) -
                    keyQueue.length +
                    1,
                  total: rotationOutcome?.recoveryKeys.length ?? keyQueue.length,
                },
              }
            : {})}
          onDone={() => setKeyQueue((queue) => queue.slice(1))}
        />
      )}

      {pendingKey === undefined && rotationOutcome !== null && (
        <RotationSummaryDialog
          outcome={rotationOutcome}
          onClose={() => setRotationOutcome(null)}
        />
      )}
    </section>
  );
}
