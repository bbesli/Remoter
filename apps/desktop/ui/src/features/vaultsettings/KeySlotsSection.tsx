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
import { asFailure, ipc } from "@/lib/ipc";
import type {
  AddPasswordSlot,
  ChangePassword,
  IpcFailure,
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
  SLOT_KIND_LABEL,
  removalRefusal,
  removalWarning,
  slotDetail,
} from "./slots";
import s from "./KeySlotsSection.module.css";

const TEXT = {
  title: "Key slots",
  description:
    "Each slot independently unwraps the same vault key. Adding or removing one does not re-encrypt anything, so it is fast and safe to change your mind.",

  openedWith: "opened this session",
  neverUsed: "never used",

  change: "Change",
  rotate: "Rotate",
  remove: "Remove",

  add: "Add a slot",
  addHint: "another password · a recovery key · this device",

  unusedRecoveryTitle: "This recovery key has never been used",
  unusedRecoveryBody:
    "Generated and never used is exactly the slot most likely to be lost. If you cannot put your hands on it, rotate it now — there is no way into this vault without one of these slots.",

  invariantTitle: "A vault must keep at least one usable slot",
  invariantBody:
    "Remoter will not let you delete the last one, and deleting the recovery slot needs a typed confirmation. There is no escrow key and no support override: if every slot is lost, the file cannot be opened by anyone, including us.",

  rotateRecoveryTitle: "Rotate this recovery key",
  rotateRecoveryLead:
    "The slot is replaced with a new key. The one you hold today stops working the moment this succeeds, and the new one is shown exactly once.",
  rotateRecoveryBody:
    "The master key does not change, so nothing is re-encrypted and every other slot keeps working.",
  rotateRecoveryConfirm: "Rotate the key",
  rotateRecoveryBusy: "Generating…",
  rotateRecoveryBlocked:
    "The new key is being generated. Closing now would lose it: it is shown once and nothing can reissue it.",
  rotateRecoveryFailed: "The recovery key was not rotated.",
  cancel: "Cancel",

  expensive: "Expensive operation",
  rotateMasterTitle: "Rotate the vault master key",
  rotateMasterBody:
    'This is the right answer to "a copy of this file may have leaked while one of my keys was compromised". A new master key is generated, every slot is re-wrapped and the whole body is re-encrypted.',
  rotateMasterButton: "Rotate the master key",
  rotateMasterAside: "Old copies of the file stay readable with the old keys. Delete them.",

  removeFailed: "The slot was not removed.",
} as const;

interface KeySlotsSectionProps {
  vaultSlots: VaultSlots;
  vaultPath: string;
  /** The vault's Argon2id summary, printed on a recovery key sheet. */
  kdfSummary: string | null;
}

type AddKind = "password" | "recovery" | "keychain";

export function KeySlotsSection({ vaultSlots, vaultPath, kdfSummary }: KeySlotsSectionProps) {
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

  const refusal = removalRefusal(slots);
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
        <h2 className={s.title}>{TEXT.title}</h2>
        <p className={s.description}>{TEXT.description}</p>
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
                  <span className={s.rowName}>{slot.label}</span>
                  <Badge mono>slot {slot.index}</Badge>
                  <Badge tone="neutral">{SLOT_KIND_LABEL[slot.kind]}</Badge>
                  {vaultSlots.openedWith === slot.index && (
                    <Badge tone="success">{TEXT.openedWith}</Badge>
                  )}
                  {unusedRecovery && <Badge tone="warning">{TEXT.neverUsed}</Badge>}
                </div>
                <p className={s.rowDetail}>{slotDetail(slot)}</p>
                {unusedRecovery && <p className={s.rowAlertNote}>{TEXT.unusedRecoveryBody}</p>}
                {refusal !== null && <p className={s.rowRefusal}>{refusal}</p>}
              </div>

              <div className={s.rowActions}>
                {slot.kind === "password" && (
                  <Button size="sm" onClick={() => setChanging(slot)}>
                    {TEXT.change}
                  </Button>
                )}
                {slot.kind === "recovery" && (
                  <Button size="sm" onClick={() => setRotatingRecovery(slot)}>
                    {TEXT.rotate}
                  </Button>
                )}
                <Button
                  size="sm"
                  variant="danger"
                  disabled={refusal !== null}
                  title={refusal ?? undefined}
                  onClick={() => setRemoving(slot)}
                >
                  {TEXT.remove}
                </Button>
              </div>
            </div>
          );
        })}

        <button type="button" className={s.addRow} onClick={() => setAdding(true)}>
          <Icon name="plus" size={15} />
          <span className={s.addLabel}>{TEXT.add}</span>
          <span className={s.addHint}>{TEXT.addHint}</span>
        </button>
      </div>

      {/* A removal that failed after its dialog closed still has to be seen. */}
      {removeSlot.error !== null && removing === null && (
        <FailureNotice
          failure={asFailure(removeSlot.error)}
          title={TEXT.removeFailed}
          onRetry={() => removeSlot.reset()}
          retryLabel={TEXT.cancel}
        />
      )}

      <div className={s.divider} />

      <div className={s.expensive}>
        <span className={s.expensiveLabel}>{TEXT.expensive}</span>
        <div className={s.rotateCard}>
          <h3 className={s.rotateTitle}>{TEXT.rotateMasterTitle}</h3>
          <p className={s.rotateBody}>{TEXT.rotateMasterBody}</p>
          <div className={s.rotateActions}>
            <Button variant="danger" onClick={() => setRotatingMaster(true)}>
              {TEXT.rotateMasterButton}
            </Button>
            <span className={s.rotateAside}>{TEXT.rotateMasterAside}</span>
          </div>
        </div>
      </div>

      <Callout tone="info" title={TEXT.invariantTitle}>
        {TEXT.invariantBody}
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
          warning={removalWarning(slots, removing, vaultSlots.openedWith)}
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
          title={TEXT.rotateRecoveryTitle}
          lead={TEXT.rotateRecoveryLead}
          onDismiss={
            rotateRecovery.isPending
              ? null
              : () => {
                  rotateRecovery.reset();
                  setRotatingRecovery(null);
                }
          }
          dismissBlockedReason={TEXT.rotateRecoveryBlocked}
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
                {TEXT.cancel}
              </Button>
              <BusyButton
                variant="danger"
                busy={rotateRecovery.isPending}
                busyLabel={TEXT.rotateRecoveryBusy}
                onClick={() => rotateRecovery.mutate(rotatingRecovery.index)}
              >
                {TEXT.rotateRecoveryConfirm}
              </BusyButton>
            </>
          }
        >
          <p className={s.dialogBody}>{TEXT.rotateRecoveryBody}</p>
          {rotateRecovery.error !== null && (
            <FailureNotice
              failure={asFailure(rotateRecovery.error)}
              title={TEXT.rotateRecoveryFailed}
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
          kdfSummary={kdfSummary}
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
