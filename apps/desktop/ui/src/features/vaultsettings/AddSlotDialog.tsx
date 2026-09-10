/**
 * Adding a way into the vault.
 *
 * Three kinds, one dialog, because the choice between them is the question
 * being asked. All three re-wrap the master key under a new credential and
 * none of them touches the body, which is why adding a slot is instant on a
 * vault of any size — the dialog says so, because "this will take a while"
 * fear is what stops people enrolling a second key at all.
 *
 * The password is held in component state only until the command takes it, and
 * it never becomes a query key: a query key is a cache key, and a cache is a
 * place a secret would sit for the rest of the session. That is also why there
 * is no live strength meter here — `password_strength` is a round trip per
 * keystroke with the password as its argument, and this dialog is not worth
 * that surface.
 */

import { useState } from "react";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { TextInput } from "@/components/TextInput";
import { kdfNote } from "@/features/vault/UnlockScreen";
import type { AddPasswordSlot, IpcFailure, SlotKind } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import s from "./AddSlotDialog.module.css";

const TEXT = {
  title: "Add a key slot",
  lead: "Each slot independently unwraps the same vault key. Adding one re-wraps that key under a new credential and re-encrypts nothing, so it is instant and it is safe to change your mind.",

  kindLegend: "What kind of slot",
  kindPassword: "Another password",
  kindPasswordHelp:
    "A second password, optionally with its own key file. Useful for a colleague who must be able to open this vault without knowing yours.",
  kindRecovery: "Another recovery key",
  kindRecoveryHelp:
    "A vault may hold more than one. A sealed envelope in a safe is a legitimate reason to want a second.",
  kindKeychain: "Remember on this device",
  kindKeychainHelp:
    "Enrols this machine's credential store, so the vault opens without a prompt while you are logged in. Anyone who can use your desktop session can then open the vault.",

  label: "Name for this slot",
  labelHelp: "Shown in this list and on the unlock screen, so a slot can be told from the others.",
  labelPlaceholder: "Ops laptop",
  labelBlocked: "Give the slot a name first.",

  password: "Password",
  passwordHelp:
    "This opens the whole vault, exactly as the master password does. It should be as strong.",
  confirm: "Repeat the password",
  confirmMismatch: "The two passwords are not the same.",
  passwordBlocked: "Type the password twice, the same way.",

  keyfile: "Key file (optional)",
  keyfileHelp:
    "Any file becomes a second factor for this slot. Lose it and this slot stops working; the other slots are unaffected.",
  keyfileRefused: "Choose a different key file. The field above says why that one cannot be used.",

  recoveryNotice: "The key is generated when you press Add, shown once, and then dropped.",
  keychainNotice:
    "The token lives in this machine's keyring. Another machine cannot use this slot, and removing it here erases the token.",

  cancel: "Cancel",
  add: "Add the slot",
  adding: "Deriving the key…",
  addingStage: "Deriving a key from the new password…",
  addingBlocked:
    "The slot is already being written. This closes when the core answers — and a recovery slot has a key to hand over first.",
  failed: "The slot was not added.",
} as const;

type AddKind = Extract<SlotKind, "password" | "recovery" | "keychain">;

const KINDS: readonly { kind: AddKind; label: string; help: string }[] = [
  { kind: "password", label: TEXT.kindPassword, help: TEXT.kindPasswordHelp },
  { kind: "recovery", label: TEXT.kindRecovery, help: TEXT.kindRecoveryHelp },
  { kind: "keychain", label: TEXT.kindKeychain, help: TEXT.kindKeychainHelp },
];

interface AddSlotDialogProps {
  vaultPath: string;
  /** The kind currently being added, or null when nothing is in flight. */
  busy: AddKind | null;
  failure: IpcFailure | null;
  onAddPassword: (req: AddPasswordSlot) => void;
  onAddRecovery: (label: string) => void;
  onAddKeychain: (label: string) => void;
  onRetry: () => void;
  onClose: () => void;
}

export function AddSlotDialog({
  vaultPath,
  busy,
  failure,
  onAddPassword,
  onAddRecovery,
  onAddKeychain,
  onRetry,
  onClose,
}: AddSlotDialogProps) {
  const [kind, setKind] = useState<AddKind>("password");
  const [label, setLabel] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [keyfile, setKeyfile] = useState<string | null>(null);

  const working = busy !== null;
  const trimmed = label.trim();

  const passwordsMatch = password !== "" && password === confirm;
  const passwordProblem =
    kind !== "password"
      ? null
      : password === ""
        ? TEXT.passwordBlocked
        : !passwordsMatch
          ? TEXT.confirmMismatch
          : keyfileBlocked(keyfile, vaultPath)
            ? TEXT.keyfileRefused
            : null;

  const blockedReason =
    trimmed === "" ? TEXT.labelBlocked : passwordProblem !== null ? passwordProblem : null;

  function submit() {
    if (working || blockedReason !== null) return;
    if (kind === "password") {
      onAddPassword({ label: trimmed, password, keyfilePath: keyfile });
      return;
    }
    if (kind === "recovery") {
      onAddRecovery(trimmed);
      return;
    }
    onAddKeychain(trimmed);
  }

  return (
    <Dialog
      id="vault-add-slot"
      title={TEXT.title}
      lead={TEXT.lead}
      onDismiss={working ? null : onClose}
      dismissBlockedReason={TEXT.addingBlocked}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={working}>
            {TEXT.cancel}
          </Button>
          <BusyButton
            variant="primary"
            busy={working}
            busyLabel={TEXT.adding}
            disabled={blockedReason !== null}
            onClick={submit}
            {...(blockedReason === null ? {} : { title: blockedReason })}
          >
            {TEXT.add}
          </BusyButton>
        </>
      }
    >
      <fieldset className={s.kinds} disabled={working}>
        <legend className={s.legend}>{TEXT.kindLegend}</legend>
        {KINDS.map((option) => (
          <label
            key={option.kind}
            className={option.kind === kind ? [s.kindCard, s.kindCardOn].join(" ") : s.kindCard}
          >
            <input
              className={s.radio}
              type="radio"
              name="vault-add-slot-kind"
              value={option.kind}
              checked={option.kind === kind}
              onChange={() => setKind(option.kind)}
            />
            <span className={s.mark} aria-hidden="true" />
            <span className={s.kindText}>
              <span className={s.kindName}>{option.label}</span>
              <span className={s.kindHelp}>{option.help}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <Field label={TEXT.label} help={TEXT.labelHelp} htmlFor="vault-add-slot-label">
        <TextInput
          id="vault-add-slot-label"
          value={label}
          onChange={setLabel}
          placeholder={TEXT.labelPlaceholder}
          disabled={working}
          autoFocus
        />
      </Field>

      {kind === "password" && (
        <>
          <Field label={TEXT.password} help={TEXT.passwordHelp} htmlFor="vault-add-slot-password">
            <TextInput
              id="vault-add-slot-password"
              type="password"
              value={password}
              onChange={setPassword}
              disabled={working}
            />
          </Field>
          <Field
            label={TEXT.confirm}
            htmlFor="vault-add-slot-confirm"
            {...(confirm !== "" && !passwordsMatch ? { error: TEXT.confirmMismatch } : {})}
          >
            <TextInput
              id="vault-add-slot-confirm"
              type="password"
              value={confirm}
              onChange={setConfirm}
              disabled={working}
              invalid={confirm !== "" && !passwordsMatch}
            />
          </Field>
          <KeyfileField
            label={TEXT.keyfile}
            help={TEXT.keyfileHelp}
            path={keyfile}
            onChange={setKeyfile}
            vaultPath={vaultPath}
            disabled={working}
          />
        </>
      )}

      {/* The Argon2id cost is the security property, so the wait is explained
          rather than hidden. Same sentence as the unlock screen, from the same
          function, because a security explanation that drifts is worse than
          one that is only in one place. */}
      {busy === "password" && (
        <div className={s.busy}>
          <BusyStatus label={TEXT.addingStage} note={kdfNote(null)} size={16} />
        </div>
      )}

      {kind === "recovery" && <p className={s.notice}>{TEXT.recoveryNotice}</p>}
      {kind === "keychain" && (
        <Callout tone="warning" title={TEXT.kindKeychain}>
          {TEXT.keychainNotice}
        </Callout>
      )}

      {failure !== null && <FailureNotice failure={failure} title={TEXT.failed} onRetry={onRetry} />}
    </Dialog>
  );
}
