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
import { useLocale, useT } from "@/i18n";
import type { AddPasswordSlot, IpcFailure, SlotKind } from "@/lib/ipc";

import { Dialog } from "./Dialog";
import { KeyfileField, keyfileBlocked } from "./KeyfileField";
import s from "./AddSlotDialog.module.css";

type AddKind = Extract<SlotKind, "password" | "recovery" | "keychain">;

/**
 * The three kinds, as catalogue keys rather than resolved labels: this array is
 * module-level, and a label resolved here would not follow a language change.
 */
const KINDS = [
  { kind: "password", labelKey: "addSlot.kindPassword", helpKey: "addSlot.kindPasswordHelp" },
  { kind: "recovery", labelKey: "addSlot.kindRecovery", helpKey: "addSlot.kindRecoveryHelp" },
  { kind: "keychain", labelKey: "addSlot.kindKeychain", helpKey: "addSlot.kindKeychainHelp" },
] as const satisfies readonly { kind: AddKind; labelKey: string; helpKey: string }[];

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
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
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
        ? t("addSlot.passwordBlocked")
        : !passwordsMatch
          ? t("addSlot.confirmMismatch")
          : keyfileBlocked(keyfile, vaultPath)
            ? t("addSlot.keyfileRefused")
            : null;

  const blockedReason =
    trimmed === "" ? t("addSlot.labelBlocked") : passwordProblem !== null ? passwordProblem : null;

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
      title={t("addSlot.title")}
      lead={t("addSlot.lead")}
      onDismiss={working ? null : onClose}
      dismissBlockedReason={t("addSlot.addingBlocked")}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={working}>
            {tCommon("action.cancel")}
          </Button>
          <BusyButton
            variant="primary"
            busy={working}
            busyLabel={t("addSlot.adding")}
            disabled={blockedReason !== null}
            onClick={submit}
            {...(blockedReason === null ? {} : { title: blockedReason })}
          >
            {t("addSlot.add")}
          </BusyButton>
        </>
      }
    >
      <fieldset className={s.kinds} disabled={working}>
        <legend className={s.legend}>{t("addSlot.kindLegend")}</legend>
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
              <span className={s.kindName}>{t(option.labelKey)}</span>
              <span className={s.kindHelp}>{t(option.helpKey)}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <Field
        label={t("addSlot.label")}
        help={t("addSlot.labelHelp")}
        htmlFor="vault-add-slot-label"
      >
        <TextInput
          id="vault-add-slot-label"
          value={label}
          onChange={setLabel}
          placeholder={t("addSlot.labelPlaceholder")}
          disabled={working}
          autoFocus
        />
      </Field>

      {kind === "password" && (
        <>
          <Field
            label={t("addSlot.password")}
            help={t("addSlot.passwordHelp")}
            htmlFor="vault-add-slot-password"
          >
            <TextInput
              id="vault-add-slot-password"
              type="password"
              value={password}
              onChange={setPassword}
              disabled={working}
            />
          </Field>
          <Field
            label={t("addSlot.confirm")}
            htmlFor="vault-add-slot-confirm"
            {...(confirm !== "" && !passwordsMatch
              ? { error: t("addSlot.confirmMismatch") }
              : {})}
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
            label={t("addSlot.keyfile")}
            help={t("addSlot.keyfileHelp")}
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
          <BusyStatus label={t("addSlot.addingStage")} note={kdfNote(locale, null)} size={16} />
        </div>
      )}

      {kind === "recovery" && <p className={s.notice}>{t("addSlot.recoveryNotice")}</p>}
      {kind === "keychain" && (
        <Callout tone="warning" title={t("addSlot.kindKeychain")}>
          {t("addSlot.keychainNotice")}
        </Callout>
      )}

      {failure !== null && (
        <FailureNotice failure={failure} title={t("addSlot.failed")} onRetry={onRetry} />
      )}
    </Dialog>
  );
}
