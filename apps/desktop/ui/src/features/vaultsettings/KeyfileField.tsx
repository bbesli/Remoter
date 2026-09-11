/**
 * Choosing a key file, on the two dialogs that need one.
 *
 * The rules are the unlock screen's, imported rather than restated: any file
 * can be a key file, so the browser filters rather than forbids, and the vault
 * and its rolling backups are refused outright because a vault cannot be its
 * own key file. That refusal exists because of a real lock-out — see
 * features/vault/keyfile.ts.
 *
 * The plugin rejects when the platform has no file browser to start. Left
 * unhandled, Browse becomes a button that does nothing, which is the defect
 * this project keeps finding.
 */

import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { folderOf, keyfileFilters, keyfileRefusal } from "@/features/vault/keyfile";
import { isolateLtr, useT } from "@/i18n";

import s from "./KeyfileField.module.css";

interface KeyfileFieldProps {
  label: string;
  help: string;
  /** Null when the slot is to have no key file. */
  path: string | null;
  onChange: (path: string | null) => void;
  /** The open vault, so the browser starts in its folder and cannot pick it. */
  vaultPath: string;
  disabled?: boolean | undefined;
}

export function KeyfileField({
  label,
  help,
  path,
  onChange,
  vaultPath,
  disabled = false,
}: KeyfileFieldProps) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const [browsing, setBrowsing] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const refusal = keyfileRefusal(path ?? "", vaultPath);

  async function choose() {
    let picked: string | string[] | null;
    setBrowsing(true);
    try {
      picked = await open({
        title: t("keyfile.dialogTitle"),
        multiple: false,
        directory: false,
        filters: keyfileFilters(),
        defaultPath: path ?? folderOf(vaultPath),
      });
    } catch {
      setDialogError(t("keyfile.dialogFailed"));
      return;
    } finally {
      setBrowsing(false);
    }
    setDialogError(null);
    const chosen = Array.isArray(picked) ? picked[0] : picked;
    if (typeof chosen === "string") onChange(chosen);
  }

  return (
    <Field
      label={label}
      help={help}
      {...(refusal !== null ? { error: refusal } : {})}
    >
      <div className={s.row}>
        {/* A file path is never translated, and it is LTR by specification
            whatever the interface direction, so it is isolated rather than
            left to the bidi algorithm. */}
        <span className={s.path} title={path ?? t("keyfile.none")}>
          {path === null ? t("keyfile.none") : isolateLtr(path)}
        </span>
        <BusyButton
          size="sm"
          busy={browsing}
          busyLabel={tCommon("action.opening")}
          disabled={disabled}
          onClick={() => void choose()}
        >
          {tCommon("action.browse")}
        </BusyButton>
        {path !== null && (
          <Button size="sm" variant="ghost" disabled={disabled} onClick={() => onChange(null)}>
            {t("keyfile.clear")}
          </Button>
        )}
      </div>
      {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}
    </Field>
  );
}

/** Whether a chosen key file is usable, for the dialogs that gate on it. */
export function keyfileBlocked(path: string | null, vaultPath: string): boolean {
  return keyfileRefusal(path ?? "", vaultPath) !== null;
}
