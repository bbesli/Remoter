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

import s from "./KeyfileField.module.css";

const TEXT = {
  browse: "Browse",
  browsing: "Opening…",
  clear: "No key file",
  none: "None",
  dialogTitle: "Choose the key file for this slot",
  dialogFailed:
    "This system did not open a file browser. Type the path into the field the platform gives you, or start Remoter from a session that has one.",
} as const;

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
  const [browsing, setBrowsing] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const refusal = keyfileRefusal(path ?? "", vaultPath);

  async function choose() {
    let picked: string | string[] | null;
    setBrowsing(true);
    try {
      picked = await open({
        title: TEXT.dialogTitle,
        multiple: false,
        directory: false,
        filters: keyfileFilters(),
        defaultPath: path ?? folderOf(vaultPath),
      });
    } catch {
      setDialogError(TEXT.dialogFailed);
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
        <span className={s.path} title={path ?? TEXT.none}>
          {path ?? TEXT.none}
        </span>
        <BusyButton
          size="sm"
          busy={browsing}
          busyLabel={TEXT.browsing}
          disabled={disabled}
          onClick={() => void choose()}
        >
          {TEXT.browse}
        </BusyButton>
        {path !== null && (
          <Button size="sm" variant="ghost" disabled={disabled} onClick={() => onChange(null)}>
            {TEXT.clear}
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
