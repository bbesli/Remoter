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
 *
 * A slot that is gaining a key file can also have one made for it. Before this,
 * a vault created without a key file could only be given one the user already
 * had — the creation wizard offered to generate one, and the two places a key
 * file is added afterwards did not. Generating writes 256 random bits through
 * the core, owner-readable only, and never over an existing file: a path that is
 * already taken is refused rather than replaced, because the file already there
 * may be another vault's key file.
 */

import { useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { folderOf, keyfileFilters, keyfileRefusal } from "@/features/vault/keyfile";
import { isolateLtr, useT } from "@/i18n";
import { asFailure, ipc, type IpcFailure } from "@/lib/ipc";

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
  /**
   * Whether a new key file can be generated here. True where a slot is gaining
   * a key file; false where the field asks for the one a slot already has,
   * which no newly generated file could ever be.
   */
  canGenerate?: boolean | undefined;
}

export function KeyfileField({
  label,
  help,
  path,
  onChange,
  vaultPath,
  disabled = false,
  canGenerate = false,
}: KeyfileFieldProps) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const [browsing, setBrowsing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [generateFailure, setGenerateFailure] = useState<IpcFailure | null>(null);
  /** The file this field generated, so the note about keeping it follows the path. */
  const [generated, setGenerated] = useState<string | null>(null);

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
    if (typeof chosen === "string") {
      setGenerateFailure(null);
      onChange(chosen);
    }
  }

  async function generate() {
    setGenerating(true);
    setGenerateFailure(null);
    try {
      let target: string | null;
      try {
        target = await save({
          title: t("keyfile.generateDialogTitle"),
          defaultPath: `${folderOf(vaultPath)}${suggestedName(vaultPath)}`,
          filters: keyfileFilters(),
        });
      } catch {
        setDialogError(t("keyfile.dialogFailed"));
        return;
      }
      setDialogError(null);
      if (target === null) return;

      // The same rules as a file chosen with Browse, applied before anything
      // is written: a key file cannot be the vault or one of its backups.
      const refused = keyfileRefusal(target, vaultPath);
      if (refused !== null) {
        setDialogError(refused);
        return;
      }

      try {
        await ipc.generateKeyfile(target);
      } catch (error) {
        setGenerateFailure(asFailure(error));
        return;
      }
      setGenerated(target);
      onChange(target);
    } finally {
      setGenerating(false);
    }
  }

  const justGenerated = path !== null && path === generated;
  const besideTheVault = justGenerated && folderOf(path) === folderOf(vaultPath);

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
        {canGenerate && (
          <BusyButton
            size="sm"
            variant="secondary"
            busy={generating}
            busyLabel={t("keyfile.generating")}
            disabled={disabled || browsing}
            onClick={() => void generate()}
          >
            {t("keyfile.generate")}
          </BusyButton>
        )}
        {path !== null && (
          <Button size="sm" variant="ghost" disabled={disabled} onClick={() => onChange(null)}>
            {t("keyfile.clear")}
          </Button>
        )}
      </div>
      {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}
      {generateFailure !== null && (
        <FailureNotice failure={generateFailure} title={t("keyfile.generateFailed")} tone="warning" />
      )}
      {justGenerated && (
        <p className={s.generated} role="status">
          {t("keyfile.generated")}
        </p>
      )}
      {besideTheVault && <p className={s.dialogError}>{t("keyfile.besideTheVault")}</p>}
    </Field>
  );
}

/**
 * The name offered for a new key file: the vault's own name with `.keyfile`,
 * so the two are recognisably a pair wherever the key file ends up.
 */
function suggestedName(vaultPath: string): string {
  const cut = Math.max(vaultPath.lastIndexOf("/"), vaultPath.lastIndexOf("\\"));
  const stem = vaultPath.slice(cut + 1).replace(/\.rvault$/i, "");
  return `${stem === "" ? "remoter" : stem}.keyfile`;
}

/** Whether a chosen key file is usable, for the dialogs that gate on it. */
export function keyfileBlocked(path: string | null, vaultPath: string): boolean {
  return keyfileRefusal(path ?? "", vaultPath) !== null;
}
