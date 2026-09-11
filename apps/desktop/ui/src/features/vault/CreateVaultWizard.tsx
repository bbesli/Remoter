/**
 * The create-vault wizard: location, master password, optional key file.
 *
 * Step 4 — the recovery key — is not rendered here. A recovery key only exists
 * once `vault_create` has run, so the wizard creates the vault at the end of
 * step 3 and hands the result to the recovery screen through the store, which
 * is exactly what `Screen = { name: "recovery", result }` is for. Both surfaces
 * share `WizardShell` and `RecoveryKeyPanel`, so step 4 has one implementation.
 *
 * The master password is held in component state for the life of the wizard
 * because `vault_create` needs it. It is never logged, never put in a store
 * that outlives this screen, and the component unmounts as soon as the vault
 * exists. No other secret crosses this boundary. Nothing typed here is ever
 * interpolated into a message — the only values that reach the catalogue are a
 * cloud provider's name and an entropy figure.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { open, save } from "@tauri-apps/plugin-dialog";

import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { isolate, useStrengthText, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, PasswordStrength } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import { useImportIntent } from "./importIntent";
import { keyfileFilters, keyfileRefusal } from "./keyfile";
import { StepHeading, WizardShell } from "./RecoveryKeyScreen";
import type { WizardStep } from "./RecoveryKeyScreen";
import s from "./CreateVaultWizard.module.css";

type KeyfileChoice = "generate" | "existing" | "skip";

/**
 * An example of a complete key file path, shown in the empty field.
 *
 * A file path, so it is not translated (docs/features/i18n.md, "What is never
 * translated") and does not live in the catalogue: every segment of it would
 * have to stay a legal path in every language, and a translated one would stop
 * being the thing it is demonstrating.
 */
const EXAMPLE_KEYFILE_PATH = "/media/usb-key/acme.keyfile";

// ------------------------------------------------------------- helpers ----

/**
 * Directory names that mean the vault sits in a synced folder. Matched against
 * whole path segments, so a connection called "dropbox" in some unrelated
 * directory does not trigger the warning.
 *
 * The provider names are product names and are never translated; they are
 * interpolated into the warning rather than concatenated onto it.
 */
const CLOUD_FOLDERS: ReadonlyArray<readonly [RegExp, string]> = [
  [/^dropbox$/, "Dropbox"],
  [/^onedrive/, "OneDrive"],
  [/^google ?drive$/, "Google Drive"],
  [/^my drive$/, "Google Drive"],
  [/^googledrivefs$/, "Google Drive"],
  [/^icloud ?drive$/, "iCloud Drive"],
  [/^mobile documents$/, "iCloud Drive"],
  [/^com~apple~clouddocs$/, "iCloud Drive"],
  [/^nextcloud$/, "Nextcloud"],
  [/^owncloud$/, "ownCloud"],
  [/^box (sync|drive)$/, "Box"],
  [/^pcloud ?drive$/, "pCloud"],
  [/^megasync$/, "MEGA"],
  [/^yandex\.?disk$/, "Yandex.Disk"],
  [/^proton ?drive$/, "Proton Drive"],
  [/^seafile$/, "Seafile"],
  [/^syncthing$/, "Syncthing"],
];

function cloudProvider(folder: string): string | null {
  for (const segment of folder.split(/[\\/]+/)) {
    const name = segment.trim().toLowerCase();
    for (const [pattern, provider] of CLOUD_FOLDERS) {
      if (pattern.test(name)) return provider;
    }
  }
  return null;
}

function separatorOf(path: string): string {
  return path.includes("\\") && !path.includes("/") ? "\\" : "/";
}

function dirName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut > 0 ? path.slice(0, cut) : path.slice(0, cut + 1);
}

function baseName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut >= 0 ? path.slice(cut + 1) : path;
}

function joinPath(folder: string, file: string, separator: string): string {
  if (folder.length === 0) return file;
  const trimmed = folder.replace(/[\\/]+$/, "");
  return `${trimmed}${separator}${file}`;
}

/**
 * Fallback only. The core's `suggest_vault_path` owns the real slug rule; this
 * fills the preview during the round trip so the field does not flicker empty.
 */
function slugify(label: string): string {
  const slug = label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug.length > 0 ? slug : "vault";
}

async function pickDirectory(title: string, defaultPath: string): Promise<string | null> {
  const picked =
    defaultPath.length > 0
      ? await open({ directory: true, multiple: false, defaultPath, title })
      : await open({ directory: true, multiple: false, title });
  return typeof picked === "string" ? picked : null;
}

/**
 * Choosing an existing key file.
 *
 * The filters are the point: the first names what most people want, and
 * "All files" is not optional, because the design is explicit that any file can
 * be a key file — a .pem, an image, a random blob — and a hard filter would
 * lock out everyone whose key file is a .pem.
 */
async function pickKeyfile(title: string, defaultPath: string): Promise<string | null> {
  const filters = keyfileFilters();
  const picked =
    defaultPath.length > 0
      ? await open({ directory: false, multiple: false, defaultPath, title, filters })
      : await open({ directory: false, multiple: false, title, filters });
  return typeof picked === "string" ? picked : null;
}

/** zxcvbn-style 0–4 score, rendered as five segments like the design. */
function meterTone(score: number): "weak" | "fair" | "strong" {
  if (score <= 1) return "weak";
  if (score === 2) return "fair";
  return "strong";
}

// -------------------------------------------------------------- wizard ----

export function CreateVaultWizard() {
  const t = useT("vault");
  const tCommon = useT("common");
  // One line of copy from the import namespace, for the case where this wizard
  // is the detour between the first-run import door and the importer itself.
  const tImport = useT("import");
  const go = useApp((state) => state.go);
  const importWanted = useImportIntent((state) => state.wanted);
  const setImportWanted = useImportIntent((state) => state.setWanted);

  const [step, setStep] = useState<WizardStep>(1);
  const [maxVisited, setMaxVisited] = useState<WizardStep>(1);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<IpcFailure | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  /** Which Browse is waiting on the platform's file browser, if any. */
  const [browsing, setBrowsing] = useState<"folder" | "generateAt" | "existing" | null>(null);

  // Step 1
  const [name, setName] = useState("");
  const [suggestedPath, setSuggestedPath] = useState<string | null>(null);
  const [folderOverride, setFolderOverride] = useState<string | null>(null);
  const [acknowledgedSyncFolder, setAcknowledgedSyncFolder] = useState<string | null>(null);

  // Step 2
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [strength, setStrength] = useState<PasswordStrength | null>(null);
  const [strengthFailure, setStrengthFailure] = useState<IpcFailure | null>(null);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [generatingPassphrase, setGeneratingPassphrase] = useState(false);
  const [suggestFailed, setSuggestFailed] = useState(false);
  const [suggesting, setSuggesting] = useState(false);
  const [ratingPassword, setRatingPassword] = useState(false);
  // Bumped to re-run the strength effect after a failure the user retried.
  const [strengthAttempt, setStrengthAttempt] = useState(0);
  // The core's own `label` and `explanation` are English prose and are not
  // rendered; the interface derives both from the entropy estimate so that they
  // follow the reader's language and the locale's numbering system, exactly as
  // the bit count already did. Hooks cannot be called conditionally, so this
  // runs before there is an estimate too — with no password typed there is
  // nothing on screen to put it in.
  const strengthText = useStrengthText(strength?.entropyBits ?? 0);

  // Step 3
  const [choice, setChoice] = useState<KeyfileChoice>("skip");
  const [generateAtOverride, setGenerateAtOverride] = useState<string | null>(null);
  const [existingKeyfile, setExistingKeyfile] = useState("");

  const label = name.trim();

  // The core owns the default location and the filename slug. Debounced because
  // it runs on every keystroke of the name field.
  useEffect(() => {
    if (label.length === 0) {
      setSuggestedPath(null);
      setSuggestFailed(false);
      setSuggesting(false);
      return;
    }
    let cancelled = false;
    setSuggesting(true);
    const timer = window.setTimeout(() => {
      ipc.suggestVaultPath(label).then(
        (path) => {
          if (cancelled) return;
          setSuggestedPath(path);
          setSuggestFailed(false);
          setSuggesting(false);
        },
        () => {
          // Losing the suggestion leaves the folder field empty, which leaves
          // Continue disabled. Silently, that reads as a broken wizard.
          if (cancelled) return;
          setSuggestedPath(null);
          setSuggestFailed(true);
          setSuggesting(false);
        },
      );
    }, 250);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [label]);

  useEffect(() => {
    if (password.length === 0) {
      setStrength(null);
      setStrengthFailure(null);
      setRatingPassword(false);
      return;
    }
    let cancelled = false;
    setRatingPassword(true);
    const timer = window.setTimeout(() => {
      ipc.passwordStrength(password).then(
        (result) => {
          if (cancelled) return;
          setStrength(result);
          setStrengthFailure(null);
          setRatingPassword(false);
        },
        (error: unknown) => {
          // The gate is `strength.acceptable`, so a failure here blocks the
          // whole wizard. It has to say so rather than look like a password
          // that is merely never good enough.
          if (cancelled) return;
          setStrength(null);
          setStrengthFailure(asFailure(error));
          setRatingPassword(false);
        },
      );
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [password, strengthAttempt]);

  const separator = separatorOf(suggestedPath ?? folderOverride ?? "");
  const folder = folderOverride ?? (suggestedPath !== null ? dirName(suggestedPath) : "");
  const fileName =
    suggestedPath !== null ? baseName(suggestedPath) : `${slugify(label)}.rvault`;
  const vaultPath = joinPath(folder, fileName, separator);

  const provider = useMemo(() => cloudProvider(folder), [folder]);
  const showSyncWarning =
    provider !== null && folder.length > 0 && folder !== acknowledgedSyncFolder;

  const keyfileName = `${slugify(label)}.keyfile`;

  // The field used to start empty, on the reasoning that the only location we
  // could guess was the vault's own folder and the file ought not to live
  // there. That is advice, not a rule, and leaving the field blank meant the
  // user had to type a full path by hand — and a path that named a folder got
  // as far as the core before failing with "Is a directory".
  //
  // So: default to a complete, working path, and complete one the user has
  // only half-given. A path ending in a separator, or one whose last segment
  // is empty, is a folder; append the file name rather than refusing it.
  const completePath = (raw: string): string => {
    if (raw.length === 0) return "";
    if (/[\\/]$/.test(raw)) return joinPath(raw, keyfileName, separator);
    if (baseName(raw).length === 0) return joinPath(raw, keyfileName, separator);
    return raw;
  };

  const generateAt =
    generateAtOverride !== null
      ? completePath(generateAtOverride)
      : folder.length > 0
        ? joinPath(folder, keyfileName, separator)
        : "";
  const keyfileInVaultFolder =
    generateAt.length > 0 &&
    dirName(generateAt).replace(/[\\/]+$/, "").toLowerCase() ===
      folder.replace(/[\\/]+$/, "").toLowerCase();

  /**
   * A vault file cannot be a key file, and a generated key file must not be
   * written over one. The browser opens in the vault's own folder, so both
   * mistakes are one click away; refusing them here is cheaper than the
   * lock-out that follows.
   */
  const existingKeyfileRefused = keyfileRefusal(existingKeyfile, vaultPath);
  const generateAtRefused = keyfileRefusal(generateAt, vaultPath);

  const stepValid = useCallback(
    (which: WizardStep): boolean => {
      switch (which) {
        case 1:
          return label.length > 0 && folder.length > 0;
        case 2:
          return (
            password.length > 0 &&
            strength !== null &&
            strength.acceptable &&
            confirmation === password
          );
        case 3:
          if (choice === "skip") return true;
          if (choice === "generate") {
            return (
              generateAt.length > 0 &&
              baseName(generateAt).length > 0 &&
              generateAtRefused === null
            );
          }
          return existingKeyfile.length > 0 && existingKeyfileRefused === null;
        case 4:
          return false;
      }
    },
    [
      label,
      folder,
      password,
      strength,
      confirmation,
      choice,
      generateAt,
      generateAtRefused,
      existingKeyfile,
      existingKeyfileRefused,
    ],
  );

  /**
   * What the disabled Continue button is waiting for on this step, in the
   * order the user would fix them.
   */
  const blockedBecause = useCallback(
    (which: WizardStep): string | null => {
      switch (which) {
        case 1:
          if (label.length === 0) return t("create.blocked.name");
          if (folder.length === 0) return t("create.blocked.folder");
          return null;
        case 2:
          if (password.length === 0) return t("create.blocked.password");
          if (strength === null) {
            return strengthFailure === null
              ? t("create.blocked.strengthUnknown")
              : t("create.password.strengthFailed");
          }
          if (!strength.acceptable) return t("create.blocked.strength");
          if (confirmation !== password) return t("create.blocked.confirmation");
          return null;
        case 3:
          if (choice === "generate" && !(generateAt.length > 0 && baseName(generateAt).length > 0)) {
            return t("create.blocked.keyfileTarget");
          }
          if (choice === "generate" && generateAtRefused !== null) {
            return t("keyfile.blockedIsVault");
          }
          if (choice === "existing" && existingKeyfile.length === 0) {
            return t("create.blocked.keyfileChoice");
          }
          if (choice === "existing" && existingKeyfileRefused !== null) {
            return t("keyfile.blockedIsVault");
          }
          return null;
        case 4:
          return null;
      }
    },
    [
      t,
      label,
      folder,
      password,
      strength,
      strengthFailure,
      confirmation,
      choice,
      generateAt,
      generateAtRefused,
      existingKeyfile,
      existingKeyfileRefused,
    ],
  );

  const canGoTo = useCallback(
    (which: WizardStep): boolean => {
      if (which > maxVisited) return false;
      for (let below: WizardStep = 1; below < which; below = (below + 1) as WizardStep) {
        if (!stepValid(below)) return false;
      }
      return true;
    },
    [maxVisited, stepValid],
  );

  const goToStep = useCallback(
    (which: WizardStep) => {
      // The warning is shown once per folder: acknowledging it is leaving the
      // step with that folder still chosen.
      if (step === 1 && which > 1 && provider !== null) setAcknowledgedSyncFolder(folder);
      setStep(which);
      setMaxVisited((seen) => (which > seen ? which : seen));
    },
    [step, provider, folder],
  );

  // A dialog that refuses to open is not a dead end: every path here is also a
  // text field, so the failure says to type it instead.
  const onBrowseFolder = useCallback(() => {
    setBrowsing("folder");
    void pickDirectory(t("create.location.pickFolder"), folder)
      .then(
        (picked) => {
          setDialogError(null);
          if (picked !== null) setFolderOverride(picked);
        },
        () => setDialogError(t("create.browseFailed")),
      )
      .finally(() => setBrowsing(null));
  }, [folder, t]);

  const onBrowseGenerateAt = useCallback(() => {
    setBrowsing("generateAt");
    void save({
      defaultPath: generateAt.length > 0 ? generateAt : keyfileName,
      title: t("create.keyfile.pickSave"),
      // Same two filters as choosing one: the generated file is a key file,
      // and naming it as one is what stops it landing beside a `.rvault`
      // looking like part of the vault.
      filters: keyfileFilters(),
    })
      .then(
        (picked) => {
          setDialogError(null);
          if (picked !== null) setGenerateAtOverride(picked);
        },
        () => setDialogError(t("create.browseFailed")),
      )
      .finally(() => setBrowsing(null));
  }, [generateAt, keyfileName, t]);

  const onBrowseExisting = useCallback(() => {
    setBrowsing("existing");
    // Open where the vault will live, because that is where someone who
    // generated a key file a moment ago is most likely to have put it.
    void pickKeyfile(
      t("create.keyfile.pickExisting"),
      existingKeyfile.length > 0 ? existingKeyfile : folder,
    )
      .then(
        (picked) => {
          setDialogError(null);
          if (picked !== null) setExistingKeyfile(picked);
        },
        () => setDialogError(t("create.browseFailed")),
      )
      .finally(() => setBrowsing(null));
  }, [existingKeyfile, folder, t]);

  const onGeneratePassphrase = useCallback(() => {
    setGeneratingPassphrase(true);
    void ipc
      .generatePassphrase(5)
      .then(
        (phrase) => {
          setGenerateError(null);
          // Both fields: the confirmation guards against typing a password blind,
          // and this one is on screen. The transcription check that matters is
          // step 4.
          setPassword(phrase);
          setConfirmation(phrase);
          setRevealed(true);
        },
        () => setGenerateError(t("create.password.generateFailed")),
      )
      .finally(() => setGeneratingPassphrase(false));
  }, [t]);

  const onCreate = useCallback(() => {
    setBusy(true);
    setFailure(null);
    ipc
      .createVault({
        path: vaultPath,
        label,
        password,
        keyfilePath: choice === "existing" ? existingKeyfile : null,
        generateKeyfileAt: choice === "generate" ? generateAt : null,
      })
      .then(
        (result) => go({ name: "recovery", result }),
        (error: unknown) => {
          setFailure(asFailure(error));
          setBusy(false);
        },
      );
  }, [vaultPath, label, password, choice, existingKeyfile, generateAt, go]);

  const onNext = useCallback(() => {
    if (step === 3) {
      onCreate();
      return;
    }
    goToStep((step + 1) as WizardStep);
  }, [step, onCreate, goToStep]);

  const onBack = useCallback(() => {
    if (step === 1) {
      // Backing out of creation abandons whatever the launch screen was asked
      // for. Leaving the intent set would open the importer after some later,
      // unrelated vault creation.
      setImportWanted(false);
      go({ name: "picker" });
      return;
    }
    setStep((current) => (current - 1) as WizardStep);
  }, [step, go, setImportWanted]);

  // Nothing is written to disk until the end of step 3, which is why the first
  // two steps say the same thing.
  const footNote =
    step === 3 ? t("create.footNote.keyfileLater") : t("create.footNote.nothingCreated");

  return (
    <WizardShell
      step={step}
      onStep={busy ? null : goToStep}
      canGoTo={canGoTo}
      footNote={footNote}
      busyLabel={busy ? t("create.creating") : null}
      busyNote={busy ? t("kdf.slow") : null}
      back={busy ? null : { label: t("wizard.back"), onClick: onBack }}
      next={{
        label: step === 3 ? t("wizard.createAction") : t("wizard.continue"),
        onClick: onNext,
        disabled: !stepValid(step),
        busy,
        busyLabel: t("create.creating"),
        reason: busy ? t("create.blockedBusy") : blockedBecause(step),
      }}
    >
      {failure !== null && (
        <div className={s.failure}>
          <FailureNotice failure={failure} />
        </div>
      )}

      {dialogError !== null && <div className={s.inlineError}>{dialogError}</div>}

      {step === 1 && (
        <div className={s.step}>
          <StepHeading
            title={t("create.location.title")}
            badge={null}
            lead={t("create.location.lead")}
          />

          {/* Someone who pressed "bring across what I have" and landed on a
              create-a-vault form has every reason to think the button did
              nothing. Say where they are and what happens at the end of it. */}
          {importWanted && (
            <Callout tone="info" title={tImport("firstRun.calloutTitle")}>
              <p>{tImport("firstRun.calloutBody")}</p>
            </Callout>
          )}

          <div className={s.fields}>
            <Field
              label={t("create.location.name")}
              help={t("create.location.nameHint")}
              error=""
              htmlFor="vault-name"
            >
              <TextInput
                id="vault-name"
                value={name}
                onChange={setName}
                type="text"
                placeholder={t("create.location.namePlaceholder")}
                autoFocus
              />
            </Field>

            <Field label={t("create.location.folder")} help="" error="" htmlFor="vault-folder">
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="vault-folder"
                    value={folder}
                    onChange={setFolderOverride}
                    type="text"
                    mono
                  />
                </div>
                <BusyButton
                  variant="secondary"
                  size="md"
                  type="button"
                  busy={browsing === "folder"}
                  busyLabel={tCommon("action.opening")}
                  onClick={onBrowseFolder}
                >
                  {tCommon("action.browse")}
                </BusyButton>
              </div>
              {/* The core owns the default location and takes a round trip to
                  work it out. An empty field with no explanation reads as a
                  wizard that lost the name that was just typed. */}
              {suggesting && folder.length === 0 && (
                <div className={s.locationNote}>
                  <BusyStatus label={t("create.location.suggesting")} size={13} compact />
                </div>
              )}
              {label.length > 0 && <div className={s.derivedName}>{fileName}</div>}
              {/* The core owns the default location. When it cannot supply one
                  the field is empty and Continue is dead, so say why. */}
              {suggestFailed && folder.length === 0 && (
                <div className={s.inlineError}>{t("create.location.suggestFailed")}</div>
              )}
            </Field>
          </div>

          {/* The provider is a product name in Latin script. It is isolated so
              that in an Arabic interface the sentence around it keeps its own
              direction — see src/i18n/bidi.ts. */}
          {showSyncWarning && provider !== null && (
            <Callout
              tone="warning"
              title={t("create.location.syncTitle", { provider: isolate(provider) })}
            >
              <p className={s.calloutBody}>
                {t("create.location.syncBody", { provider: isolate(provider) })}
              </p>
              <p className={s.calloutFoot}>{t("create.location.syncOnce")}</p>
            </Callout>
          )}
        </div>
      )}

      {step === 2 && (
        <div className={s.step}>
          <StepHeading
            title={t("create.password.title")}
            badge={null}
            lead={t("create.password.lead")}
          />

          <div className={s.fields}>
            {/*
              No composition rules, by design: they reliably produce worse
              passwords. The gate is the core's own `acceptable` verdict.
            */}
            <Field label={t("create.password.field")} help="" error="" htmlFor="vault-password">
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="vault-password"
                    value={password}
                    onChange={setPassword}
                    type={revealed ? "text" : "password"}
                    mono
                  />
                </div>
                <Button
                  variant="ghost"
                  size="md"
                  type="button"
                  onClick={() => setRevealed(!revealed)}
                >
                  {revealed ? t("create.password.hide") : t("create.password.reveal")}
                </Button>
              </div>
            </Field>

            {/* Without a verdict there is no gate to pass, so the wizard is
                stuck here until the core answers. Shown beneath the field it
                rates, with a way to ask again. */}
            {strengthFailure !== null && (
              <FailureNotice
                failure={strengthFailure}
                title={t("create.password.strengthFailed")}
                onRetry={() => setStrengthAttempt((n) => n + 1)}
                retryLabel={t("create.password.strengthRetry")}
              />
            )}

            {/* The verdict comes from the core and it is the gate on this
                step, so its absence has to look like "not yet" rather than
                like a meter that will never appear. */}
            {strength === null && strengthFailure === null && ratingPassword && (
              <div className={s.strength}>
                <BusyStatus label={t("create.password.rating")} size={13} compact />
                <SkeletonRows count={1} height="var(--space-2)" widths={["100%"]} />
              </div>
            )}

            {strength !== null && (
              <div className={s.strength}>
                <div className={s.meterRow}>
                  <div className={s.meter}>
                    {[0, 1, 2, 3, 4].map((index) => (
                      <span
                        key={index}
                        className={s.segment}
                        data-on={index <= strength.score}
                        data-tone={meterTone(strength.score)}
                      />
                    ))}
                  </div>
                  <span
                    className={s.strengthLabel}
                    data-tone={strength.acceptable ? meterTone(strength.score) : "weak"}
                  >
                    {strength.acceptable ? strengthText.label : t("create.password.notYet")}
                  </span>
                  {/* The count goes through the message so the digits follow
                      the locale's numbering system and "bit" can inflect. */}
                  <span className={s.entropy}>
                    {t("create.password.bits", { count: Math.round(strength.entropyBits) })}
                  </span>
                </div>
                {/* "≈ 72 bits" changes nobody's behaviour; the sentence does. */}
                <div className={s.explanation}>{strengthText.explanation}</div>
                {!strength.acceptable && (
                  <div className={s.explanation}>{t("create.password.tooWeakHelp")}</div>
                )}
              </div>
            )}

            <Field
              label={t("create.password.confirmField")}
              help=""
              error=""
              htmlFor="vault-password-confirm"
            >
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="vault-password-confirm"
                    value={confirmation}
                    onChange={setConfirmation}
                    type={revealed ? "text" : "password"}
                    mono
                    invalid={confirmation.length > 0 && confirmation !== password}
                  />
                </div>
                {confirmation.length > 0 && confirmation === password && (
                  <span className={s.matchOk}>
                    <Icon name="check" size={16} />
                    {t("create.password.matches")}
                  </span>
                )}
                {confirmation.length > 0 && confirmation !== password && (
                  <span className={s.matchPending}>{t("create.password.mismatch")}</span>
                )}
              </div>
            </Field>

            <div className={s.generateRow}>
              <BusyButton
                variant="secondary"
                size="sm"
                type="button"
                busy={generatingPassphrase}
                busyLabel={t("create.password.generating")}
                onClick={onGeneratePassphrase}
              >
                {t("create.password.generate")}
              </BusyButton>
              <span className={s.generateHint}>{t("create.password.generateHint")}</span>
            </div>
            {generateError !== null && <div className={s.inlineError}>{generateError}</div>}
          </div>

          <Callout tone="neutral" title="">
            {t("create.password.note")}
          </Callout>
        </div>
      )}

      {step === 3 && (
        <div className={s.step}>
          <StepHeading
            title={t("create.keyfile.title")}
            badge={t("create.keyfile.optional")}
            lead={t("create.keyfile.lead")}
          />

          <div className={s.options} role="radiogroup" aria-label={t("create.keyfile.title")}>
            <label className={s.option} data-selected={choice === "generate"}>
              <input
                type="radio"
                name="keyfile-choice"
                className={s.radioInput}
                checked={choice === "generate"}
                onChange={() => setChoice("generate")}
              />
              <Icon name="file" size={18} />
              <span className={s.optionText}>
                <span className={s.optionTitle}>{t("create.keyfile.generateTitle")}</span>
                <span className={s.optionHint}>{t("create.keyfile.generateHint")}</span>
              </span>
              <span className={s.radioDot} aria-hidden="true" />
            </label>

            <label className={s.option} data-selected={choice === "existing"}>
              <input
                type="radio"
                name="keyfile-choice"
                className={s.radioInput}
                checked={choice === "existing"}
                onChange={() => setChoice("existing")}
              />
              <Icon name="folder" size={18} />
              <span className={s.optionText}>
                <span className={s.optionTitle}>{t("create.keyfile.existingTitle")}</span>
                <span className={s.optionHint}>{t("create.keyfile.existingHint")}</span>
              </span>
              <span className={s.radioDot} aria-hidden="true" />
            </label>

            <label className={s.option} data-selected={choice === "skip"}>
              <input
                type="radio"
                name="keyfile-choice"
                className={s.radioInput}
                checked={choice === "skip"}
                onChange={() => setChoice("skip")}
              />
              <Icon name="x" size={18} />
              <span className={s.optionText}>
                <span className={s.optionTitle}>{t("create.keyfile.skipTitle")}</span>
                <span className={s.optionHint}>{t("create.keyfile.skipHint")}</span>
              </span>
              <span className={s.radioDot} aria-hidden="true" />
            </label>
          </div>

          {choice === "generate" && (
            <Field
              label={t("create.keyfile.saveTo")}
              help={generateAt.length === 0 ? t("create.keyfile.saveToHint") : ""}
              error=""
              htmlFor="keyfile-generate-at"
            >
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="keyfile-generate-at"
                    value={generateAt}
                    onChange={setGenerateAtOverride}
                    type="text"
                    mono
                    placeholder={EXAMPLE_KEYFILE_PATH}
                  />
                </div>
                <BusyButton
                  variant="secondary"
                  size="md"
                  type="button"
                  busy={browsing === "generateAt"}
                  busyLabel={tCommon("action.opening")}
                  onClick={onBrowseGenerateAt}
                >
                  {tCommon("action.browse")}
                </BusyButton>
              </div>
              {/* Writing the key file over the vault, or over one of its
                  backups, destroys the thing it is meant to protect. */}
              {generateAtRefused !== null && (
                <div className={s.inlineError} role="alert">
                  {generateAtRefused}
                </div>
              )}
              {generateAt.length > 0 && generateAtRefused === null && keyfileInVaultFolder && (
                <div className={s.locationNote}>{t("create.keyfile.sameFolder")}</div>
              )}
            </Field>
          )}

          {choice === "existing" && (
            <Field label={t("keyfile.label")} help="" error="" htmlFor="keyfile-existing">
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="keyfile-existing"
                    value={existingKeyfile}
                    onChange={setExistingKeyfile}
                    type="text"
                    mono
                  />
                </div>
                <BusyButton
                  variant="secondary"
                  size="md"
                  type="button"
                  busy={browsing === "existing"}
                  busyLabel={tCommon("action.opening")}
                  onClick={onBrowseExisting}
                >
                  {tCommon("action.browse")}
                </BusyButton>
              </div>
              {/* A vault cannot be its own key file. Stated as the certainty
                  it is, before it becomes a lock-out nobody can diagnose. */}
              {existingKeyfileRefused !== null && (
                <div className={s.inlineError} role="alert">
                  {existingKeyfileRefused}
                </div>
              )}
            </Field>
          )}

          {choice !== "skip" && (
            <Callout tone="warning" title="">
              {t("create.keyfile.required")}
            </Callout>
          )}
        </div>
      )}
    </WizardShell>
  );
}
