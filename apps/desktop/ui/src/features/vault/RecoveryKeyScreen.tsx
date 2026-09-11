/**
 * The recovery key surface.
 *
 * This is step 4 of vault creation and, because the vault must already exist
 * before a recovery key can be shown, it is also the screen the store routes to
 * on `{ name: "recovery", result }` once `vault_create` returns. Both entry
 * points render the same panel; there is one implementation.
 *
 * The wizard chrome (`WizardShell`) lives here rather than in
 * `CreateVaultWizard` because this screen is the one that has to stand alone —
 * putting the frame in the wizard would mean the two files importing each
 * other.
 *
 * The transcription check is the whole mechanism of this screen. A checkbox is
 * too easy to click past (docs/security/vault-format.md, `recovery` slot), so
 * the user retypes the group the core nominates. Do not add a "later" escape.
 *
 * Every warning on this screen is flagged SECURITY-CRITICAL in
 * `locales/en/vault.json`. A translation that softens "not by you, not by us,
 * not by anyone" causes the loss it is warning about, so those strings get a
 * second reader before a translation is accepted.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import type { TFunction } from "i18next";
import { save } from "@tauri-apps/plugin-dialog";

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import { TextInput } from "@/components/TextInput";
import { formatDate, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { CreateVaultResult, IpcFailure } from "@/lib/ipc";

import { kdfSummary } from "./kdf";
import { useApp } from "@/stores/app";

import { useImportIntent } from "./importIntent";
import s from "./RecoveryKeyScreen.module.css";

export type WizardStep = 1 | 2 | 3 | 4;

/** Four steps, named once: the stepper, the counter and the bar all read it. */
const STEP_COUNT = 4;

// ------------------------------------------------------------ the frame ----

export interface WizardShellProps {
  step: WizardStep;
  /** Null once the vault exists: there is nothing to navigate back to. */
  onStep: ((step: WizardStep) => void) | null;
  canGoTo: (step: WizardStep) => boolean;
  footNote: string;
  /** Non-null while a long operation runs; the footer shows it beside a spinner. */
  busyLabel: string | null;
  /**
   * Why that operation is slow, when it is slow by design. Creation runs the
   * same Argon2id cost an unlock does, and a second of stillness with no
   * explanation is what makes people press the button again.
   */
  busyNote?: string | null | undefined;
  back: { label: string; onClick: () => void } | null;
  /**
   * `reason` is what the disabled button is waiting for. A primary action that
   * refuses a click and says nothing is the same defect as a silent failure,
   * seen from the user's side, so this is not optional in practice.
   */
  next: {
    label: string;
    onClick: () => void;
    disabled: boolean;
    reason?: string | null | undefined;
    /** The button carries the spinner while its command is in flight. */
    busy?: boolean | undefined;
    busyLabel?: string | undefined;
  };
  children: ReactNode;
}

/**
 * The stepper's four labels.
 *
 * Switched rather than indexed into an array so the catalogue key is a literal
 * the type checker can see: `t(\`wizard.step${n}\`)` would compile against any
 * string and fail at run time if a key were renamed.
 */
function stepLabel(t: TFunction<"vault">, step: WizardStep): string {
  switch (step) {
    case 1:
      return t("wizard.step1");
    case 2:
      return t("wizard.step2");
    case 3:
      return t("wizard.step3");
    case 4:
      return t("wizard.step4");
  }
}

export function WizardShell(props: WizardShellProps) {
  const { step, onStep, canGoTo, footNote, busyLabel, back, next, children } = props;
  const t = useT("vault");
  const busyNote = props.busyNote ?? null;
  const nextBusy = next.busy === true;
  const steps: WizardStep[] = [1, 2, 3, 4];
  const nextReason = next.disabled && !nextBusy ? next.reason ?? null : null;

  return (
    <div className={s.canvas}>
      <div className={s.card}>
        <div className={s.titlebar} data-tauri-drag-region>
          <Mark size={18} />
          <span className={s.title}>{t("wizard.windowTitle")}</span>
          <div className={s.spacer} />
          <span className={s.stepLabel}>
            {t("wizard.stepOf", { step, total: STEP_COUNT })}
          </span>
        </div>

        <div className={s.progress}>
          <div className={s.progressFill} style={{ width: `${(step / STEP_COUNT) * 100}%` }} />
        </div>

        <nav className={s.stepper} aria-label={t("wizard.windowTitle")}>
          {steps.map((n) => {
            const reachable = onStep !== null && canGoTo(n);
            return (
              <button
                key={n}
                type="button"
                className={s.stepButton}
                data-active={n === step}
                aria-current={n === step ? "step" : undefined}
                disabled={!reachable || n === step}
                // A step that cannot be jumped to says which of the two
                // reasons applies rather than simply not responding.
                title={
                  n === step
                    ? stepLabel(t, n)
                    : reachable
                      ? stepLabel(t, n)
                      : n > step
                        ? t("wizard.stepAhead")
                        : t("wizard.stepBlocked")
                }
                onClick={() => onStep?.(n)}
              >
                {stepLabel(t, n)}
              </button>
            );
          })}
        </nav>

        <div className={s.body}>{children}</div>

        {/* Directly above the button that started it. Out of the footer,
            because the footer is a fixed 58px row and the second line — why
            the wait is long — needs the height. */}
        {busyLabel !== null && (
          <div className={s.busyStrip}>
            <BusyStatus
              label={busyLabel}
              size={16}
              {...(busyNote === null ? {} : { note: busyNote })}
            />
          </div>
        )}

        <div className={s.footer}>
          <span className={s.footNote}>{footNote}</span>
          <div className={s.spacer} />
          {nextReason !== null && <span className={s.nextReason}>{nextReason}</span>}
          {back !== null && (
            <Button variant="secondary" size="md" type="button" onClick={back.onClick}>
              {back.label}
            </Button>
          )}
          <BusyButton
            variant="primary"
            size="md"
            type="button"
            busy={nextBusy}
            busyLabel={next.busyLabel ?? next.label}
            onClick={next.onClick}
            disabled={next.disabled}
            {...(nextReason === null ? {} : { title: nextReason })}
          >
            {next.label}
          </BusyButton>
        </div>
      </div>
    </div>
  );
}

// --------------------------------------------------------- step heading ----

export function StepHeading(props: { title: string; badge: string | null; lead: string }) {
  return (
    <div className={s.headingBlock}>
      <div className={s.headingRow}>
        <h2 className={s.heading}>{props.title}</h2>
        {props.badge !== null && <Badge tone="neutral">{props.badge}</Badge>}
      </div>
      <p className={s.lead}>{props.lead}</p>
    </div>
  );
}

// ------------------------------------------------------------- the panel ----

/** Crockford Base32 is case-insensitive and hyphens are presentation only. */
function normaliseGroup(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toUpperCase();
}

/**
 * The file name to offer in the save dialog, from the vault's own.
 *
 * Both separators, because the path came from the platform and the platform is
 * Windows about as often as it is not. The `.rvault` suffix is dropped and
 * `.txt` put in its place: the core refuses to write the sheet to a `.rvault`
 * name, and a suggested name that is then refused is a trap rather than a
 * suggestion.
 */
function sheetFileName(vaultPath: string): string {
  const cut = Math.max(vaultPath.lastIndexOf("/"), vaultPath.lastIndexOf("\\"));
  const base = cut >= 0 ? vaultPath.slice(cut + 1) : vaultPath;
  const stem = base.replace(/\.rvault$/i, "");
  return `recovery-key-${stem === "" ? "vault" : stem}.txt`;
}

/**
 * The plain-text sheet behind Save.
 *
 * Nothing here is wrapped in a bidi isolate, unlike the rendered sheet: this
 * is a text file somebody will open in an editor, print, and possibly retype
 * from. Invisible control characters in a file whose whole purpose is to be
 * copied accurately would be a poor trade for a direction hint.
 */
function sheetText(
  t: TFunction<"vault">,
  locale: string,
  result: CreateVaultResult,
  key: string,
): string {
  // A vault with no password slot has no cost to name, and half a sentence on
  // a sheet somebody will retype from is worse than one line fewer.
  const protection = kdfSummary(locale, result.kdf);
  return [
    t("recovery.sheet.title"),
    "",
    t("recovery.sheet.vault", { path: result.path }),
    t("recovery.sheet.created", { date: formatDate(locale, Date.now()) }),
    ...(protection === null ? [] : [t("recovery.sheet.protection", { summary: protection })]),
    "",
    key,
    "",
    t("recovery.sheet.warning", {
      title: t("recovery.warningTitle"),
      body: t("recovery.warningBody"),
    }),
    "",
  ].join("\n");
}

/**
 * Whether this WebView can print at all.
 *
 * Not every engine Remoter runs on has a print backend: in WKWebView
 * `window.print` is simply not there, and calling a missing function would
 * throw where an honest interface should never have offered the button. The
 * engines that do have one — WebView2 on Windows, WebKitGTK on Linux — all
 * expose it as a function, so its presence is the only signal available before
 * the click.
 *
 * Read at render time rather than at module scope: a module-scope read runs
 * once per process and would be wrong for the first screen in a test
 * environment that installs it later.
 */
function printingIsAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.print === "function";
}

/**
 * Puts text on the clipboard, by whichever route this WebView has.
 *
 * The async Clipboard API needs a secure context and a focused document, and
 * rejects rather than throwing when it does not have them. `execCommand("copy")`
 * is deprecated and is still the only thing that works in several embedded
 * WebViews, so it is the fallback rather than the first choice. Resolves to
 * whether the key is actually on the clipboard — never to "probably".
 */
async function copyText(text: string): Promise<boolean> {
  if (navigator.clipboard !== undefined) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through: a rejection here is the ordinary "no permission in this
      // context" case, not a reason to tell the user copying is impossible.
    }
  }
  return copyBySelection(text);
}

/**
 * The pre-Clipboard-API route: select text in an off-screen field and let the
 * engine copy the selection.
 *
 * The field is positioned off-screen rather than hidden, because a
 * `display: none` element cannot hold a selection and a selection is the whole
 * mechanism. It is removed on every path — the recovery key must not be left
 * sitting in a stray node.
 */
function copyBySelection(text: string): boolean {
  const field = document.createElement("textarea");
  field.value = text;
  field.setAttribute("aria-hidden", "true");
  field.setAttribute("tabindex", "-1");
  field.style.position = "fixed";
  field.style.top = "-9999px";
  field.style.opacity = "0";
  document.body.appendChild(field);
  try {
    field.focus();
    field.select();
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    field.value = "";
    field.remove();
  }
}

export interface RecoveryKeyPanelProps {
  result: CreateVaultResult;
  /** Reported upward so the shell's footer button owns the gate. */
  onConfirmedChange: (confirmed: boolean) => void;
}

export function RecoveryKeyPanel({ result, onConfirmedChange }: RecoveryKeyPanelProps) {
  const t = useT("vault");
  const { code: locale } = useLocale();
  // Composed here, not sent by the core; `null` when there is no password slot
  // to describe, in which case the sheet simply does not carry the line.
  const printedProtection = kdfSummary(locale, result.kdf);
  const [entry, setEntry] = useState("");
  const [copied, setCopied] = useState(false);
  // The clipboard write is a promise, and on a Wayland session without a
  // portal it can sit unresolved for a moment.
  const [copying, setCopying] = useState(false);
  // The save dialog, then the write, are both round trips.
  const [saving, setSaving] = useState(false);
  const [savedPath, setSavedPath] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  // A refused write comes back as a typed failure from the core, which says
  // more than any sentence this screen could compose — so it is rendered whole
  // rather than flattened into `actionError`.
  const [saveFailure, setSaveFailure] = useState<IpcFailure | null>(null);
  // Whether this engine has a printer. Fixed for the life of the screen: it
  // describes the WebView, not anything the user can change from here.
  const [printable] = useState(printingIsAvailable);

  const groups = result.recoveryKeyGroups;
  const target = normaliseGroup(groups[result.confirmGroupIndex] ?? "");
  const groupNumber = result.confirmGroupIndex + 1;
  const fullKey = useMemo(() => groups.join("-"), [groups]);

  const typed = normaliseGroup(entry);
  const confirmed = target.length > 0 && typed === target;
  const remaining = target.length - typed.length;

  useEffect(() => {
    onConfirmedChange(confirmed);
  }, [confirmed, onConfirmedChange]);

  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 2000);
    return () => window.clearTimeout(timer);
  }, [copied]);

  // The print stylesheet keys off this attribute, so it has to be cleared even
  // if the user cancels the print dialog.
  useEffect(() => {
    const clear = () => {
      delete document.body.dataset["printing"];
    };
    window.addEventListener("afterprint", clear);
    return () => {
      window.removeEventListener("afterprint", clear);
      clear();
    };
  }, []);

  const onCopy = useCallback(() => {
    setCopying(true);
    void copyText(fullKey)
      .then(
        (onClipboard) => {
          if (onClipboard) {
            setActionError(null);
            setCopied(true);
          } else {
            // Reported, never assumed. A "Copied" badge over an empty
            // clipboard is the same defect as a download that never happened.
            setCopied(false);
            setActionError(t("recovery.copyFailed"));
          }
        },
        () => setActionError(t("recovery.copyFailed")),
      )
      .finally(() => setCopying(false));
  }, [fullKey, t]);

  /**
   * Saves the sheet through the system's save dialog and the core.
   *
   * It used to be a browser download: a `Blob`, an `<a download>`, a
   * programmatic click. That is the idiom of a page inside a browser, and this
   * is a page inside a WebView, where three things are true at once — the
   * engine may decline to download at all, nothing in the DOM reports back
   * whether it did, and `anchor.click()` returns successfully either way. On
   * Windows it declined, so the one control that saves the one copy of a
   * recovery key did nothing and said nothing. The `try`/`catch` around it
   * could never have caught that; there was no error to catch.
   *
   * The replacement is the dialog the rest of the application already uses and
   * a command that returns a `Result`. Both halves can fail, both halves say
   * so, and the file is written atomically with owner-only permissions by
   * `recovery_sheet_write`.
   */
  const onSave = useCallback(() => {
    setSaving(true);
    setActionError(null);
    setSaveFailure(null);
    void (async () => {
      let destination: string | null;
      try {
        destination = await save({
          defaultPath: sheetFileName(result.path),
          title: t("recovery.saveTitle"),
          filters: [
            { name: t("recovery.filterText"), extensions: ["txt"] },
            { name: t("keyfile.filterAll"), extensions: ["*"] },
          ],
        });
      } catch {
        // The dialog plugin rejects when the platform has no file browser to
        // start, or when the capability was never granted.
        setActionError(t("recovery.saveDialogFailed"));
        return;
      }
      // Null is the user closing the dialog. Not a failure, and not a moment
      // to shout at them.
      if (destination === null) return;

      try {
        const written = await ipc.writeRecoverySheet({
          path: destination,
          text: sheetText(t, locale, result, fullKey),
        });
        setSavedPath(written.path);
      } catch (error: unknown) {
        setSavedPath(null);
        setSaveFailure(asFailure(error));
      }
    })().finally(() => setSaving(false));
  }, [fullKey, locale, result, t]);

  /**
   * Prints, and finds out whether anything was printed.
   *
   * `window.print()` returns `undefined` whether it opened a print dialog or
   * did nothing at all, so its return value says nothing. What does say
   * something is `beforeprint`: every engine that actually prepares a page
   * fires it, synchronously, before the call returns. If it never arrived,
   * nothing was printed and the user is told — rather than being left looking
   * at a page that quietly put itself into its printing state.
   */
  const onPrint = useCallback(() => {
    let prepared = false;
    const notePrepared = () => {
      prepared = true;
    };
    window.addEventListener("beforeprint", notePrepared);
    document.body.dataset["printing"] = "recovery";
    try {
      window.print();
    } catch {
      prepared = false;
    } finally {
      window.removeEventListener("beforeprint", notePrepared);
    }

    if (prepared) {
      setActionError(null);
      return;
    }
    delete document.body.dataset["printing"];
    setActionError(t("recovery.printFailed"));
  }, [t]);

  if (target.length === 0) {
    return (
      <Callout tone="danger" title={t("recovery.warningTitle")}>
        {t("recovery.brokenResult")}
      </Callout>
    );
  }

  return (
    <div className={s.step}>
      <StepHeading title={t("recovery.heading")} badge={null} lead={t("recovery.lead")} />

      <div className={s.sheet}>
        <div className={s.grid}>
          {groups.map((group, index) => (
            <span
              key={`${index}-${group}`}
              className={s.group}
              data-target={index === result.confirmGroupIndex}
              aria-label={
                index === result.confirmGroupIndex
                  ? t("recovery.targetGroupAria", { group: groupNumber })
                  : undefined
              }
            >
              {group}
            </span>
          ))}
        </div>

        <div className={s.actions}>
          <BusyButton
            variant="secondary"
            size="sm"
            type="button"
            busy={copying}
            busyLabel={t("recovery.copying")}
            onClick={onCopy}
          >
            <Icon name="copy" size={13} />
            {t("recovery.copy")}
          </BusyButton>
          <BusyButton
            variant="secondary"
            size="sm"
            type="button"
            busy={saving}
            busyLabel={t("recovery.saving")}
            onClick={onSave}
          >
            <Icon name="download" size={13} />
            {t("recovery.download")}
          </BusyButton>
          {/* Offered only where it can work. An engine with no print backend
              gets the sentence instead of the button: a control that does
              nothing teaches the user that the screen is lying to them, and
              this is the screen that can least afford that. */}
          {printable ? (
            <Button variant="secondary" size="sm" type="button" onClick={onPrint}>
              <Icon name="printer" size={13} />
              {t("recovery.print")}
            </Button>
          ) : (
            <span className={s.actionNote}>{t("recovery.printUnavailable")}</span>
          )}
          <span className={s.actionStatus} role="status">
            {copied ? t("recovery.copied") : ""}
          </span>
        </div>
      </div>

      {actionError !== null && (
        <div className={s.actionError} role="alert">
          {actionError}
        </div>
      )}

      {/* The file is outside the vault from the moment it exists, and saying
          where it landed is what lets someone check it before they leave a
          screen they cannot come back to. */}
      {savedPath !== null && (
        <Callout tone="warning" title={t("recovery.saved", { path: isolateLtr(savedPath) })}>
          {t("recovery.savedPlaintext")}
        </Callout>
      )}

      {saveFailure !== null && (
        <FailureNotice
          failure={saveFailure}
          title={t("recovery.saveFailed")}
          onRetry={onSave}
          retryLabel={t("recovery.download")}
        />
      )}

      <div className={s.confirmBlock}>
        {/* One string, not a sentence assembled around a number: split
            sentences do not survive translation. The group itself is marked in
            the grid above. */}
        <div className={s.confirmPrompt}>{t("recovery.confirmPrompt", { group: groupNumber })}</div>
        <div className={s.confirmRow}>
          <div className={s.confirmField}>
            <TextInput
              id="recovery-confirm"
              value={entry}
              onChange={(v) => setEntry(v.slice(0, target.length + 4))}
              type="text"
              mono
              autoFocus
              ariaLabel={t("recovery.confirmPrompt", { group: groupNumber })}
              invalid={remaining <= 0 && !confirmed}
            />
          </div>
          {confirmed ? (
            <span className={s.confirmOk}>
              <Icon name="check" size={16} />
              {t("recovery.matches")}
            </span>
          ) : (
            <span className={s.confirmHint}>
              {typed.length === 0
                ? ""
                : remaining > 0
                  ? t("recovery.remaining", { count: remaining })
                  : t("recovery.mismatch")}
            </span>
          )}
        </div>
      </div>

      <Callout tone="danger" title={t("recovery.warningTitle")}>
        {t("recovery.warningBody")}
      </Callout>

      {/* Only visible on paper; see the @media print block in the stylesheet.
          The path and the KDF summary are machine-written values that read
          left to right whatever the interface language is, so they are
          isolated — an Arabic sheet must not reorder a file path. */}
      <div className={s.printSheet} aria-hidden="true">
        <h1>{t("recovery.sheet.title")}</h1>
        <p>{t("recovery.sheet.vault", { path: isolateLtr(result.path) })}</p>
        {printedProtection !== null && (
          <p>{t("recovery.sheet.protection", { summary: isolateLtr(printedProtection) })}</p>
        )}
        <p className={s.printKey}>{fullKey}</p>
        <p className={s.printWarning}>
          {t("recovery.sheet.warning", {
            title: t("recovery.warningTitle"),
            body: t("recovery.warningBody"),
          })}
        </p>
      </div>
    </div>
  );
}

// -------------------------------------------------------- the standalone ----

export function RecoveryKeyScreen({ result }: { result: CreateVaultResult }) {
  const t = useT("vault");
  // The import namespace for one label, because this is where the first-run
  // import door finally lands and the button has to say so. See ./importIntent.ts.
  const tImport = useT("import");
  const go = useApp((state) => state.go);
  const importWanted = useImportIntent((state) => state.wanted);
  const setImportWanted = useImportIntent((state) => state.setWanted);
  const [confirmed, setConfirmed] = useState(false);

  /**
   * The end of vault creation, and — when the user came in through the
   * first-run import door — the start of the import.
   *
   * Two navigations, deliberately. The wizard leaves through `goBack()`, so
   * the main window has to be the screen underneath it; going straight from
   * here would leave the recovery key as the back target, and this screen must
   * never be returned to.
   */
  const onOpen = useCallback(() => {
    go({ name: "main" });
    if (!importWanted) return;
    // Consumed once: a second vault created later in the session must not
    // inherit an intent from this one.
    setImportWanted(false);
    go({ name: "import" });
  }, [go, importWanted, setImportWanted]);

  return (
    <WizardShell
      step={4}
      onStep={null}
      canGoTo={() => false}
      footNote={t("recovery.footNote")}
      busyLabel={null}
      back={null}
      next={{
        label: importWanted ? tImport("firstRun.openAndImport") : t("recovery.nextLabel"),
        onClick: onOpen,
        disabled: !confirmed,
        reason: t("recovery.confirmBlocked"),
      }}
    >
      <RecoveryKeyPanel result={result} onConfirmedChange={setConfirmed} />
    </WizardShell>
  );
}
