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

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import { TextInput } from "@/components/TextInput";
import { formatDate, isolateLtr, useLocale, useT } from "@/i18n";
import type { CreateVaultResult } from "@/lib/ipc";

import { kdfSummary } from "./kdf";
import { useApp } from "@/stores/app";

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

function baseName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut >= 0 ? path.slice(cut + 1) : path;
}

/**
 * The plain-text sheet behind Download.
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
  const [actionError, setActionError] = useState<string | null>(null);

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
    if (!navigator.clipboard) {
      setActionError(t("recovery.copyFailed"));
      return;
    }
    setCopying(true);
    void navigator.clipboard
      .writeText(fullKey)
      .then(
        () => {
          setActionError(null);
          setCopied(true);
        },
        () => setActionError(t("recovery.copyFailed")),
      )
      .finally(() => setCopying(false));
  }, [fullKey, t]);

  const onDownload = useCallback(() => {
    // No filesystem plugin is a dependency and no IPC command writes arbitrary
    // files, so the download goes through the WebView. Adding a dependency for
    // this would need an ADR.
    try {
      const blob = new Blob([sheetText(t, locale, result, fullKey)], {
        type: "text/plain;charset=utf-8",
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `recovery-key-${baseName(result.path).replace(/\.rvault$/i, "")}.txt`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 0);
      setActionError(null);
    } catch {
      setActionError(t("recovery.downloadFailed"));
    }
  }, [fullKey, locale, result, t]);

  const onPrint = useCallback(() => {
    document.body.dataset["printing"] = "recovery";
    try {
      window.print();
      setActionError(null);
    } catch {
      // Some WebView builds have no print backend at all. Without this the
      // page would just be left in its printing state with nothing happening.
      delete document.body.dataset["printing"];
      setActionError(t("recovery.printFailed"));
    }
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
          <Button variant="secondary" size="sm" type="button" onClick={onDownload}>
            <Icon name="download" size={13} />
            {t("recovery.download")}
          </Button>
          <Button variant="secondary" size="sm" type="button" onClick={onPrint}>
            <Icon name="printer" size={13} />
            {t("recovery.print")}
          </Button>
          <span className={s.actionStatus} role="status">
            {copied ? t("recovery.copied") : ""}
          </span>
        </div>
      </div>

      {actionError !== null && <div className={s.actionError}>{actionError}</div>}

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
  const go = useApp((state) => state.go);
  const [confirmed, setConfirmed] = useState(false);

  return (
    <WizardShell
      step={4}
      onStep={null}
      canGoTo={() => false}
      footNote={t("recovery.footNote")}
      busyLabel={null}
      back={null}
      next={{
        label: t("recovery.nextLabel"),
        onClick: () => go({ name: "main" }),
        disabled: !confirmed,
        reason: t("recovery.confirmBlocked"),
      }}
    >
      <RecoveryKeyPanel result={result} onConfirmedChange={setConfirmed} />
    </WizardShell>
  );
}
