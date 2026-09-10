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
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import { TextInput } from "@/components/TextInput";
import type { CreateVaultResult } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import s from "./RecoveryKeyScreen.module.css";

// v0.1 ships English only. One block per file so extraction into locales/en is
// mechanical.
const TEXT = {
  windowTitle: "Create a vault",
  stepOf: (n: number) => `Step ${n} of 4`,
  steps: ["1 · Location", "2 · Password", "3 · Key file", "4 · Recovery key"] as const,

  heading: "Your recovery key",
  lead: "Shown once, now. It is the only way back into this vault if you lose your password or your key file.",

  copy: "Copy",
  copying: "Copying…",
  copied: "Copied to the clipboard.",
  copyFailed: "This system did not allow copying. Write the key down or print it instead.",
  download: "Download as text",
  downloadFailed: "This system did not allow saving the file. Print the key instead.",
  print: "Print",
  printFailed:
    "This system did not open a print dialog. Copy the key or write it down instead.",

  /** Why the footer's button cannot be pressed yet. */
  stepBlocked: "Finish this step before moving on.",
  stepAhead: "This step is not available yet.",
  confirmBlocked: "Type the highlighted group above to continue.",

  confirmPrompt: (group: number) =>
    `Type group ${group} — the highlighted one — to confirm you have it somewhere safe.`,
  targetGroupAria: (group: number) => `Group ${group}, the one you must type back`,
  remaining: (n: number) => (n === 1 ? "One more character" : `${n} more characters`),
  matches: "That matches.",
  mismatch: "That is not the highlighted group. Check it against the key above.",

  // Verbatim from docs/security/vault-format.md. Translators are not permitted
  // to soften this; the i18n review checklist flags the string by name.
  warningTitle: "This is your only way back in.",
  warningBody:
    "If you lose your master password and this recovery key, your vault cannot be opened — not by you, not by us, not by anyone. There is no reset, no backup and no support override. Store it somewhere you would store a passport.",

  brokenResult:
    "The core returned a recovery key this screen cannot display. Do not close the application: the vault exists, and its recovery key has not been shown yet.",

  printTitle: "Remoter recovery key",
  printVault: "Vault",
  printCreated: "Created",
  printProtection: "Protection",
} as const;

/** The vault exists by the time this screen renders; the footer must say so. */
export const RECOVERY_FOOT_NOTE =
  "The vault has been created. This key is stored nowhere and will not be shown again.";
export const RECOVERY_NEXT_LABEL = "I have saved it — open the vault";

export type WizardStep = 1 | 2 | 3 | 4;

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

export function WizardShell(props: WizardShellProps) {
  const { step, onStep, canGoTo, footNote, busyLabel, back, next, children } = props;
  const busyNote = props.busyNote ?? null;
  const nextBusy = next.busy === true;
  const steps: WizardStep[] = [1, 2, 3, 4];
  const nextReason = next.disabled && !nextBusy ? next.reason ?? null : null;

  return (
    <div className={s.canvas}>
      <div className={s.card}>
        <div className={s.titlebar} data-tauri-drag-region>
          <Mark size={18} />
          <span className={s.title}>{TEXT.windowTitle}</span>
          <div className={s.spacer} />
          <span className={s.stepLabel}>{TEXT.stepOf(step)}</span>
        </div>

        <div className={s.progress}>
          <div className={s.progressFill} style={{ width: `${step * 25}%` }} />
        </div>

        <nav className={s.stepper} aria-label={TEXT.windowTitle}>
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
                    ? TEXT.steps[n - 1]
                    : reachable
                      ? TEXT.steps[n - 1]
                      : n > step
                        ? TEXT.stepAhead
                        : TEXT.stepBlocked
                }
                onClick={() => onStep?.(n)}
              >
                {TEXT.steps[n - 1]}
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

function sheetText(result: CreateVaultResult, key: string): string {
  return [
    TEXT.printTitle,
    "",
    `${TEXT.printVault}: ${result.path}`,
    `${TEXT.printCreated}: ${new Date().toISOString().slice(0, 10)}`,
    `${TEXT.printProtection}: ${result.kdfSummary}`,
    "",
    key,
    "",
    `${TEXT.warningTitle} ${TEXT.warningBody}`,
    "",
  ].join("\n");
}

export interface RecoveryKeyPanelProps {
  result: CreateVaultResult;
  /** Reported upward so the shell's footer button owns the gate. */
  onConfirmedChange: (confirmed: boolean) => void;
}

export function RecoveryKeyPanel({ result, onConfirmedChange }: RecoveryKeyPanelProps) {
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
      setActionError(TEXT.copyFailed);
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
        () => setActionError(TEXT.copyFailed),
      )
      .finally(() => setCopying(false));
  }, [fullKey]);

  const onDownload = useCallback(() => {
    // No filesystem plugin is a dependency and no IPC command writes arbitrary
    // files, so the download goes through the WebView. Adding a dependency for
    // this would need an ADR.
    try {
      const blob = new Blob([sheetText(result, fullKey)], { type: "text/plain;charset=utf-8" });
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
      setActionError(TEXT.downloadFailed);
    }
  }, [fullKey, result]);

  const onPrint = useCallback(() => {
    document.body.dataset["printing"] = "recovery";
    try {
      window.print();
      setActionError(null);
    } catch {
      // Some WebView builds have no print backend at all. Without this the
      // page would just be left in its printing state with nothing happening.
      delete document.body.dataset["printing"];
      setActionError(TEXT.printFailed);
    }
  }, []);

  if (target.length === 0) {
    return (
      <Callout tone="danger" title={TEXT.warningTitle}>
        {TEXT.brokenResult}
      </Callout>
    );
  }

  return (
    <div className={s.step}>
      <StepHeading title={TEXT.heading} badge={null} lead={TEXT.lead} />

      <div className={s.sheet}>
        <div className={s.grid}>
          {groups.map((group, index) => (
            <span
              key={`${index}-${group}`}
              className={s.group}
              data-target={index === result.confirmGroupIndex}
              aria-label={
                index === result.confirmGroupIndex ? TEXT.targetGroupAria(groupNumber) : undefined
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
            busyLabel={TEXT.copying}
            onClick={onCopy}
          >
            <Icon name="copy" size={13} />
            {TEXT.copy}
          </BusyButton>
          <Button variant="secondary" size="sm" type="button" onClick={onDownload}>
            <Icon name="download" size={13} />
            {TEXT.download}
          </Button>
          <Button variant="secondary" size="sm" type="button" onClick={onPrint}>
            <Icon name="printer" size={13} />
            {TEXT.print}
          </Button>
          <span className={s.actionStatus} role="status">
            {copied ? TEXT.copied : ""}
          </span>
        </div>
      </div>

      {actionError !== null && <div className={s.actionError}>{actionError}</div>}

      <div className={s.confirmBlock}>
        {/* One string, not a sentence assembled around a number: split
            sentences do not survive translation. The group itself is marked in
            the grid above. */}
        <div className={s.confirmPrompt}>{TEXT.confirmPrompt(groupNumber)}</div>
        <div className={s.confirmRow}>
          <div className={s.confirmField}>
            <TextInput
              id="recovery-confirm"
              value={entry}
              onChange={(v) => setEntry(v.slice(0, target.length + 4))}
              type="text"
              mono
              autoFocus
              ariaLabel={TEXT.confirmPrompt(groupNumber)}
              invalid={remaining <= 0 && !confirmed}
            />
          </div>
          {confirmed ? (
            <span className={s.confirmOk}>
              <Icon name="check" size={16} />
              {TEXT.matches}
            </span>
          ) : (
            <span className={s.confirmHint}>
              {typed.length === 0 ? "" : remaining > 0 ? TEXT.remaining(remaining) : TEXT.mismatch}
            </span>
          )}
        </div>
      </div>

      <Callout tone="danger" title={TEXT.warningTitle}>
        {TEXT.warningBody}
      </Callout>

      {/* Only visible on paper; see the @media print block in the stylesheet. */}
      <div className={s.printSheet} aria-hidden="true">
        <h1>{TEXT.printTitle}</h1>
        <p>
          {TEXT.printVault}: {result.path}
        </p>
        <p>
          {TEXT.printProtection}: {result.kdfSummary}
        </p>
        <p className={s.printKey}>{fullKey}</p>
        <p className={s.printWarning}>
          {TEXT.warningTitle} {TEXT.warningBody}
        </p>
      </div>
    </div>
  );
}

// -------------------------------------------------------- the standalone ----

export function RecoveryKeyScreen({ result }: { result: CreateVaultResult }) {
  const go = useApp((state) => state.go);
  const [confirmed, setConfirmed] = useState(false);

  return (
    <WizardShell
      step={4}
      onStep={null}
      canGoTo={() => false}
      footNote={RECOVERY_FOOT_NOTE}
      busyLabel={null}
      back={null}
      next={{
        label: RECOVERY_NEXT_LABEL,
        onClick: () => go({ name: "main" }),
        disabled: !confirmed,
        reason: TEXT.confirmBlocked,
      }}
    >
      <RecoveryKeyPanel result={result} onConfirmedChange={setConfirmed} />
    </WizardShell>
  );
}
