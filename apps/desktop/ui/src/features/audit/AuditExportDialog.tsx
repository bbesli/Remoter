/**
 * Export the log to JSON or CSV.
 *
 * Two things are said out loud here rather than buried in documentation,
 * because both change whether a person should press the button:
 *
 *  - **Exporting is itself audited.** The core appends a row saying an export
 *    happened, to where, and how many entries it carried
 *    (docs/features/recording-audit.md). A user who expects a silent read and
 *    discovers the row afterwards has been surprised by their own tool.
 *  - **The file leaves the vault's protection.** It is written in the clear,
 *    outside the encrypted body, and from then on it is an ordinary file that
 *    anyone with the disk can read.
 *
 * `aria-modal` is a promise, so this keeps it: focus enters, Tab is trapped,
 * Escape cancels, focus returns, and the screen behind stands its shortcuts
 * down through `useModalRegistration`.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";

import { Button } from "@/components/Button";
import { BusyButton } from "@/components/Busy";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { asFailure, ipc } from "@/lib/ipc";
import type { AuditExportFormat, AuditExportResult, IpcFailure } from "@/lib/ipc";
import { useFocusTrap } from "@/features/connections/focusTrap";

import { buildAuditQuery, type AuditFilterState } from "./filters";
import { formatBytes, formatCount } from "./format";
import { auditKeys } from "./queryKeys";
import s from "./AuditExportDialog.module.css";

const TEXT = {
  title: "Export the audit log",

  audited: "Exporting writes a row into this log. The export is itself an audited action.",
  plaintext: "The file is written outside the vault and is not encrypted.",
  plaintextBody:
    "It holds what happened, when, and against which host — no passwords or key material, but a full history of your connections. Anyone who can read the file can read that history.",

  format: "Format",
  formatHelp: "JSON keeps the fields as they are stored. CSV opens in a spreadsheet.",
  json: "JSON",
  csv: "CSV",

  scope: "What to write",
  scopeFiltered: "The entries you are looking at",
  scopeAll: "The whole log",
  scopeHelp: "The filter is applied to the whole range you chose, not to the page on screen.",

  path: "Write to",
  pathPlaceholder: "/home/you/audit.json",
  browse: "Choose…",
  browseFailed: "The system file dialog did not open. Type the path instead.",
  pathMissing: "Choose where to write the file first.",

  cancel: "Cancel",
  close: "Close",
  exportNow: "Export",
  exporting: "Writing the file…",
  exportFailed: "The log was not exported.",

  done: "Exported.",
  doneDetail: (entries: string, bytes: string, path: string) =>
    `${entries} written to ${path} (${bytes}). A row recording this export is now at the top of the log.`,
  doneOne: "1 entry",
  doneMany: (n: string) => `${n} entries`,
} as const;

interface AuditExportDialogProps {
  /** The filter the screen is showing, so "what you are looking at" means it. */
  filters: AuditFilterState;
  /** The instant the filter's relative range is measured from. */
  anchor: number;
  onClose: () => void;
}

type Scope = "filtered" | "all";

const EXTENSION: Record<AuditExportFormat, string> = { json: "json", csv: "csv" };

export function AuditExportDialog({ filters, anchor, onClose }: AuditExportDialogProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const queryClient = useQueryClient();

  const [format, setFormat] = useState<AuditExportFormat>("json");
  const [scope, setScope] = useState<Scope>("filtered");
  const [path, setPath] = useState("");
  const [browseFailed, setBrowseFailed] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [result, setResult] = useState<AuditExportResult | null>(null);
  const [failure, setFailure] = useState<IpcFailure | null>(null);

  useFocusTrap(true, dialogRef);
  useModalRegistration("audit.export", true);

  const exportMutation = useMutation({
    mutationFn: () =>
      ipc.exportAudit({
        path: path.trim(),
        format,
        // Absent exports everything; the paging is left off because an export
        // of one page of a filter is not what anybody means by "export".
        query: scope === "all" ? null : buildAuditQuery(filters, anchor),
      }),
    onSuccess: async (written) => {
      setFailure(null);
      setResult(written);
      // The export appended a row. The table is showing a log that no longer
      // matches what is on disk until this lands.
      await queryClient.invalidateQueries({ queryKey: auditKeys.all() });
    },
    onError: (error: unknown) => {
      setResult(null);
      setFailure(asFailure(error));
    },
  });

  const busy = exportMutation.isPending;

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // A write already in flight cannot be called back, and closing the
      // dialog would leave the user with no idea whether the file exists.
      if (busy) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);

  const browse = async () => {
    setBrowseFailed(false);
    try {
      const chosen = await save({
        defaultPath: `remoter-audit.${EXTENSION[format]}`,
        filters: [{ name: format.toUpperCase(), extensions: [EXTENSION[format]] }],
      });
      if (chosen !== null) setPath(chosen);
    } catch {
      // Every path here is also typeable, so a dialog that refuses to open is
      // an inconvenience rather than a dead end.
      setBrowseFailed(true);
    }
  };

  const pathMissing = path.trim() === "";

  const submit = () => {
    setAttempted(true);
    if (pathMissing || busy) return;
    exportMutation.mutate();
  };

  return (
    <div className={s.backdrop}>
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-label={TEXT.title}
        tabIndex={-1}
      >
        <h2 className={s.title}>{TEXT.title}</h2>

        <p className={s.audited}>
          <Icon name="alert" size={14} />
          {TEXT.audited}
        </p>

        {result === null ? (
          <>
            <Callout tone="warning" title={TEXT.plaintext}>
              {TEXT.plaintextBody}
            </Callout>

            <Field label={TEXT.format} help={TEXT.formatHelp}>
              <div className={s.choices} role="radiogroup" aria-label={TEXT.format}>
                <ChoiceButton
                  label={TEXT.json}
                  selected={format === "json"}
                  disabled={busy}
                  onSelect={() => setFormat("json")}
                />
                <ChoiceButton
                  label={TEXT.csv}
                  selected={format === "csv"}
                  disabled={busy}
                  onSelect={() => setFormat("csv")}
                />
              </div>
            </Field>

            <Field label={TEXT.scope} help={TEXT.scopeHelp}>
              <div className={s.choices} role="radiogroup" aria-label={TEXT.scope}>
                <ChoiceButton
                  label={TEXT.scopeFiltered}
                  selected={scope === "filtered"}
                  disabled={busy}
                  onSelect={() => setScope("filtered")}
                />
                <ChoiceButton
                  label={TEXT.scopeAll}
                  selected={scope === "all"}
                  disabled={busy}
                  onSelect={() => setScope("all")}
                />
              </div>
            </Field>

            <Field
              label={TEXT.path}
              htmlFor="audit-export-path"
              error={attempted && pathMissing ? TEXT.pathMissing : undefined}
              help={browseFailed ? TEXT.browseFailed : undefined}
            >
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="audit-export-path"
                    value={path}
                    onChange={setPath}
                    mono
                    disabled={busy}
                    invalid={attempted && pathMissing}
                    placeholder={TEXT.pathPlaceholder}
                    ariaLabel={TEXT.path}
                  />
                </div>
                <Button variant="secondary" onClick={() => void browse()} disabled={busy}>
                  {TEXT.browse}
                </Button>
              </div>
            </Field>

            {failure !== null && (
              <FailureNotice
                failure={failure}
                title={TEXT.exportFailed}
                onRetry={busy ? undefined : submit}
              />
            )}

            <div className={s.actions}>
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                {TEXT.cancel}
              </Button>
              <BusyButton
                variant="primary"
                busy={busy}
                busyLabel={TEXT.exporting}
                onClick={submit}
                title={pathMissing ? TEXT.pathMissing : undefined}
              >
                {TEXT.exportNow}
              </BusyButton>
            </div>
          </>
        ) : (
          <>
            <Callout tone="info" title={TEXT.done}>
              {TEXT.doneDetail(
                result.entries === 1 ? TEXT.doneOne : TEXT.doneMany(formatCount(result.entries)),
                formatBytes(result.bytes),
                result.path,
              )}
            </Callout>
            <div className={s.actions}>
              <Button variant="primary" onClick={onClose}>
                {TEXT.close}
              </Button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

interface ChoiceButtonProps {
  label: string;
  selected: boolean;
  disabled: boolean;
  onSelect: () => void;
}

/**
 * A radio in the shape of a button. `role="radio"` rather than a styled
 * `<input>` so the pressed state is announced, and so the pair reads as one
 * choice rather than two independent toggles.
 */
function ChoiceButton({ label, selected, disabled, onSelect }: ChoiceButtonProps) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      className={selected ? `${s.choice} ${s.choiceOn}` : s.choice}
      disabled={disabled}
      onClick={onSelect}
    >
      {label}
    </button>
  );
}
