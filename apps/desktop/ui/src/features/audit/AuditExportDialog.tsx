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
 * Both are flagged security-critical in `locales/en/audit.json`: a translation
 * that softens either one removes the only warning there is.
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
import { formatBytes, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { AuditExportFormat, AuditExportResult, IpcFailure } from "@/lib/ipc";
import { useFocusTrap } from "@/features/connections/focusTrap";

import { buildAuditQuery, type AuditFilterState } from "./filters";
import { auditKeys } from "./queryKeys";
import s from "./AuditExportDialog.module.css";

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
  const t = useT("audit");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

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
        // A file name and a file-type name, neither of which is translated:
        // the extension is part of the format and the label the system dialog
        // shows for it is the format's own name.
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
        aria-label={t("export.title")}
        tabIndex={-1}
      >
        <h2 className={s.title}>{t("export.title")}</h2>

        <p className={s.audited}>
          <Icon name="alert" size={14} />
          {t("export.audited")}
        </p>

        {result === null ? (
          <>
            <Callout tone="warning" title={t("export.plaintext")}>
              {t("export.plaintextBody")}
            </Callout>

            <Field label={t("export.formatLabel")} help={t("export.formatHelp")}>
              <div className={s.choices} role="radiogroup" aria-label={t("export.formatLabel")}>
                <ChoiceButton
                  label={t("export.json")}
                  selected={format === "json"}
                  disabled={busy}
                  onSelect={() => setFormat("json")}
                />
                <ChoiceButton
                  label={t("export.csv")}
                  selected={format === "csv"}
                  disabled={busy}
                  onSelect={() => setFormat("csv")}
                />
              </div>
            </Field>

            <Field label={t("export.scopeLabel")} help={t("export.scopeHelp")}>
              <div className={s.choices} role="radiogroup" aria-label={t("export.scopeLabel")}>
                <ChoiceButton
                  label={t("export.scopeFiltered")}
                  selected={scope === "filtered"}
                  disabled={busy}
                  onSelect={() => setScope("filtered")}
                />
                <ChoiceButton
                  label={t("export.scopeAll")}
                  selected={scope === "all"}
                  disabled={busy}
                  onSelect={() => setScope("all")}
                />
              </div>
            </Field>

            <Field
              label={t("export.pathLabel")}
              htmlFor="audit-export-path"
              error={attempted && pathMissing ? t("export.pathMissing") : undefined}
              help={browseFailed ? t("export.browseFailed") : undefined}
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
                    placeholder={t("export.pathPlaceholder")}
                    ariaLabel={t("export.pathLabel")}
                  />
                </div>
                <Button variant="secondary" onClick={() => void browse()} disabled={busy}>
                  {t("export.browse")}
                </Button>
              </div>
            </Field>

            {failure !== null && (
              <FailureNotice
                failure={failure}
                title={t("export.failed")}
                onRetry={busy ? undefined : submit}
              />
            )}

            <div className={s.actions}>
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                {tCommon("action.cancel")}
              </Button>
              <BusyButton
                variant="primary"
                busy={busy}
                busyLabel={t("export.busy")}
                onClick={submit}
                title={pathMissing ? t("export.pathMissing") : undefined}
              >
                {t("export.submit")}
              </BusyButton>
            </div>
          </>
        ) : (
          <>
            <Callout tone="info" title={t("export.done")}>
              {/* The count is a plural inside the message rather than a number
                  glued to a noun, and the path is isolated: a file path reads
                  left-to-right whatever script its directories are in, and an
                  un-isolated one drags the size in brackets after it. */}
              {t("export.doneDetail", {
                count: result.entries,
                path: isolateLtr(result.path),
                size: formatBytes(locale, result.bytes),
              })}
            </Callout>
            <div className={s.actions}>
              <Button variant="primary" onClick={onClose}>
                {tCommon("action.close")}
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
