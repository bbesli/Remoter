/**
 * Export the connection tree — or one folder of it — to a file.
 *
 * Two things are said before the button rather than after it, because both
 * change whether a person should press it:
 *
 *  - **No secret is written.** No password, no private key, no passphrase, in
 *    any of the three formats. The core's writers are never handed one.
 *  - **The file is not encrypted.** It is a list of every server, address and
 *    account in the export, readable by anyone who can read the file.
 *
 * And that the export is recorded in the audit log, so the row it leaves there
 * is not a surprise.
 *
 * After the write the form gives way to what the core reported: how many
 * connections made it into the file, and the notes on what the format could
 * not say the way the vault says it — a connection an OpenSSH config has no
 * place for, a route whose hop has the same name as another connection. Those
 * are the things a person would otherwise find out in a terminal, later.
 *
 * `aria-modal` is a promise, so this keeps it: focus enters, Tab is trapped,
 * Escape cancels, focus returns, and the window behind stands its shortcuts
 * down through `useModalRegistration`.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { auditKeys } from "@/features/audit/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { formatBytes, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, TreeExportFormat, TreeExportResult } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { describeNote } from "./notes";
import s from "./TreeExportDialog.module.css";

export const EXPORT_MODAL_ID = "tree.export";

interface TreeExportDialogProps {
  /** The folder or connection the dialog was opened on; null is the whole vault. */
  rootId: string | null;
  onClose: () => void;
}

type Scope = "node" | "vault";

const FORMATS: readonly TreeExportFormat[] = ["csv", "ssh-config", "json"];

/** The extension each format is saved with. An OpenSSH config has none of its own. */
const EXTENSION: Record<TreeExportFormat, string> = {
  csv: "csv",
  "ssh-config": "config",
  json: "json",
};

export function TreeExportDialog({ rootId, onClose }: TreeExportDialogProps) {
  const t = useT("connections");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const queryClient = useQueryClient();
  const nodes = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });
  const root = useMemo(
    () => (rootId === null ? null : (nodes.data?.find((node) => node.id === rootId) ?? null)),
    [nodes.data, rootId],
  );

  const [format, setFormat] = useState<TreeExportFormat>("csv");
  const [scope, setScope] = useState<Scope>(rootId === null ? "vault" : "node");
  const [path, setPath] = useState("");
  const [browseFailed, setBrowseFailed] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [result, setResult] = useState<TreeExportResult | null>(null);
  const [failure, setFailure] = useState<IpcFailure | null>(null);

  useFocusTrap(true, dialogRef);
  useModalRegistration(EXPORT_MODAL_ID, true);

  const exportMutation = useMutation({
    mutationFn: () =>
      ipc.exportTree({
        path: path.trim(),
        format,
        rootId: scope === "node" ? rootId : null,
      }),
    onSuccess: async (written) => {
      setFailure(null);
      setResult(written);
      // The export appended a row to the audit log.
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
      // A write in flight cannot be called back, and closing now would leave
      // the user not knowing whether the file exists.
      if (busy) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);

  const chooseFormat = (next: TreeExportFormat) => {
    // A path whose extension came from the previous format follows the new
    // one; a path the user typed with an extension of their own is theirs.
    const previous = `.${EXTENSION[format]}`;
    if (path.endsWith(previous)) {
      setPath(`${path.slice(0, -previous.length)}.${EXTENSION[next]}`);
    }
    setFormat(next);
  };

  const browse = async () => {
    setBrowseFailed(false);
    try {
      const chosen = await save({
        defaultPath: `${fileStem(scope === "node" ? (root?.name ?? null) : null)}.${EXTENSION[format]}`,
        filters: [{ name: formatLabel(t, format), extensions: [EXTENSION[format]] }],
      });
      if (chosen !== null) setPath(chosen);
    } catch {
      // Every path is also typeable, so a dialog that will not open is an
      // inconvenience rather than a dead end.
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
            <Callout tone="warning" title={t("export.noSecrets")}>
              {t("export.plaintextBody")}
            </Callout>

            {rootId !== null && (
              <Field label={t("export.scopeLabel")}>
                <div className={s.choices} role="radiogroup" aria-label={t("export.scopeLabel")}>
                  <ChoiceButton
                    label={t("export.scopeNode", { name: isolate(root?.name ?? "") })}
                    selected={scope === "node"}
                    disabled={busy}
                    onSelect={() => setScope("node")}
                  />
                  <ChoiceButton
                    label={t("export.scopeVault")}
                    selected={scope === "vault"}
                    disabled={busy}
                    onSelect={() => setScope("vault")}
                  />
                </div>
              </Field>
            )}

            <Field label={t("export.formatLabel")} help={formatHelp(t, format)}>
              <div className={s.choices} role="radiogroup" aria-label={t("export.formatLabel")}>
                {FORMATS.map((candidate) => (
                  <ChoiceButton
                    key={candidate}
                    label={formatLabel(t, candidate)}
                    selected={format === candidate}
                    disabled={busy}
                    onSelect={() => chooseFormat(candidate)}
                  />
                ))}
              </div>
            </Field>

            <Field
              label={t("export.pathLabel")}
              htmlFor="tree-export-path"
              error={attempted && pathMissing ? t("export.pathMissing") : undefined}
              help={browseFailed ? t("export.browseFailed") : undefined}
            >
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="tree-export-path"
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
              {t("export.doneDetail", {
                written: result.report.connections - result.report.skipped,
                total: result.report.connections,
                path: isolateLtr(result.path),
                size: formatBytes(locale, result.bytes),
              })}
            </Callout>

            {result.report.notes.length > 0 && (
              <section className={s.notes} aria-labelledby="tree-export-notes">
                <h3 className={s.notesTitle} id="tree-export-notes">
                  {t("export.notesTitle", {
                    count: result.report.notes.length + result.report.notesDropped,
                  })}
                </h3>
                <ul className={s.notesList}>
                  {result.report.notes.map((note, index) => (
                    // The core's order is the tree's order, and two notes can
                    // be identical; the position is the identity.
                    <li key={index}>{describeNote(t, note)}</li>
                  ))}
                </ul>
                {result.report.notesDropped > 0 && (
                  <p className={s.notesMore}>
                    {t("export.notesMore", { count: result.report.notesDropped })}
                  </p>
                )}
              </section>
            )}

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

type ConnectionsT = ReturnType<typeof useT<"connections">>;

function formatLabel(t: ConnectionsT, format: TreeExportFormat): string {
  switch (format) {
    case "csv":
      return t("export.csv");
    case "ssh-config":
      return t("export.sshConfig");
    case "json":
      return t("export.json");
  }
}

function formatHelp(t: ConnectionsT, format: TreeExportFormat): string {
  switch (format) {
    case "csv":
      return t("export.csvHelp");
    case "ssh-config":
      return t("export.sshConfigHelp");
    case "json":
      return t("export.jsonHelp");
  }
}

/**
 * A file name to offer, from the exported folder's name.
 *
 * The characters no file system on the three platforms accepts are replaced,
 * not the whole name: a folder called `Üretim` should be offered as
 * `Üretim.csv`, not as something ASCII.
 */
export function fileStem(name: string | null): string {
  const cleaned = (name ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[ -/\\:*?"<>|]+/g, "-")
    .replace(/^[\s.-]+|[\s.-]+$/g, "");
  return cleaned === "" ? "remoter-connections" : cleaned;
}

interface ChoiceButtonProps {
  label: string;
  selected: boolean;
  disabled: boolean;
  onSelect: () => void;
}

/** A radio in the shape of a button, as the audit export draws it. */
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
