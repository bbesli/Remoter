/**
 * Removing something, and saying what that means before it happens.
 *
 * Three things this dialog does that a plain "Are you sure?" does not, each
 * because the command surface makes it possible and the alternative is a lie:
 *
 * **It counts first.** A recursive removal walks the tree, and a walk that has
 * started cannot be un-started. `previewRemoval` reads the tree with the same
 * listing the browser uses and reports what is down there, so the sentence
 * above the button is about this folder rather than about folders in general.
 * The count is bounded, and when it stops early it says the number is a floor.
 *
 * **It says that links are not followed.** That is a real guarantee from the
 * engine — its walk stats with `symlink_metadata`, so a link to a directory is
 * unlinked rather than emptied — and it is the difference between removing a
 * build directory and removing whatever a symlink in it points at.
 *
 * **It reports afterwards.** `sftp_delete` returns what it managed rather than
 * `Ok(())`, because an interrupted walk leaves the tree half-removed. A dialog
 * that closed on the first response would turn "nine of twelve" into "done".
 * So the dialog stays open on anything short of complete, and says which.
 */

import { useEffect, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { isolate, useFailureText, useT } from "@/i18n";
import {
  asFailure,
  ipc,
  type DirectoryEntry,
  type IpcFailure,
  type SftpDeleteReport,
} from "@/lib/ipc";
import { invalidatePane } from "@/lib/queryKeys";

import { DialogFrame } from "./DialogFrame";
import { PREVIEW_LIMIT, previewRemoval, type RemovalPreview } from "./preview";

import s from "./DeleteDialog.module.css";

interface DeleteDialogProps {
  paneId: number;
  entry: DirectoryEntry;
  onClose: () => void;
}

export function DeleteDialog({ paneId, entry, onClose }: DeleteDialogProps) {
  const t = useT("files");
  const tCommon = useT("common");
  const queryClient = useQueryClient();

  const [preview, setPreview] = useState<RemovalPreview | null>(null);
  const [scanning, setScanning] = useState(true);
  const [scanProblem, setScanProblem] = useState<IpcFailure | null>(null);
  const [report, setReport] = useState<SftpDeleteReport | null>(null);
  const [problem, setProblem] = useState<IpcFailure | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    setScanning(true);
    setScanProblem(null);
    void previewRemoval(entry, (path) => ipc.listDirectory(paneId, path), controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setPreview(result);
        setScanning(false);
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        // Only the root listing can reject — the walk swallows the rest and
        // marks itself truncated. If even that failed, the extent is unknown,
        // and a removal of unknown extent is what this dialog exists to refuse.
        setScanProblem(asFailure(error));
        setScanning(false);
      });
    return () => controller.abort();
  }, [paneId, entry]);

  const inside = preview === null ? 0 : preview.files + preview.directories;
  // Recursive only where there is something inside. An empty directory goes
  // through `SSH_FXP_RMDIR`, which is the smaller, non-walking operation.
  const recursive = entry.kind === "directory" && inside > 0;

  const run = useMutation({
    mutationFn: () => ipc.deletePath(paneId, entry.path, recursive),
    onSuccess: async (result) => {
      setProblem(null);
      setReport(result);
      // Whatever it managed is already gone from the server; the listing is
      // stale either way.
      await invalidatePane(queryClient, paneId);
      if (result.complete) onClose();
    },
    onError: (error: unknown) => {
      setReport(null);
      setProblem(asFailure(error));
    },
  });

  const busy = run.isPending;
  const blocked = scanProblem !== null;

  return (
    <DialogFrame
      id="files.delete"
      title={t("delete.title", { name: isolate(entry.displayName) })}
      busy={busy}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {report === null ? tCommon("action.cancel") : tCommon("action.close")}
          </Button>
          {report === null && (
            <Button
              variant="danger"
              onClick={() => {
                run.mutate();
              }}
              disabled={busy || scanning || blocked}
            >
              {recursive ? t("delete.confirmTree") : t("delete.confirm")}
            </Button>
          )}
        </>
      }
    >
      {/* SECURITY-CRITICAL copy: there is no trash on the far side. It is first
          in the reading order rather than tucked under the buttons. */}
      <Callout tone="danger">{t("delete.permanent")}</Callout>

      {scanning && (
        <p className={s.scanning}>
          <Spinner size={14} label={t("delete.scanning")} />
          <span>{t("delete.scanning")}</span>
        </p>
      )}

      {scanProblem !== null && (
        <>
          <FailureNotice failure={scanProblem} title={t("delete.scanFailed")} />
          <p>{t("delete.scanFailedNote")}</p>
        </>
      )}

      {!scanning && preview !== null && entry.kind === "directory" && (
        <>
          <p className={s.summary}>
            {t("delete.summary", { files: preview.files, folders: preview.directories })}
          </p>
          {preview.truncated && <p className={s.note}>{t("delete.truncated", { limit: PREVIEW_LIMIT })}</p>}
          {preview.links > 0 && <p className={s.note}>{t("delete.links")}</p>}
          {preview.sample.length > 0 && (
            <>
              <p className={s.sampleHeading}>{t("delete.sample")}</p>
              <ul className={s.sample}>
                {preview.sample.map((path) => (
                  // The escaped path, isolated so one entry cannot reorder the
                  // list around it. Text, never markup.
                  <li key={path}>{isolate(path)}</li>
                ))}
              </ul>
              {inside > preview.sample.length && (
                <p className={s.note}>{t("delete.more", { count: inside - preview.sample.length })}</p>
              )}
            </>
          )}
          {!recursive && <p className={s.note}>{t("delete.emptyDirHint")}</p>}
        </>
      )}

      {busy && <p className={s.scanning}>{t("delete.running")}</p>}

      {report !== null && <DeleteReport report={report} />}

      {problem !== null && (
        <FailureNotice
          failure={problem}
          onRetry={
            busy
              ? undefined
              : () => {
                  run.mutate();
                }
          }
        />
      )}
    </DialogFrame>
  );
}

/**
 * What the removal actually did.
 *
 * Only rendered when something is left over — a complete removal closes the
 * dialog, because a confirmation that demands a second acknowledgement for the
 * ordinary case is a confirmation people stop reading.
 */
function DeleteReport({ report }: { report: SftpDeleteReport }) {
  const t = useT("files");
  const counts = { files: report.filesRemoved, folders: report.directoriesRemoved };

  return (
    <Callout tone={report.complete ? "neutral" : "warning"}>
      <p>{report.complete ? t("delete.report.complete", counts) : t("delete.report.partial", counts)}</p>
      {report.cancelled && <p>{t("delete.report.cancelled")}</p>}
      {report.limitReached && <p>{t("delete.report.limitReached")}</p>}
      {report.failures.length > 0 && (
        <>
          <p>{t("delete.report.failures")}</p>
          <ul className={s.sample}>
            {report.failures.map((item) => (
              <li key={item.path}>
                <RemovalFailureRow path={item.path} code={item.code} english={item.message} />
              </li>
            ))}
          </ul>
        </>
      )}
    </Callout>
  );
}

/**
 * One path that could not be removed, with the reason in the reader's language.
 *
 * The core sends a stable `code` and an English sentence. `useFailureText` is
 * the lookup that turns the first into the catalogue's sentence and falls back
 * to the second for a code nobody has translated yet — the same path every
 * other failure in the application takes, rather than the English being printed
 * because it happened to be in the struct.
 */
function RemovalFailureRow({ path, code, english }: { path: string; code: string; english: string }) {
  const text = useFailureText({ code, message: english, detail: null, actions: [] });
  return (
    <>
      <span className={s.failurePath}>{isolate(path)}</span>
      <span className={s.failureReason}>{text.message}</span>
    </>
  );
}
