/**
 * Files the remote desktop copied, and saving them here.
 *
 * A copy of text on the server lands on this machine's clipboard by itself. A
 * copy of files cannot, and should not: the local clipboard has no way to hold
 * a file that has not arrived, and fetching every file the moment the server
 * copies it would pull a folder of gigabytes across the link because someone
 * pressed Ctrl+C in Explorer. So the copy is *shown* — how many, how large, the
 * first few names — and nothing moves until the user picks a folder.
 *
 * Three rules shape what is drawn.
 *
 * **The names are the server's.** They arrive escaped by the core and are shown
 * isolated, as data inside a translated sentence, never as part of it.
 *
 * **A save is never silent.** While it runs it says how far it has got and can
 * be stopped; when it ends it says where the files went, or why it stopped and
 * that the files which arrived whole were kept.
 *
 * **It sits above the picture, not on it**, with the other notices: a remote
 * desktop uses all four of its edges.
 */

import { useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { formatBytes, isolate, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure } from "@/lib/ipc";
import { useSessions, type SessionRecord } from "./store";

import s from "./ClipboardFilesBar.module.css";

/** How many names the offer shows before it says how many more there are. */
const LISTED = 3;

/**
 * Why a save stopped, by the catalogue key the adapter sent.
 *
 * Written out rather than derived, so that a translator sees a finite list and
 * a reason the interface has no sentence for falls back to a general one
 * rather than to a key on screen.
 */
const FAILURE_KEYS = {
  "rdp.clipboard_save_refused": "surface.framebuffer.clipboardFiles.failed.refused",
  "rdp.clipboard_save_write_failed": "surface.framebuffer.clipboardFiles.failed.writeFailed",
  "rdp.clipboard_save_nothing": "surface.framebuffer.clipboardFiles.failed.nothing",
  "rdp.clipboard_save_busy": "surface.framebuffer.clipboardFiles.failed.busy",
  "rdp.clipboard_files_unsupported": "surface.framebuffer.clipboardFiles.failed.unsupported",
} as const;

type FailureKey = (typeof FAILURE_KEYS)[keyof typeof FAILURE_KEYS];

function failureKey(reason: string): FailureKey | "surface.framebuffer.clipboardFiles.failed.other" {
  return (FAILURE_KEYS as Record<string, FailureKey | undefined>)[reason] ??
    "surface.framebuffer.clipboardFiles.failed.other";
}

export function ClipboardFilesBar({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const [failure, setFailure] = useState<IpcFailure | null>(null);
  const [dialogFailed, setDialogFailed] = useState(false);

  const { offer, transfer } = record.clipboardFiles;
  const tabId = record.tabId;
  const sessionId = record.sessionId;
  const running = record.phase === "running" && sessionId !== null;

  const patchFiles = (next: Partial<SessionRecord["clipboardFiles"]>) => {
    const current = useSessions.getState().byId[tabId]?.clipboardFiles;
    if (current === undefined) return;
    useSessions.getState().patch(tabId, { clipboardFiles: { ...current, ...next } });
  };

  const save = () => {
    if (sessionId === null) return;
    setFailure(null);
    setDialogFailed(false);
    void (async () => {
      let chosen: string | string[] | null;
      try {
        chosen = await open({
          directory: true,
          multiple: false,
          title: t("surface.framebuffer.clipboardFiles.dialogTitle"),
        });
      } catch {
        setDialogFailed(true);
        return;
      }
      if (typeof chosen !== "string") return;
      try {
        await ipc.saveClipboardFiles(sessionId, chosen);
      } catch (error) {
        setFailure(asFailure(error));
      }
    })();
  };

  const cancel = () => {
    if (sessionId === null) return;
    void ipc.cancelClipboardSave(sessionId).catch((error: unknown) => {
      setFailure(asFailure(error));
    });
  };

  if (offer === null && transfer === null && failure === null) return null;

  // By their top-level names: `Reports`, not `Reports/q1.xlsx`. The count
  // after them covers everything else, folders' contents included.
  const shown = (offer?.files ?? []).filter((file) => !file.path.includes("/")).slice(0, LISTED);
  const hidden = offer === null ? 0 : Math.max(offer.totalEntries - shown.length, 0);

  return (
    <div className={s.bar} role="region" aria-label={t("surface.framebuffer.clipboardFiles.label")}>
      {failure !== null && (
        <FailureNotice
          failure={failure}
          title={t("surface.framebuffer.clipboardFiles.saveRefused")}
          tone="warning"
        >
          <Button variant="ghost" size="sm" onClick={() => setFailure(null)}>
            {tCommon("action.dismiss")}
          </Button>
        </FailureNotice>
      )}

      {transfer?.kind === "saving" ? (
        <div className={s.row} role="status">
          <Icon name="download" size={14} />
          <span className={s.text}>
            {t("surface.framebuffer.clipboardFiles.saving", {
              done: transfer.doneFiles,
              total: transfer.totalFiles,
              doneSize: formatBytes(locale, transfer.doneBytes),
              totalSize: formatBytes(locale, transfer.totalBytes),
            })}
          </span>
          <progress
            className={s.progress}
            max={Math.max(transfer.totalBytes, 1)}
            value={Math.min(transfer.doneBytes, Math.max(transfer.totalBytes, 1))}
            aria-label={t("surface.framebuffer.clipboardFiles.progressLabel")}
          />
          <Button variant="ghost" size="sm" onClick={cancel} disabled={!running}>
            {tCommon("action.cancel")}
          </Button>
        </div>
      ) : transfer?.kind === "finished" ? (
        <div className={s.row} role="status">
          <Icon name="check" size={14} />
          <span className={s.text}>
            {t("surface.framebuffer.clipboardFiles.finished", {
              count: transfer.files,
              directory: isolate(transfer.directory),
            })}
          </span>
          <Button variant="ghost" size="sm" onClick={() => patchFiles({ transfer: null })}>
            {tCommon("action.dismiss")}
          </Button>
        </div>
      ) : transfer?.kind === "failed" ? (
        <div className={[s.row, s.failed].join(" ")} role="alert">
          <Icon name="alert" size={14} />
          <span className={s.text}>{t(failureKey(transfer.reason))}</span>
          <Button variant="ghost" size="sm" onClick={() => patchFiles({ transfer: null })}>
            {tCommon("action.dismiss")}
          </Button>
        </div>
      ) : null}

      {offer !== null && transfer?.kind !== "saving" && (
        <div className={s.row}>
          <Icon name="copy" size={14} />
          <span className={s.text}>
            {t("surface.framebuffer.clipboardFiles.offered", {
              count: offer.totalEntries,
              size: formatBytes(locale, offer.totalBytes),
            })}
            <span className={s.names}>
              {shown.map((file) => isolate(file.path)).join(", ")}
              {hidden > 0 &&
                ` ${t("surface.framebuffer.clipboardFiles.more", { count: hidden })}`}
            </span>
          </span>
          <Button variant="secondary" size="sm" onClick={save} disabled={!running}>
            {t("surface.framebuffer.clipboardFiles.save")}
          </Button>
          <Button variant="ghost" size="sm" onClick={() => patchFiles({ offer: null })}>
            {tCommon("action.dismiss")}
          </Button>
        </div>
      )}

      {dialogFailed && (
        <p className={s.note}>{t("surface.framebuffer.clipboardFiles.dialogFailed")}</p>
      )}
    </div>
  );
}
