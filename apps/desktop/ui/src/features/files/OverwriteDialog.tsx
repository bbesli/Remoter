/**
 * What a transfer will land on, asked before it lands on it.
 *
 * # The defect this closes
 *
 * Neither direction asked anything. An upload truncated whatever was at the
 * remote path and a download truncated whatever was at the local one, and
 * `sftp_preflight` — the command whose entire purpose is to answer "is
 * something already there?" — was exposed on the command surface and called by
 * nothing. A transfer is destructive on its destination side; there is no trash
 * on either end and no undo anywhere, so the only acceptable shape is the one
 * the delete dialog already has: say what will be lost, then ask.
 *
 * # Three answers, and the third is the one that matters
 *
 * Preflight distinguishes "nothing is there", "this is what is there", and
 * "nobody could look" — the last being a local destination that could not be
 * read, which arrives as `sftp.local-destination-unreadable`. Drawing the third
 * as the first is how a file manager quietly replaces a file it said was
 * absent, so those get their own section and their own sentence, and they are
 * still sent: a destination nobody could inspect is not a reason to refuse the
 * transfer, only a reason not to claim anything about it.
 *
 * A destination that is a **folder** is different again: a transfer cannot
 * replace one, so those requests are dropped from the batch rather than queued
 * to fail against a server that will refuse them one at a time.
 *
 * A **source** that is a folder is different a third time. It expands into one
 * transfer per file underneath it, merging into whatever is at the destination
 * and replacing only the names that collide — which is neither "this file will
 * be replaced" nor "nothing is there", and is said as its own thing.
 *
 * # It is a check, not a lock
 *
 * A file created in the gap between the preflight and the enqueue is still
 * overwritten. Nothing in SFTP offers the alternative — there is no atomic
 * create-if-absent across the operations a transfer needs — and the case this
 * closes is the one that actually happens: the file that was already there when
 * the user pressed the button.
 */

import { useMemo } from "react";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { formatBytes, formatDateTime, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import type { TransferDirection, TransferPreflight, TransferRequest } from "@/lib/ipc";

import { DialogFrame } from "./DialogFrame";

import s from "./OverwriteDialog.module.css";

export interface OverwriteDecision {
  /** The requests to queue, in the order they were given. */
  requests: TransferRequest[];
}

interface OverwriteDialogProps {
  /** The batch as asked for. */
  requests: readonly TransferRequest[];
  /** One answer per request, by position. */
  answers: readonly TransferPreflight[];
  /** Whether "continue interrupted transfers" is on for this batch. */
  resume: boolean;
  /** True while the enqueue this dialog started is in flight. */
  busy: boolean;
  onConfirm: (decision: OverwriteDecision) => void;
  onClose: () => void;
}

/**
 * Which way the batch goes, for wording the confirming button.
 *
 * `null` for a mixed batch — which the panes cannot currently produce, but a
 * button that said "replace the file on the server" over a batch that also
 * writes locally would be naming the wrong side of a destructive act.
 */
function directionOf(answers: readonly TransferPreflight[]): TransferDirection | null {
  const first = answers[0]?.direction ?? null;
  if (first === null) return null;
  return answers.every((answer) => answer.direction === first) ? first : null;
}

export function OverwriteDialog({
  requests,
  answers,
  resume,
  busy,
  onConfirm,
  onClose,
}: OverwriteDialogProps) {
  const t = useT("files");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

  const groups = useMemo(() => {
    const replacing: TransferPreflight[] = [];
    const folders: TransferPreflight[] = [];
    const blocked: TransferPreflight[] = [];
    const unchecked: TransferPreflight[] = [];
    for (const answer of answers) {
      // Order matters: a destination that is a directory cannot be written at
      // all, which outranks everything else that could be said about it.
      if (answer.directory && !answer.sourceIsFolder) blocked.push(answer);
      else if (answer.sourceIsFolder) folders.push(answer);
      else if (answer.problem !== null) unchecked.push(answer);
      else if (answer.exists) replacing.push(answer);
    }
    return { replacing, folders, blocked, unchecked };
  }, [answers]);

  // Everything except the destinations that are folders. A request with no
  // answer at all is kept rather than dropped: the preflight not covering it
  // is not evidence that the user did not ask for it.
  const blockedIndices = useMemo(
    () => new Set(groups.blocked.map((answer) => answer.index)),
    [groups.blocked],
  );
  const sending = useMemo(
    () => requests.filter((_, index) => !blockedIndices.has(index)),
    [requests, blockedIndices],
  );

  const direction = directionOf(answers);
  const replacingCount = groups.replacing.length;

  const confirmLabel =
    replacingCount === 0
      ? t("overwrite.confirm", { count: 0 })
      : direction === "download"
        ? t("overwrite.confirmDownload", { count: replacingCount })
        : direction === "upload"
          ? t("overwrite.confirmUpload", { count: replacingCount })
          : t("overwrite.confirm", { count: replacingCount });

  return (
    <DialogFrame
      id="files.overwrite"
      title={t("overwrite.title", { count: replacingCount })}
      busy={busy}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {tCommon("action.cancel")}
          </Button>
          <Button
            variant={replacingCount > 0 ? "danger" : "primary"}
            disabled={busy || sending.length === 0}
            onClick={() => {
              onConfirm({ requests: sending });
            }}
          >
            {confirmLabel}
          </Button>
        </>
      }
    >
      {replacingCount > 0 && (
        <Callout tone="warning">{t("overwrite.permanent")}</Callout>
      )}

      {replacingCount > 0 && (
        <>
          <p className={s.heading}>{t("overwrite.listHeading")}</p>
          <ul className={s.sample}>
            {groups.replacing.map((answer) => (
              <li key={answer.index}>
                <PathLine answer={answer} />
                <span className={s.existing}>
                  {t("overwrite.existing", {
                    size: answer.size === null ? t("value.unknown") : formatBytes(locale, answer.size),
                    when:
                      answer.modified === null
                        ? t("value.unknown")
                        : formatDateTime(locale, answer.modified * 1000, "short"),
                  })}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      {resume && replacingCount > 0 && <p className={s.note}>{t("overwrite.resumeNote")}</p>}

      {groups.folders.length > 0 && (
        <>
          <p className={s.heading}>{t("overwrite.folderHeading", { count: groups.folders.length })}</p>
          <ul className={s.sample}>
            {groups.folders.map((answer) => (
              <li key={answer.index}>
                <PathLine answer={answer} />
              </li>
            ))}
          </ul>
          <p className={s.note}>{t("overwrite.folderNote")}</p>
        </>
      )}

      {groups.blocked.length > 0 && (
        <>
          <p className={s.heading}>{t("overwrite.blockedHeading", { count: groups.blocked.length })}</p>
          <ul className={s.sample}>
            {groups.blocked.map((answer) => (
              <li key={answer.index}>
                <PathLine answer={answer} />
              </li>
            ))}
          </ul>
          <p className={s.note}>{t("overwrite.blockedNote")}</p>
        </>
      )}

      {groups.unchecked.length > 0 && (
        <>
          <p className={s.heading}>{t("overwrite.uncheckedHeading", { count: groups.unchecked.length })}</p>
          <ul className={s.sample}>
            {groups.unchecked.map((answer) => (
              <li key={answer.index}>
                <PathLine answer={answer} />
              </li>
            ))}
          </ul>
          <p className={s.note}>{t("overwrite.uncheckedNote")}</p>
        </>
      )}

      <p className={s.note}>{t("overwrite.sending", { count: sending.length })}</p>
    </DialogFrame>
  );
}

/**
 * One destination path.
 *
 * Always the escaped form the core sent: a download's destination takes its
 * file name from the remote path, so half of it was chosen by the server. A
 * remote path is isolated in the reader's direction; a local one is forced
 * left-to-right, which is what a filesystem path is by specification.
 */
function PathLine({ answer }: { answer: TransferPreflight }) {
  return (
    <span className={s.path}>
      {answer.direction === "download"
        ? isolateLtr(answer.destinationDisplay)
        : isolate(answer.destinationDisplay)}
    </span>
  );
}
