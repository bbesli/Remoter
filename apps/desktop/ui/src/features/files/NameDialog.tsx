/**
 * Creating a folder and renaming an entry — one dialog, because they are one
 * question: what should this be called?
 *
 * # Why the rename field is pre-filled with the escaped name
 *
 * A listing shows `displayName`, never the raw one, so that a name carrying a
 * right-to-left override cannot draw itself as something it is not. The rename
 * field therefore starts from the same string the row showed: pre-filling with
 * the raw name would put the invisible characters back into an editable field,
 * where they are invisible again and where the user cannot tell which of them
 * they just deleted.
 *
 * The consequence is that accepting the pre-filled value *renames the file* —
 * to the visible, written-out form. That is usually exactly what someone
 * opening this dialog on such a file wants, and it is never a surprise, because
 * `rename.escapedWarning` says so above the field whenever the name is not
 * clean. What the dialog must never do is quietly send the escaped text as if
 * it were the original: the "unchanged" check below compares against the *raw*
 * name, so on a hostile name the button stays enabled and the rename is real.
 *
 * The old name always travels as `entry.name`, raw. The escaped form addresses
 * nothing, here or anywhere.
 */

import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { TextInput } from "@/components/TextInput";
import { isolate, useT } from "@/i18n";
import { asFailure, ipc, type DirectoryEntry, type IpcFailure } from "@/lib/ipc";
import { invalidatePane } from "@/lib/queryKeys";

import { DialogFrame } from "./DialogFrame";
import { joinPath, validateName, type NameRefusal } from "./path";

interface NameDialogProps {
  paneId: number;
  /** The folder the new entry goes in, raw. For a rename, the entry's parent. */
  directory: string;
  /** The same, escaped. Shown, never sent. */
  directoryDisplay: string;
  /** Absent for a new folder; present for a rename. */
  entry?: DirectoryEntry | undefined;
  onClose: () => void;
}

const REFUSAL_KEYS = {
  empty: "name.empty",
  separator: "name.separator",
  dots: "name.dots",
  control: "name.control",
} as const satisfies Record<NameRefusal, string>;

export function NameDialog({ paneId, directory, directoryDisplay, entry, onClose }: NameDialogProps) {
  const t = useT("files");
  const tCommon = useT("common");
  const queryClient = useQueryClient();

  const renaming = entry !== undefined;
  const [value, setValue] = useState(entry?.displayName ?? "");
  const [attempted, setAttempted] = useState(false);
  const [problem, setProblem] = useState<IpcFailure | null>(null);

  const trimmed = value.trim();
  const refusal = validateName(value);
  // Compared against the raw name, not the escaped one. See the header.
  const unchanged = renaming && entry !== undefined && trimmed === entry.name;
  const refusalText =
    refusal !== null ? t(REFUSAL_KEYS[refusal]) : unchanged ? t("name.unchanged") : null;

  const run = useMutation({
    mutationFn: async () => {
      const target = joinPath(directory, trimmed);
      if (renaming && entry !== undefined) {
        // The old path travels raw, exactly as the server sent it.
        await ipc.renamePath(paneId, entry.path, target);
        return;
      }
      await ipc.makeDirectory(paneId, target);
    },
    onSuccess: async () => {
      await invalidatePane(queryClient, paneId);
      onClose();
    },
    onError: (error: unknown) => {
      setProblem(asFailure(error));
    },
  });

  const busy = run.isPending;

  const submit = () => {
    setAttempted(true);
    setProblem(null);
    if (refusalText !== null || busy) return;
    run.mutate();
  };

  const title = renaming
    ? t("rename.title", { name: isolate(entry?.displayName ?? "") })
    : t("newFolder.title");

  return (
    <DialogFrame
      id={renaming ? "files.rename" : "files.new-folder"}
      title={title}
      busy={busy}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            {tCommon("action.cancel")}
          </Button>
          <Button variant="primary" onClick={submit} disabled={busy}>
            {renaming ? t("rename.apply") : t("newFolder.create")}
          </Button>
        </>
      }
    >
      {!renaming && (
        // A path, so it is forced left-to-right rather than left to the bidi
        // algorithm to infer from whatever the first folder is called.
        <p>{t("newFolder.in", { path: isolate(directoryDisplay) })}</p>
      )}

      {renaming && entry !== undefined && !isClean(entry) && (
        <Callout tone="warning">{t("rename.escapedWarning")}</Callout>
      )}

      <Field
        label={renaming ? t("rename.label") : t("newFolder.label")}
        htmlFor="files-name"
        {...(attempted && refusalText !== null ? { error: refusalText } : {})}
      >
        <TextInput
          id="files-name"
          value={value}
          onChange={setValue}
          autoFocus
          mono
          disabled={busy}
          invalid={attempted && refusalText !== null}
          onKeyDown={(e) => {
            if (e.key === "Enter") submit();
          }}
        />
      </Field>

      {problem !== null && (
        <FailureNotice failure={problem} onRetry={busy ? undefined : submit} />
      )}
    </DialogFrame>
  );
}

/** Whether the name is exactly what it appears to be. */
function isClean(entry: DirectoryEntry): boolean {
  const r = entry.risks;
  return !r.control && !r.bidi && !r.invisible && !r.separator;
}
