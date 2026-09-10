/**
 * Step 1 — the file, and what the core thinks it is.
 *
 * Detection is the core's job, not a guess from the file extension, so the
 * format shown here is what the content says. The user can still overrule it:
 * a `confCons.xml` saved under another name, or a CSV the sniffer would not
 * commit to, is exactly the case where the person holding the file knows more
 * than the sniffer does.
 */

import { useCallback, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import type { ImportDetection, ImportSource, IpcFailure } from "@/lib/ipc";

import s from "./ImportWizard.module.css";

const TEXT = {
  title: "Choose the file to import",
  lead: "Remoter reads the file to work out what it is. Nothing is written to your vault until you commit, and the parse runs in the core, not in this window.",
  browse: "Choose a file",
  browsing: "Opening…",
  dialogTitle: "Choose a file to import",
  dialogFailed: "The system file dialog did not open. Type the path instead.",
  pathLabel: "Path to the file",
  detecting: "Reading the file's header…",
  detectFailed: "That file could not be read.",
  retry: "Read it again",
  unknownTitle: "Remoter does not recognise this file",
  unknownBody:
    "Nothing in it matched a format this build can read. If you know what it is, choose it below and Remoter will parse it as that. If it parses into nonsense, nothing is lost: the preview is where you would see it, and the preview writes nothing.",
  formatLabel: "Parse it as",
  detected: (label: string) => `${label}, detected from the file`,
  overridden: (label: string) => `${label}, chosen by you`,
  needsPassword: "This file is encrypted. The next step asks for its password.",
  noPassword: "No document password is needed for this file.",
  sources: [
    {
      id: "mremoteng" as ImportSource,
      label: "mRemoteNG",
      hint: "confCons.xml, with or without a document password",
    },
    {
      id: "ssh-config" as ImportSource,
      label: "OpenSSH config",
      hint: "~/.ssh/config, including ProxyJump and Include",
    },
    { id: "csv" as ImportSource, label: "CSV", hint: "A header row and one connection per line" },
  ],
} as const;

interface SourceStepProps {
  path: string;
  onPath: (path: string) => void;
  detection: ImportDetection | null;
  detecting: boolean;
  failure: IpcFailure | null;
  onRetry: () => void;
  /** The format the parse will use: the user's choice, or detection's. */
  source: ImportSource | null;
  onSource: (source: ImportSource) => void;
  overridden: boolean;
}

export function SourceStep({
  path,
  onPath,
  detection,
  detecting,
  failure,
  onRetry,
  source,
  onSource,
  overridden,
}: SourceStepProps) {
  const [browsing, setBrowsing] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const onBrowse = useCallback(() => {
    setBrowsing(true);
    void open({ directory: false, multiple: false, title: TEXT.dialogTitle })
      .then(
        (picked) => {
          setDialogError(null);
          if (typeof picked === "string") onPath(picked);
        },
        () => setDialogError(TEXT.dialogFailed),
      )
      .finally(() => setBrowsing(false));
  }, [onPath]);

  const chosen = TEXT.sources.find((entry) => entry.id === source) ?? null;
  const label =
    chosen === null
      ? null
      : overridden
        ? TEXT.overridden(chosen.label)
        : TEXT.detected(detection?.formatLabel ?? chosen.label);

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{TEXT.title}</h2>
        <p className={s.stepLead}>{TEXT.lead}</p>
      </div>

      <div className={s.card}>
        <div className={s.fileRow}>
          <span className={s.fileIcon} aria-hidden="true">
            <Icon name="file" size={17} />
          </span>
          <div className={s.fileMeta}>
            <span className={s.fileName}>{path === "" ? "No file chosen" : baseName(path)}</span>
            <span className={s.fileFacts}>
              {detection === null
                ? path === ""
                  ? "Choose a file, or type its path."
                  : path
                : `${formatBytes(detection.sizeBytes)}${label === null ? "" : " · "}`}
              {detection !== null && label !== null && <strong>{label}</strong>}
            </span>
          </div>
          <div className={s.spacer} />
          <BusyButton busy={browsing} busyLabel={TEXT.browsing} onClick={onBrowse}>
            {TEXT.browse}
          </BusyButton>
        </div>

        <TextInput
          value={path}
          onChange={onPath}
          mono
          ariaLabel={TEXT.pathLabel}
          placeholder="/home/you/.ssh/config"
        />

        {dialogError !== null && <p className={s.stepLead}>{dialogError}</p>}
        {detecting && <BusyStatus label={TEXT.detecting} />}
        {failure !== null && !detecting && (
          <FailureNotice
            failure={failure}
            title={TEXT.detectFailed}
            onRetry={onRetry}
            retryLabel={TEXT.retry}
          />
        )}
        {detection !== null && detection.format === null && !overridden && (
          <Callout tone="warning" title={TEXT.unknownTitle}>
            <p>{TEXT.unknownBody}</p>
          </Callout>
        )}
        {detection !== null && source !== null && (
          <p className={s.stepLead}>
            {detection.passwordRequired ? TEXT.needsPassword : TEXT.noPassword}
          </p>
        )}
      </div>

      <div className={s.card}>
        <span className={s.sectionLabel}>{TEXT.formatLabel}</span>
        <div className={s.formatList} role="radiogroup" aria-label={TEXT.formatLabel}>
          {TEXT.sources.map((entry) => (
            <button
              key={entry.id}
              type="button"
              role="radio"
              aria-checked={source === entry.id}
              className={s.formatOption}
              data-selected={source === entry.id}
              onClick={() => onSource(entry.id)}
            >
              <span>{entry.label}</span>
              <span className={s.formatHint}>{entry.hint}</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function baseName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut === -1 ? path : path.slice(cut + 1);
}

/** Sizes are shown because a 40 MB confCons.xml explains a slow parse. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 1 : 0)} kB`;
  return `${(kb / 1024).toFixed(1)} MB`;
}
