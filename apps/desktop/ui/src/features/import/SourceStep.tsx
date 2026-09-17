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
import { formatBytes, isolateLtr, useLocale, useT } from "@/i18n";
import type { ImportDetection, ImportSource, IpcFailure } from "@/lib/ipc";

import s from "./ImportWizard.module.css";

/**
 * The importers this build has, each with the two catalogue keys that name it.
 * The wire values are the core's; the labels and hints are copy. Remoter's own
 * archive is first: it is the one that brings passwords from another Remoter.
 */
const SOURCES: readonly {
  id: ImportSource;
  labelKey:
    | "source.format.archiveLabel"
    | "source.format.mremotengLabel"
    | "source.format.sshConfigLabel"
    | "source.format.csvLabel";
  hintKey:
    | "source.format.archiveHint"
    | "source.format.mremotengHint"
    | "source.format.sshConfigHint"
    | "source.format.csvHint";
}[] = [
  {
    id: "remoter-archive",
    labelKey: "source.format.archiveLabel",
    hintKey: "source.format.archiveHint",
  },
  {
    id: "mremoteng",
    labelKey: "source.format.mremotengLabel",
    hintKey: "source.format.mremotengHint",
  },
  {
    id: "ssh-config",
    labelKey: "source.format.sshConfigLabel",
    hintKey: "source.format.sshConfigHint",
  },
  { id: "csv", labelKey: "source.format.csvLabel", hintKey: "source.format.csvHint" },
];

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
  const t = useT("import");
  const { code: locale } = useLocale();
  const [browsing, setBrowsing] = useState(false);
  const [dialogError, setDialogError] = useState<string | null>(null);

  const onBrowse = useCallback(() => {
    setBrowsing(true);
    void open({ directory: false, multiple: false, title: t("source.dialogTitle") })
      .then(
        (picked) => {
          setDialogError(null);
          if (typeof picked === "string") onPath(picked);
        },
        () => setDialogError(t("source.dialogFailed")),
      )
      .finally(() => setBrowsing(false));
  }, [onPath, t]);

  const chosen = SOURCES.find((entry) => entry.id === source) ?? null;
  // A format's name is a product name and is never translated; it is isolated
  // because it is dropped into a translated sentence. When detection made the
  // choice its own label wins, being the more specific of the two
  // ("mRemoteNG 1.77" rather than "mRemoteNG"); when the user overruled
  // detection, the name of what they picked is the honest thing to show.
  const label =
    chosen === null
      ? null
      : overridden
        ? t("source.chosenAs", { label: isolateLtr(t(chosen.labelKey)) })
        : t("source.detectedAs", {
            label: isolateLtr(detection?.formatLabel ?? t(chosen.labelKey)),
          });

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{t("source.title")}</h2>
        <p className={s.stepLead}>{t("source.lead")}</p>
      </div>

      <div className={s.card}>
        <div className={s.fileRow}>
          <span className={s.fileIcon} aria-hidden="true">
            <Icon name="file" size={17} />
          </span>
          <div className={s.fileMeta}>
            {/* A file name and a path are the user's own text and are left to
                right by specification — a Windows path or an Arabic file name
                would otherwise reorder around its separators. */}
            <span className={s.fileName}>
              {path === "" ? t("source.noFile") : isolateLtr(baseName(path))}
            </span>
            {/* The size is shown because a 40 MB confCons.xml explains a slow
                parse. Through Intl, so a German reader gets 1.234,5 and an
                Egyptian Arabic one gets Arabic-Indic digits. */}
            <span className={s.fileFacts}>
              {detection === null
                ? path === ""
                  ? t("source.noFileHint")
                  : isolateLtr(path)
                : `${formatBytes(locale, detection.sizeBytes)}${label === null ? "" : " · "}`}
              {detection !== null && label !== null && <strong>{label}</strong>}
            </span>
          </div>
          <div className={s.spacer} />
          <BusyButton busy={browsing} busyLabel={t("source.browsing")} onClick={onBrowse}>
            {t("source.browse")}
          </BusyButton>
        </div>

        <TextInput
          value={path}
          onChange={onPath}
          mono
          ariaLabel={t("source.pathLabel")}
          placeholder={t("source.pathPlaceholder")}
        />

        {dialogError !== null && <p className={s.stepLead}>{dialogError}</p>}
        {detecting && <BusyStatus label={t("source.detecting")} />}
        {failure !== null && !detecting && (
          <FailureNotice
            failure={failure}
            title={t("source.detectFailed")}
            onRetry={onRetry}
            retryLabel={t("source.retry")}
          />
        )}
        {detection !== null && detection.format === null && !overridden && (
          <Callout tone="warning" title={t("source.unknownTitle")}>
            <p>{t("source.unknownBody")}</p>
          </Callout>
        )}
        {detection !== null && source !== null && (
          <p className={s.stepLead}>
            {detection.passwordRequired ? t("source.needsPassword") : t("source.noPassword")}
          </p>
        )}
      </div>

      <div className={s.card}>
        <span className={s.sectionLabel}>{t("source.formatLabel")}</span>
        <div className={s.formatList} role="radiogroup" aria-label={t("source.formatLabel")}>
          {SOURCES.map((entry) => (
            <button
              key={entry.id}
              type="button"
              role="radio"
              aria-checked={source === entry.id}
              className={s.formatOption}
              data-selected={source === entry.id}
              onClick={() => onSource(entry.id)}
            >
              <span>{t(entry.labelKey)}</span>
              <span className={s.formatHint}>{t(entry.hintKey)}</span>
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
