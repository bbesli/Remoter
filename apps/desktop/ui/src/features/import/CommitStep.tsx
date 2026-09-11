/**
 * Step 7 — the commit.
 *
 * The last screen on which nothing has happened yet, so it repeats the numbers
 * one final time and says plainly what pressing the button does: one
 * transaction, all of it or none of it, and no way back afterwards.
 *
 * The button is the only control here. Everything else on this step is the
 * sentence that makes pressing it an informed act.
 */

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { isolate, useT } from "@/i18n";
import type { IpcFailure } from "@/lib/ipc";

import type { IncludedCounts } from "./selection";
import s from "./ImportWizard.module.css";

interface CommitStepProps {
  counts: IncludedCounts;
  excludedCount: number;
  destinationLabel: string | null;
  committing: boolean;
  failure: IpcFailure | null;
  onCommit: () => void;
}

export function CommitStep({
  counts,
  excludedCount,
  destinationLabel,
  committing,
  failure,
  onCommit,
}: CommitStepProps) {
  const t = useT("import");
  // A folder's breadcrumb is the user's own text and is isolated; the phrase
  // that stands in for "no folder at all" is interface copy and is not.
  const destination =
    destinationLabel === null ? t("destination.top") : isolate(destinationLabel);

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{t("commit.title")}</h2>
        <p className={s.stepLead}>{t("commit.lead")}</p>
      </div>

      <div className={s.card}>
        <span className={s.sectionLabel}>{t("commit.into", { folder: destination })}</span>
        <div className={s.counts}>
          <Count value={counts.connections} label={t("commit.countConnections")} />
          <Count value={counts.folders} label={t("commit.countFolders")} />
          <Count value={counts.credentials} label={t("commit.countCredentials")} />
          <Count value={counts.secrets} label={t("commit.countSecrets")} />
          <Count value={excludedCount} label={t("commit.countExcluded")} />
        </div>
      </div>

      <Callout tone="warning" title={t("commit.transactionTitle")}>
        <p>{t("commit.transactionBody")}</p>
      </Callout>

      {failure !== null && !committing && (
        <FailureNotice
          failure={failure}
          title={t("commit.failed")}
          onRetry={onCommit}
          retryLabel={t("commit.retry")}
        />
      )}

      {committing && (
        <BusyStatus label={t("commit.committing")} note={t("commit.committingNote")} size={16} />
      )}

      {counts.total === 0 ? (
        <p className={s.stepLead}>{t("commit.nothing")}</p>
      ) : (
        <div className={s.rowActions}>
          <BusyButton
            variant="primary"
            busy={committing}
            busyLabel={t("commit.committing")}
            onClick={onCommit}
          >
            {t("commit.commit", { count: counts.total })}
          </BusyButton>
        </div>
      )}
    </div>
  );
}

function Count({ value, label }: { value: number; label: string }) {
  return (
    <div className={s.count}>
      <span className={s.countValue}>{value}</span>
      <span className={s.countLabel}>{label}</span>
    </div>
  );
}
