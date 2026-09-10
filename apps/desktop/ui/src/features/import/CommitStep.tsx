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
import type { IpcFailure } from "@/lib/ipc";

import type { IncludedCounts } from "./selection";
import s from "./ImportWizard.module.css";

const TEXT = {
  title: "Ready to write",
  lead: "This is the step that touches your vault. Everything before it happened in the core's own memory.",
  into: (folder: string) => `Into ${folder}`,
  top: "the top level of the vault",
  connections: "connections",
  folders: "folders",
  credentials: "credentials",
  secrets: "passwords sealed",
  excluded: "unticked, and not written",
  commit: (n: number) => `Import ${n} ${n === 1 ? "item" : "items"}`,
  committing: "Writing the import as one transaction…",
  committingNote:
    "Every node and every sealed password lands together. If anything fails, the vault file is left exactly as it was.",
  failed: "The import was not written.",
  retry: "Try again",
  transactionTitle: "One transaction, and no undo",
  transactionBody:
    "Either all of this reaches your vault file or none of it does. Remoter cannot undo an import afterwards, so anything you did not want should be unticked in the preview before you press the button — deleting it from the tree is the only remedy after.",
  nothing: "Nothing is ticked, so there is nothing to write. Go back to the preview and tick something.",
} as const;

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
  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{TEXT.title}</h2>
        <p className={s.stepLead}>{TEXT.lead}</p>
      </div>

      <div className={s.card}>
        <span className={s.sectionLabel}>{TEXT.into(destinationLabel ?? TEXT.top)}</span>
        <div className={s.counts}>
          <Count value={counts.connections} label={TEXT.connections} />
          <Count value={counts.folders} label={TEXT.folders} />
          <Count value={counts.credentials} label={TEXT.credentials} />
          <Count value={counts.secrets} label={TEXT.secrets} />
          <Count value={excludedCount} label={TEXT.excluded} />
        </div>
      </div>

      <Callout tone="warning" title={TEXT.transactionTitle}>
        <p>{TEXT.transactionBody}</p>
      </Callout>

      {failure !== null && !committing && (
        <FailureNotice
          failure={failure}
          title={TEXT.failed}
          onRetry={onCommit}
          retryLabel={TEXT.retry}
        />
      )}

      {committing && <BusyStatus label={TEXT.committing} note={TEXT.committingNote} size={16} />}

      {counts.total === 0 ? (
        <p className={s.stepLead}>{TEXT.nothing}</p>
      ) : (
        <div className={s.rowActions}>
          <BusyButton
            variant="primary"
            busy={committing}
            busyLabel={TEXT.committing}
            onClick={onCommit}
          >
            {TEXT.commit(counts.total)}
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
