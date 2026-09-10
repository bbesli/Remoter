/**
 * Step 8 — what was written.
 *
 * Two things on this screen exist because they are true and unwelcome:
 *
 *   - a file protected by mRemoteNG's default password, or by the legacy
 *     AES-CBC scheme, has already leaked every credential it holds to anyone
 *     who ever had a copy. Those passwords are now in the vault, and they are
 *     still the passwords the servers accept. Saying "rotate them" is the only
 *     honest ending.
 *   - there is no undo. The core writes the import in one transaction and has
 *     no command to take it back, so this screen says what to do instead
 *     rather than offering a button that would fail.
 */

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import type { ImportReport, ImportResult } from "@/lib/ipc";

import { fileWasExposed, preservedLines, usedDefaultPassword } from "./findings";
import s from "./ImportWizard.module.css";

const TEXT = {
  title: (n: number) => `${n} ${n === 1 ? "item is" : "items are"} in your vault`,
  lead: (folder: string) => `Written into ${folder} as one transaction.`,
  top: "the top level of the vault",
  imported: "imported",
  skipped: "unticked by you",
  attention: "need a look",
  secrets: "passwords sealed",

  rotateTitle: "Rotate these credentials",
  rotateDefault:
    "came out of a file encrypted with mRemoteNG's well-known default password. Anyone who has ever held a copy of that file already knows them.",
  rotateLegacy:
    "came out of a file encrypted with the legacy AES-CBC scheme, whose key was an unsalted hash of the password. Anyone who has held a copy of that file could have read them.",
  rotateAfter:
    "They are safe in the vault now, but they are still the passwords the servers accept. Change them there, then update them here.",

  noUndoTitle: "There is no undo",
  noUndoBody:
    "Remoter cannot take an import back. If this is not what you wanted, delete the imported nodes from the tree — they are together under the folder you chose, which is why choosing one is worth doing.",

  preservedHead: "Kept but not interpreted",
  preservedNote:
    "Nothing was discarded. If a later version of Remoter learns to read these, they will be there.",

  done: "Done",
  another: "Import another file",
} as const;

interface ResultStepProps {
  result: ImportResult;
  /** The report from the preview that produced this result. */
  report: ImportReport | null;
  destinationLabel: string | null;
  onDone: () => void;
  onAnother: () => void;
}

export function ResultStep({
  result,
  report,
  destinationLabel,
  onDone,
  onAnother,
}: ResultStepProps) {
  const findings = report?.findings ?? [];
  const exposed = fileWasExposed(findings) && result.secretsStored > 0;
  const preserved = preservedLines(findings);

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.resultHead}>
        <span className={s.resultBadge} aria-hidden="true">
          <Icon name="check" size={17} />
        </span>
        <div className={s.stepHead}>
          <h2 className={s.stepTitle}>{TEXT.title(result.imported)}</h2>
          <p className={s.stepLead}>{TEXT.lead(destinationLabel ?? TEXT.top)}</p>
        </div>
      </div>

      <div className={s.tiles}>
        <Tile value={result.imported} label={TEXT.imported} tone="success" />
        <Tile value={result.skipped} label={TEXT.skipped} tone="muted" />
        <Tile
          value={result.needsAttention}
          label={TEXT.attention}
          tone={result.needsAttention > 0 ? "warning" : "muted"}
        />
        <Tile
          value={result.secretsStored}
          label={TEXT.secrets}
          tone={result.secretsStored > 0 ? "warning" : "muted"}
        />
      </div>

      {exposed && (
        <Callout tone="danger" title={TEXT.rotateTitle}>
          <p>
            {`${result.secretsStored} ${result.secretsStored === 1 ? "password" : "passwords"} `}
            {usedDefaultPassword(findings) ? TEXT.rotateDefault : TEXT.rotateLegacy}
          </p>
          <p>{TEXT.rotateAfter}</p>
        </Callout>
      )}

      <Callout tone="neutral" title={TEXT.noUndoTitle}>
        <p>{TEXT.noUndoBody}</p>
      </Callout>

      {preserved.length > 0 && (
        <div className={s.findingGroup}>
          <span className={s.sectionLabel}>{TEXT.preservedHead}</span>
          <div className={s.preserved}>
            {preserved.map((line) => (
              <div key={line.field} className={s.preservedLine}>
                <span className={s.preservedField}>{line.field}</span>
                <span>{line.detail}</span>
              </div>
            ))}
          </div>
          <p className={s.panelNote}>{TEXT.preservedNote}</p>
        </div>
      )}

      <div className={s.rowActions}>
        <Button variant="primary" onClick={onDone}>
          {TEXT.done}
        </Button>
        <Button onClick={onAnother}>{TEXT.another}</Button>
      </div>
    </div>
  );
}

function Tile({
  value,
  label,
  tone,
}: {
  value: number;
  label: string;
  tone: "success" | "warning" | "muted";
}) {
  return (
    <div className={s.tile}>
      <div className={s.tileValue} data-tone={tone}>
        {value}
      </div>
      <div className={s.tileLabel}>{label}</div>
    </div>
  );
}
