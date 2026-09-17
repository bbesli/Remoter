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
import { isolate, useT } from "@/i18n";
import type { ImportReport, ImportResult } from "@/lib/ipc";

import { FindingItem } from "./FindingItem";
import { fileWasExposed, preservedLines, refusedItems, usedDefaultPassword } from "./findings";
import s from "./ImportWizard.module.css";

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
  const t = useT("import");
  const findings = report?.findings ?? [];
  const exposed = fileWasExposed(findings) && result.secretsStored > 0;
  const preserved = preservedLines(t, findings);
  /**
   * What the parser refused. Named here rather than left to the report step,
   * which the reader may have walked straight past: this is the last screen of
   * the flow and the only one they are guaranteed to have seen.
   */
  const refused = refusedItems(findings);
  /**
   * The count the core counted, which can exceed the findings shown when the
   * findings list hit its ceiling. The count is what the heading states; the
   * list below it is as much of the detail as survived.
   */
  const refusedCount = report?.counts.skipped ?? refused.length;
  const partial = refusedCount > 0;
  // The folder's breadcrumb is the user's own text; the stand-in for "no
  // folder at all" is interface copy and needs no isolate.
  const destination =
    destinationLabel === null ? t("destination.top") : isolate(destinationLabel);

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.resultHead}>
        {/* A partial import does not get a green tick. See the note on
            `.resultBadge[data-tone="warning"]`. */}
        <span
          className={s.resultBadge}
          {...(partial ? { "data-tone": "warning" } : {})}
          aria-hidden="true"
        >
          <Icon name={partial ? "alert" : "check"} size={17} />
        </span>
        <div className={s.stepHead}>
          <h2 className={s.stepTitle}>{t("result.title", { count: result.imported })}</h2>
          <p className={s.stepLead}>{t("result.lead", { folder: destination })}</p>
        </div>
      </div>

      {partial && (
        <Callout tone="warning" title={t("result.refusedTitle", { count: refusedCount })}>
          <p>{t("result.refusedBody")}</p>
          {refused.length > 0 && (
            <ul className={s.findingList}>
              {refused.map((finding, index) => (
                // Keyed by position: two entries in a confCons.xml may carry
                // the same name, and the list is ordered by the file.
                <FindingItem key={index} finding={finding} />
              ))}
            </ul>
          )}
          {refused.length < refusedCount && (
            <p className={s.panelNote}>
              {t("result.refusedNotAllListed", { count: refusedCount - refused.length })}
            </p>
          )}
        </Callout>
      )}

      <div className={s.tiles}>
        <Tile value={result.imported} label={t("result.countImported")} tone="success" />
        <Tile value={result.skipped} label={t("result.countSkipped")} tone="muted" />
        <Tile
          value={result.needsAttention}
          label={t("result.countAttention")}
          tone={result.needsAttention > 0 ? "warning" : "muted"}
        />
        <Tile
          value={result.secretsStored}
          label={t("result.countSecrets")}
          tone={result.secretsStored > 0 ? "warning" : "muted"}
        />
      </div>

      {(result.replaced > 0 || result.unchanged > 0 || result.merged > 0) && (
        <Callout tone="neutral" title={t("result.conflictsTitle")}>
          {result.replaced > 0 && <p>{t("result.replaced", { count: result.replaced })}</p>}
          {result.unchanged > 0 && <p>{t("result.unchanged", { count: result.unchanged })}</p>}
          {result.merged > 0 && <p>{t("result.merged", { count: result.merged })}</p>}
        </Callout>
      )}

      {exposed && (
        <Callout tone="danger" title={t("result.rotateTitle")}>
          {/* One sentence, not a count glued to a clause: how many passwords
              are at stake and why is one statement, and its word order is not
              English's everywhere. */}
          <p>
            {usedDefaultPassword(findings)
              ? t("result.rotateDefault", { count: result.secretsStored })
              : t("result.rotateLegacy", { count: result.secretsStored })}
          </p>
          <p>{t("result.rotateAfter")}</p>
        </Callout>
      )}

      <Callout tone="neutral" title={t("result.noUndoTitle")}>
        <p>{t("result.noUndoBody")}</p>
      </Callout>

      {preserved.length > 0 && (
        <div className={s.findingGroup}>
          <span className={s.sectionLabel}>{t("result.preservedHead")}</span>
          <div className={s.preserved}>
            {preserved.map((line) => (
              <div key={line.field} className={s.preservedLine}>
                <span className={s.preservedField}>{line.field}</span>
                <span>{line.detail}</span>
              </div>
            ))}
          </div>
          <p className={s.panelNote}>{t("result.preservedNote")}</p>
        </div>
      )}

      <div className={s.rowActions}>
        <Button variant="primary" onClick={onDone}>
          {t("result.done")}
        </Button>
        <Button onClick={onAnother}>{t("result.another")}</Button>
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
