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

import { fileWasExposed, preservedLines, usedDefaultPassword } from "./findings";
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
  // The folder's breadcrumb is the user's own text; the stand-in for "no
  // folder at all" is interface copy and needs no isolate.
  const destination =
    destinationLabel === null ? t("destination.top") : isolate(destinationLabel);

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.resultHead}>
        <span className={s.resultBadge} aria-hidden="true">
          <Icon name="check" size={17} />
        </span>
        <div className={s.stepHead}>
          <h2 className={s.stepTitle}>{t("result.title", { count: result.imported })}</h2>
          <p className={s.stepLead}>{t("result.lead", { folder: destination })}</p>
        </div>
      </div>

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
