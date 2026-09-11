/**
 * Step 5 — the report: what came in, what could not be mapped, and why.
 *
 * Grouped by severity, worst first, because the reader's question is "is there
 * anything here I have to act on?" and the answer must be at the top.
 *
 * The last section is the one people do not expect: where a setting had no
 * equivalent in the domain model it was kept verbatim in a custom field rather
 * than dropped. Saying so is reassuring, and it is true — which is why it is
 * built from the core's own findings rather than written as a promise.
 */

import { Callout } from "@/components/Callout";
import { useT } from "@/i18n";
import type { ImportReport } from "@/lib/ipc";

import { FindingItem } from "./FindingItem";
import { bySeverity, preservedLines } from "./findings";
import s from "./ImportWizard.module.css";

interface ReportStepProps {
  report: ImportReport;
}

export function ReportStep({ report }: ReportStepProps) {
  const t = useT("import");
  const alerts = bySeverity(report.findings, "alert");
  const warnings = bySeverity(report.findings, "warning");
  const info = bySeverity(report.findings, "info");
  const preserved = preservedLines(t, report.findings);

  return (
    <div className={s.step}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{t("report.title")}</h2>
        <p className={s.stepLead}>{t("report.lead")}</p>
      </div>

      <div className={s.tiles}>
        <Tile value={report.counts.folders} label={t("report.countFolders")} />
        <Tile value={report.counts.connections} label={t("report.countConnections")} />
        <Tile value={report.counts.credentials} label={t("report.countCredentials")} />
        <Tile
          value={report.counts.secrets}
          label={t("report.countSecrets")}
          tone={report.counts.secrets > 0 ? "warning" : "muted"}
        />
        <Tile
          value={report.counts.skipped}
          label={t("report.countSkipped")}
          tone={report.counts.skipped > 0 ? "warning" : "muted"}
        />
      </div>

      {report.findings.length === 0 && <p className={s.stepLead}>{t("report.none")}</p>}

      <Group label={t("report.groupAlerts")} findings={alerts} />
      <Group label={t("report.groupWarnings")} findings={warnings} />
      <Group label={t("report.groupInfo")} findings={info} />

      {report.counts.skipped > 0 && (
        <Callout tone="neutral" title={t("report.skippedTitle")}>
          <p>{t("report.skippedBody")}</p>
        </Callout>
      )}

      {preserved.length > 0 && (
        <div className={s.findingGroup}>
          <span className={s.sectionLabel}>{t("report.preservedHead")}</span>
          <div className={s.preserved}>
            {preserved.map((line) => (
              <div key={line.field} className={s.preservedLine}>
                <span className={s.preservedField}>{line.field}</span>
                <span>{line.detail}</span>
              </div>
            ))}
          </div>
          <p className={s.panelNote}>{t("report.preservedNote")}</p>
        </div>
      )}
    </div>
  );
}

function Group({
  label,
  findings,
}: {
  label: string;
  findings: ReadonlyArray<ImportReport["findings"][number]>;
}) {
  if (findings.length === 0) return null;
  return (
    <section className={s.findingGroup}>
      <span className={s.sectionLabel}>{label}</span>
      <ul className={s.findingList}>
        {findings.map((finding, i) => (
          <FindingItem key={`${finding.kind}-${i}`} finding={finding} />
        ))}
      </ul>
    </section>
  );
}

function Tile({
  value,
  label,
  tone,
}: {
  value: number;
  label: string;
  tone?: "warning" | "muted" | "success" | undefined;
}) {
  return (
    <div className={s.tile}>
      <div className={s.tileValue} {...(tone === undefined ? {} : { "data-tone": tone })}>
        {value}
      </div>
      <div className={s.tileLabel}>{label}</div>
    </div>
  );
}
