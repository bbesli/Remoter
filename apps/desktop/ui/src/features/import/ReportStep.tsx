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
import type { ImportReport } from "@/lib/ipc";

import { FindingItem } from "./FindingItem";
import { bySeverity, preservedLines } from "./findings";
import s from "./ImportWizard.module.css";

const TEXT = {
  title: "What the parse found",
  lead: "Read this before you commit. Everything on it is still changeable — the preview is one step back, and nothing has been written.",
  parsed: "Parsed",
  folders: "folders",
  connections: "connections",
  credentials: "credentials",
  secrets: "passwords recovered",
  skipped: "skipped by the parser",
  alerts: "Act on these",
  warnings: "Worth knowing",
  info: "For the record",
  none: "Nothing to report. The file mapped cleanly.",
  preservedHead: "Kept but not interpreted",
  preservedNote:
    "Nothing was discarded. If a later version of Remoter learns to read these, they will be there.",
  skippedTitle: "Some items were left out by the parser",
  skippedBody:
    "They are listed above with the reason. They are not in the preview and will not be imported; the file itself is untouched, so nothing about them is lost.",
} as const;

interface ReportStepProps {
  report: ImportReport;
}

export function ReportStep({ report }: ReportStepProps) {
  const alerts = bySeverity(report.findings, "alert");
  const warnings = bySeverity(report.findings, "warning");
  const info = bySeverity(report.findings, "info");
  const preserved = preservedLines(report.findings);

  return (
    <div className={s.step}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{TEXT.title}</h2>
        <p className={s.stepLead}>{TEXT.lead}</p>
      </div>

      <div className={s.tiles}>
        <Tile value={report.counts.folders} label={TEXT.folders} />
        <Tile value={report.counts.connections} label={TEXT.connections} />
        <Tile value={report.counts.credentials} label={TEXT.credentials} />
        <Tile
          value={report.counts.secrets}
          label={TEXT.secrets}
          tone={report.counts.secrets > 0 ? "warning" : "muted"}
        />
        <Tile
          value={report.counts.skipped}
          label={TEXT.skipped}
          tone={report.counts.skipped > 0 ? "warning" : "muted"}
        />
      </div>

      {report.findings.length === 0 && <p className={s.stepLead}>{TEXT.none}</p>}

      <Group label={TEXT.alerts} findings={alerts} />
      <Group label={TEXT.warnings} findings={warnings} />
      <Group label={TEXT.info} findings={info} />

      {report.counts.skipped > 0 && (
        <Callout tone="neutral" title={TEXT.skippedTitle}>
          <p>{TEXT.skippedBody}</p>
        </Callout>
      )}

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
