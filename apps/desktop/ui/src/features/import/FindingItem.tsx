/**
 * One finding, rendered.
 *
 * Severity carries an icon and a tint, never colour alone: the report is read
 * by people deciding whether to rotate a set of credentials, and "the red one"
 * is not a distinction a monochrome display or a colour-blind reader can make.
 */

import { Icon } from "@/components/Icon";
import type { ImportFinding } from "@/lib/ipc";

import { describeFinding } from "./findings";
import s from "./ImportWizard.module.css";

interface FindingItemProps {
  finding: ImportFinding;
  /** The side panel's condensed form: one line, no card. */
  compact?: boolean | undefined;
}

export function FindingItem({ finding, compact = false }: FindingItemProps) {
  const view = describeFinding(finding);
  const icon = view.severity === "info" ? "check" : "alert";

  if (compact) {
    return (
      <li className={s.compactFinding}>
        <span className={s.findingIcon} data-severity={view.severity} aria-hidden="true">
          <Icon name={icon} size={13} />
        </span>
        <span>{view.title}</span>
      </li>
    );
  }

  return (
    <li className={s.finding} data-severity={view.severity}>
      <span className={s.findingIcon} aria-hidden="true">
        <Icon name={icon} size={15} />
      </span>
      <div className={s.findingBody}>
        <p className={s.findingTitle}>{view.title}</p>
        {view.body !== "" && <p className={s.findingText}>{view.body}</p>}
        {view.code !== null && <span className={s.findingCode}>{view.code}</span>}
      </div>
    </li>
  );
}
