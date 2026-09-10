/**
 * How an audit row reads.
 *
 * The outcome carries a glyph, a word and a colour — three signals, of which
 * colour is the one that can be missing. A colour-only outcome column is
 * unreadable to a colour-blind reviewer, unreadable in a printed export, and
 * unreadable in high contrast where the palette flattens. So the word is always
 * there and the glyph is always there; the tint is the third thing, not the
 * only thing. (docs/ui/design-system.md, principle 5.)
 *
 * Formatters are built once at module scope. At tens of thousands of rows,
 * constructing an `Intl.DateTimeFormat` per row is measurable.
 */

import type { AuditCategory, AuditOutcome } from "@/lib/ipc";
import type { IconName } from "@/components/Icon";

export type OutcomeTone = "success" | "warning" | "danger";

export interface OutcomeLook {
  /** The word. Present whatever the colour does. */
  word: string;
  icon: IconName;
  tone: OutcomeTone;
}

const OUTCOME_LOOK: Record<AuditOutcome, OutcomeLook> = {
  success: { word: "Succeeded", icon: "check", tone: "success" },
  failure: { word: "Failed", icon: "x", tone: "danger" },
  // Refused, not broken: the action was understood and not permitted. The lock
  // says that in a glyph, which "failed" would not.
  denied: { word: "Denied", icon: "lock", tone: "warning" },
};

const UNKNOWN_OUTCOME: OutcomeLook = { word: "Unknown", icon: "alert", tone: "warning" };

/**
 * The outcome's appearance.
 *
 * Falls back rather than throwing: a vault written by a newer build can hold an
 * outcome this one has no name for, and dropping the row — or crashing the
 * table — would hide exactly the entry someone is looking for.
 */
export function outcomeLook(outcome: AuditOutcome): OutcomeLook {
  return OUTCOME_LOOK[outcome] ?? UNKNOWN_OUTCOME;
}

/**
 * Chip labels.
 *
 * `node` is a change to something in the tree — a connection created, renamed,
 * deleted. `connection` is an attempt to actually reach a host. They are
 * different questions and the words have to keep them apart, which is why
 * neither is called "Connections" alone.
 */
const CATEGORY_LABEL: Record<AuditCategory, string> = {
  vault: "Vault",
  node: "Connection records",
  secret: "Secrets",
  connection: "Sessions",
  warning: "Warnings",
};

export function categoryLabel(category: AuditCategory): string {
  return CATEGORY_LABEL[category] ?? titleCase(category);
}

/** The category shown on a row. `null` is an event this build has no name for. */
export function rowCategoryLabel(category: AuditCategory | null): string {
  return category === null ? "Other" : categoryLabel(category);
}

const OUTCOME_LABEL: Record<AuditOutcome, string> = {
  success: "Succeeded",
  failure: "Failed",
  denied: "Denied",
};

export function outcomeLabel(outcome: AuditOutcome): string {
  return OUTCOME_LABEL[outcome] ?? titleCase(outcome);
}

/**
 * `host_key.changed` reads as "host key changed".
 *
 * The stored spelling is kept in the row's title attribute, because an event
 * name is what someone greps an export for.
 */
export function eventLabel(event: string): string {
  return event.replace(/[._-]+/g, " ").trim();
}

function titleCase(value: string): string {
  const words = eventLabel(value);
  return words.charAt(0).toUpperCase() + words.slice(1);
}

const ROW_TIME = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

const FULL_TIME = new Intl.DateTimeFormat(undefined, {
  dateStyle: "full",
  timeStyle: "long",
});

const COUNT = new Intl.NumberFormat();

/** The compact stamp in the Time column. */
export function formatRowTime(at: number): string {
  return ROW_TIME.format(new Date(at));
}

/** The unambiguous stamp, with the year and the zone, for the row's tooltip. */
export function formatFullTime(at: number): string {
  return FULL_TIME.format(new Date(at));
}

export function formatCount(value: number): string {
  return COUNT.format(value);
}

/** File sizes for the export result. Decimal units, as the platform reports. */
export function formatBytes(bytes: number): string {
  if (bytes < 1000) return `${formatCount(bytes)} bytes`;
  const units = ["kB", "MB", "GB"];
  let value = bytes / 1000;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit] ?? "kB"}`;
}
