/**
 * The filter bar.
 *
 * Every value in it comes from the core: the categories and outcomes from
 * `audit_filters`, the nodes from the tree. Nothing here is a hardcoded list,
 * because a hardcoded list drifts — the build that adds a category would leave
 * this screen with no chip for it and no sign that anything was missing.
 *
 * Until the vocabulary arrives the chips are skeletons rather than a guess, and
 * the range control still works: a time range needs no vocabulary.
 */

import clsx from "clsx";

import { Button } from "@/components/Button";
import { Icon } from "@/components/Icon";
import { Skeleton } from "@/components/Busy";
import type { AuditFilters, TreeNode } from "@/lib/ipc";

import { categoryLabel, formatCount, outcomeLabel } from "./format";
import {
  DEFAULT_FILTERS,
  isNarrowed,
  TIME_RANGES,
  toggle,
  type AuditFilterState,
  type TimeRange,
} from "./filters";
import s from "./AuditFilterBar.module.css";

const TEXT = {
  region: "Audit log filters",
  range: "Time",
  rangeLabels: {
    "24h": "Last 24 hours",
    "7d": "Last 7 days",
    "30d": "Last 30 days",
    "90d": "Last 90 days",
    all: "Everything",
  } as Record<TimeRange, string>,

  categories: "Event category",
  outcomes: "Outcome",
  loadingVocabulary: "Reading the log's own filter list…",

  node: "Node",
  anyNode: "Any node",
  nodesLoading: "Reading the tree…",

  clear: "Clear filters",
  matching: (n: string) => `${n} matching`,
  matchingOne: "1 matching",
} as const;

interface AuditFilterBarProps {
  value: AuditFilterState;
  onChange: (next: AuditFilterState) => void;
  /** The core's vocabulary. `undefined` while `audit_filters` is in flight. */
  available: AuditFilters | undefined;
  nodes: readonly TreeNode[] | undefined;
  /** How many entries match, once a page has answered. */
  total: number | null;
}

export function AuditFilterBar({ value, onChange, available, nodes, total }: AuditFilterBarProps) {
  const nodeOptions = (nodes ?? [])
    // A separator concerns nothing and is never the subject of an audit row.
    .filter((node) => node.kind !== "separator")
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div className={s.bar} role="group" aria-label={TEXT.region}>
      <label className={s.control}>
        <span className={s.controlLabel}>{TEXT.range}</span>
        <select
          className={s.select}
          value={value.range}
          onChange={(e) => onChange({ ...value, range: e.target.value as TimeRange })}
        >
          {TIME_RANGES.map((range) => (
            <option key={range} value={range}>
              {TEXT.rangeLabels[range]}
            </option>
          ))}
        </select>
      </label>

      <div className={s.chips} role="group" aria-label={TEXT.categories}>
        {available === undefined ? (
          <ChipSkeletons count={4} label={TEXT.loadingVocabulary} />
        ) : (
          available.categories.map((category) => {
            const on = value.categories.includes(category);
            return (
              <button
                key={category}
                type="button"
                aria-pressed={on}
                className={clsx(s.chip, on && s.chipOn, category === "warning" && s.chipWarning)}
                onClick={() => onChange({ ...value, categories: toggle(value.categories, category) })}
              >
                {category === "warning" && <Icon name="alert" size={12} />}
                {categoryLabel(category)}
              </button>
            );
          })
        )}
      </div>

      <div className={s.chips} role="group" aria-label={TEXT.outcomes}>
        {available === undefined ? (
          <ChipSkeletons count={3} label={TEXT.loadingVocabulary} />
        ) : (
          available.outcomes.map((outcome) => {
            const on = value.outcomes.includes(outcome);
            return (
              <button
                key={outcome}
                type="button"
                aria-pressed={on}
                className={clsx(s.chip, on && s.chipOn)}
                onClick={() => onChange({ ...value, outcomes: toggle(value.outcomes, outcome) })}
              >
                {outcomeLabel(outcome)}
              </button>
            );
          })
        )}
      </div>

      <label className={s.control}>
        <span className={s.controlLabel}>{TEXT.node}</span>
        <select
          className={s.select}
          value={value.nodeId ?? ""}
          disabled={nodes === undefined}
          title={nodes === undefined ? TEXT.nodesLoading : undefined}
          onChange={(e) =>
            onChange({ ...value, nodeId: e.target.value === "" ? null : e.target.value })
          }
        >
          <option value="">{TEXT.anyNode}</option>
          {nodeOptions.map((node) => (
            <option key={node.id} value={node.id}>
              {node.host === null || node.host === "" ? node.name : `${node.name} — ${node.host}`}
            </option>
          ))}
        </select>
      </label>

      <div className={s.spacer} />

      {total !== null && (
        <span className={s.total}>
          {total === 1 ? TEXT.matchingOne : TEXT.matching(formatCount(total))}
        </span>
      )}

      {isNarrowed(value) && (
        <Button variant="ghost" size="sm" onClick={() => onChange(DEFAULT_FILTERS)}>
          {TEXT.clear}
        </Button>
      )}
    </div>
  );
}

function ChipSkeletons({ count, label }: { count: number; label: string }) {
  return (
    <span className={s.chipSkeletons} role="status" aria-label={label}>
      {Array.from({ length: count }, (_unused, index) => (
        <Skeleton key={index} width="5.5rem" height="var(--space-6)" />
      ))}
    </span>
  );
}
