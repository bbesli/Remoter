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
import { isolate, isolateLtr, useT } from "@/i18n";
import type { AuditFilters, TreeNode } from "@/lib/ipc";

import { categoryLabel, outcomeLabel, type AuditT } from "./format";
import {
  DEFAULT_FILTERS,
  isNarrowed,
  TIME_RANGES,
  toggle,
  type AuditFilterState,
  type TimeRange,
} from "./filters";
import s from "./AuditFilterBar.module.css";

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
  const t = useT("audit");

  const nodeOptions = (nodes ?? [])
    // A separator concerns nothing and is never the subject of an audit row.
    .filter((node) => node.kind !== "separator")
    .slice()
    .sort((a, b) => a.name.localeCompare(b.name));

  return (
    <div className={s.bar} role="group" aria-label={t("filters.region")}>
      <label className={s.control}>
        <span className={s.controlLabel}>{t("filters.timeLabel")}</span>
        <select
          className={s.select}
          value={value.range}
          onChange={(e) => onChange({ ...value, range: e.target.value as TimeRange })}
        >
          {TIME_RANGES.map((range) => (
            <option key={range} value={range}>
              {rangeLabel(t, range)}
            </option>
          ))}
        </select>
      </label>

      <div className={s.chips} role="group" aria-label={t("filters.categories")}>
        {available === undefined ? (
          <ChipSkeletons count={4} label={t("filters.loadingVocabulary")} />
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
                {categoryLabel(t, category)}
              </button>
            );
          })
        )}
      </div>

      <div className={s.chips} role="group" aria-label={t("filters.outcomes")}>
        {available === undefined ? (
          <ChipSkeletons count={3} label={t("filters.loadingVocabulary")} />
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
                {outcomeLabel(t, outcome)}
              </button>
            );
          })
        )}
      </div>

      <label className={s.control}>
        <span className={s.controlLabel}>{t("filters.nodeLabel")}</span>
        <select
          className={s.select}
          value={value.nodeId ?? ""}
          disabled={nodes === undefined}
          title={nodes === undefined ? t("filters.nodesLoading") : undefined}
          onChange={(e) =>
            onChange({ ...value, nodeId: e.target.value === "" ? null : e.target.value })
          }
        >
          <option value="">{t("filters.anyNode")}</option>
          {nodeOptions.map((node) => (
            <option key={node.id} value={node.id}>
              {node.host === null || node.host === ""
                ? node.name
                : // Two values from the vault, in either script, joined by a
                  // separator the catalogue owns. Both are isolated so that an
                  // Arabic entry name cannot drag the hostname across the dash
                  // — the host is isolateLtr because a hostname reads
                  // left-to-right whatever characters happen to be in it.
                  t("filters.nodeOption", {
                    name: isolate(node.name),
                    host: isolateLtr(node.host),
                  })}
            </option>
          ))}
        </select>
      </label>

      <div className={s.spacer} />

      {total !== null && (
        // A plural, not a formatted number with a word after it: the count and
        // its noun are one phrase in the languages that inflect one on the
        // other. `#` inside the message formats the number for the locale.
        <span className={s.total}>{t("filters.matching", { count: total })}</span>
      )}

      {isNarrowed(value) && (
        <Button variant="ghost" size="sm" onClick={() => onChange(DEFAULT_FILTERS)}>
          {t("filters.clear")}
        </Button>
      )}
    </div>
  );
}

/**
 * The label for one time window.
 *
 * A switch rather than a computed key so that adding a range to `TIME_RANGES`
 * without adding its message is a compile error rather than a marker on screen.
 */
function rangeLabel(t: AuditT, range: TimeRange): string {
  switch (range) {
    case "24h":
      return t("filters.range.24h");
    case "7d":
      return t("filters.range.7d");
    case "30d":
      return t("filters.range.30d");
    case "90d":
      return t("filters.range.90d");
    case "all":
      return t("filters.range.all");
  }
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
