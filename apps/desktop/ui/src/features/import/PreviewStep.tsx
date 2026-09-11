/**
 * Step 4 — the preview.
 *
 * Nothing has been written. Every node the core would create is on screen with
 * a tick beside it, the counts above the tree follow the ticks, and the panel
 * beside it says what the report will say at length.
 *
 * The honest note about conflicts belongs here rather than in a step of its
 * own. The core does not compare an import against what is already in the
 * vault, so a name that already exists arrives as a second copy. Unticking it
 * now is the only thing that prevents that, and this is the screen where the
 * user can still do it.
 */

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { useT } from "@/i18n";
import type { ImportPreview } from "@/lib/ipc";

import { FindingItem } from "./FindingItem";
import { gatewayFindingCount, sortedBySeverity } from "./findings";
import { ImportTree } from "./ImportTree";
import { includedCounts, type ImportTreeIndex } from "./selection";
import s from "./ImportWizard.module.css";

interface PreviewStepProps {
  preview: ImportPreview;
  index: ImportTreeIndex;
  excluded: ReadonlySet<string>;
  onToggle: (id: string) => void;
  onIncludeAll: () => void;
  onExcludeAll: () => void;
  collapsed: ReadonlySet<string>;
  onToggleCollapsed: (id: string) => void;
  filter: string;
  onFilter: (value: string) => void;
  visible: ReadonlySet<string> | null;
}

export function PreviewStep({
  preview,
  index,
  excluded,
  onToggle,
  onIncludeAll,
  onExcludeAll,
  collapsed,
  onToggleCollapsed,
  filter,
  onFilter,
  visible,
}: PreviewStepProps) {
  const t = useT("import");
  const counts = includedCounts(index, excluded);
  const attention = sortedBySeverity(
    preview.report.findings.filter((f) => f.severity !== "info"),
  ).slice(0, 4);
  const attentionTotal = preview.report.findings.filter((f) => f.severity !== "info").length;
  const gateways = Math.max(gatewayFindingCount(preview.report.findings), counts.gateways);

  return (
    <div className={s.step}>
      <div className={s.headRow}>
        <div className={s.stepHead}>
          <h2 className={s.stepTitle}>{t("preview.title")}</h2>
          <p className={s.stepLead}>{t("preview.lead")}</p>
        </div>
        <div className={s.spacer} />
        <div className={s.counts}>
          <Count value={counts.connections} label={t("preview.countConnections")} />
          <Count value={counts.folders} label={t("preview.countFolders")} />
          <Count value={counts.credentials} label={t("preview.countCredentials")} />
          <Count
            value={attentionTotal}
            label={t("preview.countAttention")}
            tone={attentionTotal > 0 ? "warning" : undefined}
          />
        </div>
      </div>

      {preview.report.truncated && (
        <Callout tone="warning" title={t("preview.truncatedTitle")}>
          <p>{t("preview.truncatedBody")}</p>
        </Callout>
      )}

      <div className={s.panels}>
        <div className={s.treePanel}>
          <div className={s.panelHead}>
            <span className={s.sectionLabel}>{t("preview.treeHead")}</span>
            <div className={s.spacer} />
            <span className={s.panelNote}>{t("preview.treeNote")}</span>
          </div>
          <div className={s.treeToolbar}>
            <span className={s.treeSearch}>
              <TextInput
                value={filter}
                onChange={onFilter}
                placeholder={t("preview.filter")}
                ariaLabel={t("preview.filter")}
              />
            </span>
            <Button variant="ghost" size="sm" onClick={onIncludeAll}>
              {t("preview.includeAll")}
            </Button>
            <Button variant="ghost" size="sm" onClick={onExcludeAll}>
              {t("preview.excludeAll")}
            </Button>
            <span className={s.panelNote}>
              {t("preview.ticked", { included: counts.total, total: preview.nodes.length })}
            </span>
          </div>
          <ImportTree
            index={index}
            excluded={excluded}
            onToggle={onToggle}
            collapsed={collapsed}
            onToggleCollapsed={onToggleCollapsed}
            visible={visible}
          />
        </div>

        <div className={s.side}>
          <div className={s.panel}>
            <span className={s.sectionLabel}>{t("preview.attentionHead")}</span>
            {attention.length === 0 ? (
              <p className={s.panelNote}>{t("preview.attentionNone")}</p>
            ) : (
              <ul className={s.cleanList}>
                {attention.map((finding, i) => (
                  <FindingItem key={`${finding.kind}-${i}`} finding={finding} compact />
                ))}
                {attentionTotal > attention.length && (
                  <li className={s.panelNote}>
                    {t("preview.attentionMore", { count: attentionTotal - attention.length })}
                  </li>
                )}
              </ul>
            )}
          </div>

          <div className={s.panel}>
            <span className={s.sectionLabel}>{t("preview.cleanHead")}</span>
            <ul className={s.cleanList}>
              <Clean>{t("preview.cleanFolders", { count: counts.folders })}</Clean>
              <Clean>{t("preview.cleanCredentials", { count: counts.credentials })}</Clean>
              {gateways > 0 && <Clean>{t("preview.cleanGateways", { count: gateways })}</Clean>}
              {counts.secrets > 0 && (
                <Clean>{t("preview.cleanSecrets", { count: counts.secrets })}</Clean>
              )}
            </ul>
          </div>

          <Callout tone="warning" title={t("preview.conflictsTitle")}>
            <p>{t("preview.conflictsBody")}</p>
          </Callout>
        </div>
      </div>
    </div>
  );
}

function Count({
  value,
  label,
  tone,
}: {
  value: number;
  label: string;
  tone?: "warning" | undefined;
}) {
  return (
    <div className={s.count}>
      <span className={s.countValue} {...(tone === undefined ? {} : { "data-tone": tone })}>
        {value}
      </span>
      <span className={s.countLabel}>{label}</span>
    </div>
  );
}

function Clean({ children }: { children: string }) {
  return (
    <li className={s.cleanItem}>
      <span className={s.cleanTick} aria-hidden="true">
        <Icon name="check" size={12} />
      </span>
      {children}
    </li>
  );
}
