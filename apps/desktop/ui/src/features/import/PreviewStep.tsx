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
import type { ImportPreview } from "@/lib/ipc";

import { FindingItem } from "./FindingItem";
import { gatewayFindingCount, sortedBySeverity } from "./findings";
import { ImportTree } from "./ImportTree";
import { includedCounts, type ImportTreeIndex } from "./selection";
import s from "./ImportWizard.module.css";

const TEXT = {
  title: "This is what you will get",
  lead: "Nothing has been written yet. Untick anything you do not want.",
  connections: "connections",
  folders: "folders",
  credentials: "credentials",
  attention: "need attention",
  treeHead: "Tree as it will be created",
  treeNote: "inheritance preserved",
  filter: "Filter by name, host or user",
  includeAll: "Tick everything",
  excludeAll: "Untick everything",
  ticked: (included: number, total: number) => `${included} of ${total} ticked`,
  attentionHead: "Needs attention",
  attentionNone: "The parse found nothing that needs a decision from you.",
  attentionMore: (n: number) => `${n} more on the next step.`,
  cleanHead: "Mapped cleanly",
  cleanFolders: (n: number) => `${n} ${n === 1 ? "folder" : "folders"} with their inheritance`,
  cleanCredentials: (n: number) =>
    `${n} credential ${n === 1 ? "object" : "objects"} and their links`,
  cleanGateways: (n: number) =>
    `${n} jump-host ${n === 1 ? "chain" : "chains"} from ProxyJump, wired up as real gateways`,
  cleanSecrets: (n: number) =>
    `${n} ${n === 1 ? "password" : "passwords"} to seal into the vault on commit`,
  conflictsTitle: "Remoter will not merge with what is already there",
  conflictsBody:
    "This import cannot compare itself against your vault, so anything whose name already exists arrives as a second copy beside the first. Untick it here — that is the only place it can be stopped, because an import cannot be undone once it is committed.",
  truncatedTitle: "This is not the whole file",
  truncatedBody:
    "A safety limit stopped the parse before the end of the document. What you see is everything Remoter read, and importing it is safe; it will not be everything the file contains.",
} as const;

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
          <h2 className={s.stepTitle}>{TEXT.title}</h2>
          <p className={s.stepLead}>{TEXT.lead}</p>
        </div>
        <div className={s.spacer} />
        <div className={s.counts}>
          <Count value={counts.connections} label={TEXT.connections} />
          <Count value={counts.folders} label={TEXT.folders} />
          <Count value={counts.credentials} label={TEXT.credentials} />
          <Count
            value={attentionTotal}
            label={TEXT.attention}
            tone={attentionTotal > 0 ? "warning" : undefined}
          />
        </div>
      </div>

      {preview.report.truncated && (
        <Callout tone="warning" title={TEXT.truncatedTitle}>
          <p>{TEXT.truncatedBody}</p>
        </Callout>
      )}

      <div className={s.panels}>
        <div className={s.treePanel}>
          <div className={s.panelHead}>
            <span className={s.sectionLabel}>{TEXT.treeHead}</span>
            <div className={s.spacer} />
            <span className={s.panelNote}>{TEXT.treeNote}</span>
          </div>
          <div className={s.treeToolbar}>
            <span className={s.treeSearch}>
              <TextInput
                value={filter}
                onChange={onFilter}
                placeholder={TEXT.filter}
                ariaLabel={TEXT.filter}
              />
            </span>
            <Button variant="ghost" size="sm" onClick={onIncludeAll}>
              {TEXT.includeAll}
            </Button>
            <Button variant="ghost" size="sm" onClick={onExcludeAll}>
              {TEXT.excludeAll}
            </Button>
            <span className={s.panelNote}>{TEXT.ticked(counts.total, preview.nodes.length)}</span>
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
            <span className={s.sectionLabel}>{TEXT.attentionHead}</span>
            {attention.length === 0 ? (
              <p className={s.panelNote}>{TEXT.attentionNone}</p>
            ) : (
              <ul className={s.cleanList}>
                {attention.map((finding, i) => (
                  <FindingItem key={`${finding.kind}-${i}`} finding={finding} compact />
                ))}
                {attentionTotal > attention.length && (
                  <li className={s.panelNote}>
                    {TEXT.attentionMore(attentionTotal - attention.length)}
                  </li>
                )}
              </ul>
            )}
          </div>

          <div className={s.panel}>
            <span className={s.sectionLabel}>{TEXT.cleanHead}</span>
            <ul className={s.cleanList}>
              <Clean>{TEXT.cleanFolders(counts.folders)}</Clean>
              <Clean>{TEXT.cleanCredentials(counts.credentials)}</Clean>
              {gateways > 0 && <Clean>{TEXT.cleanGateways(gateways)}</Clean>}
              {counts.secrets > 0 && <Clean>{TEXT.cleanSecrets(counts.secrets)}</Clean>}
            </ul>
          </div>

          <Callout tone="warning" title={TEXT.conflictsTitle}>
            <p>{TEXT.conflictsBody}</p>
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
