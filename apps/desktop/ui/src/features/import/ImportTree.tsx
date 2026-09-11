/**
 * The tree as it would be created, with every node includable or excludable.
 *
 * This is the whole point of the wizard. Somebody bringing four hundred
 * connections across needs to see exactly what they are about to get and to
 * untick the 2019 archive folder before it lands, so nothing here is
 * summarised: every node the core would create has a row and a tick.
 *
 * Two things the row says that nothing else in the interface would:
 *
 *   - `gateway ×N` — a ProxyJump that became a real gateway chain. It is the
 *     most valuable thing the importer does and it is invisible unless the
 *     preview shows it.
 *   - `+N kept` — settings with no home in the domain model, preserved in
 *     custom fields rather than dropped.
 *
 * The tick is a real checkbox. A folder whose subtree is partly unticked shows
 * the indeterminate state, which only the DOM property can set.
 */

import { useEffect, useRef } from "react";

import { Badge } from "@/components/Badge";
import { Icon, type IconName } from "@/components/Icon";
import { isolate, isolateLtr, useT } from "@/i18n";
import type { ImportNode } from "@/lib/ipc";

import { tickState, type ImportTreeIndex, type TickState } from "./selection";
import s from "./ImportWizard.module.css";

const KIND_ICON: Record<ImportNode["kind"], IconName> = {
  folder: "folder",
  connection: "server",
  credential: "key",
};

const KIND_CLASS: Record<ImportNode["kind"], string> = {
  folder: s.rowIconFolder ?? "",
  connection: s.rowIconConnection ?? "",
  credential: s.rowIconCredential ?? "",
};

interface ImportTreeProps {
  index: ImportTreeIndex;
  excluded: ReadonlySet<string>;
  onToggle: (id: string) => void;
  collapsed: ReadonlySet<string>;
  onToggleCollapsed: (id: string) => void;
  /** `null` means no filter is active and every row is drawn. */
  visible: ReadonlySet<string> | null;
}

export function ImportTree({
  index,
  excluded,
  onToggle,
  collapsed,
  onToggleCollapsed,
  visible,
}: ImportTreeProps) {
  const t = useT("import");
  const rows: ImportNode[] = [];
  for (const id of index.order) {
    const node = index.byId.get(id);
    if (node === undefined) continue;
    if (visible !== null && !visible.has(id)) continue;
    const hidden = (index.ancestors.get(id) ?? []).some((ancestor) => collapsed.has(ancestor));
    if (hidden) continue;
    rows.push(node);
  }

  if (rows.length === 0) return <p className={s.emptyTree}>{t("tree.empty")}</p>;

  // Deliberately not `role="tree"`: the ARIA tree pattern promises roving
  // focus and arrow-key navigation, and this is a list of checkboxes with a
  // visual hierarchy. Claiming the pattern without the keys is the same class
  // of lie as `aria-modal` without a focus trap.
  return (
    <div className={s.treeScroll} role="group" aria-label={t("tree.group")}>
      {rows.map((node) => (
        <TreeRow
          key={node.id}
          node={node}
          depth={index.depth.get(node.id) ?? 0}
          state={tickState(excluded, index, node.id)}
          hasChildren={(index.children.get(node.id) ?? []).length > 0}
          collapsed={collapsed.has(node.id)}
          onToggle={onToggle}
          onToggleCollapsed={onToggleCollapsed}
        />
      ))}
    </div>
  );
}

interface TreeRowProps {
  node: ImportNode;
  depth: number;
  state: TickState;
  hasChildren: boolean;
  collapsed: boolean;
  onToggle: (id: string) => void;
  onToggleCollapsed: (id: string) => void;
}

function TreeRow({
  node,
  depth,
  state,
  hasChildren,
  collapsed,
  onToggle,
  onToggleCollapsed,
}: TreeRowProps) {
  const t = useT("import");
  const check = useRef<HTMLInputElement>(null);

  // `indeterminate` exists only as a DOM property; there is no attribute for
  // it, so a partly-unticked folder can only be shown from an effect.
  useEffect(() => {
    if (check.current !== null) check.current.indeterminate = state === "partial";
  }, [state]);

  // Host, port and account name came out of the file and are the user's own
  // text in whatever script they wrote it. `host:port` is left-to-right by
  // specification — an IPv6 literal reads backwards under first-strong
  // inference — while a user name takes its direction from itself.
  const address = [node.host, node.port === null ? null : `:${node.port}`]
    .filter((part) => part !== null && part !== "")
    .join("");
  const meta = address === "" ? "" : isolateLtr(address);
  const user =
    node.username === null || node.username === "" ? "" : ` · ${isolate(node.username)}`;

  return (
    <div
      className={state === "off" ? `${s.row} ${s.rowOff}` : s.row}
      style={{ paddingInlineStart: `calc(${depth} * var(--space-4))` }}
    >
      {hasChildren ? (
        <button
          type="button"
          className={s.disclosure}
          onClick={() => onToggleCollapsed(node.id)}
          aria-expanded={!collapsed}
          aria-label={
            collapsed
              ? t("tree.expandNode", { name: isolate(node.name) })
              : t("tree.collapseNode", { name: isolate(node.name) })
          }
        >
          <Icon name={collapsed ? "chevron-right" : "chevron-down"} size={13} />
        </button>
      ) : (
        <span className={s.disclosureSpacer} />
      )}

      <input
        ref={check}
        type="checkbox"
        className={s.check}
        checked={state !== "off"}
        onChange={() => onToggle(node.id)}
        aria-label={node.name}
      />

      <span className={`${s.rowIcon} ${KIND_CLASS[node.kind]}`} aria-hidden="true">
        <Icon name={KIND_ICON[node.kind]} size={13} />
      </span>

      <span className={s.rowName}>{node.name}</span>
      {meta !== "" && (
        <span className={s.rowMeta}>
          {meta}
          {user}
        </span>
      )}

      <span className={s.rowTags}>
        {node.gatewayHops > 0 && (
          <Badge tone="accent" title={t("tree.gatewayTitle", { count: node.gatewayHops })}>
            {t("tree.gateway", { hops: node.gatewayHops })}
          </Badge>
        )}
        {node.hasSecret && (
          <Badge tone="warning" title={t("tree.secretTitle")}>
            {t("tree.secret")}
          </Badge>
        )}
        {node.credentialInherited && (
          <Badge tone="success" title={t("tree.inheritedTitle")}>
            {t("tree.inherited")}
          </Badge>
        )}
        {node.customFields > 0 && (
          <Badge tone="neutral" title={t("tree.keptTitle", { count: node.customFields })}>
            {t("tree.kept", { count: node.customFields })}
          </Badge>
        )}
      </span>
    </div>
  );
}
