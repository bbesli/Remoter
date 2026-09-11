/**
 * One row of the connection tree.
 *
 * The row is a plain `div` with `role="treeitem"` rather than a button: the
 * tree owns focus and moves a cursor with `aria-activedescendant`, which is
 * what lets Up/Down behave the way every file manager has taught people to
 * expect. A row full of nested buttons would fight that.
 *
 * Everything here is remote-authored text — names, hostnames, tags — so it is
 * rendered as text and never as markup.
 *
 * The row is also the drag source and the drop target. It decides only which
 * band of itself the pointer is in; whether that band can accept the drag is
 * the tree's question, because only the tree knows what is being dragged.
 */

import { memo, type CSSProperties, type DragEvent, type MouseEvent } from "react";
import clsx from "clsx";

import { Badge } from "@/components/Badge";
import { Icon, type IconName } from "@/components/Icon";
import { useT } from "@/i18n";
import type { TreeNode } from "@/lib/ipc";

import s from "./NodeRow.module.css";

/**
 * The drag payload carries a node id under a private type.
 *
 * Not `text/plain`: a drop into another application would then paste the
 * contents of a vault into it.
 */
export const NODE_DRAG_MIME = "application/x-remoter-node";

/** Where a drop would put the dragged node relative to this row. */
export type DropBand = "before" | "into" | "after";

/**
 * Which band of the row the pointer is in.
 *
 * Outer quarters mean "between two rows", the middle half means "inside this
 * row". Every file manager splits a row this way, so the gesture needs no
 * teaching — but it does mean the between-bands are only a few pixels tall,
 * which is why the indicator has to be unmistakable once you are in one.
 */
function bandAt(e: DragEvent<HTMLElement>): DropBand {
  const rect = e.currentTarget.getBoundingClientRect();
  const offset = rect.height === 0 ? 0.5 : (e.clientY - rect.top) / rect.height;
  if (offset < 0.25) return "before";
  if (offset > 0.75) return "after";
  return "into";
}

/** Protocols the shipped adapters cover; anything else falls back to a server. */
function protocolGlyph(protocol: string | null): IconName {
  switch (protocol) {
    case "sftp":
      return "file";
    case "rdp":
    case "vnc":
      return "server";
    default:
      return "server";
  }
}

/**
 * The colour a protocol carries in the sidebar and the palette.
 *
 * Exported because the command palette lists the same nodes and must not
 * invent a second colour language for them.
 */
export function protocolClass(protocol: string | null): string | undefined {
  switch (protocol) {
    case "ssh":
      return s.protoSsh;
    case "rdp":
      return s.protoRdp;
    case "sftp":
      return s.protoSftp;
    case "vnc":
      return s.protoVnc;
    default:
      return undefined;
  }
}

/** The icon that stands for a node in any list. */
export function nodeGlyph(node: TreeNode): IconName {
  switch (node.kind) {
    case "folder":
    case "group":
      return "folder";
    case "credential":
      return "key";
    case "separator":
      return "file";
    case "connection":
      return protocolGlyph(node.protocol);
  }
}

export interface NodeRowProps {
  node: TreeNode;
  /** Nesting level; 0 is a root or a favourite. */
  depth: number;
  hasChildren: boolean;
  expanded: boolean;
  selected: boolean;
  /** The keyboard cursor, which moves independently of the selection. */
  cursored: boolean;
  /** DOM id, so the tree can point `aria-activedescendant` at this row. */
  domId: string;
  /** False for the favourites projection, which has no position to drag from. */
  draggable: boolean;
  /** False for rows that are a projection rather than a place in the tree. */
  droppable: boolean;
  /** True while this row is the node being dragged. */
  dragging: boolean;
  /** The band the drag is hovering, or null when this row is not the target. */
  dropBand: DropBand | null;
  /** True when the hovered band cannot accept the drag. */
  dropRefused: boolean;
  /** Callbacks take the id so the tree can memoise them across renders. */
  onToggle: (id: string) => void;
  onSelect: (id: string) => void;
  onActivate: (id: string) => void;
  onContextMenu: (id: string, x: number, y: number) => void;
  onDragStartRow: (id: string) => void;
  /** Returns false when the band cannot take the drag, so the row can refuse it. */
  onDragOverRow: (id: string, band: DropBand) => boolean;
  onDragLeaveRow: (id: string) => void;
  onDropRow: (id: string) => void;
  onDragEndRow: () => void;
}

export const NodeRow = memo(function NodeRow({
  node,
  depth,
  hasChildren,
  expanded,
  selected,
  cursored,
  domId,
  draggable,
  droppable,
  dragging,
  dropBand,
  dropRefused,
  onToggle,
  onSelect,
  onActivate,
  onContextMenu,
  onDragStartRow,
  onDragOverRow,
  onDragLeaveRow,
  onDropRow,
  onDragEndRow,
}: NodeRowProps) {
  const t = useT("connections");
  const indent = { "--tree-depth": String(depth) } as CSSProperties;

  if (node.kind === "separator") {
    return (
      <div className={s.separatorRow} style={indent} role="separator" id={domId}>
        <span className={s.separatorLine} />
      </div>
    );
  }

  const isFolder = node.kind === "folder" || node.kind === "group";
  const firstTag = node.tags.length > 0 ? node.tags[0] : undefined;

  const handleContextMenu = (e: MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    onSelect(node.id);
    onContextMenu(node.id, e.clientX, e.clientY);
  };

  const handleDragStart = (e: DragEvent<HTMLDivElement>) => {
    if (!draggable) {
      e.preventDefault();
      return;
    }
    e.dataTransfer.setData(NODE_DRAG_MIME, node.id);
    e.dataTransfer.effectAllowed = "move";
    onDragStartRow(node.id);
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    // Whatever happens here, the background handler must not also claim this
    // event and read it as a drop onto the top level.
    e.stopPropagation();
    if (!droppable) return;
    if (!onDragOverRow(node.id, bandAt(e))) return;
    // Only an accepted target calls preventDefault. Without it the platform
    // draws its own refusal cursor, which is exactly the state a refused band
    // should be in.
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    // Moving onto the row's own glyph or label fires a leave; ignore those or
    // the indicator flickers across the width of the row.
    const next = e.relatedTarget;
    if (next instanceof Node && e.currentTarget.contains(next)) return;
    onDragLeaveRow(node.id);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    if (!droppable) return;
    e.preventDefault();
    e.stopPropagation();
    onDropRow(node.id);
  };

  return (
    <div
      id={domId}
      role="treeitem"
      aria-level={depth + 1}
      aria-selected={selected}
      {...(hasChildren ? { "aria-expanded": expanded } : {})}
      className={clsx(
        s.row,
        selected && s.selected,
        cursored && s.cursored,
        dragging && s.dragging,
        dropBand !== null && dropRefused && s.dropRefused,
        dropBand === "into" && !dropRefused && s.dropInto,
        dropBand === "before" && !dropRefused && s.dropBefore,
        dropBand === "after" && !dropRefused && s.dropAfter,
      )}
      style={indent}
      draggable={draggable}
      onClick={() => onSelect(node.id)}
      onDoubleClick={() => onActivate(node.id)}
      onContextMenu={handleContextMenu}
      onDragStart={handleDragStart}
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onDragEnd={onDragEndRow}
    >
      {hasChildren ? (
        <button
          type="button"
          className={s.chevron}
          aria-label={expanded ? t("row.collapse") : t("row.expand")}
          tabIndex={-1}
          onClick={(e) => {
            e.stopPropagation();
            onToggle(node.id);
          }}
        >
          <Icon name={expanded ? "chevron-down" : "chevron-right"} size={12} />
        </button>
      ) : (
        <span className={s.chevronSpacer} />
      )}

      <span
        className={clsx(
          s.glyph,
          isFolder && s.folderGlyph,
          node.kind === "credential" && s.credentialGlyph,
          node.kind === "connection" && protocolClass(node.protocol),
        )}
      >
        <Icon name={nodeGlyph(node)} size={14} />
      </span>

      <span className={clsx(s.name, isFolder && s.folderName)}>{node.name}</span>

      <span className={s.spacer} />

      <span className={s.meta}>
        {/*
          The DTO carries one count per node and its meaning follows the kind:
          on a folder it is the number of fields descendants inherit from it,
          on a credential the number of nodes that take their login from it.
        */}
        {isFolder && node.inheritedFieldCount > 0 && (
          <Badge mono title={t("row.inheritsHint")}>
            {t("row.inheritsCount", { count: node.inheritedFieldCount })}
          </Badge>
        )}
        {node.kind === "credential" && (
          <Badge mono title={t("row.usedByHint")}>
            {t("row.usedByCount", { count: node.inheritedFieldCount })}
          </Badge>
        )}
        {node.kind === "connection" && node.protocol !== null && (
          <span className={s.protocol}>{node.protocol}</span>
        )}
        {firstTag !== undefined && !isFolder && (
          <Badge tone="neutral" mono>
            {firstTag}
          </Badge>
        )}
        {firstTag !== undefined && isFolder && node.inheritedFieldCount === 0 && (
          <Badge tone="neutral" mono>
            {firstTag}
          </Badge>
        )}
      </span>
    </div>
  );
});
