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
 *
 * **The gesture is built on pointer events, not on HTML5 drag-and-drop.**
 * Under Tauri on Windows the webview's own drop target is revoked before the
 * page ever sees it: `dragDropEnabled` defaults to true, which makes wry
 * `RevokeDragDrop()` every WebView2 child window and register an `IDropTarget`
 * that understands file drops alone. An in-page drag then produces a
 * `dragstart` and nothing else — no `dragover`, no `drop`, no cursor — which
 * is exactly the "dragging does nothing" this tree shipped with, on the one
 * platform none of us develops on. Pointer events are not routed through that
 * target and behave the same on every platform.
 *
 * It also makes the gesture testable. jsdom implements `PointerEvent` and
 * implements neither `DragEvent` nor `DataTransfer`, so a drag written on
 * pointer events can be exercised end to end in the suite; one written on
 * HTML5 drag events cannot, which is the other half of why this went
 * unnoticed.
 *
 * There is no payload and no MIME type any more, because there was never a
 * reader for one: a drag never left the window, and the tree carries the
 * dragged id in its own state.
 */

import { memo, type CSSProperties, type MouseEvent, type PointerEvent } from "react";
import clsx from "clsx";

import { Badge } from "@/components/Badge";
import { Icon, type IconName } from "@/components/Icon";
import { useT } from "@/i18n";
import type { TreeNode } from "@/lib/ipc";

import s from "./NodeRow.module.css";

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
export function bandAt(rect: DOMRect, clientY: number): DropBand {
  const offset = rect.height === 0 ? 0.5 : (clientY - rect.top) / rect.height;
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
  movable: boolean;
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
  /** A press landed on this row; the tree decides whether it becomes a drag. */
  onPressRow: (id: string, x: number, y: number) => void;
  /**
   * The pointer is over this row's `band`.
   *
   * Returns true when the tree claimed the move — a drag is in flight and this
   * row is its target, accepted or refused. An unclaimed move must be left to
   * bubble; see `handlePointerMove`.
   */
  onPointerOverRow: (id: string, band: DropBand, x: number, y: number) => boolean;
  onPointerLeaveRow: (id: string) => void;
}

export const NodeRow = memo(function NodeRow({
  node,
  depth,
  hasChildren,
  expanded,
  selected,
  cursored,
  domId,
  movable,
  droppable,
  dragging,
  dropBand,
  dropRefused,
  onToggle,
  onSelect,
  onActivate,
  onContextMenu,
  onPressRow,
  onPointerOverRow,
  onPointerLeaveRow,
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

  const handlePointerDown = (e: PointerEvent<HTMLDivElement>) => {
    if (!movable) return;
    // Primary button only, and never touch: on a tablet the same gesture is
    // how the sidebar is scrolled, and a tree that cannot be scrolled is a
    // worse trade than one that cannot be reordered by finger. The keyboard
    // path in the tree is the equivalent that is always available.
    if (e.button !== 0 || e.pointerType === "touch") return;
    onPressRow(node.id, e.clientX, e.clientY);
  };

  const handlePointerMove = (e: PointerEvent<HTMLDivElement>) => {
    // A row that is a projection rather than a place in the tree — the
    // favourites section — cannot take a drop, so it must not swallow the
    // move either: the scroller behind it reads an unclaimed move as the top
    // level, and without this fall-through the favourites are a dead band
    // that silently eats the drag. (The HTML5 version stopped the event
    // *before* this guard, which is exactly how that happened.)
    if (!droppable) return;
    const rect = e.currentTarget.getBoundingClientRect();
    if (!onPointerOverRow(node.id, bandAt(rect, e.clientY), e.clientX, e.clientY)) return;
    // Claimed: this row is the drag's target, so the background must not also
    // read the same move as a drop onto the top level.
    e.stopPropagation();
  };

  const handlePointerLeave = (e: PointerEvent<HTMLDivElement>) => {
    // Moving onto the row's own glyph or label fires a leave; ignore those or
    // the indicator flickers across the width of the row.
    const next = e.relatedTarget;
    if (next instanceof Node && e.currentTarget.contains(next)) return;
    onPointerLeaveRow(node.id);
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
      onClick={() => onSelect(node.id)}
      onDoubleClick={() => onActivate(node.id)}
      onContextMenu={handleContextMenu}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
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
