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
 * The row is the drag source. It is **not** the drop target any more: a row
 * that can take a drop publishes `data-drop-id`, and the tree hit-tests the
 * pointer against the document to find it. The row used to answer
 * `pointermove` itself, which made the drop target whichever element the
 * webview chose to deliver the move to — and once the pointer is captured, as
 * it is here for the length of the drag, every move goes to the one element
 * holding the capture and no other row hears a thing. That is a drag that
 * works until the moment something takes the pointer, which is the failure
 * that kept coming back.
 *
 * A separator publishes `data-drop-id` too. It is a gap someone drew between
 * two entries, which is a *position*, so it takes a drop the way the gap it
 * stands for would — and it is dragged the same way, for the same reason. What
 * kept it from being a drag source was that it has no name, so the move came
 * out as "Moved “” above “x”"; the answer to that was four sentences in the
 * catalogue, not a line the user is not allowed to move.
 *
 * `data-container` says whether this row *presents itself* as something that
 * holds entries, which is not the same as whether it can. A group wears the
 * folder glyph and holds nothing (docs/architecture/data-model.md), and it
 * keeps its middle band anyway: someone who aims at the inside of a thing that
 * looks like a folder has to be told why it is not one, and a row that
 * silently reordered instead would answer a question nobody asked. Whether the
 * drop can then happen is the tree's to decide — see `planDrop`.
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
 * A row that reads as a container is split in three: outer quarters mean
 * "between two rows", the middle half means "inside this one". Every file
 * manager splits a container this way, so the gesture needs no teaching.
 *
 * A row that plainly holds nothing is split in **two**, and that is the whole
 * of why reordering was reported as broken. Giving a connection a middle band
 * meant that aiming at the row you want to sit next to — which is what
 * everyone does — landed in a band whose only possible answer was "only a
 * folder can hold other entries". Half of every attempt to reorder was refused
 * by construction, and the refusal was about containment, so it read as though
 * the tree had misunderstood the gesture. It had: there was nothing to
 * understand, because there is no "inside" a connection.
 */
export function bandAt(rect: DOMRect, clientY: number, container: boolean): DropBand {
  const offset = rect.height === 0 ? 0.5 : (clientY - rect.top) / rect.height;
  if (!container) return offset < 0.5 ? "before" : "after";
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
  onPressRow: (id: string, x: number, y: number, pointerId: number, row: HTMLElement) => void;
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
}: NodeRowProps) {
  const t = useT("connections");
  const indent = { "--tree-depth": String(depth) } as CSSProperties;

  const handlePointerDown = (e: PointerEvent<HTMLDivElement>) => {
    if (!movable) return;
    // Primary button only, and never touch: on a tablet the same gesture is
    // how the sidebar is scrolled, and a tree that cannot be scrolled is a
    // worse trade than one that cannot be reordered by finger. The keyboard
    // path in the tree is the equivalent that is always available.
    if (e.button !== 0 || e.pointerType === "touch") return;
    onPressRow(node.id, e.clientX, e.clientY, e.pointerId, e.currentTarget);
  };

  /*
   * A separator is a gap that was drawn on purpose, and a gap between two
   * siblings is a position. It therefore carries `data-drop-id` like any other
   * row and splits into two bands like any other row that holds nothing.
   *
   * Returning early *before* the attribute was the hole: `closest()` walked
   * straight past a separator to the scroller, so a node dropped on the line
   * between two folders was read as a drop on the background and went to the
   * end of the top level — a different place from the one the pointer was over,
   * with no refusal and no indicator to say so.
   *
   * **It is a drag source as well**, which it was not until now. A press on
   * one produced no gesture at all — no indicator, no chip, no refusal, no
   * announcement — because the only thing standing in the way was that the
   * catalogue had no sentence for moving a thing with no name. A line whose
   * entire meaning is where it sits, in a tree that can be rearranged by
   * dragging, that alone cannot be dragged, is an asymmetry nobody can see the
   * reason for. `describeMove` now has four sentences for it.
   */
  if (node.kind === "separator") {
    return (
      <div
        className={clsx(
          s.separatorRow,
          dragging && s.dragging,
          dropBand !== null && dropRefused && s.dropRefused,
          dropBand === "before" && !dropRefused && s.dropBefore,
          dropBand === "after" && !dropRefused && s.dropAfter,
        )}
        style={indent}
        role="separator"
        id={domId}
        {...(droppable ? { "data-drop-id": node.id } : {})}
        onPointerDown={handlePointerDown}
      >
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

  return (
    <div
      id={domId}
      role="treeitem"
      /*
       * The tree's hit test looks for these. A row that is a projection rather
       * than a place — the favourites section — carries neither, so the hit
       * test walks past it to the scroller and reads the move as the top
       * level, which is what a favourite has to mean: it cannot take a drop
       * and it must not swallow the drag either.
       */
      {...(droppable ? { "data-drop-id": node.id } : {})}
      {...(droppable && isFolder ? { "data-container": "true" } : {})}
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
