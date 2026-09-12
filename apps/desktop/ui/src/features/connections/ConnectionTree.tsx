/**
 * The connection tree.
 *
 * The parent→children index is built once from the flat list the core returns.
 * A vault with several hundred nodes is ordinary, and filtering the flat list
 * inside every row turns that into quadratic work on every keystroke.
 *
 * Selection and the keyboard cursor are separate. Up and Down move the cursor;
 * Enter commits it to the selection. That is what the keyboard map in
 * docs/features/connections.md describes, and it is what lets someone walk a
 * folder without the inspector following every step.
 *
 * Organisation is by drag-and-drop, with a keyboard equivalent on Ctrl/Cmd and
 * the arrow keys. The tree refuses a cycle or a non-folder parent while the
 * drag is still in the air rather than letting the core reject it afterwards;
 * when the core rejects a move anyway — a depth limit, a vault write that
 * failed — its message is shown on the tree, not swallowed.
 *
 * The drag is built on pointer events rather than on HTML5 drag-and-drop. See
 * the note at the top of `NodeRow.tsx`: under Tauri on Windows the page never
 * receives `dragover` or `drop` at all, so the HTML5 version of this was dead
 * on the platform most of its users are on, and jsdom cannot express the HTML5
 * version either, so nothing in the suite noticed.
 *
 * The gesture is owned here, at the scroller, and not by the rows. The pointer
 * is captured for the length of the drag and the target is found by hit-testing
 * the document at the pointer's coordinates — `pointerTarget` below. Rows
 * answering `pointermove` themselves made the drop target a function of which
 * element the webview decided to deliver the move to, and a captured pointer
 * delivers every move to one element: the drag then kept its source row and
 * silently refused everything, which is "dragging does nothing" for a second
 * time and for a second reason. Capture is also what keeps the moves coming
 * when the pointer leaves the window, which no per-row handler can do.
 *
 * A refusal is shown on the tree as well as announced. A drop the application
 * refused and a drag the application never received look identical when the
 * only channel is a visually hidden live region — which is the ambiguity that
 * let the Windows defect survive as long as it did.
 *
 * Still missing, and tracked: the move does not yet show the inheritance diff
 * that docs/features/connections.md asks for. That needs a core command to
 * preview what a re-parent changes across the subtree, and there is none.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { TFunction } from "i18next";
import clsx from "clsx";

import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import {
  compareInLocale,
  documentDirection,
  foldForSearch,
  foldInvariant,
  inlineStartOffset,
  isolate,
  useFailureText,
  useLocale,
  useT,
} from "@/i18n";
import { asFailure, ipc, type IpcFailure, type TreeNode } from "@/lib/ipc";
import { invalidateAfterTreeChange, qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { isConnectable, openSession } from "@/features/sessions";

import { bandAt, NodeRow, nodeGlyph, protocolClass, type DropBand } from "./NodeRow";
import { useConnectionEditor } from "./ConnectionEditor";
import { useFocusTrap } from "./focusTrap";
import s from "./ConnectionTree.module.css";

/**
 * There is no favourite flag in the node DTO, so the sidebar reads the tag the
 * rest of the application uses for it. Tags cross-cut the tree by design.
 */
const FAVOURITE_TAGS: ReadonlySet<string> = new Set(["favourite", "favorite"]);

/** The children map keys roots under a value no node id can collide with. */
const ROOT_KEY = " root";

/** Keeps the context menu clear of the window edge it was opened against. */
const MENU_MARGIN = 180;

/**
 * Where the menu should sit, given the physical point it was opened at.
 *
 * `clientX` counts from the left edge of the viewport in every layout, but the
 * menu grows toward the reading end — rightwards under LTR, leftwards under
 * RTL — so the edge it can fall off is a *different physical edge* in each
 * direction. Clamping against the right edge in both was the bug that made an
 * Arabic layout's menu run off the left of the window.
 *
 * The y axis needs no such mapping: the block axis is top-to-bottom in every
 * locale this application ships, so `top` is already the logical property.
 */
function menuAnchor(x: number, y: number): { x: number; y: number } {
  const clampedX =
    documentDirection() === "rtl"
      ? Math.max(x, MENU_MARGIN)
      : Math.min(x, window.innerWidth - MENU_MARGIN);
  return { x: clampedX, y: Math.min(y, window.innerHeight - MENU_MARGIN) };
}

/** How long a drag rests on a closed folder before the folder opens under it. */
const AUTO_EXPAND_MS = 600;

/**
 * How far the pointer travels before a press becomes a drag.
 *
 * Below it the gesture is still a click — selecting a row, or hitting its
 * chevron — and a tree that started re-parenting on a two-pixel wobble would
 * be unusable with a trackpad.
 */
const DRAG_THRESHOLD_PX = 4;

/**
 * Dragging toward the edge of the sidebar scrolls it.
 *
 * The platform did this for free while the gesture was a native drag. A
 * pointer drag has to do it itself, and without it a tree longer than the
 * sidebar can only be reordered within the screenful the drag started on —
 * which for a real vault is most of the moves someone wants to make.
 */
const EDGE_SCROLL_PX = 28;
const EDGE_SCROLL_STEP = 14;
const EDGE_SCROLL_MS = 40;

/** The gap left between siblings when a sort order has to be respaced. */
const RESPACE_STRIDE = 16;

type Section = "favourite" | "tree";

interface VisibleRow {
  key: string;
  node: TreeNode;
  depth: number;
  hasChildren: boolean;
  expanded: boolean;
  section: Section;
}

interface MenuState {
  x: number;
  y: number;
  /** Null when the menu was opened on empty space rather than on a row. */
  nodeId: string | null;
}

/** Where a drop would land, in terms the sibling list understands. */
interface DropPlan {
  parentId: string | null;
  /** Index among the destination's children with the dragged node removed. */
  index: number;
}

interface DropState {
  /** Null when the pointer is over the background rather than over a row. */
  targetId: string | null;
  band: DropBand;
  /** Null when the move is impossible; `reason` then says why. */
  plan: DropPlan | null;
  reason: string | null;
}

/**
 * A press that may or may not turn into a drag.
 *
 * Held in a ref rather than in state because `pointermove` fires many times a
 * second and because the handlers that read it — including the window-level
 * ones that catch a release outside the sidebar — must never see a value one
 * render behind the pointer.
 */
interface DragGesture {
  id: string;
  startX: number;
  startY: number;
  /** The pointer this gesture belongs to, so the capture can be given back. */
  pointerId: number;
  /** The row the press landed on, which is what holds the capture. */
  row: HTMLElement;
  /** False until the pointer has moved far enough to mean a drag. */
  active: boolean;
  /** The dragged node's subtree: everywhere it cannot land. Empty until active. */
  blocked: ReadonlySet<string>;
}

/**
 * The row under a point, by hit test rather than by event target.
 *
 * `elementFromPoint` is the only thing that answers "what is the pointer over"
 * once the pointer is captured, because from then on every event names the
 * capturing element and nothing else. The fallback to the event's own target
 * is for jsdom, which has no layout and therefore no `elementFromPoint`; a
 * test that dispatches on the row it means still reads the way it did.
 *
 * A row publishes `data-drop-id` only when it is a real place in the tree, so
 * the favourites projection resolves to null here and is read as background.
 */
function pointerTarget(x: number, y: number, fallback: EventTarget | null): HTMLElement | null {
  const hit =
    typeof document.elementFromPoint === "function"
      ? document.elementFromPoint(x, y)
      : fallback instanceof Element
        ? fallback
        : null;
  return hit?.closest<HTMLElement>("[data-drop-id]") ?? null;
}

/** One `node_move` call. A reorder sometimes needs several. */
interface MoveStep {
  id: string;
  parentId: string | null;
  sortOrder: number;
}

/**
 * A failure from a move, read out.
 *
 * Its own component because `useFailureText` is a hook and the announcement is
 * produced inside a live region that otherwise holds a plain string. Without
 * this the sentence around the failure was Turkish and the failure inside it
 * was English, which is the one combination worse than either alone.
 */
function MoveFailureAnnouncement({
  failure,
  t,
}: {
  failure: IpcFailure;
  t: TFunction<"connections">;
}) {
  const text = useFailureText(failure);
  // The core's sentence arrives complete and punctuated, so it is interpolated
  // rather than glued on with a full stop that a language putting the subject
  // last would want somewhere else.
  return <>{t("move.failedAnnounce", { reason: text.message })}</>;
}

function rowDomId(key: string): string {
  return `tree-row-${key}`;
}

function sameDrop(a: DropState | null, b: DropState | null): boolean {
  if (a === null || b === null) return a === b;
  return (
    a.targetId === b.targetId &&
    a.band === b.band &&
    a.reason === b.reason &&
    a.plan?.parentId === b.plan?.parentId &&
    a.plan?.index === b.plan?.index
  );
}

/**
 * The `node_move` calls that land `draggedId` at `plan.index`.
 *
 * `siblings` is the destination's children with the dragged node already taken
 * out, in display order.
 *
 * `sortOrder` is an `i64` in the core, so the usual trick of picking the
 * midpoint between two neighbours only works when there is an integer between
 * them — and `node_create` hands out consecutive integers, so usually there is
 * not. When the neighbours are adjacent the whole sibling list is respaced
 * instead, which costs one call per row that actually changes.
 */
function movesFor(plan: DropPlan, draggedId: string, siblings: readonly TreeNode[]): MoveStep[] {
  const before = plan.index > 0 ? siblings[plan.index - 1] : undefined;
  const after = siblings[plan.index];

  if (before === undefined || after === undefined) {
    const anchor = before ?? after;
    if (anchor === undefined) {
      return [{ id: draggedId, parentId: plan.parentId, sortOrder: 0 }];
    }
    const sortOrder = before === undefined ? anchor.sortOrder - 1 : anchor.sortOrder + 1;
    return [{ id: draggedId, parentId: plan.parentId, sortOrder }];
  }

  const gap = after.sortOrder - before.sortOrder;
  if (gap >= 2) {
    const sortOrder = before.sortOrder + Math.floor(gap / 2);
    return [{ id: draggedId, parentId: plan.parentId, sortOrder }];
  }

  const order: (TreeNode | null)[] = [
    ...siblings.slice(0, plan.index),
    null,
    ...siblings.slice(plan.index),
  ];

  // Start the respacing high enough that no existing sibling's order ever goes
  // down. Each step is its own vault write, so a run that fails halfway has to
  // leave the siblings in the order they were already in; that holds when every
  // row only moves up and the rows are written from the bottom of the list
  // upwards, which is what the descending loop below does.
  let base = 0;
  order.forEach((entry, i) => {
    if (entry !== null) base = Math.max(base, entry.sortOrder - i * RESPACE_STRIDE);
  });

  const steps: MoveStep[] = [];
  for (let i = order.length - 1; i >= 0; i -= 1) {
    const entry = order[i];
    if (entry === undefined) continue;
    const sortOrder = base + i * RESPACE_STRIDE;
    if (entry === null) steps.push({ id: draggedId, parentId: plan.parentId, sortOrder });
    else if (entry.sortOrder !== sortOrder) {
      steps.push({ id: entry.id, parentId: plan.parentId, sortOrder });
    }
  }
  return steps;
}

/**
 * The sentence a completed move is announced with.
 *
 * `t` is passed in rather than read from a hook: this is a pure function, and
 * the names in it are user data from the vault, so every one is isolated
 * before it reaches the message. Without that a folder named in Arabic
 * reverses the English sentence it lands in.
 */
function describeMove(
  t: TFunction<"connections">,
  dragged: TreeNode,
  target: TreeNode | null,
  band: DropBand,
): string {
  const name = isolate(dragged.name);
  if (target === null) return t("move.movedToTop", { name });
  switch (band) {
    case "into":
      return t("move.movedInto", { name, parent: isolate(target.name) });
    case "before":
      return t("move.movedAbove", { name, anchor: isolate(target.name) });
    case "after":
      return t("move.movedBelow", { name, anchor: isolate(target.name) });
  }
}

export function ConnectionTree() {
  const t = useT("connections");
  const tCommon = useT("common");
  // Two things here need the language the *reader* chose rather than the one
  // the operating system is set to: the filter folds under its casing rules,
  // and the tree is ordered by its collation. See `filtered` and `index`.
  const { code: locale } = useLocale();
  const selectedNodeId = useApp((st) => st.selectedNodeId);
  const select = useApp((st) => st.select);
  const expanded = useApp((st) => st.expanded);
  const toggleExpanded = useApp((st) => st.toggleExpanded);
  const setPaletteOpen = useApp((st) => st.setPaletteOpen);
  const openEditor = useConnectionEditor((st) => st.open);

  const queryClient = useQueryClient();
  const nodesQuery = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });

  const [filter, setFilter] = useState("");
  const [cursorKey, setCursorKey] = useState<string | null>(null);
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [pendingDelete, setPendingDelete] = useState<TreeNode | null>(null);
  const [dragId, setDragId] = useState<string | null>(null);
  const [drop, setDrop] = useState<DropState | null>(null);
  const [announcement, setAnnouncement] = useState("");
  /**
   * Why nothing moved, shown on the tree.
   *
   * The live region below is a 1×1 clipped box, so a refused drop used to
   * leave a sighted user with no feedback at all at the moment of release —
   * indistinguishable from a drag the application never received. It is set
   * alongside the announcement rather than instead of it, and deliberately
   * carries no `role="alert"`: the polite live region already reads it, and
   * two channels announcing the same sentence is worse than one.
   */
  const [refusal, setRefusal] = useState<string | null>(null);
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const confirmRef = useRef<HTMLDivElement | null>(null);
  const chipRef = useRef<HTMLDivElement | null>(null);
  const dragPoint = useRef({ x: 0, y: 0 });

  // `pointermove` fires many times a second and the release has to read the
  // plan the last one computed, so the plan lives in a ref and the state
  // exists only to paint the indicator.
  const dropRef = useRef<DropState | null>(null);
  const gesture = useRef<DragGesture | null>(null);
  const autoExpand = useRef<{ id: string; timer: number } | null>(null);
  const edgeScroll = useRef<{ direction: -1 | 1; timer: number } | null>(null);
  const pendingAnnouncement = useRef("");

  /*
   * A credential attached to a connection is part of that connection — its
   * username and its secret, which the connection's own row already stands
   * for — so it is not an entry of its own here. A row per server-plus-login
   * would double the length of the tree and name something the user never
   * created; a *shared* credential stays a first-class row, because organising
   * those is the point of having them.
   *
   * The core leaves attached credentials out of `tree_list` for the same
   * reason. This is the interface's half of that invariant, so a sidebar built
   * from a list that carried one — a cached response from an older build,
   * say — still draws the tree the user was promised.
   */
  const nodes = useMemo(
    () => (nodesQuery.data ?? []).filter((n) => n.attachedTo === null),
    [nodesQuery.data],
  );

  // One pass over the flat list; every later question is a map lookup.
  const index = useMemo(() => {
    const byId = new Map<string, TreeNode>();
    const children = new Map<string, TreeNode[]>();
    for (const node of nodes) byId.set(node.id, node);
    for (const node of nodes) {
      const key = node.parentId ?? ROOT_KEY;
      const bucket = children.get(key);
      if (bucket === undefined) children.set(key, [node]);
      else bucket.push(node);
    }
    for (const bucket of children.values()) {
      // `localeCompare` with no locale sorts by the *operating system's*
      // language, not the one the interface is in, so the same vault came out
      // in a different order on a colleague's machine. `locale` is the
      // language the reader actually chose; see `compareInLocale`.
      bucket.sort(
        (a, b) => a.sortOrder - b.sortOrder || compareInLocale(a.name, b.name, locale),
      );
    }
    return { byId, children };
  }, [nodes, locale]);

  // `FAVOURITE_TAGS` is a pair of ASCII spellings this application treats as a
  // flag, not a word in the reader's language — so the tag folds invariantly.
  // Folding it in the reader's language would be its own bug: under Turkish
  // rules "FAVOURITE" folds to "favourıte" and matches neither constant.
  const favourites = useMemo(
    () => nodes.filter((n) => n.tags.some((tag) => FAVOURITE_TAGS.has(foldInvariant(tag)))),
    [nodes],
  );

  /**
   * Nodes the filter keeps, plus the ancestors that lead to them.
   *
   * **The query is folded twice, because the haystack is two kinds of text.**
   * A node's name and its tags are words somebody wrote in a language, and
   * they fold in the reader's. A hostname, a username and a protocol name are
   * not: they are identifiers on a remote system, and `docs/features/i18n.md`
   * puts them with file paths and IP addresses outside all three folds — the
   * protocol explicitly, as "`[0-9A-Z]`, a protocol name shown in capitals".
   *
   * The protocol was in that sentence before it was in the haystack, so typing
   * `rdp` into the filter found nothing while the same word typed into the
   * import preview — which folds `host`, `username` and `protocol` together in
   * `features/import/selection.ts` — found every row. Two screens filtering the
   * same node over different fields is the drift a shared claim is supposed to
   * prevent, so the field list here now matches that one.
   *
   * Folding everything in the reader's language was worse than useless for the
   * second kind. Under Turkish rules `VDI-GW.corp` folds to `vdı-gw.corp` and
   * `API-EU-01` to `apı-eu-01`, so a Turkish reader typing "vdi" or "api"
   * found *nothing*, on hosts a colleague with an English interface could find
   * by typing exactly the same letters. Folding the identifiers invariantly
   * and the words in the reader's language is what the shortcut table already
   * does with its prose and its key caps, for the same reason.
   *
   * A query is not required to say which kind it is: it is folded both ways
   * and a node matches if either side does. The cost of that is a query
   * spanning a name and a hostname at once — "berlin vdi" — which no longer
   * matches; the two are separate fields and always were, and the old
   * behaviour of joining them was never something the interface promised.
   */
  const filtered = useMemo(() => {
    const typed = filter.trim();
    const needle = foldForSearch(typed, locale);
    const identifierNeedle = foldInvariant(typed);
    if (needle === "") return null;
    const keep = new Set<string>();
    const forceOpen = new Set<string>();
    for (const node of nodes) {
      const words = [node.name, ...node.tags];
      const identifiers = [node.host ?? "", node.username ?? "", node.protocol ?? ""];
      const hit =
        words.some((w) => foldForSearch(w, locale).includes(needle)) ||
        identifiers.some((id) => foldInvariant(id).includes(identifierNeedle));
      if (!hit) continue;
      keep.add(node.id);
      let parent = node.parentId;
      for (let hops = 0; parent !== null && hops < 64; hops += 1) {
        keep.add(parent);
        forceOpen.add(parent);
        parent = index.byId.get(parent)?.parentId ?? null;
      }
    }
    return { keep, forceOpen };
  }, [filter, nodes, index, locale]);

  const rows = useMemo(() => {
    const out: VisibleRow[] = [];
    if (filtered === null) {
      for (const fav of favourites) {
        out.push({
          key: `fav:${fav.id}`,
          node: fav,
          depth: 0,
          hasChildren: false,
          expanded: false,
          section: "favourite",
        });
      }
    }

    const walk = (parentKey: string, depth: number) => {
      const bucket = index.children.get(parentKey);
      if (bucket === undefined) return;
      for (const node of bucket) {
        if (filtered !== null && !filtered.keep.has(node.id)) continue;
        const kids = index.children.get(node.id);
        const hasChildren = kids !== undefined && kids.length > 0;
        const isOpen =
          hasChildren && (filtered === null ? expanded.has(node.id) : filtered.forceOpen.has(node.id));
        out.push({
          key: `tree:${node.id}`,
          node,
          depth,
          hasChildren,
          expanded: isOpen,
          section: "tree",
        });
        if (isOpen) walk(node.id, depth + 1);
      }
    };
    walk(ROOT_KEY, 0);
    return out;
  }, [favourites, filtered, index, expanded]);

  const cursorIndex = cursorKey === null ? -1 : rows.findIndex((r) => r.key === cursorKey);

  // Follow a selection made elsewhere — the palette, most often. The ref keeps
  // this to actual changes of selection, so expanding a folder does not drag
  // the cursor back to whatever is selected.
  const lastSyncedSelection = useRef<string | null>(null);
  useEffect(() => {
    if (selectedNodeId === null || selectedNodeId === lastSyncedSelection.current) return;
    lastSyncedSelection.current = selectedNodeId;
    setCursorKey(`tree:${selectedNodeId}`);
  }, [selectedNodeId]);

  useEffect(() => {
    if (cursorKey === null) return;
    document.getElementById(rowDomId(cursorKey))?.scrollIntoView({ block: "nearest" });
  }, [cursorKey]);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => ipc.deleteNode(id),
    onSuccess: async (_void, id) => {
      await invalidateAfterTreeChange(queryClient);
      if (selectedNodeId === id) select(null);
      setPendingDelete(null);
    },
  });

  /**
   * A move changes the tree, the shell's copy of it, and the resolution of
   * every node in the moved subtree, so all of it is refetched — through the
   * one helper that knows the full set of keys, rather than a hand-picked list
   * that the shell would then disagree with. Failures refetch too: a respace
   * can fail partway through, and the rows on screen must then show what the
   * vault actually holds.
   */
  const refreshTree = useCallback(() => invalidateAfterTreeChange(queryClient), [queryClient]);

  const moveMutation = useMutation({
    mutationFn: async (steps: MoveStep[]) => {
      for (const step of steps) {
        await ipc.moveNode(step.id, step.parentId, step.sortOrder);
      }
    },
    onSuccess: async () => {
      await refreshTree();
      setAnnouncement(pendingAnnouncement.current);
    },
    onError: async () => {
      await refreshTree();
      // The failure announcement is rendered from `moveMutation.error` rather
      // than assembled here, because turning a failure into a sentence is
      // `useFailureText`'s job and a hook cannot be called from a callback.
      // Clearing the string leaves the live region to the failure alone, and
      // stops the last success being re-announced when the failure is
      // dismissed.
      setAnnouncement("");
    },
  });

  const { mutate: startMove, reset: resetMove } = moveMutation;

  const runMove = useCallback(
    (steps: MoveStep[], success: string) => {
      if (steps.length === 0) return;
      pendingAnnouncement.current = success;
      // A move that is actually happening answers whatever the last refusal
      // said, so the note explaining the last one goes with it.
      setRefusal(null);
      resetMove();
      startMove(steps);
    },
    [startMove, resetMove],
  );

  /**
   * Nothing moved, and this is why.
   *
   * Both halves matter and they are different audiences: the note is read off
   * the screen, the announcement is read out. Every refusal in this component
   * — a drop the tree would not take, a Ctrl+arrow with nowhere to go — goes
   * through here so that neither audience can be served without the other.
   */
  const refuse = useCallback((reason: string) => {
    setRefusal(reason);
    setAnnouncement(reason);
  }, []);

  const onSelect = useCallback(
    (id: string) => {
      // Claim the sync below before selecting, so clicking a favourite leaves
      // the cursor on the favourite row rather than jumping into the tree.
      lastSyncedSelection.current = id;
      setCursorKey((current) => (current === `fav:${id}` ? current : `tree:${id}`));
      select(id);
      scrollerRef.current?.focus();
    },
    [select],
  );

  const onToggle = useCallback((id: string) => toggleExpanded(id), [toggleExpanded]);

  /**
   * What a double-click does.
   *
   * On a connection it opens a session — that is what double-clicking a
   * connection means in a connection manager, and the palette and the context
   * menu agree with it. On anything else there is no session to open, so it
   * opens the entry's settings instead.
   */
  const onActivate = useCallback(
    (id: string) => {
      const node = index.byId.get(id);
      if (isConnectable(node)) {
        openSession(node);
        return;
      }
      openEditor({ mode: "edit", nodeId: id });
    },
    [index, openEditor],
  );

  // The menu is positioned in viewport coordinates, so it has to be kept
  // inside the window rather than trusting the click point near an edge.
  const onContextMenu = useCallback((id: string, x: number, y: number) => {
    setMenu({ ...menuAnchor(x, y), nodeId: id });
  }, []);

  // The row hands back an id; the menu needs the node, which only the index
  // this component holds can supply.
  const menuNode = menu?.nodeId == null ? null : (index.byId.get(menu.nodeId) ?? null);

  useEffect(() => {
    if (menu === null) return;
    const dismiss = () => setMenu(null);
    const onEscape = (e: globalThis.KeyboardEvent) => {
      if (e.key === "Escape") setMenu(null);
    };
    window.addEventListener("click", dismiss);
    window.addEventListener("resize", dismiss);
    window.addEventListener("blur", dismiss);
    window.addEventListener("keydown", onEscape);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("resize", dismiss);
      window.removeEventListener("blur", dismiss);
      window.removeEventListener("keydown", onEscape);
    };
  }, [menu]);

  // ------------------------------------------------- delete confirmation ----

  /*
   * The confirmation is an `alertdialog`, which is a promise that it is the
   * only thing on screen. It was not keeping that promise: focus never entered
   * it, Escape did nothing, and the tree behind it went on answering the arrow
   * keys. The trap moves focus in, keeps Tab inside, and hands focus back when
   * it closes; the guard in `onKeyDown` stops the tree acting underneath it.
   */
  useFocusTrap(pendingDelete !== null, confirmRef);
  useModalRegistration("tree.delete-confirmation", pendingDelete !== null);

  const deletePending = deleteMutation.isPending;
  useEffect(() => {
    if (pendingDelete === null) return;
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      // A delete already writing the vault cannot be called back, so Escape
      // does nothing rather than pretending it can — the same guard the Cancel
      // button carries.
      if (deletePending) return;
      setPendingDelete(null);
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [pendingDelete, deletePending]);

  // Closing puts the keyboard back on the row it was opened from. The tree
  // carries its cursor as `aria-activedescendant`, so focusing the scroller is
  // focusing the row — and the context menu that opened some of these is gone
  // by now, which leaves the trap's own restore nowhere to go.
  const confirmWasOpen = useRef(false);
  useEffect(() => {
    const open = pendingDelete !== null;
    if (!open && confirmWasOpen.current) scrollerRef.current?.focus();
    confirmWasOpen.current = open;
  }, [pendingDelete]);

  // ------------------------------------------------------------- moving ----

  /**
   * Every id the dragged node cannot land inside: itself and its subtree.
   *
   * Computed once, when the drag starts, and kept on the gesture rather than
   * derived from state. A `pointermove` can start the drag and land on a
   * target in the same event, and a set derived from `useState` would still be
   * one render behind at that moment — which would silently plan the first
   * hover of every drag against an empty set.
   */
  const subtreeOf = useCallback(
    (id: string): ReadonlySet<string> => {
      const out = new Set<string>([id]);
      const stack = [id];
      while (stack.length > 0) {
        const current = stack.pop();
        if (current === undefined) continue;
        for (const kid of index.children.get(current) ?? []) {
          out.add(kid.id);
          stack.push(kid.id);
        }
      }
      return out;
    },
    [index],
  );

  const siblingsWithout = useCallback(
    (parentId: string | null, exclude: string | null): TreeNode[] => {
      const bucket = index.children.get(parentId ?? ROOT_KEY) ?? [];
      return exclude === null ? bucket : bucket.filter((n) => n.id !== exclude);
    },
    [index],
  );

  const cancelAutoExpand = useCallback(() => {
    if (autoExpand.current === null) return;
    window.clearTimeout(autoExpand.current.timer);
    autoExpand.current = null;
  }, []);

  const armAutoExpand = useCallback(
    (id: string) => {
      if (autoExpand.current?.id === id) return;
      cancelAutoExpand();
      const timer = window.setTimeout(() => {
        autoExpand.current = null;
        // Read the store rather than the render's copy: the timer outlives the
        // render that armed it, and the folder may have been opened since.
        const store = useApp.getState();
        if (!store.expanded.has(id)) store.toggleExpanded(id);
      }, AUTO_EXPAND_MS);
      autoExpand.current = { id, timer };
    },
    [cancelAutoExpand],
  );

  useEffect(() => cancelAutoExpand, [cancelAutoExpand]);

  const stopEdgeScroll = useCallback(() => {
    if (edgeScroll.current === null) return;
    window.clearInterval(edgeScroll.current.timer);
    edgeScroll.current = null;
  }, []);

  /**
   * Scroll the sidebar while the pointer rests against one of its edges.
   *
   * On a repeating timer rather than on the pointer's own movement: the
   * gesture that needs this is holding still at the edge waiting for the
   * target to come into view, and that produces no further `pointermove`.
   */
  const updateEdgeScroll = useCallback(
    (y: number) => {
      const el = scrollerRef.current;
      // Nothing to scroll — a short tree, or a test environment with no
      // layout — so there is nothing to arm either.
      if (el === null || el.scrollHeight <= el.clientHeight) {
        stopEdgeScroll();
        return;
      }
      const rect = el.getBoundingClientRect();
      const direction =
        y < rect.top + EDGE_SCROLL_PX ? -1 : y > rect.bottom - EDGE_SCROLL_PX ? 1 : 0;
      if (direction === 0) {
        stopEdgeScroll();
        return;
      }
      if (edgeScroll.current?.direction === direction) return;
      stopEdgeScroll();
      const timer = window.setInterval(() => {
        const node = scrollerRef.current;
        if (node === null) return;
        node.scrollTop += direction * EDGE_SCROLL_STEP;
      }, EDGE_SCROLL_MS);
      edgeScroll.current = { direction, timer };
    },
    [stopEdgeScroll],
  );

  useEffect(() => stopEdgeScroll, [stopEdgeScroll]);

  /**
   * Put the chip where the pointer is.
   *
   * Written straight to the element rather than kept in state: the chip has to
   * track the pointer at the rate the pointer moves, and a render per
   * `pointermove` across a few hundred rows is the one place in this component
   * where that cost is real. The last point is remembered so the chip can be
   * placed on the frame it first appears, which is after the move that started
   * the drag has already been handled.
   */
  const chipTo = useCallback((x: number, y: number) => {
    dragPoint.current = { x, y };
    const chip = chipRef.current;
    if (chip !== null) chip.style.transform = `translate(${String(x)}px, ${String(y)}px)`;
  }, []);

  useEffect(() => {
    if (dragId === null) return;
    const { x, y } = dragPoint.current;
    chipTo(x, y);
  }, [dragId, chipTo]);

  const setDropState = useCallback((next: DropState | null) => {
    if (sameDrop(dropRef.current, next)) return;
    dropRef.current = next;
    setDrop(next);
  }, []);

  const clearDrop = useCallback(() => {
    cancelAutoExpand();
    setDropState(null);
  }, [cancelAutoExpand, setDropState]);

  /**
   * What a drop on this target would do — or why it cannot happen.
   *
   * Refusing here rather than letting the core refuse is the point: a drop the
   * interface offers and then fails is worse than one it never offers.
   */
  const planDrop = useCallback(
    (targetId: string | null, band: DropBand): DropState => {
      const held = gesture.current;
      if (held === null || !held.active) {
        return { targetId, band, plan: null, reason: null };
      }
      const dragId = held.id;
      const blocked = held.blocked;
      if (targetId === null) {
        const roots = siblingsWithout(null, dragId);
        return {
          targetId: null,
          band: "into",
          plan: { parentId: null, index: roots.length },
          reason: null,
        };
      }

      const target = index.byId.get(targetId);
      if (target === undefined) {
        return { targetId, band, plan: null, reason: t("move.refuseGone") };
      }
      if (target.id === dragId) {
        return { targetId, band, plan: null, reason: t("move.refuseSelf") };
      }

      if (band === "into") {
        if (blocked.has(target.id)) {
          return { targetId, band, plan: null, reason: t("move.refuseDescendant") };
        }
        // A group is not a container in the core, whatever its glyph suggests.
        if (target.kind !== "folder") {
          return { targetId, band, plan: null, reason: t("move.refuseNotFolder") };
        }
        const kids = siblingsWithout(target.id, dragId);
        return { targetId, band, plan: { parentId: target.id, index: kids.length }, reason: null };
      }

      const parentId = target.parentId;
      if (parentId !== null && blocked.has(parentId)) {
        return { targetId, band, plan: null, reason: t("move.refuseDescendant") };
      }
      const sibs = siblingsWithout(parentId, dragId);
      const at = sibs.findIndex((n) => n.id === target.id);
      if (at < 0) return { targetId, band, plan: null, reason: t("move.refuseGone") };
      return {
        targetId,
        band,
        plan: { parentId, index: band === "before" ? at : at + 1 },
        reason: null,
      };
    },
    [index, siblingsWithout, t],
  );

  /** A press landed on a row. It is not a drag until the pointer moves. */
  const onPressRow = useCallback(
    (id: string, x: number, y: number, pointerId: number, row: HTMLElement) => {
      gesture.current = {
        id,
        startX: x,
        startY: y,
        pointerId,
        row,
        active: false,
        blocked: new Set(),
      };
    },
    [],
  );

  /**
   * Take the pointer for the rest of the gesture.
   *
   * What capture buys is that the moves keep coming when the pointer leaves
   * the window or passes over anything that would otherwise take it — which is
   * the half of a pointer drag that no per-row handler can provide, and the
   * half that differs most between webviews.
   *
   * Two things about it are deliberate and were both learned the hard way.
   *
   * It happens when the press becomes a **drag**, not when the press lands. A
   * captured pointer retargets the compatibility mouse events too, so a
   * capture taken on `pointerdown` sends the `click` that follows an ordinary
   * press to the capturing element instead of to the row — and clicking a row
   * stops selecting it. A click is a press that never travelled, so deferring
   * the capture past the threshold leaves clicks alone entirely.
   *
   * It is taken on the **row**, not on the scroller, for the same reason: the
   * click after a drag then still belongs to the row it came from. A row can
   * be replaced mid-gesture, and losing the capture that way is survivable —
   * moves bubble to the scroller, which is where they are handled anyway.
   *
   * Guarded because jsdom has no pointer capture at all, and because a
   * `pointerId` the webview has already released throws `NotFoundError`.
   */
  const capture = useCallback((held: DragGesture) => {
    if (typeof held.row.setPointerCapture !== "function") return;
    try {
      held.row.setPointerCapture(held.pointerId);
    } catch {
      // Capture is an improvement, not a requirement — see above.
    }
  }, []);

  /**
   * Promotes a press to a drag once the pointer has really travelled.
   *
   * Returns whether a drag is in flight, so the move handler can start one and
   * plan against it in the same event.
   */
  const advanceGesture = useCallback(
    (x: number, y: number): boolean => {
      const held = gesture.current;
      if (held === null) return false;
      if (held.active) return true;
      if (
        Math.abs(x - held.startX) < DRAG_THRESHOLD_PX &&
        Math.abs(y - held.startY) < DRAG_THRESHOLD_PX
      ) {
        return false;
      }
      held.active = true;
      held.blocked = subtreeOf(held.id);
      capture(held);
      setMenu(null);
      // Whatever the last refusal was about, the user is answering it by
      // dragging again; leaving it up would make the tree accumulate stale
      // explanations.
      setRefusal(null);
      setDragId(held.id);
      return true;
    },
    [subtreeOf, capture],
  );

  /**
   * The pointer moved, wherever the event happened to be delivered.
   *
   * Everything the drag needs is decided from the coordinates: which row is
   * under them, which band of it, and whether the pointer is over the tree at
   * all. A point outside the scroller plans nothing — a release over the
   * session area or the title bar has to move nothing, and reading it as the
   * top level would turn every drag abandoned off the side of the sidebar into
   * a re-parent nobody asked for.
   */
  const onPointerAt = useCallback(
    (x: number, y: number, from: EventTarget | null) => {
      if (!advanceGesture(x, y)) return;
      chipTo(x, y);
      updateEdgeScroll(y);

      const scroller = scrollerRef.current;
      const box = scroller?.getBoundingClientRect();
      // A zero-sized box is jsdom, which has no layout; there the pointer is
      // taken to be over the tree, because nothing else can be established.
      const outside =
        box !== undefined &&
        (box.width > 0 || box.height > 0) &&
        (x < box.left || x > box.right || y < box.top || y > box.bottom);
      if (outside) {
        clearDrop();
        return;
      }

      const row = pointerTarget(x, y, from);
      const id = row?.dataset["dropId"];
      if (row === null || id === undefined) {
        cancelAutoExpand();
        setDropState(planDrop(null, "into"));
        return;
      }

      const band = bandAt(row.getBoundingClientRect(), y, row.dataset["container"] === "true");
      const next = planDrop(id, band);
      setDropState(next);

      // Resting on a closed folder opens it, so a nested target can be reached
      // without dropping the node and picking it up again.
      const kids = index.children.get(id);
      const canOpen =
        band === "into" &&
        next.plan !== null &&
        kids !== undefined &&
        kids.length > 0 &&
        !expanded.has(id);
      if (canOpen) armAutoExpand(id);
      else cancelAutoExpand();
    },
    [
      advanceGesture,
      chipTo,
      updateEdgeScroll,
      clearDrop,
      planDrop,
      setDropState,
      index,
      expanded,
      armAutoExpand,
      cancelAutoExpand,
    ],
  );

  const endGesture = useCallback(() => {
    const held = gesture.current;
    if (held !== null && typeof held.row.releasePointerCapture === "function") {
      try {
        held.row.releasePointerCapture(held.pointerId);
      } catch {
        // Already released, which is the ordinary case after a `pointerup`.
      }
    }
    gesture.current = null;
    stopEdgeScroll();
    clearDrop();
    setDragId(null);
  }, [clearDrop, stopEdgeScroll]);

  const commitDrop = useCallback(() => {
    const state = dropRef.current;
    const held = gesture.current;
    const draggedId = held !== null && held.active ? held.id : null;
    endGesture();
    if (draggedId === null || state === null) return;

    const dragged = index.byId.get(draggedId);
    if (dragged === undefined) return;
    if (state.plan === null) {
      refuse(state.reason ?? t("move.refuseGone"));
      return;
    }

    const sibs = siblingsWithout(state.plan.parentId, draggedId);
    const target = state.targetId === null ? null : (index.byId.get(state.targetId) ?? null);
    runMove(
      movesFor(state.plan, draggedId, sibs),
      describeMove(t, dragged, target, state.band),
    );
  }, [index, siblingsWithout, runMove, endGesture, refuse, t]);

  const cancelDrag = useCallback(() => {
    const held = gesture.current;
    const wasDragging = held !== null && held.active;
    endGesture();
    if (wasDragging) setAnnouncement(t("move.cancelled"));
  }, [endGesture, t]);

  /**
   * The end of the gesture, wherever it happens.
   *
   * On the window rather than on the scroller: a release outside the sidebar
   * — over the session area, over the title bar, off the window entirely — has
   * to end the drag too, or the tree is left holding a pointer it will never
   * hear from again. The drop target is whatever the last move planned, so a
   * release over nothing simply moves nothing.
   *
   * Escape cancels, which native drag-and-drop gave for free and a pointer
   * drag has to implement.
   */
  useEffect(() => {
    const onUp = () => {
      if (gesture.current === null) return;
      commitDrop();
    };
    const onCancel = () => {
      if (gesture.current === null) return;
      cancelDrag();
    };
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape" || gesture.current === null) return;
      e.stopPropagation();
      cancelDrag();
    };
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onCancel);
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onCancel);
      window.removeEventListener("keydown", onKey, true);
    };
  }, [commitDrop, cancelDrag]);

  /** Ctrl/Cmd with an arrow key: the same four moves, without a pointer. */
  const keyboardMove = useCallback(
    (row: VisibleRow, action: "up" | "down" | "out" | "in") => {
      // A favourite row is a projection of a tag, not a position in the tree.
      if (row.section !== "tree") return;
      const node = row.node;
      const sibs = index.children.get(node.parentId ?? ROOT_KEY) ?? [];
      const at = sibs.findIndex((n) => n.id === node.id);
      if (at < 0) return;
      const without = siblingsWithout(node.parentId, node.id);

      switch (action) {
        case "up": {
          if (at === 0) {
            refuse(t("move.atFirst", { name: isolate(node.name) }));
            return;
          }
          const anchor = without[at - 1];
          const plan: DropPlan = { parentId: node.parentId, index: at - 1 };
          runMove(
            movesFor(plan, node.id, without),
            anchor === undefined
              ? t("move.movedToTop", { name: isolate(node.name) })
              : t("move.movedAbove", {
                  name: isolate(node.name),
                  anchor: isolate(anchor.name),
                }),
          );
          return;
        }
        case "down": {
          if (at >= sibs.length - 1) {
            refuse(t("move.atLast", { name: isolate(node.name) }));
            return;
          }
          const anchor = without[at];
          const plan: DropPlan = { parentId: node.parentId, index: at + 1 };
          runMove(
            movesFor(plan, node.id, without),
            anchor === undefined
              ? t("move.movedToTop", { name: isolate(node.name) })
              : t("move.movedBelow", {
                  name: isolate(node.name),
                  anchor: isolate(anchor.name),
                }),
          );
          return;
        }
        case "out": {
          const parentId = node.parentId;
          if (parentId === null) {
            refuse(t("move.atTopLevel", { name: isolate(node.name) }));
            return;
          }
          const parent = index.byId.get(parentId);
          if (parent === undefined) return;
          const uncles = siblingsWithout(parent.parentId, node.id);
          const parentAt = uncles.findIndex((n) => n.id === parent.id);
          if (parentAt < 0) return;
          const plan: DropPlan = { parentId: parent.parentId, index: parentAt + 1 };
          runMove(
            movesFor(plan, node.id, uncles),
            t("move.movedOutOf", { name: isolate(node.name), parent: isolate(parent.name) }),
          );
          return;
        }
        case "in": {
          const previous = at === 0 ? undefined : sibs[at - 1];
          if (previous === undefined || previous.kind !== "folder") {
            refuse(t("move.cannotIndent", { name: isolate(node.name) }));
            return;
          }
          const kids = siblingsWithout(previous.id, node.id);
          const plan: DropPlan = { parentId: previous.id, index: kids.length };
          // Open the folder, or the node the user just moved leaves the screen.
          if (!expanded.has(previous.id)) toggleExpanded(previous.id);
          runMove(
            movesFor(plan, node.id, kids),
            t("move.movedInto", { name: isolate(node.name), parent: isolate(previous.name) }),
          );
          return;
        }
      }
    },
    [index, siblingsWithout, runMove, expanded, toggleExpanded, refuse, t],
  );

  // ------------------------------------------------------------ keyboard ----

  const moveCursor = (delta: number) => {
    if (rows.length === 0) return;
    const next = cursorIndex < 0 ? 0 : Math.min(rows.length - 1, Math.max(0, cursorIndex + delta));
    const row = rows[next];
    if (row !== undefined) setCursorKey(row.key);
  };

  const cursorRow = cursorIndex >= 0 ? rows[cursorIndex] : undefined;

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    // The delete confirmation is modal. The tree does not move its cursor,
    // open folders or re-parent anything while it is up.
    if (pendingDelete !== null) return;

    if ((e.ctrlKey || e.metaKey) && cursorRow !== undefined) {
      switch (e.key) {
        case "ArrowUp":
          e.preventDefault();
          keyboardMove(cursorRow, "up");
          return;
        case "ArrowDown":
          e.preventDefault();
          keyboardMove(cursorRow, "down");
          return;
        case "ArrowLeft":
          e.preventDefault();
          keyboardMove(cursorRow, "out");
          return;
        case "ArrowRight":
          e.preventDefault();
          keyboardMove(cursorRow, "in");
          return;
        default:
      }
    }

    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        moveCursor(1);
        return;
      case "ArrowUp":
        e.preventDefault();
        moveCursor(-1);
        return;
      case "ArrowRight": {
        if (cursorRow === undefined) return;
        e.preventDefault();
        if (cursorRow.hasChildren && !cursorRow.expanded) toggleExpanded(cursorRow.node.id);
        else if (cursorRow.hasChildren) moveCursor(1);
        return;
      }
      case "ArrowLeft": {
        if (cursorRow === undefined) return;
        e.preventDefault();
        if (cursorRow.hasChildren && cursorRow.expanded) {
          toggleExpanded(cursorRow.node.id);
          return;
        }
        const parentId = cursorRow.node.parentId;
        if (parentId !== null) setCursorKey(`tree:${parentId}`);
        return;
      }
      case "Enter": {
        if (cursorRow === undefined) return;
        e.preventDefault();
        select(cursorRow.node.id);
        return;
      }
      case "F2": {
        if (cursorRow === undefined) return;
        e.preventDefault();
        openEditor({ mode: "edit", nodeId: cursorRow.node.id });
        return;
      }
      case "Delete": {
        if (cursorRow === undefined) return;
        e.preventDefault();
        setPendingDelete(cursorRow.node);
        return;
      }
      default:
    }
  };

  /** Where a new node goes: inside the selected folder, else beside the selection. */
  // Only a folder can hold children. `NodeKind::is_container` in remoter-core
  // matches Folder alone, so offering a group here produced a create that the
  // core refused with NotAContainer — the same rule the drop logic already
  // enforces, applied inconsistently. A group carries a folder glyph, which is
  // exactly why this was easy to get wrong.
  const creationParent = (anchor: TreeNode | null): string | null => {
    if (anchor === null) return null;
    if (anchor.kind === "folder") return anchor.id;
    return anchor.parentId;
  };

  const selectedNode = selectedNodeId === null ? null : (index.byId.get(selectedNodeId) ?? null);

  const descendantCount = (id: string): number => {
    let total = 0;
    const stack = [id];
    while (stack.length > 0) {
      const current = stack.pop();
      if (current === undefined) continue;
      const kids = index.children.get(current);
      if (kids === undefined) continue;
      total += kids.length;
      for (const kid of kids) stack.push(kid.id);
    }
    return total;
  };

  const failure = nodesQuery.error !== null ? asFailure(nodesQuery.error) : null;
  const deleteFailure = deleteMutation.error !== null ? asFailure(deleteMutation.error) : null;
  const moveFailure = moveMutation.error !== null ? asFailure(moveMutation.error) : null;
  const rootTargeted = drop !== null && drop.targetId === null;
  const draggedNode = dragId === null ? null : (index.byId.get(dragId) ?? null);
  // What the chip says when the pointer is somewhere the drop cannot happen.
  // Shown while the pointer is still down, which is the only moment it can
  // change anything: the same sentence after the release explains a failure,
  // and before it prevents one.
  const hoverRefusal = drop !== null && drop.plan === null ? drop.reason : null;

  return (
    <div className={s.sidebar}>
      <div className={s.search}>
        <span className={s.searchField}>
          <TextInput
            value={filter}
            onChange={setFilter}
            placeholder={t("tree.filterPlaceholder")}
            ariaLabel={t("tree.filterLabel")}
          />
        </span>
        <button
          type="button"
          className={s.shortcut}
          title={t("tree.openPalette")}
          aria-label={t("tree.openPalette")}
          onClick={() => setPaletteOpen(true)}
        >
          {/* eslint-disable remoter-i18n/no-literal-jsx-text --
              key names. A keycap says Ctrl whatever the interface language is
              (docs/features/i18n.md, "What is never translated"). The block
              form rather than disable-next-line: a bare text child starts on
              the line the comment ends on, so the one-line directive covers
              nothing. */}
          Ctrl K
          {/* eslint-enable remoter-i18n/no-literal-jsx-text */}
        </button>
      </div>

      {failure !== null && (
        <div className={s.notice}>
          {/* Through `FailureNotice`, so the core's English `code` becomes this
              reader's sentence. Rendering `failure.message` here was one
              English paragraph in an otherwise translated sidebar. */}
          <FailureNotice failure={failure} title={t("tree.loadFailed")} />
        </div>
      )}

      {/* A move writes the vault, so the rows do not settle instantly. The
          live region below is silent to anyone who can see the screen. */}
      {moveMutation.isPending && (
        <div className={s.status}>
          <BusyStatus label={t("move.inProgress")} size={14} />
        </div>
      )}

      {/*
        A move that fails has to fail where the user is looking. What went
        wrong and what to do about it are the core's to say, so the notice
        keeps all of it — but in the reader's language, which is what
        `FailureNotice` is for. The hand-built callout this replaces rendered
        the English `message` and `detail`, and joined the English action list
        into prose with a separator of its own: an ordered list of next steps
        turned into a run-on sentence, in a language the reader had not chosen.
      */}
      {moveFailure !== null && (
        <div className={s.notice}>
          <FailureNotice failure={moveFailure} title={t("move.failed")}>
            <Button variant="ghost" size="sm" onClick={() => resetMove()}>
              {tCommon("action.dismiss")}
            </Button>
          </FailureNotice>
        </div>
      )}

      <div
        ref={scrollerRef}
        className={clsx(s.scroller, dragId !== null && s.dragging, rootTargeted && s.dropRoot)}
        role="tree"
        aria-label={t("tree.label")}
        tabIndex={0}
        {...(cursorKey === null ? {} : { "aria-activedescendant": rowDomId(cursorKey) })}
        onKeyDown={onKeyDown}
        onContextMenu={(e) => {
          if (e.target !== e.currentTarget) return;
          e.preventDefault();
          setMenu({ ...menuAnchor(e.clientX, e.clientY), nodeId: null });
        }}
        onPointerMove={(e) => {
          // Every move in the gesture arrives here, whether it bubbled from a
          // row or was delivered straight to this element by the capture. What
          // it is over is a question for the hit test, not for the target.
          onPointerAt(e.clientX, e.clientY, e.target);
        }}
        onPointerLeave={(e) => {
          // Only reached when the capture was refused: a captured pointer is
          // treated as though it were still over this element, so it fires no
          // boundary events until it is released. Without the capture the
          // drag is still in flight — the release is handled on the window —
          // but it is over nothing, so it plans nothing.
          const next = e.relatedTarget;
          if (next instanceof Node && e.currentTarget.contains(next)) return;
          clearDrop();
        }}
      >
        {/* A blank sidebar and an empty vault look identical, so the wait is
            drawn in the shape of the rows that are coming. */}
        {nodesQuery.isPending && (
          <>
            <div className={s.status}>
              <BusyStatus label={t("tree.loading")} size={14} />
            </div>
            <div className={s.skeleton}>
              <SkeletonRows count={6} height="var(--space-5)" />
            </div>
          </>
        )}

        {rows.map((row, i) => {
          const previous = i === 0 ? undefined : rows[i - 1];
          const header =
            row.section === "favourite" && previous === undefined ? (
              <div className={s.sectionHeader} key="h-fav">
                <span className={s.sectionGlyph}>
                  <Icon name="star" size={12} />
                </span>
                {t("tree.sectionFavourites")}
              </div>
            ) : row.section === "tree" && (previous === undefined || previous.section === "favourite") ? (
              <div className={s.sectionHeader} key="h-tree">
                {t("tree.sectionAll")}
              </div>
            ) : null;

          const targeted =
            row.section === "tree" && drop !== null && drop.targetId === row.node.id;

          return (
            <div key={row.key}>
              {header}
              <NodeRow
                node={row.node}
                depth={row.depth}
                hasChildren={row.hasChildren}
                expanded={row.expanded}
                selected={row.node.id === selectedNodeId}
                cursored={row.key === cursorKey}
                domId={rowDomId(row.key)}
                movable={row.section === "tree"}
                droppable={row.section === "tree"}
                dragging={row.section === "tree" && row.node.id === dragId}
                dropBand={targeted && drop !== null ? drop.band : null}
                dropRefused={targeted && drop !== null && drop.plan === null}
                onToggle={onToggle}
                onSelect={onSelect}
                onActivate={onActivate}
                onContextMenu={onContextMenu}
                onPressRow={onPressRow}
              />
            </div>
          );
        })}

        {nodesQuery.isSuccess && rows.length === 0 && (
          <p className={s.empty}>
            {filter.trim() === ""
              ? t("tree.emptyVault")
              : t("tree.noMatches", { query: isolate(filter.trim()) })}
          </p>
        )}
      </div>

      {/*
        Why nothing moved, where the person who made the gesture is looking.
        A refused drop used to reach the live region alone — a 1×1 clipped box
        — so a sighted user released the pointer and saw the tree simply not
        change, which is indistinguishable from a drag the application never
        received. Tone is `warning` rather than `danger`: nothing broke, and a
        `danger` callout carries `role="alert"`, which would announce the same
        sentence a second time over the live region below.

        Below the tree and not above it. Above, the callout appeared between
        the search box and the first row and pushed every row down the height
        of three of them — so the answer to "that did not work, try again" was
        a list that had moved under the pointer, and the second attempt landed
        two rows off. A refusal must not rearrange the thing it is about.
      */}
      {refusal !== null && (
        <div className={s.notice}>
          <Callout tone="warning" title={t("move.failed")}>
            {refusal}
            <div className={s.noticeActions}>
              <Button variant="ghost" size="sm" onClick={() => setRefusal(null)}>
                {tCommon("action.dismiss")}
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {/*
        What is in the air, under the pointer that is carrying it.

        The drag had no cursor-borne affordance at all: the source row dimmed
        and a two-pixel rule appeared somewhere in a list of twenty-eight-pixel
        rows. That is enough to confirm a gesture you already believe in and
        not enough to discover one, and "it does nothing" is what an
        undiscoverable gesture looks like from outside. The chip names the
        entry so there is no doubt what was picked up, and carries the refusal
        while the pointer is still down, so the reason arrives before the
        release rather than after it.

        `aria-hidden`, because this is the sighted half of a channel whose
        other half is the live region below; both describing the same drag
        would mean hearing it twice.
      */}
      {draggedNode !== null && (
        <div ref={chipRef} className={s.chipAnchor} aria-hidden="true">
          <div className={clsx(s.chip, hoverRefusal !== null && s.chipRefused)}>
            <span className={s.chipRow}>
              <span
                className={clsx(
                  s.chipGlyph,
                  draggedNode.kind === "connection" && protocolClass(draggedNode.protocol),
                )}
              >
                <Icon name={nodeGlyph(draggedNode)} size={13} />
              </span>
              <span className={s.chipName}>{draggedNode.name}</span>
            </span>
            {hoverRefusal !== null && <span className={s.chipReason}>{hoverRefusal}</span>}
          </div>
        </div>
      )}

      {/* Drag-and-drop is invisible to a screen reader; this is where it speaks. */}
      <div className={s.live} role="status" aria-live="polite">
        {moveMutation.isPending ? (
          t("move.inProgress")
        ) : moveFailure !== null ? (
          <MoveFailureAnnouncement failure={moveFailure} t={t} />
        ) : (
          announcement
        )}
      </div>

      <div className={s.footer}>
        <span className={s.footerGrow}>
          <Button
            variant="secondary"
            size="sm"
            fullWidth
            onClick={() =>
              openEditor({
                mode: "create",
                parentId: creationParent(selectedNode),
                kind: "connection",
              })
            }
          >
            <Icon name="plus" size={13} />
            {t("tree.newConnection")}
          </Button>
        </span>
        <Button
          variant="ghost"
          size="sm"
          title={t("tree.newFolder")}
          ariaLabel={t("tree.newFolder")}
          onClick={() =>
            openEditor({ mode: "create", parentId: creationParent(selectedNode), kind: "folder" })
          }
        >
          <Icon name="folder" size={14} />
        </Button>
      </div>

      {menu !== null && (
        <div
          className={s.menu}
          role="menu"
          // `inset-inline-start`, not `left`: this is the one box in the
          // frontend positioned from JavaScript rather than from a stylesheet,
          // and it was also the one physical inset left anywhere. `menu.x` is
          // a physical viewport coordinate — see `inlineStartOffset` for why
          // that has to be mirrored before it can be used logically. The menu
          // is `position: fixed`, so the containing block is the viewport and
          // `window.innerWidth` is the right width to mirror against; it is
          // read at render rather than stored because the menu dismisses
          // itself on `resize`, so this value cannot go stale while it is open.
          style={{
            insetInlineStart: `${inlineStartOffset(menu.x, window.innerWidth, documentDirection())}px`,
            top: `${menu.y}px`,
          }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* First, because it is what the menu is most often opened for. */}
          <button
            type="button"
            role="menuitem"
            className={s.menuItem}
            disabled={!isConnectable(menuNode)}
            onClick={() => {
              if (!isConnectable(menuNode)) return;
              setMenu(null);
              openSession(menuNode);
            }}
          >
            <Icon name="server" size={13} />
            {t("menu.connect")}
          </button>
          <div className={s.menuSeparator} />
          <button
            type="button"
            role="menuitem"
            className={s.menuItem}
            onClick={() => {
              setMenu(null);
              openEditor({
                mode: "create",
                parentId: creationParent(menuNode),
                kind: "connection",
              });
            }}
          >
            <Icon name="plus" size={13} />
            {t("tree.newConnection")}
          </button>
          <button
            type="button"
            role="menuitem"
            className={s.menuItem}
            onClick={() => {
              setMenu(null);
              openEditor({ mode: "create", parentId: creationParent(menuNode), kind: "folder" });
            }}
          >
            <Icon name="folder" size={13} />
            {t("tree.newFolder")}
          </button>
          <div className={s.menuSeparator} />
          <button
            type="button"
            role="menuitem"
            className={s.menuItem}
            disabled={menuNode === null}
            onClick={() => {
              if (menuNode === null) return;
              setMenu(null);
              openEditor({ mode: "edit", nodeId: menuNode.id });
            }}
          >
            <Icon name="settings" size={13} />
            {t("menu.edit")}
          </button>
          <button
            type="button"
            role="menuitem"
            className={clsx(s.menuItem, s.menuDanger)}
            disabled={menuNode === null}
            onClick={() => {
              if (menuNode === null) return;
              setMenu(null);
              setPendingDelete(menuNode);
            }}
          >
            <Icon name="trash" size={13} />
            {t("menu.delete")}
          </button>
        </div>
      )}

      {pendingDelete !== null && (
        <div className={s.confirmBackdrop}>
          <div
            ref={confirmRef}
            className={s.confirm}
            role="alertdialog"
            aria-modal="true"
            aria-label={t("delete.title")}
            // Somewhere for focus to land if the buttons are ever taken away.
            tabIndex={-1}
          >
            <h2 className={s.confirmTitle}>{t("delete.title")}</h2>
            <Callout tone="danger">
              {/* The name is the subject of the two sentences that follow, so
                  it stays a span of its own rather than being interpolated
                  into them: it is user data of any length and any script, and
                  it carries the weight the rest of the callout does not. The
                  dash is layout punctuation between the two, not copy. */}
              <span className={s.confirmName}>{isolate(pendingDelete.name)}</span>
              {descendantCount(pendingDelete.id) > 0 ? (
                <>
                  {" — "}
                  {t("delete.contains", { count: descendantCount(pendingDelete.id) })}{" "}
                </>
              ) : (
                " "
              )}
              {t("delete.irreversible")}
            </Callout>
            {deleteFailure !== null && (
              <FailureNotice failure={deleteFailure} title={t("delete.failed")} />
            )}
            <div className={s.confirmActions}>
              <Button
                variant="ghost"
                onClick={() => setPendingDelete(null)}
                disabled={deleteMutation.isPending}
              >
                {tCommon("action.cancel")}
              </Button>
              <BusyButton
                variant="danger"
                busy={deleteMutation.isPending}
                busyLabel={t("delete.inProgress")}
                onClick={() => deleteMutation.mutate(pendingDelete.id)}
              >
                {t("delete.confirm")}
              </BusyButton>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
