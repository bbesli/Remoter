/**
 * The preview tree, and what the user has ticked in it.
 *
 * All of this is pure and lives outside the components because it is the part
 * that has to be right: the preview is the only thing standing between a file
 * and four hundred new nodes in someone's vault, and an off-by-one in "exclude
 * this folder" is invisible until after the commit that cannot be undone.
 *
 * The exclusion set holds every excluded id explicitly, and two invariants keep
 * it consistent with what the core will do:
 *
 *   - excluding a node excludes its whole subtree, because
 *     `ImportCommit.excludedIds` says a folder takes its children with it;
 *   - including a node includes its ancestors, because an included child under
 *     an excluded folder is a state the core cannot honour — the folder is
 *     dropped and the child goes with it, whatever the tick said.
 */

import type { ImportNode } from "@/lib/ipc";

export interface ImportTreeIndex {
  byId: ReadonlyMap<string, ImportNode>;
  /** Children of each node, in `sortOrder`. Roots are under the `null` key. */
  children: ReadonlyMap<string | null, ImportNode[]>;
  /** Depth-first order, the order the tree is drawn in. */
  order: readonly string[];
  depth: ReadonlyMap<string, number>;
  descendants: ReadonlyMap<string, readonly string[]>;
  ancestors: ReadonlyMap<string, readonly string[]>;
}

/** Ticked, unticked, or a folder with some of its subtree unticked. */
export type TickState = "on" | "off" | "partial";

export interface IncludedCounts {
  folders: number;
  connections: number;
  credentials: number;
  /** Nodes whose password the vault will have to seal. */
  secrets: number;
  /** Connections that arrive with a gateway chain already wired up. */
  gateways: number;
  total: number;
}

/**
 * Indexes a preview's nodes into the shape the tree is drawn from.
 *
 * Two hostile-input guards, because this data came out of a file someone else
 * wrote:
 *
 *   - a node whose `parentId` names nothing in the preview is treated as a
 *     root rather than dropped. A truncated parse can cut a parent loose, and
 *     hiding its children would understate what is about to be created — the
 *     one thing this screen must never do.
 *   - a parent cycle is broken at the first node already seen, so a crafted
 *     file cannot hang the interface in a walk that never ends.
 */
export function indexNodes(nodes: readonly ImportNode[]): ImportTreeIndex {
  const byId = new Map<string, ImportNode>();
  for (const node of nodes) byId.set(node.id, node);

  const children = new Map<string | null, ImportNode[]>();
  for (const node of nodes) {
    const parent = node.parentId !== null && byId.has(node.parentId) ? node.parentId : null;
    const bucket = children.get(parent);
    if (bucket === undefined) children.set(parent, [node]);
    else bucket.push(node);
  }
  for (const bucket of children.values()) {
    bucket.sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name));
  }

  const order: string[] = [];
  const depth = new Map<string, number>();
  const ancestors = new Map<string, readonly string[]>();
  const seen = new Set<string>();

  const walk = (parentId: string | null, level: number, path: readonly string[]): void => {
    for (const node of children.get(parentId) ?? []) {
      if (seen.has(node.id)) continue;
      seen.add(node.id);
      order.push(node.id);
      depth.set(node.id, level);
      ancestors.set(node.id, path);
      walk(node.id, level + 1, [...path, node.id]);
    }
  };
  walk(null, 0, []);

  // Anything the walk never reached is in a cycle. It still has to be drawn,
  // so it lands at the top level rather than vanishing.
  for (const node of nodes) {
    if (seen.has(node.id)) continue;
    seen.add(node.id);
    order.push(node.id);
    depth.set(node.id, 0);
    ancestors.set(node.id, []);
  }

  const descendants = new Map<string, readonly string[]>();
  // Reverse depth-first order visits every child before its parent, so each
  // node's list is built from lists that are already complete.
  for (let i = order.length - 1; i >= 0; i -= 1) {
    const id = order[i];
    if (id === undefined) continue;
    const own: string[] = [];
    for (const child of children.get(id) ?? []) {
      own.push(child.id, ...(descendants.get(child.id) ?? []));
    }
    descendants.set(id, own);
  }

  return { byId, children, order, depth, descendants, ancestors };
}

/** Unticks a node and everything under it. */
export function excludeNode(
  excluded: ReadonlySet<string>,
  index: ImportTreeIndex,
  id: string,
): Set<string> {
  const next = new Set(excluded);
  next.add(id);
  for (const child of index.descendants.get(id) ?? []) next.add(child);
  return next;
}

/**
 * Ticks a node, everything under it, and every folder above it.
 *
 * The ancestors are the part that matters: without them the tick would show a
 * connection coming across while its parent folder — and therefore the
 * connection — was still excluded.
 */
export function includeNode(
  excluded: ReadonlySet<string>,
  index: ImportTreeIndex,
  id: string,
): Set<string> {
  const next = new Set(excluded);
  next.delete(id);
  for (const child of index.descendants.get(id) ?? []) next.delete(child);
  for (const ancestor of index.ancestors.get(id) ?? []) next.delete(ancestor);
  return next;
}

export function toggleNode(
  excluded: ReadonlySet<string>,
  index: ImportTreeIndex,
  id: string,
): Set<string> {
  return excluded.has(id) ? includeNode(excluded, index, id) : excludeNode(excluded, index, id);
}

export function tickState(
  excluded: ReadonlySet<string>,
  index: ImportTreeIndex,
  id: string,
): TickState {
  if (excluded.has(id)) return "off";
  const kids = index.descendants.get(id) ?? [];
  for (const child of kids) {
    if (excluded.has(child)) return "partial";
  }
  return "on";
}

export function includedCounts(
  index: ImportTreeIndex,
  excluded: ReadonlySet<string>,
): IncludedCounts {
  const counts: IncludedCounts = {
    folders: 0,
    connections: 0,
    credentials: 0,
    secrets: 0,
    gateways: 0,
    total: 0,
  };
  for (const id of index.order) {
    if (excluded.has(id)) continue;
    const node = index.byId.get(id);
    if (node === undefined) continue;
    counts.total += 1;
    if (node.kind === "folder") counts.folders += 1;
    else if (node.kind === "connection") counts.connections += 1;
    else counts.credentials += 1;
    if (node.hasSecret) counts.secrets += 1;
    if (node.gatewayHops > 0) counts.gateways += 1;
  }
  return counts;
}

/**
 * The exclusion list to send with the commit: only the topmost excluded node of
 * each excluded subtree.
 *
 * Sending the whole set would work — the core takes a folder's children with
 * it either way — but four hundred ids for one unticked archive folder is a
 * payload nobody can read in a log or a test failure.
 */
export function excludedRoots(index: ImportTreeIndex, excluded: ReadonlySet<string>): string[] {
  const roots: string[] = [];
  for (const id of index.order) {
    if (!excluded.has(id)) continue;
    const path = index.ancestors.get(id) ?? [];
    if (path.some((ancestor) => excluded.has(ancestor))) continue;
    roots.push(id);
  }
  return roots;
}

/**
 * The rows a filter leaves visible: every match, every ancestor of a match so
 * the match keeps its place in the tree, and everything under a matching
 * folder so unticking it still means what it says.
 *
 * Returns `null` for an empty query, which the tree reads as "no filter" and
 * draws everything.
 */
export function matchingIds(index: ImportTreeIndex, query: string): ReadonlySet<string> | null {
  const needle = query.trim().toLowerCase();
  if (needle === "") return null;

  const visible = new Set<string>();
  for (const id of index.order) {
    const node = index.byId.get(id);
    if (node === undefined) continue;
    const haystack = [node.name, node.host ?? "", node.username ?? "", node.protocol ?? ""]
      .join(" ")
      .toLowerCase();
    if (!haystack.includes(needle)) continue;
    visible.add(id);
    for (const ancestor of index.ancestors.get(id) ?? []) visible.add(ancestor);
    for (const child of index.descendants.get(id) ?? []) visible.add(child);
  }
  return visible;
}
