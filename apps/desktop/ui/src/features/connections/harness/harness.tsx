/**
 * The connection tree, in a real browser, against a fake core.
 *
 * jsdom has no layout, no `elementFromPoint` and no pointer capture, so the
 * three decisions this gesture actually depends on — which element receives a
 * move, which element is under the point, and who holds the pointer — are all
 * stood in for by the unit suite. Every defect this gesture has shipped lived
 * in exactly those three, which is why the suite kept passing over them.
 *
 * This page mounts the real `ConnectionTree` with a fake `invoke`, so a driver
 * outside the page can send real mouse input through the browser's own input
 * pipeline (`Input.dispatchMouseEvent` over CDP) and read back what the tree
 * did. Nothing here mocks the component: the fake is the core, one layer below
 * `@/lib/ipc`, and it *applies* the moves it is sent so a scenario can assert
 * the resulting order rather than the calls that produced it.
 *
 * Run it with `harness/drive.mjs`; that file documents the invocation.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { I18nProvider } from "@/i18n";
import type { TreeNode } from "@/lib/ipc";

import { ConnectionTree } from "../ConnectionTree";

import "@/styles/base.css";

interface Call {
  cmd: string;
  args: Record<string, unknown> | undefined;
}

/** A row's box in viewport coordinates, which is what the driver aims at. */
interface Box {
  top: number;
  bottom: number;
  left: number;
  right: number;
  height: number;
}

/** What the driver reads back. Everything is plain JSON. */
interface HarnessApi {
  calls: () => Call[];
  moves: () => Call[];
  reset: () => void;
  nodes: () => { id: string; parentId: string | null; sortOrder: number; name: string }[];
  /** Siblings left sharing a sort order — empty unless a run half-applied. */
  duplicates: () => { parentId: string | null; sortOrder: number; ids: string[] }[];
  /** Sibling ids in drawn order, for the parent named — null is the top level. */
  order: (parentId: string | null) => string[];
  /** Where a node's row is, by the DOM id the tree gives it. */
  rect: (nodeId: string) => Box | null;
  /** Everything on screen, so a scenario can assert what a person would read. */
  text: () => string;
  /** The live region's current sentence, which is what a screen reader gets. */
  live: () => string;
  /** The row the tree considers selected. */
  selected: () => string | null;
}

function boxOf(el: Element | null): Box | null {
  if (el === null) return null;
  const r = el.getBoundingClientRect();
  return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, height: r.height };
}

declare global {
  interface Window {
    __TAURI_INTERNALS__: {
      invoke: (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;
    };
    harness: HarnessApi;
  }
}

function base(over: Partial<TreeNode> & { id: string }): TreeNode {
  return {
    parentId: null,
    sortOrder: 0,
    kind: "connection",
    name: over.id,
    description: "",
    tags: [],
    colour: null,
    protocol: "ssh",
    host: null,
    port: null,
    username: null,
    secretKind: null,
    keyFormat: null,
    hasPassphrase: false,
    agentCommentFilter: null,
    credentialId: null,
    attachedCredentialId: null,
    gateway: null,
    attachedTo: null,
    credentialChange: null,
    inheritedFieldCount: 0,
    updatedAt: 0,
    ...over,
  };
}

/**
 * A freshly imported tree: contiguous sort orders, which is the case the
 * respacing in `movesFor` was costing a call per sibling for.
 *
 * Top level, in order: a folder holding two servers, a separator, a group,
 * then `?servers=` of them, thirty by default. Sort orders run 0 upwards with
 * no gaps anywhere.
 */
function fixture(): TreeNode[] {
  const asked = Number(new URLSearchParams(window.location.search).get("servers"));
  const servers = Number.isFinite(asked) && asked > 0 ? asked : 30;
  const nodes: TreeNode[] = [
    base({ id: "f1", kind: "folder", name: "Berlin", protocol: null, sortOrder: 0 }),
    base({ id: "c1", name: "db-01", parentId: "f1", sortOrder: 0 }),
    base({ id: "c2", name: "db-02", parentId: "f1", sortOrder: 1 }),
    base({ id: "sep1", kind: "separator", name: "", protocol: null, sortOrder: 1 }),
    base({ id: "g1", kind: "group", name: "Ops", protocol: null, sortOrder: 2 }),
  ];
  for (let i = 0; i < servers; i += 1) {
    const n = String(i + 1).padStart(3, "0");
    nodes.push(base({ id: `s${n}`, name: `srv-${n}`, sortOrder: 3 + i }));
  }
  return nodes;
}

const nodes = fixture();
const calls: Call[] = [];

/**
 * Which `node_move` calls refuse, counting from one since the last reset.
 *
 * A reorder is several calls and each is a separate vault write, so the
 * interesting failure is not "the vault is unwritable" but "the third write of
 * five did not land". `?failAt=2` is how a scenario reproduces that, and
 * `?failAt=2,3` reproduces the one after it: the write that fails while the
 * tree is putting the run back. The rejection carries the shape `asFailure`
 * reads, so the tree renders it the way it renders a refusal from the core.
 */
const failAt = new Set(
  (new URLSearchParams(window.location.search).get("failAt") ?? "")
    .split(",")
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n) && n > 0),
);
let moveCount = 0;

function moveNode(id: string, parentId: string | null, sortOrder: number): void {
  const node = nodes.find((n) => n.id === id);
  if (node === undefined) throw new Error(`no such node: ${id}`);
  node.parentId = parentId;
  node.sortOrder = sortOrder;
}

/** Siblings sharing one sort order: what a half-applied run must never leave. */
function duplicateOrders(): { parentId: string | null; sortOrder: number; ids: string[] }[] {
  const seen = new Map<string, string[]>();
  for (const n of nodes) {
    const key = `${n.parentId ?? ""}#${String(n.sortOrder)}`;
    seen.set(key, [...(seen.get(key) ?? []), n.id]);
  }
  return [...seen.entries()]
    .filter(([, ids]) => ids.length > 1)
    .map(([key, ids]) => {
      const [parent, order] = key.split("#");
      return {
        parentId: parent === "" ? null : (parent ?? null),
        sortOrder: Number(order),
        ids,
      };
    });
}

window.__TAURI_INTERNALS__ = {
  invoke: (cmd, args) => {
    calls.push({ cmd, args });
    switch (cmd) {
      case "settings_get":
        return Promise.resolve({ locale: "en" });
      case "tree_list":
        return Promise.resolve(nodes.map((n) => ({ ...n })));
      case "node_move": {
        const id = args?.["id"];
        const parentId = args?.["parentId"] ?? null;
        const sortOrder = args?.["sortOrder"];
        if (typeof id !== "string" || typeof sortOrder !== "number") {
          return Promise.reject(new Error("bad node_move"));
        }
        moveCount += 1;
        if (failAt.has(moveCount)) {
          return Promise.reject({
            code: "vault.write-failed",
            message: "The vault could not be written.",
            detail: null,
            actions: [],
          });
        }
        moveNode(id, typeof parentId === "string" ? parentId : null, sortOrder);
        return Promise.resolve(undefined);
      }
      default:
        return Promise.reject(new Error(`unhandled command: ${cmd}`));
    }
  },
};

window.harness = {
  calls: () => calls.map((c) => ({ ...c })),
  moves: () => calls.filter((c) => c.cmd === "node_move").map((c) => ({ ...c })),
  reset: () => {
    calls.length = 0;
    moveCount = 0;
  },
  duplicates: duplicateOrders,
  nodes: () =>
    nodes.map((n) => ({ id: n.id, parentId: n.parentId, sortOrder: n.sortOrder, name: n.name })),
  order: (parentId) =>
    nodes
      .filter((n) => n.parentId === parentId)
      .sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name))
      .map((n) => n.id),
  rect: (nodeId) => boxOf(document.getElementById(`tree-row-tree:${nodeId}`)),
  text: () => document.body.innerText,
  live: () => document.querySelector('[role="status"]')?.textContent ?? "",
  selected: () =>
    document.querySelector('[aria-selected="true"]')?.id.replace("tree-row-tree:", "") ?? null,
};

const root = document.getElementById("root");
if (root === null) throw new Error("#root is missing");

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider
      client={
        new QueryClient({
          defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
        })
      }
    >
      <I18nProvider>
        <ConnectionTree />
      </I18nProvider>
    </QueryClientProvider>
  </StrictMode>,
);
