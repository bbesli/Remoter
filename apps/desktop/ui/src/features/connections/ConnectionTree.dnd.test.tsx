/**
 * Reproduction harness for drag-and-drop in the connection tree.
 *
 * Temporary: written to measure what the tree actually does when a row is
 * dragged, because nothing in the suite exercised the pointer path at all.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useApp } from "@/stores/app";
import type { TreeNode } from "@/lib/ipc";

import { ConnectionTree } from "./ConnectionTree";
import { useConnectionEditor } from "./ConnectionEditor";

const { ipcMock } = vi.hoisted(() => ({
  ipcMock: { listNodes: vi.fn(), deleteNode: vi.fn(), moveNode: vi.fn() },
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

function node(over: Partial<TreeNode> & { id: string }): TreeNode {
  return {
    parentId: null,
    sortOrder: 0,
    kind: "connection",
    name: "node",
    description: "",
    tags: [],
    colour: null,
    protocol: null,
    host: null,
    port: null,
    username: null,
    secretKind: null,
    keyFormat: null,
    hasPassphrase: false,
    agentCommentFilter: null,
    credentialId: null,
    attachedCredentialId: null,
    attachedTo: null,
    credentialChange: null,
    inheritedFieldCount: 0,
    updatedAt: 0,
    ...over,
  };
}

/**
 * A stand-in for `DataTransfer`, which jsdom does not implement.
 *
 * The drag has to carry its payload across three separate events, so the same
 * instance is handed to all three, exactly as the platform would.
 */
class FakeDataTransfer {
  private readonly store = new Map<string, string>();
  effectAllowed = "none";
  dropEffect = "none";
  setData(type: string, value: string): void {
    this.store.set(type, value);
  }
  getData(type: string): string {
    return this.store.get(type) ?? "";
  }
  get types(): string[] {
    return [...this.store.keys()];
  }
}

/**
 * jsdom implements no `DragEvent`, so `fireEvent.dragOver` falls back to the
 * bare `Event` constructor and silently drops `clientY` — which is the one
 * property the row reads to decide which band the pointer is in. A `MouseEvent`
 * carries it, and React dispatches on the event's type rather than its class.
 */
function fireDrag(
  el: HTMLElement,
  type: "dragstart" | "dragover" | "drop" | "dragend",
  dataTransfer: FakeDataTransfer,
  clientY: number,
): void {
  const ev = new MouseEvent(type, { bubbles: true, cancelable: true, clientY });
  Object.defineProperty(ev, "dataTransfer", { value: dataTransfer });
  fireEvent(el, ev);
}

/** jsdom has no layout, so a row's height is 0 and every band would be "into". */
function withHeight(el: HTMLElement, top: number, height: number): void {
  el.getBoundingClientRect = () =>
    ({ top, left: 0, bottom: top + height, right: 200, width: 200, height, x: 0, y: top }) as DOMRect;
}

function renderTree() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ConnectionTree />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  useApp.setState({
    openModals: new Set<string>(),
    selectedNodeId: null,
    expanded: new Set<string>(["f1"]),
  });
  useConnectionEditor.setState({ target: null });
  Element.prototype.scrollIntoView = vi.fn();
});

const TREE: TreeNode[] = [
  node({ id: "f1", kind: "folder", name: "Berlin", sortOrder: 0 }),
  node({ id: "c1", name: "web-01", protocol: "ssh", sortOrder: 1 }),
  node({ id: "c2", name: "db-01", protocol: "ssh", parentId: "f1", sortOrder: 0 }),
  node({ id: "c3", name: "db-02", protocol: "ssh", parentId: "f1", sortOrder: 1 }),
];

describe("dragging a row", () => {
  it("drops a connection into a folder", async () => {
    ipcMock.listNodes.mockResolvedValue(TREE);
    ipcMock.moveNode.mockResolvedValue(undefined);
    renderTree();

    const source = await screen.findByRole("treeitem", { name: /web-01/ });
    const folder = screen.getByRole("treeitem", { name: /Berlin/ });
    withHeight(source, 24, 24);
    withHeight(folder, 0, 24);

    const dt = new FakeDataTransfer();
    fireDrag(source, "dragstart", dt, 36);
    // Middle of the row: the "into" band.
    fireDrag(folder, "dragover", dt, 12);
    fireDrag(folder, "drop", dt, 12);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalled());
    expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 2);
  });

  it("reorders a connection above its sibling", async () => {
    ipcMock.listNodes.mockResolvedValue(TREE);
    ipcMock.moveNode.mockResolvedValue(undefined);
    renderTree();

    const source = await screen.findByRole("treeitem", { name: /db-02/ });
    const anchor = screen.getByRole("treeitem", { name: /db-01/ });
    withHeight(source, 48, 24);
    withHeight(anchor, 24, 24);

    const dt = new FakeDataTransfer();
    fireDrag(source, "dragstart", dt, 60);
    // Top quarter of db-01: the "before" band.
    fireDrag(anchor, "dragover", dt, 26);
    fireDrag(anchor, "drop", dt, 26);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalled());
    expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1);
  });
});
