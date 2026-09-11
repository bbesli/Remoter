/**
 * Ctrl/Cmd with an arrow key: the same four moves, without a pointer.
 *
 * It shares `runMove` and `movesFor` with the drag, so most of what is checked
 * here is the half the drag cannot reach: the four keyboard intentions, the
 * refusals at the ends of a list, and the respacing that happens when two
 * neighbouring sort orders leave no integer between them.
 *
 * That last one matters more than it looks. `node_create` hands out
 * consecutive integers, so a tree that has never been reordered has *no* gaps
 * anywhere, which means the respace path is the ordinary case for a real vault
 * and the midpoint path is the exception. It had no test either.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { TFunction } from "i18next";

import { i18n, isolate } from "@/i18n";
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
 * The catalogue the application ships, not a paste of it — see the same helper
 * in `ConnectionTree.dnd.test.tsx`. Fixed to the namespace, so a key that stops
 * existing is a compile error rather than a test asserting on a key name.
 */
function message(): TFunction<"connections"> {
  return i18n().getFixedT(null, "connections");
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

/** Puts the keyboard cursor on the row named `name`, from the top of the tree. */
async function cursorTo(name: RegExp): Promise<void> {
  const user = userEvent.setup();
  screen.getByRole("tree").focus();
  const rows = screen.getAllByRole("treeitem");
  const at = rows.findIndex((row) => name.test(row.textContent ?? ""));
  expect(at).toBeGreaterThanOrEqual(0);
  for (let i = 0; i <= at; i += 1) await user.keyboard("{ArrowDown}");
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

/**
 * Sort orders spaced by 16, so a midpoint exists. The respace suite below uses
 * a tree with none.
 *
 *   📁 Berlin      f1   0
 *      🖥 db-01    c2   0
 *      🖥 db-02    c3   16
 *   🖥 web-01      c1   16
 */
const SPACED: TreeNode[] = [
  node({ id: "f1", kind: "folder", name: "Berlin", sortOrder: 0 }),
  node({ id: "c2", name: "db-01", protocol: "ssh", parentId: "f1", sortOrder: 0 }),
  node({ id: "c3", name: "db-02", protocol: "ssh", parentId: "f1", sortOrder: 16 }),
  node({ id: "c1", name: "web-01", protocol: "ssh", sortOrder: 16 }),
];

async function mount(nodes: TreeNode[]) {
  ipcMock.listNodes.mockResolvedValue(nodes);
  ipcMock.moveNode.mockResolvedValue(undefined);
  renderTree();
  await waitFor(() => expect(screen.getAllByRole("treeitem").length).toBeGreaterThan(0));
}

describe("Ctrl with an arrow key", () => {
  it("moves an entry down past its next sibling", async () => {
    await mount(SPACED);
    await cursorTo(/db-01/);

    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    // Past db-02, which sorts at 16 and has nothing after it.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c2", "f1", 17));
  });

  it("moves an entry up past the sibling above it", async () => {
    await mount(SPACED);
    await cursorTo(/db-02/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1));
  });

  it("moves an entry into the folder directly above it, opening it", async () => {
    // Berlin is closed to begin with, so the row would otherwise vanish into a
    // folder the user cannot see.
    useApp.setState({ expanded: new Set<string>() });
    await mount(SPACED);
    await cursorTo(/web-01/);

    await userEvent.keyboard("{Control>}{ArrowRight}{/Control}");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 17));
    expect(useApp.getState().expanded.has("f1")).toBe(true);
  });

  it("moves an entry out of its folder, to just after it", async () => {
    await mount(SPACED);
    await cursorTo(/db-01/);

    await userEvent.keyboard("{Control>}{ArrowLeft}{/Control}");

    // Berlin sorts at 0 among the roots and web-01 at 16, so there is room.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c2", null, 8));
  });
});

describe("a keyboard move with nowhere to go", () => {
  it("says so on the tree, not only into the live region", async () => {
    await mount(SPACED);
    await cursorTo(/db-01/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    const expected = message()("move.atFirst", { name: isolate("db-01") });
    await waitFor(() => expect(screen.getAllByText(expected).length).toBeGreaterThan(0));
    // The same fix as the refused drop: a sighted user pressing Ctrl+Up on the
    // first row used to get nothing at all, which is indistinguishable from a
    // shortcut the application never received.
    const live = screen.getByRole("status");
    expect(screen.getAllByText(expected).some((el) => !live.contains(el))).toBe(true);
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });

  it("refuses to indent under something that is not a folder", async () => {
    await mount(SPACED);
    await cursorTo(/db-02/);

    await userEvent.keyboard("{Control>}{ArrowRight}{/Control}");

    const expected = message()("move.cannotIndent", { name: isolate("db-02") });
    await waitFor(() => expect(screen.getAllByText(expected).length).toBeGreaterThan(0));
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });

  it("refuses to outdent something already at the top level", async () => {
    await mount(SPACED);
    await cursorTo(/web-01/);

    await userEvent.keyboard("{Control>}{ArrowLeft}{/Control}");

    const expected = message()("move.atTopLevel", { name: isolate("web-01") });
    await waitFor(() => expect(screen.getAllByText(expected).length).toBeGreaterThan(0));
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });
});

/**
 * Three roots at 0, 1 and 2 — what `node_create` produces and what a vault
 * that has never been reordered actually looks like.
 */
const ADJACENT: TreeNode[] = [
  node({ id: "a", name: "alpha", protocol: "ssh", sortOrder: 0 }),
  node({ id: "b", name: "bravo", protocol: "ssh", sortOrder: 1 }),
  node({ id: "c", name: "charlie", protocol: "ssh", sortOrder: 2 }),
];

describe("when two neighbours leave no integer between them", () => {
  it("respaces the list instead of giving up", async () => {
    await mount(ADJACENT);
    await cursorTo(/charlie/);

    // Between alpha (0) and bravo (1): no midpoint exists, so `sort_order`
    // being an i64 in the core forces a respace.
    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledTimes(2));
    const calls = ipcMock.moveNode.mock.calls;
    // Written from the bottom of the list upwards, and every row that moves at
    // all moves *up* the number line. A run that fails halfway then leaves the
    // siblings in the order they were already in rather than in a new wrong
    // one; alpha keeps 0 and is never written.
    expect(calls[0]).toEqual(["b", null, 32]);
    expect(calls[1]).toEqual(["c", null, 16]);
    for (const [, , order] of calls as [string, string | null, number][]) {
      expect(order).toBeGreaterThan(0);
    }
  });

  it("announces the move it actually made", async () => {
    await mount(ADJACENT);
    await cursorTo(/charlie/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    const expected = message()("move.movedAbove", {
      name: isolate("charlie"),
      anchor: isolate("bravo"),
    });
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain(expected));
  });
});

describe("a favourite row", () => {
  it("cannot be moved from, because it is a tag and not a place", async () => {
    // The favourites projection draws the same node a second time. Ctrl+Down
    // on it must do nothing rather than move the entry it is standing for,
    // which would move a row the user is not looking at.
    await mount([
      node({ id: "a", name: "alpha", protocol: "ssh", sortOrder: 0, tags: ["favourite"] }),
      node({ id: "b", name: "bravo", protocol: "ssh", sortOrder: 16 }),
    ]);
    screen.getByRole("tree").focus();
    // The first row is the favourite.
    await userEvent.keyboard("{ArrowDown}");
    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });
});
