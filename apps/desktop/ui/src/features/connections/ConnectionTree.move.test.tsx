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
import { act, render, screen, waitFor } from "@testing-library/react";
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
    gateway: null,
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

/**
 * A sentence the catalogue does not carry yet — the ones `pending` in
 * `ConnectionTree.tsx` stands in for.
 *
 * Read through the same i18next instance the component reads, so the
 * assertion is "whatever this key resolves to" rather than a paste of either
 * the humanised fallback it resolves to today or the sentence that will
 * replace it. The cast is what `pending` itself does, and for the same reason:
 * the key is not in `ParseKeys` until the catalogue has it.
 */
function pendingMessage(key: string, values: Record<string, string> = {}): string {
  return i18n().getFixedT(null, "connections")(key as never, values);
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

    // Past db-02, which sorts at 16 and has nothing after it. A stride past
    // the end rather than the next integer: the end of a list is the one place
    // room is free, and taking 17 would put the next two entries back into the
    // adjacent pair that costs a respace.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c2", "f1", 32));
  });

  it("moves an entry up past the sibling above it", async () => {
    await mount(SPACED);
    await cursorTo(/db-02/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    // Below db-01, which sorts at 0; a stride below it, for the reason above.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -16));
  });

  it("moves an entry into the folder directly above it, opening it", async () => {
    // Berlin is closed to begin with, so the row would otherwise vanish into a
    // folder the user cannot see.
    useApp.setState({ expanded: new Set<string>() });
    await mount(SPACED);
    await cursorTo(/web-01/);

    await userEvent.keyboard("{Control>}{ArrowRight}{/Control}");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 32));
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
    // all moves *up* the number line; alpha keeps 0 and is never written.
    //
    // That is not by itself enough to make a half-applied run safe — the value
    // a sibling is given is sometimes the one the moved entry has not vacated
    // yet, which is what "a run of calls that stops in the middle" below is
    // about. Here the slack is off the end of the list, so it is not: bravo
    // takes 32 and charlie was at 2.
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

/**
 * What a reorder costs, in calls.
 *
 * Every `node_move` is a whole vault write — read, decrypt, apply, re-encrypt,
 * fsync, rename — so the number of them is not a micro-optimisation, it is how
 * long the tree sits still after a keystroke. Respacing the entire sibling list
 * made one Ctrl+Up on a thirty-three-entry top level cost thirty-two calls,
 * measured in a real browser, and four hundred entries cost four hundred.
 *
 * Only the siblings between the insertion point and the nearest slack have to
 * move, and the node being moved has just left a gap of its own. The bound
 * below is what makes that a claim rather than an intention.
 */
describe("the cost of one reorder", () => {
  /** Twelve roots at 0 to 11: an imported tree, with no gap anywhere. */
  const CONTIGUOUS: TreeNode[] = Array.from({ length: 12 }, (_, i) =>
    node({
      id: `n${String(i)}`,
      name: `srv-${String(i).padStart(2, "0")}`,
      protocol: "ssh",
      sortOrder: i,
    }),
  );

  /** A core that applies what it is sent, so the order can be asserted. */
  function vault(nodes: TreeNode[]): TreeNode[] {
    const live = nodes.map((n) => ({ ...n }));
    ipcMock.listNodes.mockImplementation(() => Promise.resolve(live.map((n) => ({ ...n }))));
    ipcMock.moveNode.mockImplementation((id: string, parentId: string | null, sortOrder: number) => {
      const found = live.find((n) => n.id === id);
      if (found !== undefined) {
        found.parentId = parentId;
        found.sortOrder = sortOrder;
      }
      return Promise.resolve(undefined);
    });
    return live;
  }

  function order(live: TreeNode[]): string[] {
    return [...live]
      .sort((a, b) => a.sortOrder - b.sortOrder || a.name.localeCompare(b.name))
      .map((n) => n.id);
  }

  it("moves one entry up for two calls, not one per sibling", async () => {
    await mount(CONTIGUOUS);
    // After `mount`, which sets its own resolved values for both of these.
    const live = vault(CONTIGUOUS);
    await cursorTo(/srv-08/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    // The effect first: srv-08 is above srv-07 and nothing else has moved.
    await waitFor(() =>
      expect(order(live)).toEqual([
        "n0", "n1", "n2", "n3", "n4", "n5", "n6", "n8", "n7", "n9", "n10", "n11",
      ]),
    );
    // Then the price of it. Eleven siblings; this used to be all of them.
    expect(ipcMock.moveNode).toHaveBeenCalledTimes(2);
  });

  it("moves the first entry down for two calls, making room from below", async () => {
    // The mirror of the case above: the slack the search finds is off the
    // bottom of the list rather than the gap the moved entry left behind, so
    // this is the other of the two directions `movesFor` searches.
    await mount(CONTIGUOUS);
    const live = vault(CONTIGUOUS);
    await cursorTo(/srv-00/);

    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    await waitFor(() =>
      expect(order(live)).toEqual([
        "n1", "n0", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9", "n10", "n11",
      ]),
    );
    expect(ipcMock.moveNode).toHaveBeenCalledTimes(2);
  });
});

/**
 * A run of `node_move` calls that stops in the middle.
 *
 * The cheap respace above buys its two calls by putting a sibling on the sort
 * order the moved entry has not vacated yet — there is no third integer to
 * hold either of them in the meantime, which is why the old whole-list respace
 * was the price of avoiding this. So the calls are not independent: stop after
 * the first and two siblings share an order, which the sidebar breaks by name
 * in the reader's language and `storage.rs` breaks by `sort_order, id`. It
 * survives a restart and nothing on screen says so.
 *
 * Reproduced by driving the real component in a real browser with the second
 * call refused, before it was fixed: `srv-009` and `srv-010` both at 12.
 * These are the same run in jsdom, asserting the vault rather than the calls.
 */
describe("a run of calls that stops in the middle", () => {
  /** Twelve roots at 0 to 11 — an import, with no gap to use anywhere. */
  const CONTIGUOUS: TreeNode[] = Array.from({ length: 12 }, (_, i) =>
    node({
      id: `n${String(i)}`,
      name: `srv-${String(i).padStart(2, "0")}`,
      protocol: "ssh",
      sortOrder: i,
    }),
  );

  const WRITE_FAILED = {
    code: "vault.write-failed",
    message: "The vault could not be written.",
    detail: null,
    actions: [],
  };

  /**
   * A core that applies what it is sent, and refuses the calls named.
   *
   * Counting calls rather than matching on the arguments: what makes the
   * difference is *where* in the run the write fails, and the walk-back's own
   * calls are numbered in the same sequence — which is how the recovery is
   * made to fail too.
   */
  function vault(nodes: TreeNode[], refuse: ReadonlySet<number>): TreeNode[] {
    const live = nodes.map((n) => ({ ...n }));
    let call = 0;
    ipcMock.listNodes.mockImplementation(() => Promise.resolve(live.map((n) => ({ ...n }))));
    ipcMock.moveNode.mockImplementation(
      (id: string, parentId: string | null, sortOrder: number) => {
        call += 1;
        if (refuse.has(call)) return Promise.reject(WRITE_FAILED);
        const found = live.find((n) => n.id === id);
        if (found !== undefined) {
          found.parentId = parentId;
          found.sortOrder = sortOrder;
        }
        return Promise.resolve(undefined);
      },
    );
    return live;
  }

  /** Siblings left sharing one sort order. Empty is the only acceptable answer. */
  function sharedOrders(live: readonly TreeNode[]): string[][] {
    const bySlot = new Map<string, string[]>();
    for (const n of live) {
      const slot = `${n.parentId ?? ""}#${String(n.sortOrder)}`;
      bySlot.set(slot, [...(bySlot.get(slot) ?? []), n.id]);
    }
    return [...bySlot.values()].filter((ids) => ids.length > 1);
  }

  function order(live: readonly TreeNode[]): string[] {
    return [...live].sort((a, b) => a.sortOrder - b.sortOrder).map((n) => n.id);
  }

  it("leaves no two siblings sharing a sort order, and puts the list back", async () => {
    await mount(CONTIGUOUS);
    const live = vault(CONTIGUOUS, new Set([2]));
    const before = order(live);
    await cursorTo(/srv-08/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await screen.findByText(message()("move.failed"));
    // The first call landed — srv-07 was pushed up onto the order srv-08 was
    // still holding — and the walk-back took it off again.
    expect(sharedOrders(live)).toEqual([]);
    expect(order(live)).toEqual(before);
    expect(ipcMock.moveNode).toHaveBeenCalledTimes(3);
  });

  it("says so when the vault could not be put back either", async () => {
    await mount(CONTIGUOUS);
    // The second call fails, and so does the first call of the walk-back.
    const live = vault(CONTIGUOUS, new Set([2, 3]));
    await cursorTo(/srv-08/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await screen.findByText(message()("move.failed"));
    // Nothing can be done about the state — that is the point of the sentence.
    // What must not happen is the tree keeping it to itself.
    expect(sharedOrders(live)).not.toEqual([]);
    const sentence = pendingMessage("move.notUndone");
    await waitFor(() => expect(screen.getAllByText(sentence).length).toBeGreaterThan(0));
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toContain(sentence),
    );
  });

  it("says nothing of the kind when the walk-back worked", async () => {
    await mount(CONTIGUOUS);
    vault(CONTIGUOUS, new Set([2]));
    await cursorTo(/srv-08/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await screen.findByText(message()("move.failed"));
    expect(screen.queryByText(pendingMessage("move.notUndone"))).not.toBeInTheDocument();
  });
});

/**
 * What the tree says while a run of vault writes is going on.
 *
 * One reorder is one call when there is a gap to land in and two hundred when
 * there is not — a node carried from the end of a four-hundred-entry imported
 * list to the middle of it, measured in a real browser. For all of that the
 * sidebar said "Moving…" and nothing else, which is the same thing at call
 * three as it is at call a hundred and ninety.
 */
describe("how long the move is taking", () => {
  const CONTIGUOUS: TreeNode[] = Array.from({ length: 12 }, (_, i) =>
    node({
      id: `n${String(i)}`,
      name: `srv-${String(i).padStart(2, "0")}`,
      protocol: "ssh",
      sortOrder: i,
    }),
  );

  /** A core that holds each call until the test lets it finish. */
  function gatedVault(nodes: TreeNode[]): { live: TreeNode[]; finish: () => void } {
    const live = nodes.map((n) => ({ ...n }));
    const waiting: (() => void)[] = [];
    ipcMock.listNodes.mockImplementation(() => Promise.resolve(live.map((n) => ({ ...n }))));
    ipcMock.moveNode.mockImplementation(
      (id: string, parentId: string | null, sortOrder: number) =>
        new Promise<void>((resolve) => {
          waiting.push(() => {
            const found = live.find((n) => n.id === id);
            if (found !== undefined) {
              found.parentId = parentId;
              found.sortOrder = sortOrder;
            }
            resolve();
          });
        }),
    );
    return {
      live,
      finish: () => {
        const next = waiting.shift();
        if (next !== undefined) next();
      },
    };
  }

  it("counts the vault writes as they land", async () => {
    await mount(CONTIGUOUS);
    const gate = gatedVault(CONTIGUOUS);
    await cursorTo(/srv-08/);

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    // Two calls, none of them finished yet.
    const bar = await screen.findByRole("progressbar");
    expect(bar).toHaveAttribute("aria-valuemax", "2");
    expect(bar).toHaveAttribute("aria-valuenow", "0");

    await act(async () => {
      gate.finish();
    });
    await waitFor(() =>
      expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "1"),
    );

    await act(async () => {
      gate.finish();
    });
    // And it goes away when the run does, rather than sitting at "1 of 2".
    await waitFor(() => expect(screen.queryByRole("progressbar")).not.toBeInTheDocument());
  });

  it("does not draw a bar for a move that is one call", async () => {
    // A gap to land in, so nothing is respaced: the wait is one write and a
    // progress bar for it would be noise that appears and vanishes.
    await mount(SPACED);
    const gate = gatedVault(SPACED);
    await cursorTo(/db-01/);

    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    // The sentence is on screen and in the live region at once, which is why
    // this counts them rather than asking for the one.
    await waitFor(() =>
      expect(screen.getAllByText(message()("move.inProgress")).length).toBeGreaterThan(0),
    );
    expect(screen.queryByRole("progressbar")).not.toBeInTheDocument();
    await act(async () => {
      gate.finish();
    });
  });
});

/**
 * The sentence a keyboard move is announced with, when one end of it has no
 * name.
 *
 * The drag path was fixed for this and the keyboard path was not: it built its
 * announcement from `without[at - 1]` directly, with no name check, so
 * Ctrl+Up onto a separator said `Moved “web-01” above “”` — a sentence with a
 * hole where the only description of where the entry went should be. Both go
 * through `announceMove` now.
 */
describe("moving past a separator with the keyboard", () => {
  /**
   *   📁 Munich    f2   0
   *   ─────────    sp   1
   *   🖥 web-01    c1   2
   */
  const WITH_LINE: TreeNode[] = [
    node({ id: "f2", kind: "folder", name: "Munich", sortOrder: 0 }),
    node({ id: "sp", kind: "separator", name: "", sortOrder: 1 }),
    node({ id: "c1", name: "web-01", protocol: "ssh", sortOrder: 2 }),
  ];

  /**
   * Walks the cursor to a row by id.
   *
   * Not `cursorTo`, which counts `treeitem`s: a separator is a `separator`, so
   * it is a row the cursor stops on and not a row that helper can count.
   */
  async function cursorToRow(id: string): Promise<void> {
    const user = userEvent.setup();
    const tree = screen.getByRole("tree");
    tree.focus();
    for (let i = 0; i < 20; i += 1) {
      if (tree.getAttribute("aria-activedescendant") === `tree-row-tree:${id}`) return;
      await user.keyboard("{ArrowDown}");
    }
    throw new Error(`the cursor never reached ${id}`);
  }

  it("names the nearest entry that has a name, rather than quoting an empty one", async () => {
    await mount(WITH_LINE);
    await cursorToRow("c1");

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    // Munich, not the line: both describe the same gap, and one of them can be
    // read out. The sentence with the hole in it is what naming the target
    // gives, and it is the thing being asserted against.
    const hole = message()("move.movedAbove", { name: isolate("web-01"), anchor: isolate("") });
    const expected = message()("move.movedBelow", {
      name: isolate("web-01"),
      anchor: isolate("Munich"),
    });
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain(expected));
    expect(screen.getByRole("status").textContent).not.toContain(hole);
  });

  it("moves the line itself, and says so without quoting its name", async () => {
    // The other end of the same sentence: a separator is a drag source and a
    // Ctrl+arrow source, so it is also the *subject* of an announcement.
    await mount(WITH_LINE);
    await cursorToRow("sp");

    await userEvent.keyboard("{Control>}{ArrowUp}{/Control}");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("sp", null, -16));
    const hole = message()("move.movedAbove", { name: isolate(""), anchor: isolate("Munich") });
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toContain(
        pendingMessage("move.movedSeparatorAbove", { anchor: isolate("Munich") }),
      ),
    );
    expect(screen.getByRole("status").textContent).not.toContain(hole);
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
