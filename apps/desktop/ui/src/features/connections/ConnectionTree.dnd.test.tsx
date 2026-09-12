/**
 * Dragging a row, end to end.
 *
 * This feature shipped with no test at all, which is why nobody knew it was
 * dead on Windows: the HTML5 version of it could not be exercised here either.
 * jsdom implements `PointerEvent` and implements neither `DragEvent` nor
 * `DataTransfer`, so a gesture built on pointer events — which is what the
 * tree now uses, for the platform reason in `NodeRow.tsx` — is a gesture the
 * suite can actually perform.
 *
 * What jsdom still cannot supply is layout: every element reports a zero-sized
 * rectangle, and the band maths is entirely about where in a row's height the
 * pointer is. `layOutRows` gives the rendered rows the geometry a browser
 * would, so "the top half of this row" means something, and `installHitTest`
 * answers `elementFromPoint` from the same geometry. Those two are the whole
 * of what is stood in for; everything else here is the component's own code
 * path.
 *
 * The hit test is not a convenience. This suite passed in full while the
 * feature did not work, because it dispatched `pointermove` straight at the
 * row each case had in mind — which skips both of the decisions a browser
 * makes and the tree was wrong about: which element receives the event, and
 * which element is under the point. The gesture below travels across the rows
 * in the steps a mouse takes, and the cases that matter most run twice: once
 * delivered to the row under the pointer, and once delivered to the scroller,
 * as a captured pointer delivers everything.
 *
 * Every case below is one the owner tries within a minute of it working.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { TFunction } from "i18next";

import { i18n, isolate } from "@/i18n";
import { useApp } from "@/stores/app";
import type { TreeNode } from "@/lib/ipc";

import { ConnectionTree } from "./ConnectionTree";
import { useConnectionEditor } from "./ConnectionEditor";
import type { DropBand } from "./NodeRow";
import rowStyles from "./NodeRow.module.css";

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
 * The catalogue the application ships, not a paste of it.
 *
 * A sentence pasted here would let this file keep passing against wording no
 * screen shows any more — the same reason `ConnectionTree.test.tsx` reads the
 * Turkish file rather than quoting it. Fixed to the namespace so the keys below
 * are checked against the catalogue at compile time rather than at run time.
 */
function message(): TFunction<"connections"> {
  return i18n().getFixedT(null, "connections");
}

/* ------------------------------------------------------------ the gesture -- */

/** Row height in the pretend layout below. Any value works; this one is real. */
const ROW_H = 24;

/**
 * Give every rendered row the geometry jsdom does not compute.
 *
 * Rows are stacked in DOM order, which is the order they are drawn in. Call it
 * again after anything that adds or removes a row — an auto-expand, a refetch.
 */
function layOutRows(): void {
  screen.getAllByRole("treeitem").forEach((row, i) => {
    const top = i * ROW_H;
    row.getBoundingClientRect = () =>
      ({
        top,
        bottom: top + ROW_H,
        left: 0,
        right: 260,
        width: 260,
        height: ROW_H,
        x: 0,
        y: top,
        toJSON: () => ({}),
      }) as DOMRect;
  });
}

/**
 * The browser's own hit test, answered from the geometry above.
 *
 * This is the piece that makes the gesture below a gesture rather than a
 * sequence of well-aimed function calls. A mouse does not dispatch events at
 * elements; it dispatches them at coordinates, and the browser decides what is
 * underneath. Firing `pointermove` straight at the row the test has in mind
 * skips that decision — and the decision is where the component was wrong, so
 * every test that skipped it passed while the feature did not work.
 *
 * jsdom has no layout and therefore no `elementFromPoint` of its own, so the
 * tree falls back to the event's target when it is missing. Installing it is
 * how the suite gets to exercise the path a browser actually takes.
 */
function installHitTest(): void {
  const target = document as Document & {
    elementFromPoint?: (x: number, y: number) => Element | null;
  };
  target.elementFromPoint = (x: number, y: number): Element | null => {
    for (const row of screen.queryAllByRole("treeitem")) {
      const r = row.getBoundingClientRect();
      if (x >= r.left && x < r.right && y >= r.top && y < r.bottom) return row;
    }
    return screen.queryByRole("tree");
  };
}

function removeHitTest(): void {
  const target = document as Document & { elementFromPoint?: unknown };
  // Put jsdom back the way it was found — no `elementFromPoint` at all — so a
  // test in another file cannot inherit this one's pretend layout.
  Reflect.deleteProperty(target, "elementFromPoint");
}

/** The y coordinate `fraction` of the way down `el`. */
function inRow(el: HTMLElement, fraction: number): number {
  const rect = el.getBoundingClientRect();
  return rect.top + rect.height * fraction;
}

/** The y coordinate inside `el` that means `band`, per `bandAt`. */
function bandY(el: HTMLElement, band: DropBand): number {
  const rect = el.getBoundingClientRect();
  if (band === "before") return rect.top + 2;
  if (band === "after") return rect.bottom - 2;
  return rect.top + rect.height / 2;
}

const POINTER = { pointerId: 1, pointerType: "mouse", button: 0, isPrimary: true } as const;

/** Press a row. On its own this is a click, not a drag. */
function press(row: HTMLElement): void {
  fireEvent.pointerDown(row, {
    ...POINTER,
    clientX: 10,
    clientY: row.getBoundingClientRect().top + ROW_H / 2,
  });
}

/** Move the pointer over `el`, at `y` if given and over its middle otherwise. */
function moveOver(el: HTMLElement, y?: number): void {
  fireEvent.pointerMove(el, {
    ...POINTER,
    clientX: 10,
    clientY: y ?? el.getBoundingClientRect().top + ROW_H / 2,
  });
}

function release(el: HTMLElement): void {
  fireEvent.pointerUp(el, { ...POINTER, clientX: 10, clientY: bandY(el, "into") });
}

/**
 * Move the pointer to `y`, delivered the way the platform would deliver it.
 *
 * `to` is the element the event is dispatched at. A webview that has granted
 * the capture the tree asks for names the scroller every time, whatever the
 * pointer is over; one that has not names the row under it. Both have to end
 * in the same place, which is the whole point of hit-testing rather than
 * trusting the target.
 */
function moveTo(y: number, to: HTMLElement): void {
  fireEvent.pointerMove(to, { ...POINTER, clientX: 10, clientY: y });
}

/**
 * A pointer travelling from where it is to `y`, in the steps a mouse takes.
 *
 * A mouse emits a move every few pixels, and the first several of them are
 * still over the row the press landed on — so the drag threshold, the refusal
 * on the source row and the crossing of every row in between all happen, in
 * that order, before the target is ever reached. One jump to the destination
 * exercises none of it.
 */
function travel(fromY: number, toY: number, captured: boolean): void {
  const scroller = screen.getByRole("tree");
  const step = fromY < toY ? 6 : -6;
  for (let y = fromY + step; (step > 0 ? y < toY : y > toY); y += step) {
    moveTo(y, captured ? scroller : rowAt(y));
  }
  moveTo(toY, captured ? scroller : rowAt(toY));
}

/** The row the geometry puts under `y`, or the scroller when there is none. */
function rowAt(y: number): HTMLElement {
  for (const row of screen.queryAllByRole("treeitem")) {
    const r = row.getBoundingClientRect();
    if (y >= r.top && y < r.bottom) return row;
  }
  return screen.getByRole("tree");
}

/** The whole gesture: pick `from` up, travel to `y`, let go there. */
function dragTo(from: HTMLElement, y: number, captured = false): void {
  const startY = inRow(from, 0.5);
  press(from);
  travel(startY, y, captured);
  fireEvent.pointerUp(captured ? screen.getByRole("tree") : rowAt(y), {
    ...POINTER,
    clientX: 10,
    clientY: y,
  });
}

/** The whole gesture, aimed at a band of `to`. */
function drag(from: HTMLElement, to: HTMLElement, band: DropBand): void {
  dragTo(from, bandY(to, band));
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

/** The rows as drawn, by name, so an assertion can be about order. */
function rowNames(): string[] {
  return screen
    .getAllByRole("treeitem")
    .map((row) => row.textContent ?? "")
    .map((text) => text.trim());
}

afterEach(removeHitTest);

beforeEach(() => {
  vi.clearAllMocks();
  vi.useRealTimers();
  useApp.setState({
    openModals: new Set<string>(),
    selectedNodeId: null,
    expanded: new Set<string>(["f1"]),
  });
  useConnectionEditor.setState({ target: null });
  Element.prototype.scrollIntoView = vi.fn();
});

/**
 * Berlin holds two servers and a sub-folder; Munich is closed and holds one.
 *
 * Ops is a *group*: it wears the folder glyph and cannot hold anything, which
 * is the one case where refusing a drop is still the right answer.
 *
 *   📁 Berlin        f1   (open)
 *      🖥 db-01      c2
 *      🖥 db-02      c3
 *      📁 Wedding    f3
 *   📁 Munich        f2   (closed)
 *      🖥 cache-01   c4
 *   🖥 web-01        c1
 *   📁 Ops           g1   (a group)
 */
const TREE: TreeNode[] = [
  node({ id: "f1", kind: "folder", name: "Berlin", sortOrder: 0 }),
  node({ id: "c2", name: "db-01", protocol: "ssh", parentId: "f1", sortOrder: 0 }),
  node({ id: "c3", name: "db-02", protocol: "ssh", parentId: "f1", sortOrder: 1 }),
  node({ id: "f3", kind: "folder", name: "Wedding", parentId: "f1", sortOrder: 2 }),
  node({ id: "f2", kind: "folder", name: "Munich", sortOrder: 1 }),
  node({ id: "c4", name: "cache-01", protocol: "ssh", parentId: "f2", sortOrder: 0 }),
  node({ id: "c1", name: "web-01", protocol: "ssh", sortOrder: 2 }),
  node({ id: "g1", kind: "group", name: "Ops", sortOrder: 3 }),
];

async function mountTree(nodes: TreeNode[] = TREE) {
  ipcMock.listNodes.mockResolvedValue(nodes);
  renderTree();
  await screen.findByRole("treeitem", { name: /Berlin/ });
  layOutRows();
  installHitTest();
}

function row(name: RegExp): HTMLElement {
  return screen.getByRole("treeitem", { name });
}

describe("dropping a connection onto a folder", () => {
  it("puts it inside that folder, after what is already there", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    drag(row(/web-01/), row(/Berlin/), "into");

    // Berlin's last child sorts at 2, so the newcomer takes 3 — the order the
    // vault stores, not the order the rows happen to be drawn in.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 3));
    expect(ipcMock.moveNode).toHaveBeenCalledTimes(1);
  });

  it("refuses a connection dropped onto a group, which only looks like a folder", async () => {
    await mountTree();

    drag(row(/web-01/), row(/Ops/), "into");

    // Twice over, by design: once on the tree and once in the live region.
    const reason = message()("move.refuseNotFolder");
    await waitFor(() => expect(screen.getAllByText(reason)).toHaveLength(2));
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });
});

/**
 * The half of the row that used to answer "only a folder can hold other
 * entries".
 *
 * A connection has no inside, so its height is halved rather than split in
 * three: the top half means above it and the bottom half below it, and there
 * is no band in the middle whose only possible answer is a refusal. Every one
 * of these lands on the body of the row — 35% and 65% of the way down, which
 * is where a person aims when they mean "put it next to this one" and which
 * the three-band split read as "put it inside this one".
 */
describe("reordering by dropping on the body of a row", () => {
  it("lands above the row when the drop is on its top half", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/db-02/), inRow(row(/db-01/), 0.35));

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1));
    expect(screen.queryByText(message()("move.refuseNotFolder"))).not.toBeInTheDocument();
  });

  it("lands below the row when the drop is on its bottom half", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/web-01/), inRow(row(/db-01/), 0.65));

    // Announced as what it is, which is also the only description of where it
    // went that does not depend on the sort orders the respacing picks.
    const below = message()("move.movedBelow", {
      name: isolate("web-01"),
      anchor: isolate("db-01"),
    });
    await waitFor(() => expect(screen.getByRole("status").textContent).toContain(below));
    expect(ipcMock.moveNode).toHaveBeenCalled();
  });

  it("still reaches the inside of a folder, which does keep a middle band", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/web-01/), inRow(row(/Berlin/), 0.5));

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 3));
  });
});

/**
 * Where the pointer is, not where the event was delivered.
 *
 * Once a webview grants the pointer capture the tree asks for, every move in
 * the gesture is dispatched at the capturing element — here the scroller —
 * whatever the pointer is over. A tree that reads the target of the event
 * instead of hit-testing the point sees the same element for the whole drag,
 * finds no row under it, and reads every move as the background: the node goes
 * to the top level, or nowhere, and never into the folder the pointer was
 * plainly sitting on. That is a drag that stops working the moment something
 * takes the pointer, which is a thing platforms do differently and none of
 * them announce.
 */
describe("a drag whose moves are all delivered to one element", () => {
  it("still drops into the folder the pointer is over", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/web-01/), inRow(row(/Berlin/), 0.5), true);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f1", 3));
  });

  it("still reorders against the row the pointer is over", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/db-02/), inRow(row(/db-01/), 0.35), true);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1));
  });
});

describe("dropping a connection between two rows", () => {
  it("lands it there, in that order", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    // The top quarter of db-01 is the gap above it.
    drag(row(/db-02/), row(/db-01/), "before");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1));
  });

  it("is stored rather than only drawn: the new order survives a reload", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);
    // What the vault holds once the move has been written. The tree refetches
    // after a move, so this is the list the rows are rebuilt from.
    const reordered = TREE.map((n) => (n.id === "c3" ? { ...n, sortOrder: -1 } : n));
    ipcMock.listNodes.mockResolvedValue(reordered);

    drag(row(/db-02/), row(/db-01/), "before");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c3", "f1", -1));
    // Refetched, not patched locally: the rows on screen are what the core
    // returned.
    await waitFor(() => expect(ipcMock.listNodes.mock.calls.length).toBeGreaterThan(1));
    await waitFor(() => {
      const names = rowNames();
      expect(names.findIndex((n) => n.includes("db-02"))).toBeLessThan(
        names.findIndex((n) => n.includes("db-01")),
      );
    });
  });

  it("draws the indicator in the gap it would land in, not on the row", async () => {
    await mountTree();

    press(row(/db-02/));
    const anchor = row(/db-01/);
    moveOver(anchor, bandY(anchor, "before"));

    // Nothing is being entered, so the row must not light up as a container.
    expect(anchor.className).toContain(rowStyles["dropBefore"]);
    expect(anchor.className).not.toContain(rowStyles["dropInto"]);
  });
});

describe("dropping a folder", () => {
  it("moves the whole subtree with one call, never its children", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    // Munich is closed and holds cache-01.
    drag(row(/Munich/), row(/Berlin/), "into");

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("f2", "f1", 3));
    // Re-parenting is one row update in the core (data-model.md: parent_id plus
    // sort_order, not a materialised path). A child that was also moved would
    // mean the interface is re-implementing the tree.
    expect(ipcMock.moveNode).toHaveBeenCalledTimes(1);
    expect(ipcMock.moveNode).not.toHaveBeenCalledWith("c4", expect.anything(), expect.anything());
  });

  it("keeps its contents underneath it once the tree comes back", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);
    ipcMock.listNodes.mockResolvedValue(
      TREE.map((n) => (n.id === "f2" ? { ...n, parentId: "f1", sortOrder: 3 } : n)),
    );

    drag(row(/Munich/), row(/Berlin/), "into");
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalled());

    await act(async () => {
      useApp.getState().toggleExpanded("f2");
    });
    // cache-01 followed its folder: it is still Munich's child, now two levels
    // down rather than one.
    const nested = await screen.findByRole("treeitem", { name: /cache-01/ });
    expect(nested).toHaveAttribute("aria-level", "3");
  });

  it("cannot be dropped into something it contains, and says so where it can be read", async () => {
    await mountTree();

    // Wedding is inside Berlin, so Berlin cannot go inside Wedding.
    drag(row(/Berlin/), row(/Wedding/), "into");

    const reason = message()("move.refuseDescendant");
    await waitFor(() => expect(screen.getAllByText(reason).length).toBeGreaterThan(0));

    // The point of the fix: at least one of those is somewhere a sighted user
    // is looking, not only in the clipped live region. A refusal that reaches
    // the live region alone is indistinguishable from a drag the application
    // never received — which is the ambiguity that hid the Windows defect.
    const live = screen.getByRole("status");
    expect(screen.getAllByText(reason).some((el) => !live.contains(el))).toBe(true);
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });

  it("lets the refusal be dismissed once it has been read", async () => {
    await mountTree();
    drag(row(/Berlin/), row(/Wedding/), "into");
    const reason = message()("move.refuseDescendant");
    await waitFor(() => expect(screen.getAllByText(reason).length).toBeGreaterThan(0));

    fireEvent.click(screen.getByRole("button", { name: i18n().t("common:action.dismiss") }));

    const live = screen.getByRole("status");
    expect(screen.queryAllByText(reason).every((el) => live.contains(el))).toBe(true);
  });
});

describe("dropping on the empty space below the tree", () => {
  it("moves the entry to the top level", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    press(row(/db-01/));
    const scroller = screen.getByRole("tree");
    // The background, below the last row.
    fireEvent.pointerMove(scroller, { ...POINTER, clientX: 10, clientY: 400 });
    fireEvent.pointerUp(scroller, { ...POINTER, clientX: 10, clientY: 400 });

    // Three roots already (0, 1, 2), so the newcomer lands after the last.
    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c2", null, 4));
  });

  it("treats a favourite row as background rather than as a dead band", async () => {
    // A favourite is a projection of a tag, not a place in the tree. It cannot
    // take a drop — but it must not swallow the drag either, which is what it
    // did while the row stopped the event before checking whether it could
    // accept it.
    await mountTree(
      TREE.map((n) => (n.id === "c1" ? { ...n, tags: ["favourite"] } : n)),
    );
    ipcMock.moveNode.mockResolvedValue(undefined);

    const favourite = screen.getAllByRole("treeitem", { name: /web-01/ })[0];
    expect(favourite).toBeDefined();
    if (favourite === undefined) return;

    press(row(/db-01/));
    moveOver(favourite);
    release(favourite);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c2", null, 4));
  });
});

describe("hovering a closed folder", () => {
  it("opens it, so a target inside it is reachable without letting go", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    press(row(/web-01/));
    moveOver(row(/Munich/), bandY(row(/Munich/), "into"));

    // Munich is closed and cache-01 is not on screen.
    expect(screen.queryByRole("treeitem", { name: /cache-01/ })).not.toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(700);
    });
    const nested = await screen.findByRole("treeitem", { name: /cache-01/ });

    // Same drag, now reaching the row that has just appeared.
    layOutRows();
    moveOver(nested, bandY(nested, "after"));
    release(nested);

    await waitFor(() => expect(ipcMock.moveNode).toHaveBeenCalledWith("c1", "f2", 1));
    vi.useRealTimers();
  });
});

describe("a move the core refuses", () => {
  it("leaves the rows where they were and says why", async () => {
    await mountTree();
    const before = rowNames();
    ipcMock.moveNode.mockRejectedValue({
      code: "node.depth-limit",
      message: "That would nest the tree deeper than 64 levels.",
      detail: null,
      actions: ["Move it somewhere shallower"],
    });

    drag(row(/web-01/), row(/Berlin/), "into");

    await screen.findByText(message()("move.failed"));
    // The core's own sentence, not a house paraphrase of it.
    expect(screen.getByText("That would nest the tree deeper than 64 levels.")).toBeInTheDocument();
    // Refetched after the failure, so what is drawn is what the vault holds.
    await waitFor(() => expect(ipcMock.listNodes.mock.calls.length).toBeGreaterThan(1));
    await waitFor(() => expect(rowNames()).toEqual(before));
  });
});

describe("gestures that are not a drag", () => {
  it("a press that does not travel is a click", async () => {
    await mountTree();
    const target = row(/web-01/);

    fireEvent.pointerDown(target, { ...POINTER, clientX: 10, clientY: 10 });
    // Two pixels: a trackpad wobble, not an intention.
    fireEvent.pointerMove(target, { ...POINTER, clientX: 12, clientY: 11 });
    fireEvent.pointerUp(target, { ...POINTER, clientX: 12, clientY: 11 });
    fireEvent.click(target);

    expect(ipcMock.moveNode).not.toHaveBeenCalled();
    expect(useApp.getState().selectedNodeId).toBe("c1");
  });

  it("takes no pointer capture until the press has become a drag", async () => {
    // A guard on the mechanism, because what it protects is platform
    // behaviour jsdom cannot express — the same kind of guard, and for the
    // same reason, as the `draggable` one below.
    //
    // A captured pointer retargets the compatibility mouse events as well as
    // the pointer ones, so a capture taken on `pointerdown` sends the `click`
    // that ends an ordinary press to whatever holds the capture rather than to
    // the row. Under WebView2 that meant clicking a connection stopped
    // selecting it, which is a far worse failure than the one the capture is
    // there to prevent — and every test in this file still passed, because
    // jsdom has no pointer capture to retarget anything.
    await mountTree();
    const target = row(/web-01/);
    const captured: number[] = [];
    target.setPointerCapture = (id: number) => captured.push(id);

    fireEvent.pointerDown(target, { ...POINTER, clientX: 10, clientY: 10 });
    fireEvent.pointerMove(target, { ...POINTER, clientX: 12, clientY: 11 });
    expect(captured).toEqual([]);

    // Past the threshold, and now it is worth holding on to.
    fireEvent.pointerMove(target, { ...POINTER, clientX: 40, clientY: 11 });
    expect(captured).toEqual([POINTER.pointerId]);
  });

  it("a touch press scrolls the sidebar rather than picking a row up", async () => {
    // The same gesture is how a tablet scrolls. A tree that cannot be scrolled
    // is a worse trade than one that cannot be reordered by finger, and the
    // keyboard equivalent is always there.
    await mountTree();
    const source = row(/web-01/);
    fireEvent.pointerDown(source, {
      ...POINTER,
      pointerType: "touch",
      clientY: bandY(source, "into"),
    });
    moveOver(row(/Berlin/), bandY(row(/Berlin/), "into"));
    release(row(/Berlin/));

    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });

  it("Escape abandons a drag in flight", async () => {
    await mountTree();

    press(row(/web-01/));
    moveOver(row(/Berlin/), bandY(row(/Berlin/), "into"));
    fireEvent.keyDown(document.body, { key: "Escape" });
    release(row(/Berlin/));

    expect(ipcMock.moveNode).not.toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toContain(message()("move.cancelled")),
    );
  });

  it("a release outside the sidebar moves nothing", async () => {
    await mountTree();

    press(row(/web-01/));
    moveOver(row(/Berlin/), bandY(row(/Berlin/), "into"));
    // Out of the scroller entirely — over the session area, say.
    fireEvent.pointerLeave(screen.getByRole("tree"), { ...POINTER, relatedTarget: document.body });
    fireEvent.pointerUp(document.body, { ...POINTER });

    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });
});

describe("dragging toward the edge of the sidebar", () => {
  /**
   * Give the scroller the one thing jsdom has no concept of: a scrolling box.
   *
   * `scrollHeight`, `clientHeight` and `scrollTop` are all zero and inert
   * without a layout engine, so the element is taught that it is 120px tall
   * over 600px of content and that its `scrollTop` is a value that sticks.
   */
  function makeScrollable(el: HTMLElement): { get: () => number } {
    let scrollTop = 0;
    Object.defineProperty(el, "scrollHeight", { value: 600, configurable: true });
    Object.defineProperty(el, "clientHeight", { value: 120, configurable: true });
    Object.defineProperty(el, "scrollTop", {
      configurable: true,
      get: () => scrollTop,
      set: (v: number) => {
        scrollTop = Math.max(0, Math.min(480, v));
      },
    });
    el.getBoundingClientRect = () =>
      ({
        top: 0,
        bottom: 120,
        left: 0,
        right: 260,
        width: 260,
        height: 120,
        x: 0,
        y: 0,
        toJSON: () => ({}),
      }) as DOMRect;
    return { get: () => scrollTop };
  }

  it("keeps scrolling while the pointer rests against it", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await mountTree();
    const scroller = screen.getByRole("tree");
    const scrolled = makeScrollable(scroller);

    press(row(/Berlin/));
    // Down against the bottom edge of the 120px-tall scroller, and held there:
    // no further pointer movement, which is exactly the case a move-driven
    // implementation gets wrong.
    fireEvent.pointerMove(scroller, { ...POINTER, clientX: 10, clientY: 115 });
    await act(async () => {
      vi.advanceTimersByTime(200);
    });

    expect(scrolled.get()).toBeGreaterThan(0);

    // And it stops when the drag does, rather than scrolling for ever.
    const reached = scrolled.get();
    fireEvent.pointerUp(scroller, { ...POINTER, clientX: 10, clientY: 115 });
    await act(async () => {
      vi.advanceTimersByTime(200);
    });
    expect(scrolled.get()).toBe(reached);
    vi.useRealTimers();
  });

  it("scrolls the other way against the top edge, and stops in the middle", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    await mountTree();
    const scroller = screen.getByRole("tree");
    const scrolled = makeScrollable(scroller);
    scroller.scrollTop = 200;

    press(row(/Berlin/));
    fireEvent.pointerMove(scroller, { ...POINTER, clientX: 10, clientY: 4 });
    await act(async () => {
      vi.advanceTimersByTime(200);
    });
    expect(scrolled.get()).toBeLessThan(200);

    // Back into the body of the list: nothing more should move on its own.
    const reached = scrolled.get();
    fireEvent.pointerMove(scroller, { ...POINTER, clientX: 10, clientY: 60 });
    await act(async () => {
      vi.advanceTimersByTime(200);
    });
    expect(scrolled.get()).toBe(reached);
    vi.useRealTimers();
  });
});

describe("the gesture is not HTML5 drag-and-drop", () => {
  it("marks no row as natively draggable", async () => {
    // A guard on the decision rather than on a behaviour, because the
    // behaviour it protects cannot be reached from here.
    //
    // Under Tauri on Windows the webview's own drop target is revoked before
    // the page sees it — `dragDropEnabled` defaults to true, wry calls
    // `RevokeDragDrop()` on every WebView2 child window and registers a file
    // drop handler in its place — so `dragover` and `drop` never arrive and a
    // `draggable` row produces a `dragstart` and then silence. That is the
    // whole reported defect, and jsdom implements neither `DragEvent` nor
    // `DataTransfer`, so no test in this file could ever observe it.
    //
    // Putting `draggable` back on a row would reintroduce it on the one
    // platform none of the tests run on, and a native drag also suppresses the
    // pointer events this gesture is built from, so the two cannot coexist.
    await mountTree();
    for (const el of screen.getAllByRole("treeitem")) {
      expect(el).not.toHaveAttribute("draggable", "true");
    }
  });
});

/**
 * What a person can see while the pointer is still down.
 *
 * The drag reported as broken twice was, on the second round, a drag that
 * worked: a row dimmed by 60% and a two-pixel rule between two rows of a
 * twenty-eight-pixel list. There was nothing under the pointer at all, so
 * there was nothing to tell you that the thing you had picked up was in your
 * hand, and no way to find out that the gesture existed by trying it. These
 * are about the visible half.
 */
describe("what the pointer carries", () => {
  it("names the entry in the air, under the pointer", async () => {
    await mountTree();

    press(row(/web-01/));
    travel(inRow(row(/web-01/), 0.5), inRow(row(/Berlin/), 0.5), false);

    // Twice on screen now: the row it came from, and the chip carrying it.
    expect(screen.getAllByText("web-01").length).toBeGreaterThan(1);
  });

  it("says why a target will not take it, before the pointer is released", async () => {
    await mountTree();
    const reason = message()("move.refuseNotFolder");
    expect(screen.queryByText(reason)).not.toBeInTheDocument();

    // Held over a group, not released. The sentence has to be readable now,
    // while the gesture can still be redirected — afterwards it only explains
    // a move that has already failed to happen.
    press(row(/web-01/));
    travel(inRow(row(/web-01/), 0.5), inRow(row(/Ops/), 0.5), false);

    expect(screen.getByText(reason)).toBeInTheDocument();
    expect(ipcMock.moveNode).not.toHaveBeenCalled();
  });

  it("puts the chip down when the drag ends", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    dragTo(row(/web-01/), inRow(row(/Berlin/), 0.5));

    await waitFor(() => expect(screen.getAllByText("web-01")).toHaveLength(1));
  });
});

describe("a refused drop", () => {
  it("explains itself below the tree, so the rows do not move under the pointer", async () => {
    // The explanation used to open between the search box and the first row,
    // which pushed the whole list down the height of three rows — so the
    // answer to "that did not work, try again" was a tree that had moved, and
    // the second attempt landed somewhere else again.
    await mountTree();

    drag(row(/web-01/), row(/Ops/), "into");

    const reason = message()("move.refuseNotFolder");
    const tree = screen.getByRole("tree");
    const live = screen.getByRole("status");
    await waitFor(() => expect(screen.getAllByText(reason).length).toBeGreaterThan(0));

    const onScreen = screen.getAllByText(reason).filter((el) => !live.contains(el));
    expect(onScreen.length).toBeGreaterThan(0);
    for (const el of onScreen) {
      expect(tree.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
  });
});

describe("what the dragged row looks like", () => {
  it("dims while it is in the air and comes back afterwards", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);
    const source = row(/web-01/);

    press(source);
    moveOver(row(/Berlin/), bandY(row(/Berlin/), "into"));
    expect(source.className).toContain(rowStyles["dragging"]);

    release(row(/Berlin/));
    await waitFor(() => expect(row(/web-01/).className).not.toContain(rowStyles["dragging"]));
  });

  it("names the announcement after the move that actually happened", async () => {
    await mountTree();
    ipcMock.moveNode.mockResolvedValue(undefined);

    drag(row(/web-01/), row(/Berlin/), "into");

    const expected = message()("move.movedInto", {
      name: isolate("web-01"),
      parent: isolate("Berlin"),
    });
    await waitFor(() =>
      expect(screen.getByRole("status").textContent).toContain(expected),
    );
  });
});
