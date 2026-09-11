/**
 * The context menu opens the way the reader reads.
 *
 * It is the only box in the frontend positioned from JavaScript rather than
 * from a stylesheet, and it was the only physical inset left anywhere: a
 * `style={{ left }}` built from `clientX`. `left` pins a box's left edge and
 * lets it grow rightwards, which under RTL sends the menu back across the part
 * of the page the user has already read and off toward the edge they started
 * from — and, near the left window edge, off the window entirely, because the
 * clamp was guarding the wrong side.
 *
 * These tests assert the placement in both directions, because the interesting
 * part is that one coordinate has to produce two different answers.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

/** Mirrors `MENU_MARGIN` in ConnectionTree.tsx: the room the menu needs. */
const MENU_MARGIN = 180;

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
 * Opens the menu at one pointer position and hands back the element plus the
 * teardown, so a test that wants both directions can unmount the first tree
 * before mounting the second — two trees in the document at once make every
 * role query ambiguous.
 */
async function openMenuAt(clientX: number): Promise<{ menu: HTMLElement; close: () => void }> {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const { unmount } = render(
    <QueryClientProvider client={client}>
      <ConnectionTree />
    </QueryClientProvider>,
  );

  const tree = await screen.findByRole("tree");
  // The background handler, which ignores anything bubbling from a row.
  fireEvent.contextMenu(tree, { clientX, clientY: 40 });
  return { menu: screen.getByRole("menu"), close: unmount };
}

beforeEach(() => {
  vi.clearAllMocks();
  ipcMock.listNodes.mockResolvedValue([node({ id: "conn-1", name: "web-01", protocol: "ssh" })]);
  useApp.setState({ openModals: new Set<string>(), selectedNodeId: null });
  useConnectionEditor.setState({ target: null });
  Element.prototype.scrollIntoView = vi.fn();
});

afterEach(() => {
  document.documentElement.removeAttribute("dir");
});

describe("the tree context menu", () => {
  it("uses no physical inset in either direction", async () => {
    // The rule docs/features/i18n.md states and the audit greps for. Asserted
    // first because every other assertion here would still pass if `left` were
    // set alongside `inset-inline-start` — and `left` would win under RTL.
    for (const dir of ["ltr", "rtl"]) {
      document.documentElement.setAttribute("dir", dir);
      const { menu, close } = await openMenuAt(300);
      expect(menu.style.left).toBe("");
      expect(menu.style.right).toBe("");
      expect(menu.style.insetInlineStart).not.toBe("");
      close();
    }
  });

  it("measures from the left edge under ltr", async () => {
    document.documentElement.setAttribute("dir", "ltr");
    const { menu } = await openMenuAt(300);
    expect(menu.style.insetInlineStart).toBe("300px");
    expect(menu.style.top).toBe("40px");
  });

  it("measures from the right edge under rtl", async () => {
    document.documentElement.setAttribute("dir", "rtl");
    const { menu } = await openMenuAt(300);
    // `inset-inline-start` counts from the right in an RTL containing block, so
    // the same pointer position is a different number — and the menu then grows
    // leftwards, toward the direction the reader is scanning.
    expect(menu.style.insetInlineStart).toBe(`${window.innerWidth - 300}px`);
    // The block axis is top-to-bottom in every locale shipped, so y is
    // unchanged by the mirroring.
    expect(menu.style.top).toBe("40px");
  });

  it("clamps against the edge the menu actually grows toward", async () => {
    // Under LTR the menu grows right, so a click near the right edge is pulled
    // back; under RTL it grows left, so the click near the *left* edge is. The
    // old clamp guarded the right edge in both, which let an Arabic layout push
    // the menu straight off the window.
    document.documentElement.setAttribute("dir", "ltr");
    const ltr = await openMenuAt(window.innerWidth - 10);
    expect(ltr.menu.style.insetInlineStart).toBe(`${window.innerWidth - MENU_MARGIN}px`);
    ltr.close();

    document.documentElement.setAttribute("dir", "rtl");
    const rtl = await openMenuAt(10);
    // Clamped to MENU_MARGIN from the left edge, which is innerWidth-margin
    // from the right — leaving exactly MENU_MARGIN of room to unfold into.
    expect(rtl.menu.style.insetInlineStart).toBe(`${window.innerWidth - MENU_MARGIN}px`);
  });
});
