/**
 * What the sidebar draws, and what it deliberately does not.
 *
 * A credential attached to a connection is part of that connection — the
 * username and secret its own row already stands for — so it is not an entry
 * of its own. A shared credential is: organising those is the point of having
 * them, and one that vanished from the tree could not be moved, renamed or
 * pointed at.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useApp } from "@/stores/app";
import type { TreeNode } from "@/lib/ipc";

import { ConnectionTree } from "./ConnectionTree";
import { useConnectionEditor } from "./ConnectionEditor";

// Hoisted with the `vi.mock` call below, which runs before the imports above.
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
  useApp.setState({ openModals: new Set<string>(), selectedNodeId: null });
  useConnectionEditor.setState({ target: null });
  // jsdom implements no layout, so it has no `scrollIntoView`; the tree keeps
  // the keyboard cursor in view with it.
  Element.prototype.scrollIntoView = vi.fn();
});

describe("credentials in the sidebar", () => {
  it("draws a shared credential and not one attached to a connection", async () => {
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "conn-1", name: "web-01", protocol: "ssh", attachedCredentialId: "cred-own" }),
      // The connection's own login. The core leaves it out of `tree_list`;
      // one that arrived anyway must not become a row.
      node({ id: "cred-own", kind: "credential", name: "web-01", attachedTo: "conn-1" }),
      node({ id: "cred-shared", kind: "credential", name: "svc-deploy" }),
    ]);

    renderTree();

    expect(await screen.findByRole("treeitem", { name: /svc-deploy/ })).toBeInTheDocument();
    // One row for the server, not one per server-plus-login.
    expect(screen.getAllByRole("treeitem", { name: /web-01/ })).toHaveLength(1);
  });
});
