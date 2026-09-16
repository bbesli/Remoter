/**
 * Jump hosts in the connection editor.
 *
 * Until this section existed a gateway chain could only arrive by importing an
 * `ssh_config`. What is pinned here is what the editor actually *sends* — the
 * patch the core receives — because that is what a session will traverse:
 *
 *  - a folder's chain is shown on a connection beneath it, with its source;
 *  - overriding it with nothing is an explicit empty chain, not "inherit";
 *  - choosing hops sends them in order;
 *  - reverting sends `clearOverrides: ["gateway"]`;
 *  - only SSH connections are offered, and never the node itself.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { EffectiveConnection, TreeNode } from "@/lib/ipc";
import { withoutBidi } from "@/test/bidi";

import { ConnectionEditor, useConnectionEditor, type EditorTarget } from "./ConnectionEditor";

const { ipcMock } = vi.hoisted(() => ({
  ipcMock: {
    listNodes: vi.fn(),
    resolveNode: vi.fn(),
    createNode: vi.fn(),
    updateNode: vi.fn(),
    inspectKey: vi.fn(),
    protocolSchemas: vi.fn(),
  },
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
    name: over.id,
    description: "",
    tags: [],
    colour: null,
    protocol: "ssh",
    host: `${over.id}.example.internal`,
    port: 22,
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

function resolved(nodeId: string, gatewayChain: string[]): EffectiveConnection {
  return {
    nodeId,
    protocol: "ssh",
    fields: [],
    gatewayChain,
    tags: [],
    credentialAttached: false,
  };
}

const BASTION = node({ id: "bastion" });
const JUMP = node({ id: "jump-2" });
const TERMINAL_SERVER = node({ id: "terminal-server", protocol: "rdp", port: 3389 });
const PRODUCTION = node({
  id: "production",
  kind: "folder",
  protocol: null,
  host: null,
  port: null,
  gateway: [{ nodeId: "bastion", credentialId: null }],
});
const DB = node({ id: "db-01", parentId: "production" });
const LOOSE = node({ id: "web-01" });

function renderEditor(target: EditorTarget) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  useConnectionEditor.setState({ target });
  return render(
    <QueryClientProvider client={client}>
      <ConnectionEditor />
    </QueryClientProvider>,
  );
}

function section(): HTMLElement {
  const title = screen.getByText("Jump hosts");
  const found = title.parentElement;
  if (found === null) throw new Error("no jump host section");
  return found;
}

beforeEach(() => {
  vi.clearAllMocks();
  useConnectionEditor.setState({ target: null });
  ipcMock.listNodes.mockResolvedValue([BASTION, JUMP, TERMINAL_SERVER, PRODUCTION, DB, LOOSE]);
  ipcMock.resolveNode.mockImplementation(async (id: string) =>
    resolved(id, id === "db-01" ? ["bastion"] : []),
  );
  ipcMock.updateNode.mockResolvedValue(LOOSE);
  ipcMock.createNode.mockResolvedValue(LOOSE);
  ipcMock.protocolSchemas.mockResolvedValue([]);
});

describe("jump hosts", () => {
  it("shows the chain a folder passes down, and where it comes from", async () => {
    renderEditor({ mode: "edit", nodeId: "db-01" });
    await screen.findByText("Jump hosts");

    const box = section();
    expect(withoutBidi(box.textContent ?? "")).toContain("bastion");
    expect(withoutBidi(box.textContent ?? "")).toContain("inherited from production");
  });

  it("sends an explicit empty chain when a connection is told to connect directly", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "db-01" });
    await screen.findByText("Jump hosts");

    await user.click(within(section()).getByRole("button", { name: "Override here" }));
    expect(within(section()).getByText("Connects directly")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    const [id, patch] = ipcMock.updateNode.mock.calls[0] ?? [];
    expect(id).toBe("db-01");
    expect(patch).toMatchObject({ gateway: [] });
    expect(patch?.clearOverrides ?? []).not.toContain("gateway");
  });

  it("sends the hops chosen, in the order of travel", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "web-01" });
    await screen.findByText("Jump hosts");

    await user.click(within(section()).getByRole("button", { name: "Override here" }));
    await user.click(within(section()).getByRole("button", { name: "Add jump host" }));
    await user.click(within(section()).getByRole("button", { name: "Add jump host" }));
    // The second hop is jump-2; move it ahead of the first.
    await user.selectOptions(within(section()).getByRole("combobox", { name: "Jump host 1" }), "jump-2");
    await user.selectOptions(within(section()).getByRole("combobox", { name: "Jump host 2" }), "bastion");
    await user.click(within(section()).getByRole("button", { name: "Move jump host 2 earlier" }));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    const [, patch] = ipcMock.updateNode.mock.calls[0] ?? [];
    expect(patch?.gateway).toEqual([
      { nodeId: "bastion", credentialId: null },
      { nodeId: "jump-2", credentialId: null },
    ]);
  });

  it("goes back to the inherited chain with clearOverrides, not with an empty one", async () => {
    const user = userEvent.setup();
    ipcMock.listNodes.mockResolvedValue([
      BASTION,
      JUMP,
      PRODUCTION,
      { ...DB, gateway: [{ nodeId: "jump-2", credentialId: null }] },
    ]);
    ipcMock.resolveNode.mockResolvedValue(resolved("db-01", ["jump-2"]));
    renderEditor({ mode: "edit", nodeId: "db-01" });
    await screen.findByText("Jump hosts");

    await user.click(within(section()).getByRole("button", { name: /Revert to inherited/ }));
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    const [, patch] = ipcMock.updateNode.mock.calls[0] ?? [];
    expect(patch?.clearOverrides).toContain("gateway");
    expect(patch?.gateway).toBeUndefined();
  });

  it("offers only SSH connections, and never the connection being edited", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "web-01" });
    await screen.findByText("Jump hosts");

    await user.click(within(section()).getByRole("button", { name: "Override here" }));
    await user.click(within(section()).getByRole("button", { name: "Add jump host" }));
    const offered = within(within(section()).getByRole("combobox", { name: "Jump host 1" }))
      .getAllByRole("option")
      .map((option) => (option as HTMLOptionElement).value);

    expect(offered).toContain("bastion");
    expect(offered).toContain("jump-2");
    expect(offered).not.toContain("terminal-server");
    expect(offered).not.toContain("web-01");
  });

  it("creates a folder with jump hosts for everything that will go in it", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "create", parentId: null, kind: "folder" });
    await screen.findByText("Jump hosts");

    await user.type(screen.getByLabelText("Name"), "Staging");
    await user.click(within(section()).getByRole("button", { name: "Override here" }));
    await user.click(within(section()).getByRole("button", { name: "Add jump host" }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(ipcMock.createNode).toHaveBeenCalledTimes(1));
    const [input] = ipcMock.createNode.mock.calls[0] ?? [];
    expect(input?.gateway).toEqual([{ nodeId: "bastion", credentialId: null }]);
  });
});
