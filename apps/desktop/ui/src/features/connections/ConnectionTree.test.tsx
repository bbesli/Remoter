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
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { i18n } from "@/i18n";
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

/**
 * The Turkish sentences the assertions below expect, read off the catalogue
 * the application ships rather than pasted in.
 *
 * Pasting them would let this file keep passing against wording no screen
 * shows any more, which is the failure mode the error-catalogue guard exists
 * to prevent; and it would put the burden of a translator's edit on a test in
 * a language the person making the edit cannot read.
 */
const TR_ERRORS = Object.values(
  import.meta.glob("../../../../../../locales/tr/errors.json", {
    eager: true,
    import: "default",
  }) as Record<
    string,
    {
      vault: { locked: { message: string; actions: string[] } };
      node: { "not-a-container": { message: string; actions: string[] } };
    }
  >,
)[0];

const TURKISH = {
  vaultLocked: TR_ERRORS?.vault.locked.message ?? "",
  unlockAction: TR_ERRORS?.vault.locked.actions[0] ?? "",
  notAContainer: TR_ERRORS?.node["not-a-container"].message ?? "",
  notAContainerActions: TR_ERRORS?.node["not-a-container"].actions ?? [],
};

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

/**
 * The sidebar, read by someone whose alphabet is not English's.
 *
 * Two separate failures used to meet here, and both were invisible from an
 * English machine: a filter that folded case with English rules, and failures
 * from the core rendered in the English the core wrote them in.
 */
describe("the sidebar in Turkish", () => {
  afterEach(async () => {
    await act(async () => {
      await i18n().changeLanguage("en");
    });
  });

  async function switchToTurkish() {
    await act(async () => {
      await i18n().changeLanguage("tr");
      // Catalogues load per namespace and on demand, so a component that
      // mounts before its namespace lands renders English for one frame. That
      // is correct in the application and useless in a test: awaiting them
      // here is what makes "still English" a real failure rather than a race.
      await i18n().loadNamespaces(["connections", "common", "errors"]);
    });
  }

  it("finds a machine by the name written on it", async () => {
    // Turkish has a dotted and a dotless i. Folded with English rules the
    // name "IŞIK-01" became "isik-01" while the query "ışık" became
    // "ısık", so the row could not be reached by its own name.
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "isik", name: "IŞIK-01", protocol: "ssh", host: "isik-01.kurum.tr" }),
      node({ id: "other", name: "web-02", protocol: "ssh" }),
    ]);
    await switchToTurkish();
    renderTree();
    await screen.findByRole("treeitem", { name: /IŞIK-01/ });

    const filter = screen.getByRole("textbox");
    await userEvent.type(filter, "ışık");

    expect(screen.getByRole("treeitem", { name: /IŞIK-01/ })).toBeInTheDocument();
    expect(screen.queryByRole("treeitem", { name: /web-02/ })).not.toBeInTheDocument();
  });

  it("finds the same machine from its capitals", async () => {
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "isik", name: "ışık-01", protocol: "ssh" }),
    ]);
    await switchToTurkish();
    renderTree();
    await screen.findByRole("treeitem", { name: /ışık-01/ });

    await userEvent.type(screen.getByRole("textbox"), "IŞIK");
    expect(screen.getByRole("treeitem", { name: /ışık-01/ })).toBeInTheDocument();
  });

  it("still reads a favourite tag written in capitals", async () => {
    // The tag is an ASCII flag this application defines, not a word in the
    // reader's language: folded under Turkish rules "FAVOURITE" becomes
    // "favourıte" and the Favourites section would silently empty.
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "fav", name: "web-01", protocol: "ssh", tags: ["FAVOURITE"] }),
    ]);
    await switchToTurkish();
    renderTree();

    // Once in Favourites, once in the tree proper.
    expect(await screen.findAllByRole("treeitem", { name: /web-01/ })).toHaveLength(2);
  });

  it("says why the tree could not be read, in Turkish", async () => {
    // The core's `message` is English by design; `errors.json` is keyed by the
    // code. Rendering the message put one English paragraph in an otherwise
    // Turkish sidebar.
    ipcMock.listNodes.mockRejectedValue({
      code: "vault.locked",
      message: "No vault is open. Unlock one to see your connections.",
      detail: null,
      actions: ["Unlock a vault"],
    });
    await switchToTurkish();
    renderTree();

    expect(await screen.findByText(TURKISH.vaultLocked)).toBeInTheDocument();
    expect(screen.queryByText(/No vault is open/)).not.toBeInTheDocument();
    // The suggested action is translated too, and stays a list item rather
    // than being joined into prose.
    expect(screen.getByText(TURKISH.unlockAction)).toBeInTheDocument();
  });

  it("says why a move was refused, in Turkish, and keeps the actions a list", async () => {
    // The hand-built callout this replaced rendered the English message and
    // detail, and joined the English action list into one run-on sentence with
    // a separator of its own — an ordered list of next steps, flattened into
    // prose, in a language the reader had not chosen.
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "a", name: "web-01", protocol: "ssh", sortOrder: 0 }),
      node({ id: "b", name: "web-02", protocol: "ssh", sortOrder: 1 }),
    ]);
    ipcMock.moveNode.mockRejectedValue({
      code: "node.not-a-container",
      message: "Only folders can hold other items.",
      detail: "node b",
      actions: ["Drop it into a folder", "Drop it at the top level"],
    });
    await switchToTurkish();
    renderTree();
    await screen.findByRole("treeitem", { name: /web-01/ });

    screen.getByRole("tree").focus();
    await userEvent.keyboard("{ArrowDown}");
    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    expect(await screen.findByText(TURKISH.notAContainer)).toBeInTheDocument();
    expect(screen.queryByText(/Only folders can hold/)).not.toBeInTheDocument();

    // Two actions, two list items — not one sentence with a separator in it.
    for (const label of TURKISH.notAContainerActions) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    expect(screen.getAllByRole("listitem")).toHaveLength(TURKISH.notAContainerActions.length);

    // `detail` is the diagnostic a reader copies into a bug report, so it
    // passes through untranslated, by design.
    expect(screen.getByText("node b")).toBeInTheDocument();
  });

  it("reads the refusal out in Turkish too", async () => {
    // The live region used to interpolate the core's English sentence into a
    // Turkish one, which is the one combination worse than either alone.
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "a", name: "web-01", protocol: "ssh", sortOrder: 0 }),
      node({ id: "b", name: "web-02", protocol: "ssh", sortOrder: 1 }),
    ]);
    ipcMock.moveNode.mockRejectedValue({
      code: "node.not-a-container",
      message: "Only folders can hold other items.",
      detail: null,
      actions: ["Drop it into a folder", "Drop it at the top level"],
    });
    await switchToTurkish();
    renderTree();
    await screen.findByRole("treeitem", { name: /web-01/ });

    screen.getByRole("tree").focus();
    await userEvent.keyboard("{ArrowDown}");
    await userEvent.keyboard("{Control>}{ArrowDown}{/Control}");

    const live = await screen.findByRole("status");
    await waitFor(() => expect(live.textContent ?? "").toContain(TURKISH.notAContainer));
    expect(live.textContent ?? "").not.toContain("Only folders can hold");
  });
});
