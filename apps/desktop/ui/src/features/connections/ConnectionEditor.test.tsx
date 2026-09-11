/**
 * The login half of the connection editor.
 *
 * What is pinned here is a refusal, a silence or a consequence that would
 * otherwise only be found by hand:
 *
 *  - a username and a password typed on a connection reach the core as a
 *    connection edit. The domain model puts both on a credential, and the core
 *    routes them onto the one it attaches to that connection — the interface
 *    must not try to write a credential node itself, and must never send
 *    `credentialId` alongside them, which is refused;
 *  - a connection whose credential is INHERITED is the case that shapes the
 *    design: editing that credential would change every other connection under
 *    the folder, so nothing this editor sends may name it;
 *  - a private key with no file chosen must not reach the core, because the
 *    command would be sent an empty path and the failure would arrive from the
 *    other side of the boundary for something the form already knew;
 *  - a passphrase is asked for only when the container says one is needed,
 *    which is the entire reason `key_inspect` is called before the field is
 *    drawn.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  EffectiveConnection,
  PrivateKeyInfo,
  ResolvedField,
  TreeNode,
} from "@/lib/ipc";
import { withoutBidi } from "@/test/bidi";

import {
  ConnectionEditor,
  useConnectionEditor,
  type EditorTarget,
} from "./ConnectionEditor";

// Hoisted with the `vi.mock` calls below, which run before the imports above.
const { ipcMock, dialogOpen } = vi.hoisted(() => ({
  ipcMock: {
    listNodes: vi.fn(),
    resolveNode: vi.fn(),
    createNode: vi.fn(),
    updateNode: vi.fn(),
    inspectKey: vi.fn(),
  },
  dialogOpen: vi.fn(),
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: (...args: unknown[]) => dialogOpen(...args) as unknown,
}));

const OPENSSH: PrivateKeyInfo = {
  path: "/home/ada/.ssh/id_ed25519",
  format: "openssh",
  formatLabel: "OpenSSH",
  encrypted: false,
  sizeBytes: 464,
};

const ENCRYPTED: PrivateKeyInfo = { ...OPENSSH, encrypted: true };

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

function field(
  over: Partial<ResolvedField> & { field: string },
): ResolvedField {
  return {
    value: null,
    origin: "own",
    sourceName: null,
    sourceId: null,
    overrides: null,
    ...over,
  };
}

function resolved(over: Partial<EffectiveConnection>): EffectiveConnection {
  return {
    nodeId: "conn-1",
    protocol: "ssh",
    fields: [],
    gatewayChain: [],
    tags: [],
    credentialAttached: false,
    ...over,
  };
}

function renderEditor(target: EditorTarget) {
  // Retries would turn a rejected command into a wait rather than a failure,
  // which is the opposite of what these tests are looking at.
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

const NEW_CONNECTION: EditorTarget = {
  mode: "create",
  parentId: null,
  kind: "connection",
};

beforeEach(() => {
  vi.clearAllMocks();
  // Before the render rather than after it: the previous test's dialog is
  // still mounted when the teardown hooks run, and closing it from there is a
  // state update outside `act`.
  useConnectionEditor.setState({ target: null });
  ipcMock.listNodes.mockResolvedValue([]);
  ipcMock.createNode.mockResolvedValue(node({ id: "created" }));
  ipcMock.updateNode.mockResolvedValue(node({ id: "created" }));
  ipcMock.inspectKey.mockResolvedValue(OPENSSH);
  dialogOpen.mockResolvedValue(OPENSSH.path);
});

/** The identity fields every create has to carry before anything is judged. */
async function fillIdentity(user: ReturnType<typeof userEvent.setup>) {
  await user.type(await screen.findByLabelText("Name"), "web-01");
  await user.type(screen.getByLabelText("Hostname"), "web-01.example.net");
}

/** Every node id this edit named, whichever command it went through. */
function nodesTouched(): string[] {
  const updated = ipcMock.updateNode.mock.calls.map((call) => String(call[0]));
  const created = ipcMock.createNode.mock.calls.flatMap((call) => {
    const input = call[0] as Record<string, unknown>;
    const parent = input["parentId"];
    return typeof parent === "string" ? [parent] : [];
  });
  return [...updated, ...created];
}

describe("a username and a password on a connection", () => {
  const connection = node({
    id: "conn-1",
    name: "web-01",
    protocol: "ssh",
    host: "web-01.example.net",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([connection]);
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        fields: [field({ field: "host", value: "web-01.example.net" })],
      }),
    );
  });

  /*
   * The reported defect: the editor showed a username and a password on a
   * connection and then refused to save them, so no server could be reached.
   * A connection has no username in the data model — the core puts one on the
   * credential it attaches to that connection — and this is the call that says
   * so.
   */
  it("saves through the connection, which is what the core routes onto its own credential", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await user.type(await screen.findByLabelText("Username"), "ada");
    await user.type(screen.getByLabelText("Password"), "hunter2");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      username: "ada",
      password: "hunter2",
    });
    // A credential node the user did not ask for is not created beside it.
    expect(ipcMock.createNode).not.toHaveBeenCalled();
  });

  it("creates a new connection with its login in the same call", async () => {
    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.type(screen.getByLabelText("Username"), "ada");
    await user.type(screen.getByLabelText("Password"), "hunter2");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(ipcMock.createNode).toHaveBeenCalledTimes(1));
    const input = ipcMock.createNode.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >;
    expect(input["kind"]).toBe("connection");
    expect(input["username"]).toBe("ada");
    expect(input["password"]).toBe("hunter2");
    // Naming a shared credential and a login of its own in one request is
    // refused by the core, so the editor must never send both.
    expect(input["credentialId"]).toBeUndefined();
  });
});

/*
 * The case the whole mechanism exists for. Editing the folder's credential
 * would silently change every other connection beneath it, so setting a
 * username here creates one for this connection alone.
 */
describe("a connection whose credential comes from a folder", () => {
  const folder = node({
    id: "folder-1",
    kind: "folder",
    name: "Datacentre EU-West",
    credentialId: "cred-shared",
  });
  const shared = node({
    id: "cred-shared",
    parentId: "folder-1",
    kind: "credential",
    name: "svc-deploy",
    username: "svc-deploy",
    secretKind: "password",
  });
  const connection = node({
    id: "conn-1",
    parentId: "folder-1",
    name: "web-01",
    protocol: "ssh",
    host: "web-01.eu.example.net",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([folder, shared, connection]);
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        // No attached credential: the login belongs to the folder's, which
        // every connection under it resolves to.
        credentialAttached: false,
        fields: [
          field({ field: "host", value: "web-01.eu.example.net" }),
          field({
            field: "credential",
            value: "svc-deploy",
            origin: "inherited",
            sourceName: "Datacentre EU-West",
            sourceId: "folder-1",
          }),
          field({
            field: "username",
            value: "svc-deploy",
            origin: "inherited",
            sourceName: "Datacentre EU-West",
            sourceId: "folder-1",
          }),
        ],
      }),
    );
  });

  it("shows the inherited login and its source, and does not offer to edit it in place", async () => {
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    // The username and the folder name are vault data, so both reach the
    // screen wrapped in a bidi isolate. `withoutBidi` takes the invisible
    // characters back out; without it these queries fail for a reason nothing
    // in the output shows. See src/test/bidi.ts.
    expect(
      await screen.findByText("svc-deploy", { normalizer: withoutBidi }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("inherited from Datacentre EU-West", {
        normalizer: withoutBidi,
      }),
    ).toBeInTheDocument();
    // No control to type into: what is on screen belongs to the folder.
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
  });

  it("saves a username onto this connection alone, and says so before it does", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await user.click(
      await screen.findByRole("button", { name: "Override here" }),
    );

    // The line that says the choice has a consequence — quiet, and at the
    // moment it becomes true rather than after the fact.
    expect(
      await screen.findByText(
        /Datacentre EU-West keeps the credential it has/,
        {
          normalizer: withoutBidi,
        },
      ),
    ).toBeInTheDocument();

    const username = screen.getByLabelText("Username");
    await user.clear(username);
    await user.type(username, "ada");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    // The edit names the connection and nothing else. The folder's credential
    // is not written, not renamed and not pointed at.
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      username: "ada",
    });
    expect(ipcMock.createNode).not.toHaveBeenCalled();
    expect(nodesTouched()).toEqual(["conn-1"]);
  });

  it("hands the login back with one instruction rather than one per field", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    // Override, then change your mind: nothing of this connection's own was
    // ever saved, so there is nothing for the core to undo.
    await user.click(
      await screen.findByRole("button", { name: "Override here" }),
    );
    await user.click(
      screen.getByRole("button", { name: /Revert to inherited/ }),
    );

    expect(screen.getByRole("button", { name: "Save" })).toBeDisabled();
  });
});

describe("a connection with a login of its own", () => {
  const connection = node({
    id: "conn-1",
    parentId: "folder-1",
    name: "web-01",
    protocol: "ssh",
    host: "web-01.eu.example.net",
    // The DTO reports the attached credential's identity on the connection
    // itself; the credential is never listed as an entry of its own.
    username: "ada",
    secretKind: "password",
    credentialId: "cred-own",
    attachedCredentialId: "cred-own",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([connection]);
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        credentialAttached: true,
        fields: [
          field({ field: "host", value: "web-01.eu.example.net" }),
          field({
            field: "credential",
            value: "web-01",
            origin: "own",
            overrides: "svc-deploy",
            sourceName: "Datacentre EU-West",
          }),
          field({
            field: "username",
            value: "ada",
            origin: "own",
            overrides: "svc-deploy",
          }),
        ],
      }),
    );
  });

  it("edits it in place, without the consequence line", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    const username = await screen.findByLabelText("Username");
    expect(username).toHaveValue("ada");

    await user.clear(username);
    await user.type(username, "ada.lovelace");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      username: "ada.lovelace",
    });
  });

  it("reverts to the inherited credential as one instruction", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await user.click(
      await screen.findByRole("button", { name: /Revert to inherited/ }),
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    // `username` and `password` are not fields a connection owns, and the core
    // rejects either name here. The credential is the one that means "the
    // whole login".
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      clearOverrides: ["credential"],
    });
  });
});

/*
 * The other half of "override rather than edit in place": a shared credential
 * is edited where it lives — on its own entry in the tree — which is what
 * makes leaving it untouched from a connection a choice rather than a dead end.
 */
describe("a shared credential", () => {
  const shared = node({
    id: "cred-1",
    kind: "credential",
    name: "svc-deploy",
    username: "svc-deploy",
    secretKind: "password",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([shared]);
  });

  it("edits its own username, with no inheritance to reset", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "cred-1" });

    const username = await screen.findByLabelText("Username");
    expect(username).toHaveValue("svc-deploy");

    await user.clear(username);
    await user.type(username, "svc-build");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("cred-1", {
      username: "svc-build",
    });
    // A credential inherits nothing, so nothing here may be reset to inherited.
    expect(ipcMock.resolveNode).not.toHaveBeenCalled();
  });
});

describe("private key authentication", () => {
  it("refuses to save when no key file has been chosen", async () => {
    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /Private key/ }));
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(
      await screen.findByText(/Choose the private key file/),
    ).toBeInTheDocument();
    expect(ipcMock.createNode).not.toHaveBeenCalled();
  });

  it("does not ask for a passphrase when the key has none", async () => {
    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /Private key/ }));
    await user.click(screen.getByRole("button", { name: "Choose a key file" }));

    expect(await screen.findByText("OpenSSH")).toBeInTheDocument();
    expect(screen.queryByLabelText("Key passphrase")).not.toBeInTheDocument();
  });

  it("asks for a passphrase when the container says the key is encrypted", async () => {
    ipcMock.inspectKey.mockResolvedValue(ENCRYPTED);
    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /Private key/ }));
    await user.click(screen.getByRole("button", { name: "Choose a key file" }));

    const passphrase = await screen.findByLabelText("Key passphrase");
    // A secret is never rendered as readable text, even one the user just typed.
    expect(passphrase).toHaveAttribute("type", "password");

    await user.click(screen.getByRole("button", { name: "Create" }));
    expect(
      await screen.findByText(/protected by a passphrase/),
    ).toBeInTheDocument();
    expect(ipcMock.createNode).not.toHaveBeenCalled();
  });

  it("sends the key with the connection, for the core to attach to it", async () => {
    ipcMock.inspectKey.mockResolvedValue(ENCRYPTED);

    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /Private key/ }));
    await user.click(screen.getByRole("button", { name: "Choose a key file" }));
    await user.type(
      await screen.findByLabelText("Key passphrase"),
      "correct horse",
    );
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(ipcMock.createNode).toHaveBeenCalledTimes(1));

    const input = ipcMock.createNode.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >;
    expect(input["kind"]).toBe("connection");
    expect(input["credential"]).toEqual({
      kind: "privateKey",
      path: OPENSSH.path,
      passphrase: "correct horse",
    });
    // The password shorthand and a credential together are refused by the core.
    expect(input["password"]).toBeNull();
  });
});

describe("agent authentication", () => {
  it("chooses the agent without asking for anything secret", async () => {
    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /SSH agent/ }));
    await user.type(screen.getByLabelText("Identity comment"), "ada@laptop");
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(ipcMock.createNode).toHaveBeenCalledTimes(1));
    const input = ipcMock.createNode.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >;
    expect(input["credential"]).toEqual({
      kind: "agent",
      commentFilter: "ada@laptop",
    });
    expect(input["password"]).toBeNull();
  });
});

describe("a connection that already has a key", () => {
  const connection = node({
    id: "conn-1",
    name: "web-01",
    protocol: "ssh",
    host: "web-01.example.net",
    // Its own credential's method, reported on the connection: the credential
    // is part of it and never appears in the tree by itself.
    secretKind: "privateKey",
    keyFormat: "openssh",
    hasPassphrase: true,
    credentialId: "cred-1",
    attachedCredentialId: "cred-1",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([connection]);
    ipcMock.resolveNode.mockResolvedValue(
      resolved({ credentialAttached: true }),
    );
  });

  it("opens on the method the credential uses and leaves the stored key alone", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    const chosen = await screen.findByRole("radio", { name: /Private key/ });
    expect(chosen).toBeChecked();
    expect(screen.getByText("stored in this vault")).toBeInTheDocument();

    // Renaming touches nothing about the credential: rewriting it would mean
    // reading a key file that may no longer exist.
    const name = screen.getByLabelText("Name");
    await user.clear(name);
    await user.type(name, "web-02");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      name: "web-02",
    });
  });

  it("refuses to switch to a password without one, rather than silently keeping the key", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await user.click(await screen.findByRole("radio", { name: /^Password/ }));
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText(/Type the password this login should use/),
    ).toBeInTheDocument();
    expect(ipcMock.updateNode).not.toHaveBeenCalled();
  });
});

describe("the protocols a connection may be given", () => {
  /*
   * The restriction this replaces: the menu disabled `rdp`, `sftp` and `vnc`
   * and explained that the build opened SSH only. It was true — `session_open`
   * refused them by name — and it stopped being true the day the framebuffer
   * adapters were wired into the gate. A disabled control that has outlived its
   * reason is the same defect as a control with nothing behind it, read from
   * the other end.
   */
  it("offers all four, with none of them disabled", async () => {
    renderEditor(NEW_CONNECTION);

    const menu = await screen.findByLabelText("Protocol");
    const offered = Array.from(menu.querySelectorAll("option"));
    expect(offered.map((option) => option.value)).toEqual([
      "ssh",
      "sftp",
      "rdp",
      "vnc",
    ]);
    for (const option of offered) {
      expect(option.disabled, option.value).toBe(false);
      // The label is the protocol name and nothing else: no apology appended.
      expect(option.textContent).toBe(option.value);
    }
  });

  /*
   * RDP and VNC authenticate with a password. The agent and a private key are
   * SSH and SFTP, and offering either here would be a choice that fails at
   * connect time for a reason the editor knew before it was made.
   */
  it.each(["rdp", "vnc"])(
    "offers %s a password and nothing else",
    async (protocol) => {
      const user = userEvent.setup();
      renderEditor(NEW_CONNECTION);

      await user.selectOptions(
        await screen.findByLabelText("Protocol"),
        protocol,
      );

      expect(screen.getByLabelText("Password")).toBeInTheDocument();
      expect(
        screen.queryByRole("radio", { name: /SSH agent/ }),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByRole("radio", { name: /Private key/ }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByText(
          new RegExp(`${protocol.toUpperCase()} authenticates with a password`),
        ),
      ).toBeInTheDocument();
    },
  );
});

describe("the protocol settings a connection carries", () => {
  const windows = node({
    id: "conn-1",
    name: "dc-01",
    protocol: "rdp",
    host: "dc-01.corp.example",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([windows]);
  });

  /*
   * The section is a reading, not a form: no command writes a connection's
   * settings map, so it says so rather than drawing a control that would
   * discard what was typed into it.
   */
  it("shows what the adapter will read, and says it cannot be changed here", async () => {
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        protocol: "rdp",
        fields: [
          field({ field: "settings.domain", value: "CORP" }),
          field({
            field: "settings.network_level_authentication",
            value: "false",
            origin: "inherited",
            sourceName: "Datacentre EU-West",
          }),
        ],
      }),
    );
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    expect(await screen.findByText("Protocol settings")).toBeInTheDocument();
    expect(
      screen.getByText(/These settings cannot be changed here/),
    ).toBeInTheDocument();

    // Each setting under its own key, with the value the connection resolved.
    expect(screen.getByText("domain")).toBeInTheDocument();
    expect(withoutBidi(screen.getByText(/CORP/).textContent ?? "")).toBe(
      "CORP",
    );

    // A setting whose value has a consequence says what the consequence is —
    // and this one is the consequence that matters most on the screen.
    expect(
      screen.getByText(/credentials are sent to whatever answered the port/),
    ).toBeInTheDocument();
    // Inherited, and the screen says from where.
    expect(screen.getByText(/Datacentre EU-West/)).toBeInTheDocument();
  });

  /*
   * And what RDP does not do at all. Every item is a channel the adapter has
   * no implementation of, so there is no setting for any of them — an omission
   * that would otherwise read as an oversight rather than as the answer.
   */
  it("names what this build's RDP cannot do, even with nothing set", async () => {
    ipcMock.resolveNode.mockResolvedValue(
      resolved({ protocol: "rdp", fields: [] }),
    );
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    expect(
      await screen.findByText(
        /does not redirect the clipboard, drives, printers/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Nothing is set on this connection/),
    ).toBeInTheDocument();
  });

  /* An SSH connection with no settings of its own gets no empty section. */
  it("is absent for a protocol with nothing to say and nothing set", async () => {
    ipcMock.listNodes.mockResolvedValue([
      node({
        id: "conn-1",
        name: "web-01",
        protocol: "ssh",
        host: "web-01.example.net",
      }),
    ]);
    ipcMock.resolveNode.mockResolvedValue(resolved({ fields: [] }));
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByLabelText("Name");
    expect(screen.queryByText("Protocol settings")).not.toBeInTheDocument();
  });
});
