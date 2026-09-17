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
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  EffectiveConnection,
  PrivateKeyInfo,
  ProtocolSchema,
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
    protocolSchemas: vi.fn(),
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

/**
 * A passphrase-protected AWS EC2 `.pem`, exactly as `key_inspect` answers for
 * one.
 *
 * Every field here was read off the real command in
 * `commands::credential_tests::a_passphrase_protected_pem_becomes_a_working_credential`:
 * a legacy PKCS#1 container is reported under the label it will be *stored*
 * under, which is PKCS#8, and as encrypted. The file this came from used to be
 * refused outright, and the interface's part of that failure was that a
 * refusal, not a passphrase field, is what appeared.
 */
const AWS_PEM: PrivateKeyInfo = {
  path: "/home/ada/Downloads/dvp-api-srv-key-pair.pem",
  format: "pkcs8",
  formatLabel: "PKCS#8",
  encrypted: true,
  sizeBytes: 1876,
};

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

/**
 * The RDP schema as the adapter declares it, trimmed to what these tests read.
 *
 * Hand-written rather than imported: the point of the form is that it renders
 * whatever the adapter sends, so the tests feed it a schema rather than
 * reaching for the real one and asserting against itself. The shapes are the
 * ones `protocol_schemas` puts on the wire, and the Rust tests in
 * `crates/remoter-ipc/src/commands.rs` are what pin those to the adapters.
 */
const RDP_SCHEMA: ProtocolSchema = {
  protocol: "rdp",
  settings: [
    {
      key: "domain",
      label: "settings.rdp.domain",
      kind: { type: "text", maxLen: 255 },
      default: null,
      defaultOrigin: "fixed",
      required: false,
      options: [],
      optionsAreClosed: false,
    },
    {
      key: "network_level_authentication",
      label: "settings.rdp.network_level_authentication",
      kind: { type: "boolean" },
      default: "true",
      defaultOrigin: "fixed",
      required: false,
      options: [],
      optionsAreClosed: false,
    },
    {
      key: "desktop_width",
      label: "settings.rdp.desktop_width",
      kind: { type: "integer", min: 200, max: 8192 },
      default: "1024",
      defaultOrigin: "fixed",
      required: false,
      options: [],
      optionsAreClosed: false,
    },
    {
      // The setting the whole exercise is about: an identifier over the full
      // 32-bit space, a list of the layouts worth naming, and a default read
      // off this machine rather than a constant.
      key: "keyboard_layout",
      label: "settings.rdp.keyboard_layout",
      kind: { type: "integer", min: 0, max: 4294967295 },
      default: "1055",
      defaultOrigin: "detected",
      required: false,
      options: [
        { value: "1033", label: { kind: "message", key: "settings.keyboardLayout.us" } },
        { value: "1055", label: { kind: "message", key: "settings.keyboardLayout.turkishQ" } },
        { value: "66591", label: { kind: "message", key: "settings.keyboardLayout.turkishF" } },
      ],
      optionsAreClosed: false,
    },
  ],
};

/** VNC's floor: a closed choice, whose values are wire tokens shown as they are. */
const VNC_SCHEMA: ProtocolSchema = {
  protocol: "vnc",
  settings: [
    {
      key: "rfb_version_min",
      label: "settings.vnc.rfb_version_min",
      kind: { type: "choice" },
      default: "3.8",
      defaultOrigin: "fixed",
      required: false,
      options: [
        { value: "3.8", label: { kind: "verbatim", text: "3.8" } },
        { value: "3.7", label: { kind: "verbatim", text: "3.7" } },
        { value: "3.3", label: { kind: "verbatim", text: "3.3" } },
      ],
      optionsAreClosed: true,
    },
  ],
};

/** The sentinel the "type an identifier the list does not carry" option stores. */
const CUSTOM_OPTION = "\u0000custom";

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
  ipcMock.protocolSchemas.mockResolvedValue([]);
  dialogOpen.mockResolvedValue(OPENSSH.path);
});

/**
 * The block of a form field: its label, its control, its buttons and its
 * provenance line. `Field` wraps all of them in one element, which is what
 * makes "the Override button belonging to THIS setting" expressible.
 */
/**
 * The Credentials section alone. The jump host section below it has its own
 * "Override here" and "Revert to inherited", so a login test that asked the
 * whole dialog for one would be asking about two.
 */
async function credentialsSection(): Promise<HTMLElement> {
  const found = (await screen.findByText("Credentials")).parentElement;
  if (found === null) throw new Error("no Credentials section");
  return found;
}

function row(label: string): HTMLElement {
  const found = screen.getByText(label).parentElement;
  if (found === null) throw new Error(`no field around the label ${label}`);
  return found;
}

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
      await within(await credentialsSection()).findByRole("button", { name: "Override here" }),
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
      await within(await credentialsSection()).findByRole("button", { name: "Override here" }),
    );
    await user.click(
      within(await credentialsSection()).getByRole("button", { name: /Revert to inherited/ }),
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

  it("takes a passphrase-protected .pem from the file picker to the core", async () => {
    // The reported failure, from this side of the boundary. The file picker
    // has to offer `.pem` at all; the answer that comes back has to draw the
    // passphrase field; and what is sent has to be the path and the
    // passphrase, because the core reads the file itself and the frontend
    // never holds key material.
    ipcMock.inspectKey.mockResolvedValue(AWS_PEM);
    dialogOpen.mockResolvedValue(AWS_PEM.path);

    const user = userEvent.setup();
    renderEditor(NEW_CONNECTION);

    await fillIdentity(user);
    await user.click(screen.getByRole("radio", { name: /Private key/ }));
    await user.click(screen.getByRole("button", { name: "Choose a key file" }));

    const filters = (
      dialogOpen.mock.calls[0]?.[0] as {
        filters: { extensions: string[] }[];
      }
    ).filters;
    expect(filters.flatMap((filter) => filter.extensions)).toContain("pem");

    expect(await screen.findByText("PKCS#8")).toBeInTheDocument();
    await user.type(
      await screen.findByLabelText("Key passphrase"),
      "correct horse battery staple",
    );
    await user.click(screen.getByRole("button", { name: "Create" }));

    await waitFor(() => expect(ipcMock.createNode).toHaveBeenCalledTimes(1));
    const input = ipcMock.createNode.mock.calls[0]?.[0] as Record<
      string,
      unknown
    >;
    expect(input["credential"]).toEqual({
      kind: "privateKey",
      path: AWS_PEM.path,
      passphrase: "correct horse battery staple",
    });
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

/*
 * The defect this section exists to end: every RDP connection this product
 * ever opened told the server to decode its scancodes as US English, because
 * the adapter's default was a constant and nothing in the interface could set
 * the value. A Turkish keyboard typed Turkish into a server that had been told
 * to expect American, and nothing anywhere reported a fault — the protocol has
 * no way to say "that was the wrong character".
 *
 * The adapter's half landed first: the schema offers the layouts, defaults to
 * the one this machine reports, and says whether it read that or guessed it.
 * This is the other half — a person can now choose, and what is pinned here is
 * that the choice reaches the core in the form the wire carries.
 */
describe("the protocol settings a connection carries", () => {
  const windows = node({
    id: "conn-1",
    name: "dc-01",
    protocol: "rdp",
    host: "dc-01.corp.example",
  });

  beforeEach(() => {
    ipcMock.listNodes.mockResolvedValue([windows]);
    ipcMock.protocolSchemas.mockResolvedValue([RDP_SCHEMA]);
    ipcMock.resolveNode.mockResolvedValue(resolved({ protocol: "rdp", fields: [] }));
  });

  /** Overrides one setting and hands back the control it drew. */
  async function override(
    user: ReturnType<typeof userEvent.setup>,
    label: string,
  ): Promise<HTMLElement> {
    await user.click(within(row(label)).getByRole("button", { name: "Override here" }));
    return screen.getByLabelText(label);
  }

  it("renders one control per setting, chosen by the schema's kind", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    expect(await screen.findByText("Protocol settings")).toBeInTheDocument();

    // Free text gets a text box.
    expect(await override(user, "Windows domain")).toHaveValue("");

    // A boolean gets a switch, not a box that would accept "yes".
    await override(user, "Network Level Authentication");
    expect(
      screen.getByRole("switch", { name: "Network Level Authentication" }),
    ).toBeChecked();

    // A named set gets a picker that shows the NAME and stores the identifier.
    const layout = await override(user, "Keyboard layout");
    expect(layout).toHaveValue("1055");
    expect(
      within(layout).getByRole("option", { name: "Turkish Q" }),
    ).toBeInTheDocument();
  });

  /*
   * The end of the defect. The identifier travels, not the name: the server
   * reads `66591` out of the Client Core Data and has never heard of
   * "Turkish F".
   */
  it("sends the chosen keyboard layout as the identifier the wire carries", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    await user.selectOptions(await override(user, "Keyboard layout"), "66591");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      settings: { keyboard_layout: "66591" },
    });
  });

  /*
   * `optionsAreClosed: false` is the schema saying its list is a convenience
   * over a larger space. Microsoft publishes several hundred layout
   * identifiers; the schema names the ones worth listing, and the rest have to
   * be reachable or the picker is a wall rather than a shortcut.
   */
  it("lets an identifier the list does not carry be typed in", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    await user.selectOptions(await override(user, "Keyboard layout"), CUSTOM_OPTION);

    const typed = screen.getByLabelText("Keyboard layout");
    await user.clear(typed);
    await user.type(typed, "1031");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      settings: { keyboard_layout: "1031" },
    });
  });

  /* A closed choice gets no escape hatch, because the adapter would refuse it. */
  it("offers no free-text escape on a setting whose list is the whole of it", async () => {
    const user = userEvent.setup();
    ipcMock.protocolSchemas.mockResolvedValue([VNC_SCHEMA]);
    ipcMock.listNodes.mockResolvedValue([
      node({ id: "conn-1", name: "kiosk", protocol: "vnc", host: "kiosk.example" }),
    ]);
    ipcMock.resolveNode.mockResolvedValue(resolved({ protocol: "vnc", fields: [] }));
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    const floor = await override(user, "Lowest RFB version");
    expect(within(floor).queryByRole("option", { name: "Another identifier…" })).toBeNull();
    // A wire token is shown exactly as it stands, and never translated.
    expect(within(floor).getByRole("option", { name: "3.3" })).toBeInTheDocument();
  });

  /*
   * The three-state inheritance the rest of the editor has, applied to a
   * setting: a folder's value is shown with its source, and overriding it is
   * the same one click it is on the hostname twenty pixels above.
   */
  it("shows a folder's value with its source, and overrides it in one click", async () => {
    const user = userEvent.setup();
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        protocol: "rdp",
        fields: [
          field({
            field: "settings.keyboard_layout",
            value: "1055",
            origin: "inherited",
            sourceName: "Datacentre EU-West",
          }),
        ],
      }),
    );
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    // By name, and with where it came from.
    expect(
      within(row("Keyboard layout")).getByText("Turkish Q", { normalizer: withoutBidi }),
    ).toBeInTheDocument();
    expect(
      screen.getByText("inherited from Datacentre EU-West", { normalizer: withoutBidi }),
    ).toBeInTheDocument();

    await user.selectOptions(await override(user, "Keyboard layout"), "66591");
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      settings: { keyboard_layout: "66591" },
    });
  });

  /*
   * And the way back. "Inherit this again" and "set this to nothing" are
   * different instructions to the core, and only the first of them is what the
   * revert control means — so it sends `null` rather than an empty string.
   */
  it("clears an override with null, which is not the same as an empty value", async () => {
    const user = userEvent.setup();
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        protocol: "rdp",
        fields: [field({ field: "settings.domain", value: "CORP", origin: "own" })],
      }),
    );
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    expect(screen.getByLabelText("Windows domain")).toHaveValue("CORP");

    await user.click(
      within(row("Windows domain")).getByRole("button", { name: "Use the default" }),
    );
    await user.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(ipcMock.updateNode).toHaveBeenCalledTimes(1));
    expect(ipcMock.updateNode).toHaveBeenCalledWith("conn-1", {
      settings: { domain: null },
    });
  });

  /*
   * The bounds are the protocol's own — MS-RDPEDISP §2.2.2.2.1 for a desktop
   * width — and the form was rendered from the schema that carries them, so
   * the user is told at the field rather than by a failure notice after a
   * round trip.
   */
  it("refuses a number outside the protocol's range before sending it", async () => {
    const user = userEvent.setup();
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    const width = await override(user, "Desktop width");
    await user.clear(width);
    await user.type(width, "99999");
    await user.click(screen.getByRole("button", { name: "Save" }));

    const message = await screen.findByText(/Enter a number between/);
    expect(withoutBidi(message.textContent ?? "")).toMatch(/200/);
    expect(ipcMock.updateNode).not.toHaveBeenCalled();
  });

  /* And the core's own refusal, when one arrives for something the form allowed. */
  it("shows the core's refusal when it refuses a value the form accepted", async () => {
    const user = userEvent.setup();
    ipcMock.updateNode.mockRejectedValue({
      code: "session.setting-invalid",
      message: "The setting `domain` is not usable: it must be shorter text.",
      detail: null,
      actions: [],
    });
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    await screen.findByText("Protocol settings");
    await user.type(await override(user, "Windows domain"), "CORP");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(
      await screen.findByText(/The setting .domain. is not usable/),
    ).toBeInTheDocument();
  });

  /*
   * `defaultOrigin: "guessed"` means detection was attempted and failed, and
   * the value in place is a stand-in. Saying so is the entire reason the
   * origin crosses the boundary: a wrong keyboard layout produces the wrong
   * characters and no error, so a user who is not told concludes their
   * keyboard is broken.
   */
  it("says out loud when the default was guessed rather than detected", async () => {
    ipcMock.protocolSchemas.mockResolvedValue([
      {
        ...RDP_SCHEMA,
        settings: RDP_SCHEMA.settings.map((setting) =>
          setting.key === "keyboard_layout"
            ? { ...setting, default: "1033", defaultOrigin: "guessed" as const }
            : setting,
        ),
      },
    ]);
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    const line = await screen.findByText(/could not tell which keyboard/);
    // Named, so the user can see whether the guess is wrong.
    expect(withoutBidi(line.textContent ?? "")).toContain("US");
  });

  /* The quieter half of the same sentence, when it really was read off this machine. */
  it("names the layout it detected, and says it can be changed", async () => {
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    const line = await screen.findByText(/Detected from this computer/);
    expect(withoutBidi(line.textContent ?? "")).toContain("Turkish Q");
  });

  /*
   * And what RDP does not do at all. Every item is a channel the adapter has
   * no implementation of, so there is no setting for any of them — an omission
   * that would otherwise read as an oversight rather than as the answer.
   */
  it("names what this build's RDP cannot do", async () => {
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    expect(
      await screen.findByText(/does not redirect drives, printers or smart cards/),
    ).toBeInTheDocument();
  });

  /*
   * A key stored on the connection that this build's schema does not name.
   * `remoter-core` preserves it on purpose, so that opening a vault in an
   * older build does not discard a newer protocol's settings. It is shown,
   * because hiding it would hide the thing the preservation protects; and it
   * gets no control, because there is no type behind it to draw one from.
   */
  it("shows a setting outside the schema without offering to edit it", async () => {
    ipcMock.resolveNode.mockResolvedValue(
      resolved({
        protocol: "rdp",
        fields: [field({ field: "settings.from_the_future", value: "42", origin: "own" })],
      }),
    );
    renderEditor({ mode: "edit", nodeId: "conn-1" });

    expect(await screen.findByText(/not part of this build's settings/)).toBeInTheDocument();
    expect(screen.getByText("from_the_future")).toBeInTheDocument();
    expect(
      within(row("from_the_future")).queryByRole("button", { name: "Override here" }),
    ).toBeNull();
  });

  /* Nothing to draw and nothing to say: no empty section. */
  it("is absent for a protocol whose schema this build does not have", async () => {
    ipcMock.protocolSchemas.mockResolvedValue([]);
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
    await waitFor(() => expect(ipcMock.protocolSchemas).toHaveBeenCalled());
    expect(screen.queryByText("Protocol settings")).not.toBeInTheDocument();
  });
});
