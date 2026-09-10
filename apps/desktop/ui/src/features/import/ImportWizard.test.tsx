/**
 * The wizard end to end, in a DOM.
 *
 * What is tested here is what the wizard promises: it refuses to move on
 * without what the next step needs, it never writes before the commit, the
 * ticks in the preview decide what is written, and the two pieces of news the
 * core reports — a file protected by the published default password, and a
 * ProxyJump turned into a real gateway chain — are on screen rather than
 * buried.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type {
  ImportDetection,
  ImportNode,
  ImportPreview,
  ImportResult,
  TreeNode,
} from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn(), save: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      detectImport: vi.fn(),
      parseImport: vi.fn(),
      commitImport: vi.fn(),
      cancelImport: vi.fn(),
      listNodes: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { ImportWizard } from "./ImportWizard";

const mocked = ipc as unknown as {
  detectImport: ReturnType<typeof vi.fn>;
  parseImport: ReturnType<typeof vi.fn>;
  commitImport: ReturnType<typeof vi.fn>;
  cancelImport: ReturnType<typeof vi.fn>;
  listNodes: ReturnType<typeof vi.fn>;
};

const PATH = "/home/you/confCons.xml";

function detection(partial: Partial<ImportDetection> = {}): ImportDetection {
  return {
    path: PATH,
    sizeBytes: 2_400_000,
    format: "mremoteng",
    formatLabel: "mRemoteNG 1.77",
    passwordRequired: false,
    document: null,
    ...partial,
  };
}

function node(partial: Partial<ImportNode> & Pick<ImportNode, "id" | "name" | "kind">): ImportNode {
  return {
    parentId: null,
    sortOrder: 0,
    protocol: null,
    host: null,
    port: null,
    portInherited: false,
    username: null,
    domain: null,
    hasSecret: false,
    credentialInherited: false,
    gatewayHops: 0,
    customFields: 0,
    ...partial,
  };
}

function preview(): ImportPreview {
  return {
    importId: "import-1",
    source: "mremoteng",
    sourceLabel: "mRemoteNG",
    nodes: [
      node({ id: "prod", name: "Production", kind: "folder" }),
      node({
        id: "web1",
        name: "web-01",
        kind: "connection",
        parentId: "prod",
        host: "web-01.acme",
        port: 22,
        gatewayHops: 2,
      }),
      node({ id: "archive", name: "Archive 2019", kind: "folder", sortOrder: 1 }),
      node({ id: "old1", name: "old-01", kind: "connection", parentId: "archive", host: "old.acme" }),
    ],
    report: {
      source: "mremoteng",
      counts: { folders: 2, connections: 2, credentials: 0, secrets: 1, skipped: 0 },
      findings: [
        { severity: "alert", kind: "default_file_password" },
        { severity: "info", kind: "gateway_mapped", item: "web-01", hops: 2 },
      ],
      truncated: false,
      needsAttention: true,
    },
  };
}

function result(): ImportResult {
  return {
    source: "mremoteng",
    imported: 2,
    skipped: 2,
    folders: 1,
    connections: 1,
    credentials: 0,
    secretsStored: 1,
    needsAttention: 1,
    rootIds: ["prod"],
  };
}

function draw(ui: ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocked.listNodes.mockResolvedValue([] as TreeNode[]);
  mocked.cancelImport.mockResolvedValue(undefined);
});

/** Path typed, detected, and on to the secrets step. */
async function reachSecrets(user: ReturnType<typeof userEvent.setup>, detected: ImportDetection) {
  mocked.detectImport.mockResolvedValue(detected);
  await user.type(screen.getByLabelText("Path to the file"), PATH);
  await user.click(screen.getByRole("button", { name: "Read this file" }));
  await screen.findByRole("button", { name: "Continue" });
  await user.click(screen.getByRole("button", { name: "Continue" }));
}

describe("step gating", () => {
  it("will not leave the first step without a file, and says why", async () => {
    draw(<ImportWizard />);
    const next = screen.getByRole("button", { name: "Continue" });
    expect(next).toBeDisabled();
    expect(next).toHaveAttribute("title", "Choose the file you want to import.");
    expect(mocked.detectImport).not.toHaveBeenCalled();
  });

  it("detects the file before it will go on", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachSecrets(user, detection());
    expect(mocked.detectImport).toHaveBeenCalledWith(PATH);
    expect(screen.getByText("Nothing to supply")).toBeInTheDocument();
  });

  it("takes the format the user chooses when detection cannot read the file", async () => {
    const user = userEvent.setup();
    mocked.detectImport.mockRejectedValue({
      code: "import.unreadable",
      message: "That file could not be opened.",
      detail: "Permission denied.",
      actions: ["Check that you can read the file."],
    });
    mocked.parseImport.mockResolvedValue(preview());
    draw(<ImportWizard />);

    await user.type(screen.getByLabelText("Path to the file"), PATH);
    await user.click(screen.getByRole("button", { name: "Read this file" }));
    expect(await screen.findByText("That file could not be opened.")).toBeInTheDocument();

    await user.click(screen.getByRole("radio", { name: /CSV/ }));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("button", { name: "Read the file" }));

    await waitFor(() => expect(mocked.parseImport).toHaveBeenCalledWith(PATH, null, "csv"));
  });

  it("will not parse an encrypted file until its password is typed", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachSecrets(
      user,
      detection({
        passwordRequired: true,
        document: {
          name: "Acme",
          confVersion: "2.6",
          cipher: "gcm",
          kdfIterations: 1000,
          legacyCipher: false,
          fullFileEncryption: false,
          passwordRequired: true,
        },
      }),
    );

    const parse = screen.getByRole("button", { name: "Read the file" });
    expect(parse).toBeDisabled();
    expect(parse).toHaveAttribute(
      "title",
      "This file needs its document password before it can be read.",
    );

    await user.type(screen.getByLabelText("Document password"), "hunter2");
    expect(screen.getByRole("button", { name: "Read the file" })).toBeEnabled();
    expect(mocked.parseImport).not.toHaveBeenCalled();
  });

  it("says the file was not really protected as soon as detection knows", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachSecrets(
      user,
      detection({
        passwordRequired: false,
        document: {
          name: "Acme",
          confVersion: "2.6",
          cipher: "cbc",
          kdfIterations: null,
          legacyCipher: true,
          fullFileEncryption: false,
          passwordRequired: false,
        },
      }),
    );

    expect(screen.getByText("This file was not really protected")).toBeInTheDocument();
    expect(
      screen.getByText("This file uses legacy AES-CBC with an MD5-derived key"),
    ).toBeInTheDocument();
    // Still nothing written, and nothing parsed.
    expect(mocked.parseImport).not.toHaveBeenCalled();
    expect(mocked.commitImport).not.toHaveBeenCalled();
  });
});

describe("the preview", () => {
  async function reachPreview(user: ReturnType<typeof userEvent.setup>) {
    mocked.parseImport.mockResolvedValue(preview());
    await reachSecrets(user, detection());
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("This is what you will get");
  }

  it("shows every node, and the gateway chain that would otherwise be invisible", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    expect(screen.getByLabelText("Production")).toBeChecked();
    expect(screen.getByLabelText("web-01")).toBeChecked();
    expect(screen.getByText("gateway ×2")).toBeInTheDocument();
    // The alert from the report is on the preview too, not only in the report.
    expect(
      screen.getByText(/well-known default password/, { exact: false }),
    ).toBeInTheDocument();
  });

  it("unticking a folder unticks its children and changes the counts", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    expect(screen.getByText("4 of 4 ticked")).toBeInTheDocument();
    await user.click(screen.getByLabelText("Archive 2019"));

    expect(screen.getByLabelText("Archive 2019")).not.toBeChecked();
    expect(screen.getByLabelText("old-01")).not.toBeChecked();
    expect(screen.getByText("2 of 4 ticked")).toBeInTheDocument();
  });

  it("filters the tree without changing what is ticked", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    await user.type(screen.getByLabelText("Filter by name, host or user"), "old.acme");
    expect(screen.queryByLabelText("web-01")).not.toBeInTheDocument();
    expect(screen.getByLabelText("old-01")).toBeInTheDocument();
    expect(screen.getByLabelText("old-01")).toBeChecked();
    expect(screen.getByText("4 of 4 ticked")).toBeInTheDocument();
  });

  it("commits only what is still ticked, naming the top of each unticked subtree", async () => {
    const user = userEvent.setup();
    mocked.commitImport.mockResolvedValue(result());
    draw(<ImportWizard />);
    await reachPreview(user);

    await user.click(screen.getByLabelText("Archive 2019"));
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("button", { name: "Choose the destination" }));
    await user.click(await screen.findByRole("button", { name: "Review and commit" }));

    expect(mocked.commitImport).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Import 2 items" }));

    await waitFor(() => expect(mocked.commitImport).toHaveBeenCalledTimes(1));
    expect(mocked.commitImport).toHaveBeenCalledWith({
      importId: "import-1",
      destinationId: null,
      // "old-01" is not named: excluding its folder already excludes it.
      excludedIds: ["archive"],
    });

    expect(await screen.findByText("2 items are in your vault")).toBeInTheDocument();
    expect(screen.getByText("There is no undo")).toBeInTheDocument();
    expect(screen.getByText("Rotate these credentials")).toBeInTheDocument();
  });

  it("refuses to go on when everything has been unticked", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    await user.click(screen.getByRole("button", { name: "Untick everything" }));
    const next = screen.getByRole("button", { name: "Continue" });
    expect(next).toBeDisabled();
    expect(next).toHaveAttribute("title", "Everything is unticked. Tick at least one item to import.");
  });

  it("keeps the parse in the core until the user confirms leaving", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    await user.click(screen.getByRole("button", { name: "Close the import wizard" }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("Discard this import?")).toBeInTheDocument();
    expect(mocked.cancelImport).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole("button", { name: "Discard and leave" }));
    await waitFor(() => expect(mocked.cancelImport).toHaveBeenCalledWith("import-1"));
  });

  it("lets Escape cancel the discard dialog without dropping the parse", async () => {
    const user = userEvent.setup();
    draw(<ImportWizard />);
    await reachPreview(user);

    await user.click(screen.getByRole("button", { name: "Close the import wizard" }));
    expect(screen.getByRole("dialog")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(mocked.cancelImport).not.toHaveBeenCalled();
    expect(screen.getByText("This is what you will get")).toBeInTheDocument();
  });
});
