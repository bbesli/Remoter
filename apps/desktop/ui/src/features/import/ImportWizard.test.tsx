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

  /**
   * The case detection cannot see coming: the user picked the format by hand,
   * so there is no `<Connections>` header to read, and the file turns out to be
   * one its owner put a password on. The core says which password is missing —
   * and until this, it said so above a step with no box to type one into.
   */
  it("puts the password field on screen when the core asks for one", async () => {
    const user = userEvent.setup();
    mocked.parseImport
      .mockRejectedValueOnce({
        code: "import.password-required",
        message: "That file is encrypted and needs its document password to be read.",
        detail: null,
        actions: ["Enter the document password"],
      })
      .mockResolvedValueOnce(preview());
    draw(<ImportWizard />);

    // Detection saw no header: no document, no password wanted.
    await reachSecrets(user, detection({ passwordRequired: false, document: null }));
    expect(screen.getByText("Nothing to supply")).toBeInTheDocument();
    expect(screen.queryByLabelText("Document password")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Read the file" }));
    expect(
      await screen.findByText(
        "That file is encrypted and needs its document password to be read.",
      ),
    ).toBeInTheDocument();

    // The field is there now, and Read the file will not fire again empty.
    const field = screen.getByLabelText("Document password");
    expect(field).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read the file" })).toBeDisabled();

    await user.type(field, "correct horse");
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await waitFor(() =>
      expect(mocked.parseImport).toHaveBeenLastCalledWith(PATH, "correct horse", null),
    );
    await screen.findByText("This is what you will get");
  });

  it("asks for an archive's own password, not a document password", async () => {
    const user = userEvent.setup();
    mocked.parseImport
      .mockRejectedValueOnce({
        code: "import.archive-wrong-password",
        message: "That password does not open the archive.",
        detail: null,
        actions: ["Try the password again"],
      })
      .mockResolvedValueOnce(preview());
    draw(<ImportWizard />);

    await reachSecrets(
      user,
      detection({
        format: "remoter-archive",
        formatLabel: "remoter_archive",
        passwordRequired: true,
      }),
    );
    expect(screen.getByText("The archive is sealed")).toBeInTheDocument();
    expect(screen.queryByLabelText("Document password")).not.toBeInTheDocument();
    const field = screen.getByLabelText("Archive password");

    await user.type(field, "not it");
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    expect(await screen.findByText("That password does not open the archive.")).toBeInTheDocument();
    // Still the archive's field, still on screen, for the second try.
    await user.clear(screen.getByLabelText("Archive password"));
    await user.type(screen.getByLabelText("Archive password"), "orbit-lantern-quarry-velvet");
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await waitFor(() =>
      expect(mocked.parseImport).toHaveBeenLastCalledWith(
        PATH,
        "orbit-lantern-quarry-velvet",
        null,
      ),
    );
    await screen.findByText("This is what you will get");
  });

  it("keeps the field on screen when the password typed was the wrong one", async () => {
    const user = userEvent.setup();
    mocked.parseImport.mockRejectedValue({
      code: "import.wrong-password",
      message: "That is not the password the file was encrypted with.",
      detail: null,
      actions: ["Try again"],
    });
    draw(<ImportWizard />);

    await reachSecrets(user, detection({ passwordRequired: false, document: null }));
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("That is not the password the file was encrypted with.");

    const field = screen.getByLabelText("Document password");
    await user.type(field, "nope");
    // A wrong password is not a missing one: the user may try another.
    expect(screen.getByRole("button", { name: "Read the file" })).toBeEnabled();
    expect(mocked.commitImport).not.toHaveBeenCalled();
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

  /**
   * A partial import is the case this screen used to render as a clean success.
   * Four connections the parser could not represent showed up as a muted "2"
   * in a tile labelled "unticked by you" — a count that is not even about them
   * — under a green tick and "2 items are in your vault". Nothing on the last
   * screen of the flow said which servers were missing, and the person reading
   * it had thirty-seven to account for.
   */
  it("does not report a partial import as a clean success", async () => {
    const user = userEvent.setup();
    const partial = preview();
    partial.report.counts.skipped = 2;
    partial.report.findings = [
      ...partial.report.findings,
      { severity: "warning", kind: "skipped_item", item: "SQL_PROD", reason: "unusable_host" },
      {
        severity: "warning",
        kind: "skipped_item",
        item: "Open the ticket system",
        reason: "unsupported_kind",
      },
    ];
    mocked.parseImport.mockResolvedValue(partial);
    mocked.commitImport.mockResolvedValue(result());
    draw(<ImportWizard />);
    await reachSecrets(user, detection());
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("This is what you will get");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("button", { name: "Choose the destination" }));
    await user.click(await screen.findByRole("button", { name: "Review and commit" }));
    await user.click(screen.getByRole("button", { name: "Import 4 items" }));

    expect(await screen.findByText("2 items in the file did not come in")).toBeInTheDocument();
    // And by name, so the reader knows which servers to go and look for.
    expect(screen.getByText(/SQL_PROD/)).toBeInTheDocument();
    expect(screen.getByText(/Open the ticket system/)).toBeInTheDocument();
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

/**
 * Choosing a second file.
 *
 * Everything on this screen below the path is *about* the file at the path:
 * what detection made of it, the password its owner put on it, the refusal the
 * core came back with, and the parse the core is holding. A new file makes
 * every one of those a statement about a file that is no longer the one being
 * imported — and the wizard gates the next step on them, so a stale one is not
 * only wrong on screen, it is a door that will not open.
 */
describe("a second file", () => {
  const OTHER = "/home/you/servers.csv";

  /** Back to step 1 through the rail, and a different path typed in. */
  async function chooseInstead(user: ReturnType<typeof userEvent.setup>, next: string) {
    await user.click(screen.getByRole("button", { name: "1 Source" }));
    await user.clear(screen.getByLabelText("Path to the file"));
    await user.type(screen.getByLabelText("Path to the file"), next);
  }

  /**
   * The dead end: a password refusal about the first file was still on screen
   * against the second, still rendering a password field for a file that has
   * none, and still holding "Read the file" shut until something was typed
   * into it.
   */
  it("drops the refusal, the field and the password when a different file is chosen", async () => {
    const user = userEvent.setup();
    mocked.parseImport.mockRejectedValue({
      code: "import.wrong-password",
      message: "That is not the password the file was encrypted with.",
      detail: null,
      actions: ["Try again"],
    });
    draw(<ImportWizard />);

    await reachSecrets(user, detection({ passwordRequired: false, document: null }));
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("That is not the password the file was encrypted with.");
    await user.type(screen.getByLabelText("Document password"), "hunter2");

    mocked.detectImport.mockResolvedValue(
      detection({ path: OTHER, format: "csv", formatLabel: "CSV", passwordRequired: false }),
    );
    await chooseInstead(user, OTHER);
    await user.click(screen.getByRole("button", { name: "Read this file" }));
    await screen.findByRole("button", { name: "Continue" });
    await user.click(screen.getByRole("button", { name: "Continue" }));

    // The refusal was about the other file.
    expect(
      screen.queryByText("That is not the password the file was encrypted with."),
    ).not.toBeInTheDocument();
    // This one has no document password, so it is not asked for.
    expect(screen.queryByLabelText("Document password")).not.toBeInTheDocument();
    expect(screen.getByText("Nothing to supply")).toBeInTheDocument();
    // And the control that reads it is open, rather than waiting on a field
    // that is not on screen.
    const parse = screen.getByRole("button", { name: "Read the file" });
    expect(parse).toBeEnabled();

    // The password typed for the first file does not travel to the second.
    mocked.parseImport.mockReset();
    mocked.parseImport.mockResolvedValue(preview());
    await user.click(parse);
    await waitFor(() => expect(mocked.parseImport).toHaveBeenCalledWith(OTHER, null, null));
  });

  /** A detection failure is about a file too. */
  it("drops a detection failure when a different file is chosen", async () => {
    const user = userEvent.setup();
    mocked.detectImport.mockRejectedValueOnce({
      code: "import.unreadable",
      message: "That file could not be opened.",
      detail: "Permission denied.",
      actions: ["Check that you can read the file."],
    });
    draw(<ImportWizard />);

    await user.type(screen.getByLabelText("Path to the file"), PATH);
    await user.click(screen.getByRole("button", { name: "Read this file" }));
    await screen.findByText("That file could not be opened.");

    await chooseInstead(user, OTHER);
    expect(screen.queryByText("That file could not be opened.")).not.toBeInTheDocument();
  });

  /**
   * The worst of the family: the preview is a parse of the *first* file. Left
   * standing against a second, the rail still offers the steps that act on it
   * and the commit at the end of them would write the file the user just
   * navigated away from.
   */
  it("does not offer the previous file's preview against a new file", async () => {
    const user = userEvent.setup();
    mocked.parseImport.mockResolvedValue(preview());
    draw(<ImportWizard />);
    await reachSecrets(user, detection());
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("This is what you will get");

    await chooseInstead(user, OTHER);

    const toPreview = screen.getByRole("button", { name: "4 Preview" });
    expect(toPreview).toBeDisabled();
    expect(toPreview).toHaveAttribute("title", "Nothing has been read yet.");

    // Reading the new file replaces it — and the parse of the old one does not
    // stay resident in the core holding the passwords it recovered.
    const second = { ...preview(), importId: "import-2" };
    mocked.parseImport.mockResolvedValue(second);
    mocked.detectImport.mockResolvedValue(detection({ path: OTHER, format: "csv" }));
    await user.click(screen.getByRole("button", { name: "Read this file" }));
    await screen.findByRole("button", { name: "Continue" });
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("This is what you will get");

    await waitFor(() => expect(mocked.cancelImport).toHaveBeenCalledWith("import-1"));
    await user.click(screen.getByRole("button", { name: "Close the import wizard" }));
    await user.click(screen.getByRole("button", { name: "Discard and leave" }));
    await waitFor(() => expect(mocked.cancelImport).toHaveBeenLastCalledWith("import-2"));
  });

  /**
   * The same defect one step further on: a commit that failed did so writing
   * the first file, and the second file's last step is where that notice was
   * still sitting.
   */
  it("drops a failed commit's notice when a different file is chosen", async () => {
    const user = userEvent.setup();
    mocked.parseImport.mockResolvedValue(preview());
    mocked.commitImport.mockRejectedValue({
      code: "import.commit-failed",
      message: "The import could not be written.",
      detail: null,
      actions: ["Try again"],
    });
    draw(<ImportWizard />);

    async function toTheLastStep() {
      await user.click(screen.getByRole("button", { name: "Read the file" }));
      await screen.findByText("This is what you will get");
      await user.click(screen.getByRole("button", { name: "Continue" }));
      await user.click(screen.getByRole("button", { name: "Choose the destination" }));
      await user.click(await screen.findByRole("button", { name: "Review and commit" }));
    }

    await reachSecrets(user, detection());
    await toTheLastStep();
    await user.click(screen.getByRole("button", { name: "Import 4 items" }));
    await screen.findByText("The import could not be written.");

    mocked.detectImport.mockResolvedValue(detection({ path: OTHER, format: "csv" }));
    mocked.parseImport.mockResolvedValue({ ...preview(), importId: "import-2" });
    await chooseInstead(user, OTHER);
    await user.click(screen.getByRole("button", { name: "Read this file" }));
    await screen.findByRole("button", { name: "Continue" });
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await toTheLastStep();

    expect(screen.queryByText("The import could not be written.")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Import 4 items" })).toBeEnabled();
  });

  /**
   * Editing a path is not a decision to throw a parse away: a typo corrected
   * back to what it was finds the preview where it was left.
   */
  it("keeps the preview when the path is edited back to what it was", async () => {
    const user = userEvent.setup();
    mocked.parseImport.mockResolvedValue(preview());
    draw(<ImportWizard />);
    await reachSecrets(user, detection());
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("This is what you will get");

    await user.click(screen.getByRole("button", { name: "1 Source" }));
    const field = screen.getByLabelText("Path to the file");
    await user.type(field, "x");
    expect(screen.getByRole("button", { name: "4 Preview" })).toBeDisabled();

    await user.type(field, "{backspace}");
    expect(mocked.cancelImport).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "4 Preview" })).toBeEnabled();
  });
});
