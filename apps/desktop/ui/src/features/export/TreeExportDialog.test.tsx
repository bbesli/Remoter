/**
 * The export dialog's behaviour.
 *
 * What is pinned is what would look right in a screenshot while being wrong:
 * that opening it on a folder exports that folder and switching to the vault
 * really sends no root; that the format the user picked is the one requested
 * and the file name follows it; that nothing is written without a
 * destination; and that the core's notes reach the reader as sentences, with
 * the count of the ones the core stopped keeping.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { isolate, isolateLtr } from "@/i18n";
import type { ExportNote, TreeExportResult, TreeNode } from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      exportTree: vi.fn(),
      listNodes: vi.fn(),
    },
  };
});

import { save } from "@tauri-apps/plugin-dialog";
import { ipc } from "@/lib/ipc";

import { describeNote } from "./notes";
import { fileStem, TreeExportDialog } from "./TreeExportDialog";

const exportTree = vi.mocked(ipc.exportTree);
const listNodes = vi.mocked(ipc.listNodes);
const saveDialog = vi.mocked(save);

function node(over: Partial<TreeNode> & Pick<TreeNode, "id" | "name" | "kind">): TreeNode {
  return {
    parentId: null,
    sortOrder: 0,
    description: "",
    tags: [],
    colour: null,
    protocol: null,
    host: null,
    port: null,
    username: null,
    ...over,
  } as TreeNode;
}

const PRODUCTION = node({ id: "folder-prod", name: "Üretim", kind: "folder" });

function result(notes: ExportNote[], notesDropped = 0): TreeExportResult {
  return {
    path: "/home/you/Üretim.config",
    bytes: 2048,
    report: {
      format: "ssh-config",
      folders: 1,
      connections: 3,
      credentials: 0,
      skipped: 1,
      written: 2,
      notes,
      notesDropped,
    },
  };
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  listNodes.mockResolvedValue([PRODUCTION]);
  exportTree.mockResolvedValue(result([]));
  saveDialog.mockResolvedValue(null);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("TreeExportDialog", () => {
  it("says no secret is written and that the file is not encrypted, before anything else", () => {
    render(<TreeExportDialog rootId={null} onClose={() => {}} />, { wrapper });
    const dialog = screen.getByRole("dialog", { name: "Export connections" });
    expect(
      within(dialog).getByText("No password, private key or passphrase is written."),
    ).toBeInTheDocument();
    expect(within(dialog).getByText(/The file is not encrypted, though/)).toBeInTheDocument();
    expect(within(dialog).getByText("The export is recorded in the audit log.")).toBeInTheDocument();
    // Opened on the vault, there is no scope to choose.
    expect(within(dialog).queryByRole("radiogroup", { name: "What to export" })).toBeNull();
  });

  it("refuses to export without a destination, and says so", async () => {
    const user = userEvent.setup();
    render(<TreeExportDialog rootId={null} onClose={() => {}} />, { wrapper });

    await user.click(screen.getByRole("button", { name: "Export" }));

    expect(screen.getByText("Choose where to write the file first.")).toBeInTheDocument();
    expect(exportTree).not.toHaveBeenCalled();
  });

  it("exports the folder it was opened on, or the vault when the user says so", async () => {
    const user = userEvent.setup();
    render(<TreeExportDialog rootId={PRODUCTION.id} onClose={() => {}} />, { wrapper });

    const scope = screen.getByRole("radiogroup", { name: "What to export" });
    const folder = await within(scope).findByRole("radio", {
      name: `${isolate("Üretim")} and everything in it`,
    });
    expect(folder).toHaveAttribute("aria-checked", "true");

    await user.type(screen.getByLabelText("Write to"), "/home/you/prod.csv");
    await user.click(screen.getByRole("button", { name: "Export" }));
    await waitFor(() => expect(exportTree).toHaveBeenCalledTimes(1));
    expect(exportTree.mock.calls[0]?.[0]).toEqual({
      path: "/home/you/prod.csv",
      format: "csv",
      rootId: PRODUCTION.id,
    });
  });

  it("sends no root once the whole vault is chosen", async () => {
    const user = userEvent.setup();
    render(<TreeExportDialog rootId={PRODUCTION.id} onClose={() => {}} />, { wrapper });

    await user.click(screen.getByRole("radio", { name: "The whole vault" }));
    await user.type(screen.getByLabelText("Write to"), "/home/you/all.json");
    await user.click(screen.getByRole("radio", { name: "JSON" }));
    await user.click(screen.getByRole("button", { name: "Export" }));

    await waitFor(() => expect(exportTree).toHaveBeenCalledTimes(1));
    expect(exportTree.mock.calls[0]?.[0]).toEqual({
      path: "/home/you/all.json",
      format: "json",
      rootId: null,
    });
  });

  it("changes the file's extension with the format, and leaves a typed one alone", async () => {
    const user = userEvent.setup();
    render(<TreeExportDialog rootId={null} onClose={() => {}} />, { wrapper });
    const pathField = screen.getByLabelText("Write to");

    await user.type(pathField, "/home/you/estate.csv");
    await user.click(screen.getByRole("radio", { name: "OpenSSH config" }));
    expect(pathField).toHaveValue("/home/you/estate.config");
    expect(screen.getByText(/SSH connections as Host blocks/)).toBeInTheDocument();

    await user.clear(pathField);
    await user.type(pathField, "/home/you/estate.txt");
    await user.click(screen.getByRole("radio", { name: "JSON" }));
    expect(pathField).toHaveValue("/home/you/estate.txt");
  });

  it("offers the folder's own name, in its own script, in the save dialog", async () => {
    const user = userEvent.setup();
    saveDialog.mockResolvedValue("/home/you/Üretim.csv");
    render(<TreeExportDialog rootId={PRODUCTION.id} onClose={() => {}} />, { wrapper });
    await screen.findByRole("radio", { name: `${isolate("Üretim")} and everything in it` });

    await user.click(screen.getByRole("button", { name: "Choose…" }));

    await waitFor(() => expect(saveDialog).toHaveBeenCalledTimes(1));
    expect(saveDialog.mock.calls[0]?.[0]).toMatchObject({ defaultPath: "Üretim.csv" });
    expect(screen.getByLabelText("Write to")).toHaveValue("/home/you/Üretim.csv");
  });

  it("reports what was written and what the format could not say", async () => {
    const user = userEvent.setup();
    exportTree.mockResolvedValue(
      result(
        [
          { kind: "unsupported-protocol", item: "dc-01", protocol: "rdp" },
          { kind: "gateway-not-written", item: "db", reason: "ambiguous-hop" },
        ],
        4,
      ),
    );
    render(<TreeExportDialog rootId={null} onClose={() => {}} />, { wrapper });

    await user.type(screen.getByLabelText("Write to"), "/home/you/Üretim.config");
    await user.click(screen.getByRole("button", { name: "Export" }));

    expect(
      await screen.findByText(
        `Wrote 2 connections of 3 to ${isolateLtr("/home/you/Üretim.config")} (2.0 KiB).`,
      ),
    ).toBeInTheDocument();
    const notes = screen.getByRole("region", { name: "6 things to know about this file" });
    expect(
      within(notes).getByText(
        `${isolate("dc-01")} was left out: an OpenSSH config cannot describe a connection over RDP.`,
      ),
    ).toBeInTheDocument();
    expect(within(notes).getByText(/another connection has the same name as its jump host/)).toBeInTheDocument();
    expect(within(notes).getByText("and 4 more")).toBeInTheDocument();
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<TreeExportDialog rootId={null} onClose={onClose} />, { wrapper });
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("describeNote", () => {
  const t = ((key: string, values?: Record<string, unknown>) =>
    `${key} ${JSON.stringify(values ?? {})}`) as unknown as Parameters<typeof describeNote>[0];

  it("has a sentence for every note the core writes, with names isolated", () => {
    const notes: ExportNote[] = [
      { kind: "unsupported-protocol", item: "a", protocol: "vnc" },
      { kind: "gateway-not-written", item: "a", reason: "deleted-hop" },
      { kind: "gateway-not-written", item: "a", reason: "ambiguous-hop" },
      { kind: "gateway-not-written", item: "a", reason: "hop-outside-export" },
      { kind: "gateway-not-written", item: "a", reason: "hop-credential" },
      { kind: "gateway-not-written", item: "a", reason: "hop-not-ssh" },
      { kind: "renamed", item: "Web 01", written: "web-01" },
      { kind: "folder-name-splits", folder: "EU/West" },
      { kind: "value-not-written", item: "a", field: "identity-file" },
      { kind: "outside-reference", item: "a", target: "svc" },
    ];
    const keys = notes.map((note) => describeNote(t, note).split(" ")[0]);
    expect(new Set(keys).size).toBe(notes.length);
    for (const note of notes) {
      const sentence = describeNote(t, note);
      const name = "item" in note ? note.item : note.folder;
      expect(sentence).toContain(JSON.stringify(isolate(name)).slice(1, -1));
    }
  });

  it("still says something about a note a newer core wrote", () => {
    const future = { kind: "something-new", item: "a" } as unknown as ExportNote;
    expect(describeNote(t, future)).toMatch(/^export\.note\.valueNotWritten /);
  });
});

describe("fileStem", () => {
  it("keeps a name's own letters and replaces only what no file system accepts", () => {
    expect(fileStem("Üretim")).toBe("Üretim");
    expect(fileStem("EU/West: prod")).toBe("EU-West- prod");
    expect(fileStem("  ..")).toBe("remoter-connections");
    expect(fileStem(null)).toBe("remoter-connections");
  });
});
