/**
 * The behaviour of the screen, as opposed to the arithmetic behind it.
 *
 * Three things are pinned, all of them things that would look fine in a
 * screenshot while being wrong:
 *
 *  - a filter chip actually narrows the query, and the table shows the narrowed
 *    answer rather than the one it already had;
 *  - the outcome column carries a word, not only a colour;
 *  - the export dialog refuses to write without a destination, and says so
 *    where the user is looking rather than doing nothing.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { AuditEntry, AuditPage, AuditQuery } from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      queryAudit: vi.fn(),
      auditFilters: vi.fn(),
      exportAudit: vi.fn(),
      listNodes: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { AuditViewer } from "./AuditViewer";

const queryAudit = vi.mocked(ipc.queryAudit);
const auditFilters = vi.mocked(ipc.auditFilters);
const exportAudit = vi.mocked(ipc.exportAudit);
const listNodes = vi.mocked(ipc.listNodes);

function entry(over: Partial<AuditEntry> & Pick<AuditEntry, "id" | "event">): AuditEntry {
  return {
    at: 1_757_500_000_000,
    outcome: "success",
    category: "vault",
    warning: false,
    nodeId: null,
    nodeName: null,
    sessionId: null,
    detail: null,
    ...over,
  };
}

function page(entries: AuditEntry[]): AuditPage {
  return { entries, total: entries.length, page: 0, pageSize: 200 };
}

const UNLOCKED = entry({ id: 1, event: "vault.unlocked", detail: "Slot 2 · security key" });

const HOST_KEY = entry({
  id: 2,
  event: "host_key.changed",
  outcome: "denied",
  category: "warning",
  warning: true,
  nodeId: "node-db",
  nodeName: "db-01",
  detail: "Refused to connect. Offered key did not match the pin.",
});

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  auditFilters.mockResolvedValue({
    categories: ["vault", "node", "secret", "connection", "warning"],
    outcomes: ["success", "failure", "denied"],
    events: ["vault.unlocked", "host_key.changed"],
  });
  listNodes.mockResolvedValue([]);
  queryAudit.mockImplementation(async (query: AuditQuery) =>
    query.categories?.includes("warning") === true ? page([HOST_KEY]) : page([UNLOCKED, HOST_KEY]),
  );
  exportAudit.mockResolvedValue({
    path: "/home/you/audit.json",
    format: "json",
    entries: 2,
    bytes: 1_400,
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("AuditViewer", () => {
  it("states the guarantee the format actually delivers", async () => {
    render(<AuditViewer />, { wrapper });

    // Not "tamper-evident": the log defends against everyone outside the vault
    // and nobody inside it, and the screen has to say the second half too.
    expect(
      screen.getByText(/anyone who can open it can edit it, and Remoter would not be able to tell/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/no recording player yet/i)).toBeInTheDocument();
  });

  it("gives every outcome a word, not only a colour", async () => {
    render(<AuditViewer />, { wrapper });

    // Scoped to the table: the outcome chips in the filter bar carry the same
    // words, which is the point — the chip and the cell say the same thing.
    const table = within(await screen.findByRole("table"));
    expect(await table.findByText("Succeeded")).toBeInTheDocument();
    expect(table.getByText("Denied")).toBeInTheDocument();
  });

  it("narrows the query and the table when a category chip is pressed", async () => {
    const user = userEvent.setup();
    render(<AuditViewer />, { wrapper });

    expect(await screen.findByText("vault unlocked")).toBeInTheDocument();

    const chip = await screen.findByRole("button", { name: "Warnings" });
    await user.click(chip);

    await waitFor(() => {
      expect(screen.queryByText("vault unlocked")).not.toBeInTheDocument();
    });
    expect(screen.getByText("host key changed")).toBeInTheDocument();
    expect(chip).toHaveAttribute("aria-pressed", "true");

    const asked = queryAudit.mock.calls.map(([q]) => q);
    expect(asked.some((q) => q.categories?.includes("warning") === true)).toBe(true);
  });

  it("asks for one page at a time rather than the whole log", async () => {
    render(<AuditViewer />, { wrapper });

    await screen.findByText("vault unlocked");
    const [first] = queryAudit.mock.calls[0] ?? [];
    expect(first?.page).toBe(0);
    expect(first?.pageSize).toBe(200);
  });

  it("says an export is itself audited, and refuses one with no destination", async () => {
    const user = userEvent.setup();
    render(<AuditViewer />, { wrapper });

    await user.click(await screen.findByRole("button", { name: "Export…" }));

    const dialog = screen.getByRole("dialog");
    expect(
      within(dialog).getByText(/Exporting writes a row into this log/i),
    ).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Export" }));

    // The refusal is visible, and nothing was written.
    expect(within(dialog).getByText("Choose where to write the file first.")).toBeInTheDocument();
    expect(exportAudit).not.toHaveBeenCalled();
  });

  it("exports the filter on screen, without its paging", async () => {
    const user = userEvent.setup();
    render(<AuditViewer />, { wrapper });

    await user.click(await screen.findByRole("button", { name: "Export…" }));
    const dialog = screen.getByRole("dialog");

    await user.type(within(dialog).getByLabelText("Write to"), "/home/you/audit.json");
    await user.click(within(dialog).getByRole("button", { name: "Export" }));

    await waitFor(() => expect(exportAudit).toHaveBeenCalledTimes(1));

    const [request] = exportAudit.mock.calls[0] ?? [];
    expect(request?.path).toBe("/home/you/audit.json");
    expect(request?.format).toBe("json");
    // "Page three of a filter" is not what anybody means by an export.
    expect(request?.query).toBeDefined();
    expect(request?.query === null || request?.query === undefined).toBe(false);
    expect(Object.keys(request?.query ?? {})).not.toContain("page");

    expect(await screen.findByText(/A row recording this export is now at the top/i)).toBeInTheDocument();
  });

  it("shows the core's own message when the log cannot be read", async () => {
    queryAudit.mockRejectedValue({
      code: "vault.locked",
      message: "The vault is locked.",
      detail: "The audit log lives inside the vault body.",
      actions: ["Unlock the vault, then open the log again."],
    });

    render(<AuditViewer />, { wrapper });

    expect(await screen.findByText("The audit log could not be read.")).toBeInTheDocument();
    expect(screen.getByText("The vault is locked.")).toBeInTheDocument();
    expect(screen.getByText("The audit log lives inside the vault body.")).toBeInTheDocument();
    expect(
      screen.getByText("Unlock the vault, then open the log again."),
    ).toBeInTheDocument();
  });
});
