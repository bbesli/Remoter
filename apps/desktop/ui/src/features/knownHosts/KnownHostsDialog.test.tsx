/**
 * The known_hosts dialog's behaviour.
 *
 * Pinned: that the account's own file is offered, that nothing is written
 * before the preview has been read and the button pressed, that a host whose
 * trusted key differs is said out loud before the import, that the import
 * asks for the file the preview was of, and that a file with nothing new in
 * it offers nothing to press.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { KnownHostsPreview } from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      knownHostsLocation: vi.fn(),
      knownHostsPreview: vi.fn(),
      knownHostsImport: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { KnownHostsDialog } from "./KnownHostsDialog";

const location = vi.mocked(ipc.knownHostsLocation);
const previewOf = vi.mocked(ipc.knownHostsPreview);
const importFile = vi.mocked(ipc.knownHostsImport);

const PATH = "/home/you/.ssh/known_hosts";

function preview(over: Partial<KnownHostsPreview> = {}): KnownHostsPreview {
  return {
    path: PATH,
    entries: 6,
    keys: [
      {
        host: "db.example.com",
        port: 22,
        algorithm: "ssh-ed25519",
        fingerprint: "SHA256:differsdiffers",
        state: "differs",
      },
      {
        host: "web-01.example.com",
        port: 22,
        algorithm: "ssh-ed25519",
        fingerprint: "SHA256:newnewnew",
        state: "new",
      },
      {
        host: "git.example.com",
        port: 2200,
        algorithm: "ssh-rsa",
        fingerprint: "SHA256:newagain",
        state: "new",
      },
    ],
    total: 3,
    new: 2,
    alreadyTrusted: 0,
    differs: 1,
    unsupported: 0,
    hashedUnmatched: 2,
    hashedUnchecked: 0,
    patternsUnmatched: 0,
    revoked: 1,
    certificateAuthorities: 0,
    conflicting: 0,
    malformed: 0,
    ...over,
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
  location.mockResolvedValue(PATH);
});

describe("KnownHostsDialog", () => {
  it("offers the account's own file, and warns before anything is read", async () => {
    draw(<KnownHostsDialog onClose={vi.fn()} />);
    expect(await screen.findByDisplayValue(PATH)).toBeInTheDocument();
    expect(screen.getByText("Only import a file you trust")).toBeInTheDocument();
    expect(previewOf).not.toHaveBeenCalled();
    expect(importFile).not.toHaveBeenCalled();
  });

  it("previews, names what it keeps, and trusts only on the button", async () => {
    const user = userEvent.setup();
    previewOf.mockResolvedValue(preview());
    importFile.mockResolvedValue({ trusted: 2, alreadyTrusted: 0, differs: 1 });
    draw(<KnownHostsDialog onClose={vi.fn()} />);
    await screen.findByDisplayValue(PATH);

    await user.click(screen.getByRole("button", { name: "Read the file" }));
    expect(await screen.findByText("2 host keys to trust")).toBeInTheDocument();
    expect(previewOf).toHaveBeenCalledWith(PATH);
    expect(screen.getByText("1 host already has a different trusted key")).toBeInTheDocument();
    expect(screen.getByText(/2 hashed entries match no connection/)).toBeInTheDocument();
    expect(screen.getByText("1 key is marked revoked, and is never trusted.")).toBeInTheDocument();
    expect(screen.getByText("Another key trusted")).toBeInTheDocument();
    expect(importFile).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Trust 2 keys" }));
    await waitFor(() => expect(importFile).toHaveBeenCalledWith(PATH));
    expect(await screen.findByText("2 host keys are trusted now")).toBeInTheDocument();
    expect(
      screen.getByText("1 host kept the key Remoter already trusted."),
    ).toBeInTheDocument();
  });

  it("offers nothing to press when the file holds nothing new", async () => {
    const user = userEvent.setup();
    previewOf.mockResolvedValue(
      preview({ keys: [], total: 0, new: 0, differs: 0, alreadyTrusted: 4, hashedUnmatched: 0, revoked: 0 }),
    );
    draw(<KnownHostsDialog onClose={vi.fn()} />);
    await screen.findByDisplayValue(PATH);
    await user.click(screen.getByRole("button", { name: "Read the file" }));

    expect(
      await screen.findByText("Every key in this file is one Remoter already knows about."),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Trust 0 keys" })).toBeDisabled();
  });

  it("drops the preview when the path changes", async () => {
    const user = userEvent.setup();
    previewOf.mockResolvedValue(preview());
    draw(<KnownHostsDialog onClose={vi.fn()} />);
    const field = await screen.findByDisplayValue(PATH);
    await user.click(screen.getByRole("button", { name: "Read the file" }));
    await screen.findByText("2 host keys to trust");

    await user.type(field, ".old");
    expect(screen.queryByText("2 host keys to trust")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read the file" })).toBeEnabled();
  });
});
