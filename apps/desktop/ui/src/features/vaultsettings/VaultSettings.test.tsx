/**
 * The screen, wired to a stubbed core.
 *
 * Two things worth holding at this level. The first is the invariant: on a
 * vault with one slot, Remove is disabled and the reason is on the row, before
 * anything is clicked — the core would refuse the command, but by then the
 * user has decided to do it and, if it succeeded, there would be nothing to
 * undo. The second is that a failed read says so with the core's own message
 * instead of quietly rendering defaults, which on this screen would be a claim
 * about who can open the vault.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Slot, VaultSettings as VaultSettingsDto, VaultSlots, VaultState } from "@/lib/ipc";

const vaultState = vi.fn<() => Promise<VaultState>>();
const vaultSlots = vi.fn<() => Promise<VaultSlots>>();
const getVaultSettings = vi.fn<() => Promise<VaultSettingsDto>>();

vi.mock("@/lib/ipc", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...original,
    ipc: {
      ...original.ipc,
      vaultState: () => vaultState(),
      vaultSlots: () => vaultSlots(),
      getVaultSettings: () => getVaultSettings(),
    },
  };
});

const { VaultSettings } = await import("./VaultSettings");

const password: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_741_737_600,
  lastUsed: 1_757_462_400,
  requiresKeyfile: true,
  kdfSummary: "Argon2id, 256 MiB, t=3",
};

const recovery: Slot = {
  index: 1,
  kind: "recovery",
  label: "Recovery key",
  createdAt: 1_741_737_600,
  lastUsed: null,
  requiresKeyfile: false,
  kdfSummary: null,
};

const state: VaultState = {
  unlocked: true,
  path: "/home/alex/vaults/acme.rvault",
  label: "Acme Production",
  connectionCount: 218,
  credentialCount: 40,
  locksInSeconds: 900,
  kdfUpgradeAvailable: false,
};

function view(node: ReactNode) {
  // Retries off: a test asserting on a failure should not wait for three of
  // them, and a stubbed core does not become reachable on a second try.
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

describe("VaultSettings", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vaultState.mockResolvedValue(state);
    getVaultSettings.mockResolvedValue({
      autoLockMinutes: 15,
      lockOnScreenLock: true,
      lockOnSuspend: true,
      lockOnMinimise: false,
      sessionOnLock: "keep_running",
      recording: "on_request",
      backupCount: 3,
    });
  });

  it("lists each slot with its kind, its Argon2id summary and when it was last used", async () => {
    vaultSlots.mockResolvedValue({ slots: [password, recovery], openedWith: 0, backupCount: 3 });
    view(<VaultSettings />);

    expect(await screen.findByText("Master password")).toBeInTheDocument();
    expect(screen.getByText(/Argon2id, 256 MiB, t=3/)).toBeInTheDocument();
    expect(screen.getByText(/Needs its key file too/)).toBeInTheDocument();
    // An unused recovery key is the slot most likely to be lost, so it says so.
    expect(screen.getAllByText(/Never used/).length).toBeGreaterThan(0);
    expect(screen.getByText("never used")).toBeInTheDocument();
    expect(screen.getByText("opened this session")).toBeInTheDocument();
  });

  it("says why the last slot cannot be removed, before it is tried", async () => {
    vaultSlots.mockResolvedValue({ slots: [password], openedWith: 0, backupCount: 1 });
    view(<VaultSettings />);

    expect(await screen.findByText("Master password")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove" })).toBeDisabled();
    expect(screen.getByText(/only way into this vault/)).toBeInTheDocument();
  });

  it("allows a removal once a second slot exists", async () => {
    vaultSlots.mockResolvedValue({ slots: [password, recovery], openedWith: 0, backupCount: 3 });
    view(<VaultSettings />);

    await screen.findByText("Master password");
    for (const button of screen.getAllByRole("button", { name: "Remove" })) {
      expect(button).toBeEnabled();
    }
    expect(screen.queryByText(/only way into this vault/)).toBeNull();
  });

  it("shows the core's message when the slot table cannot be read", async () => {
    vaultSlots.mockRejectedValue({
      code: "vault.locked",
      message: "No vault is open.",
      detail: "The key slots live inside the file.",
      actions: ["Unlock a vault first"],
    });
    view(<VaultSettings />);

    expect(await screen.findByText("No vault is open.")).toBeInTheDocument();
    expect(screen.getByText("Unlock a vault first")).toBeInTheDocument();
  });

  it("switches to auto-lock and shows the stored idle timeout", async () => {
    const user = userEvent.setup();
    vaultSlots.mockResolvedValue({ slots: [password, recovery], openedWith: 0, backupCount: 3 });
    view(<VaultSettings />);

    await screen.findByText("Master password");
    await user.click(screen.getByRole("tab", { name: /auto-lock/i }));

    expect(await screen.findByRole("radio", { name: "15 min" })).toBeChecked();
    // The default, and the sentence that explains it.
    // The radio's accessible name is the whole card: the option and the
    // sentence explaining it, which is the point of the card.
    expect(screen.getByRole("radio", { name: /^Keep them running The default/ })).toBeChecked();
    expect(screen.getByText(/went for coffee/)).toBeInTheDocument();
  });
});
