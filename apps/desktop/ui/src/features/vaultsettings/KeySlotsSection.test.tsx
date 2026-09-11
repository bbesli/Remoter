/**
 * The last link in the change-password chain: what the screen hands the core.
 *
 * The dialog composes the request and the command accepts it; this is the
 * staging and wiring in between, which is the only place left where a field
 * could be dropped between the form and `invoke`. The request is asserted
 * whole, because the failure being chased is a slot refusing the credential
 * that opens it — and a dropped key file looks exactly like a wrong password.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { ChangePassword, Slot, VaultSlots } from "@/lib/ipc";

const KEYFILE = "D:\\Remoter_Vault\\devoplus.keyfile";
const VAULT = "D:\\Remoter_Vault\\devoplus.rvault";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: () => Promise.resolve("D:\\Remoter_Vault\\devoplus.keyfile"),
}));

const changeMasterPassword = vi.fn<(req: ChangePassword) => Promise<void>>();

vi.mock("@/lib/ipc", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...original,
    ipc: {
      ...original.ipc,
      changeMasterPassword: (req: ChangePassword) => changeMasterPassword(req),
    },
  };
});

const { KeySlotsSection } = await import("./KeySlotsSection");

const password: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_741_737_600,
  lastUsed: 1_757_462_400,
  requiresKeyfile: true,
  kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
};

const recovery: Slot = {
  index: 1,
  kind: "recovery",
  label: "Recovery key",
  createdAt: 1_741_737_600,
  lastUsed: null,
  requiresKeyfile: false,
  kdf: null,
};

const slots: VaultSlots = {
  slots: [password, recovery],
  openedWith: 0,
  backupCount: 3,
};

function view(node: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{node}</QueryClientProvider>);
}

describe("changing a password from the slot list", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    changeMasterPassword.mockResolvedValue(undefined);
  });

  it("hands the core the slot's index, the current password and the current key file", async () => {
    const user = userEvent.setup();
    view(<KeySlotsSection vaultSlots={slots} vaultPath={VAULT} kdf={password.kdf} />);

    await user.click(screen.getByRole("button", { name: "Change" }));

    await user.type(screen.getByLabelText("Current password"), "the-master-password");
    await user.type(screen.getByLabelText("New password"), "the-new-password");
    await user.type(screen.getByLabelText("Repeat the new password"), "the-new-password");

    const browse = screen.getAllByRole("button", { name: "Browse" });
    await user.click(browse[0] as HTMLElement);
    await user.click(browse[1] as HTMLElement);

    await user.click(screen.getByRole("button", { name: "Change the password" }));

    expect(changeMasterPassword).toHaveBeenCalledTimes(1);
    expect(changeMasterPassword).toHaveBeenCalledWith({
      slotIndex: 0,
      currentPassword: "the-master-password",
      currentKeyfilePath: KEYFILE,
      newPassword: "the-new-password",
      newKeyfilePath: KEYFILE,
    });
  });
});
