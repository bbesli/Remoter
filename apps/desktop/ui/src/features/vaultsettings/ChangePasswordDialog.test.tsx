/**
 * What the change-password dialog actually sends.
 *
 * The reported defect is a refusal — `SlotCredentialRejected` — for the very
 * password and key file that have the vault open. The core and the IPC command
 * both accept that pair when it is handed to them directly, so what is left is
 * the request this dialog composes. This asserts it field by field, with a
 * Windows path, because that is the shape the owner's key file has.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Slot } from "@/lib/ipc";

import { ChangePasswordDialog } from "./ChangePasswordDialog";

/** What the platform file browser hands back, unchanged. */
const picked = vi.hoisted(() => ({ path: "D:\\Remoter_Vault\\devoplus.keyfile" }));
const KEYFILE = "D:\\Remoter_Vault\\devoplus.keyfile";
const VAULT = "D:\\Remoter_Vault\\devoplus.rvault";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: () => Promise.resolve(picked.path),
}));

const keyfileSlot: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_741_737_600,
  lastUsed: 1_757_462_400,
  requiresKeyfile: true,
  kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
};

function setup(slot: Slot = keyfileSlot) {
  const onConfirm = vi.fn();
  render(
    <ChangePasswordDialog
      slot={slot}
      vaultPath={VAULT}
      busy={false}
      failure={null}
      onConfirm={onConfirm}
      onRetry={vi.fn()}
      onClose={vi.fn()}
    />,
  );
  return { onConfirm, user: userEvent.setup() };
}

describe("the change-password dialog", () => {
  beforeEach(() => {
    picked.path = KEYFILE;
  });

  it("sends the slot's own index, the current password and the current key file", async () => {
    const { onConfirm, user } = setup();

    await user.type(screen.getByLabelText("Current password"), "the-master-password");
    await user.type(screen.getByLabelText("New password"), "the-new-password");
    await user.type(screen.getByLabelText("Repeat the new password"), "the-new-password");

    // Two Browse buttons: the current key file, then the one from now on.
    const browse = screen.getAllByRole("button", { name: "Browse" });
    expect(browse).toHaveLength(2);
    await user.click(browse[0] as HTMLElement);
    await user.click(browse[1] as HTMLElement);

    await user.click(screen.getByRole("button", { name: "Change the password" }));

    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith({
      slotIndex: 0,
      currentPassword: "the-master-password",
      currentKeyfilePath: KEYFILE,
      newPassword: "the-new-password",
      newKeyfilePath: KEYFILE,
    });
  });

  it("will not submit at all until the current key file is chosen", async () => {
    const { onConfirm, user } = setup();

    await user.type(screen.getByLabelText("Current password"), "the-master-password");
    await user.type(screen.getByLabelText("New password"), "the-new-password");
    await user.type(screen.getByLabelText("Repeat the new password"), "the-new-password");

    await user.click(screen.getByRole("button", { name: "Change the password" }));
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
