/**
 * Giving an existing vault a key file it does not have yet, by generating one.
 *
 * The owner's case, exactly: a vault created with the wizard's default — no key
 * file — whose password slot should now need one. Before this there was only
 * Browse, which assumes a key file already exists somewhere. Every assertion is
 * on what the dialog finally sends or what the core was asked to write.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Slot } from "@/lib/ipc";

const dialog = vi.hoisted(() => ({
  saveTo: null as string | null,
  offered: [] as (string | undefined)[],
}));

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: () => Promise.resolve(null),
  save: (options: { defaultPath?: string }) => {
    dialog.offered.push(options.defaultPath);
    return Promise.resolve(dialog.saveTo);
  },
}));

const generateKeyfile = vi.hoisted(() => vi.fn<(path: string) => Promise<void>>());
vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: { ...actual.ipc, generateKeyfile } };
});

import { ChangePasswordDialog } from "./ChangePasswordDialog";

const VAULT = "D:\\Remoter_Vault\\devoplus.rvault";
const ON_A_USB_KEY = "E:\\keys\\devoplus.keyfile";

const passwordOnly: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_741_737_600,
  lastUsed: 1_757_462_400,
  requiresKeyfile: false,
  kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
};

function setup(slot: Slot = passwordOnly) {
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

async function fillPasswords(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Current password"), "the-master-password");
  await user.type(screen.getByLabelText("New password"), "the-new-password");
  await user.type(screen.getByLabelText("Repeat the new password"), "the-new-password");
}

beforeEach(() => {
  dialog.saveTo = ON_A_USB_KEY;
  dialog.offered = [];
  generateKeyfile.mockReset().mockResolvedValue(undefined);
});

describe("generating a key file for a slot that has none", () => {
  it("writes a new key file and makes the slot need it from now on", async () => {
    const { onConfirm, user } = setup();
    await fillPasswords(user);

    await user.click(screen.getByRole("button", { name: "Generate…" }));

    await waitFor(() => expect(generateKeyfile).toHaveBeenCalledWith(ON_A_USB_KEY));
    // Named after the vault, in the vault's folder, as a starting point.
    expect(dialog.offered).toEqual(["D:\\Remoter_Vault\\devoplus.keyfile"]);
    expect(await screen.findByText(/A new key file was written there/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Change the password" }));
    expect(onConfirm).toHaveBeenCalledWith(
      expect.objectContaining({ slotIndex: 0, newKeyfilePath: ON_A_USB_KEY }),
    );
  });

  it("warns, without refusing, when the new key file lands beside the vault", async () => {
    dialog.saveTo = "D:\\Remoter_Vault\\devoplus.keyfile";
    const { user } = setup();

    await user.click(screen.getByRole("button", { name: "Generate…" }));

    expect(await screen.findByText(/stops being a second factor/)).toBeInTheDocument();
  });

  it("will not write a key file over the vault itself", async () => {
    dialog.saveTo = VAULT;
    const { user } = setup();

    await user.click(screen.getByRole("button", { name: "Generate…" }));

    await waitFor(() => expect(dialog.offered).toHaveLength(1));
    expect(generateKeyfile).not.toHaveBeenCalled();
  });

  it("shows the core's refusal and keeps the slot as it was when the file cannot be written", async () => {
    generateKeyfile.mockRejectedValue({
      code: "io.already-exists",
      message: "A file already exists there, and a key file is never written over one.",
      detail: null,
      actions: [],
    });
    const { onConfirm, user } = setup();
    await fillPasswords(user);

    await user.click(screen.getByRole("button", { name: "Generate…" }));

    expect(await screen.findByText("The key file could not be written")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Change the password" }));
    expect(onConfirm).toHaveBeenCalledWith(expect.objectContaining({ newKeyfilePath: null }));
  });

  it("does nothing when the save dialog is cancelled", async () => {
    dialog.saveTo = null;
    const { user } = setup();

    await user.click(screen.getByRole("button", { name: "Generate…" }));

    await waitFor(() => expect(dialog.offered).toHaveLength(1));
    expect(generateKeyfile).not.toHaveBeenCalled();
  });

  it("offers no Generate beside the key file a slot already needs, which no new file could be", () => {
    setup({ ...passwordOnly, requiresKeyfile: true });
    // Two key file fields — the current one and the one from now on — and only
    // the second can be generated.
    expect(screen.getAllByRole("button", { name: "Browse" })).toHaveLength(2);
    expect(screen.getAllByRole("button", { name: "Generate…" })).toHaveLength(1);
  });
});
