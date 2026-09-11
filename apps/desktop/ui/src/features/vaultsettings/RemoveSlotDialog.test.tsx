/**
 * The confirmation that has to be typed.
 *
 * key-management.md: removing the recovery slot needs an explicit "I
 * understand this removes my last resort". This holds the two halves of that —
 * the button refuses until the sentence is right, and it stays refused when
 * the slot is the last one whatever is typed — because both are one boolean
 * away from being wrong, and the second one has no undo.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { Slot } from "@/lib/ipc";

import { i18n } from "@/i18n";

import { RemoveSlotDialog } from "./RemoveSlotDialog";
import { lastResortPhrase } from "./slots";

/** The sentence the dialog renders, read from the same catalogue it reads. */
const LAST_RESORT_PHRASE = lastResortPhrase(i18n().getFixedT(null, "vaultsettings"));

const recoverySlot: Slot = {
  index: 1,
  kind: "recovery",
  label: "Recovery key",
  createdAt: 1_741_737_600,
  lastUsed: null,
  requiresKeyfile: false,
  kdf: null,
};

const passwordSlot: Slot = {
  index: 0,
  kind: "password",
  label: "Master password",
  createdAt: 1_741_737_600,
  lastUsed: 1_757_462_400,
  requiresKeyfile: true,
  // What the core actually sends: the cost as numbers. 262 144 KiB is the
  // 256 MiB floor in `KdfParams::FLOOR_M_COST`.
  kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
};

function setup(props: Partial<Parameters<typeof RemoveSlotDialog>[0]> = {}) {
  const onConfirm = vi.fn();
  render(
    <RemoveSlotDialog
      slot={recoverySlot}
      refusal={null}
      warning={null}
      busy={false}
      failure={null}
      onConfirm={onConfirm}
      onRetry={vi.fn()}
      onClose={vi.fn()}
      {...props}
    />,
  );
  return { onConfirm, remove: screen.getByRole("button", { name: /remove the slot/i }) };
}

describe("RemoveSlotDialog", () => {
  it("refuses to remove a recovery slot until the sentence is typed", async () => {
    const user = userEvent.setup();
    const { onConfirm, remove } = setup();

    expect(remove).toBeDisabled();

    await user.type(screen.getByRole("textbox"), "yes");
    expect(remove).toBeDisabled();

    await user.clear(screen.getByRole("textbox"));
    await user.type(screen.getByRole("textbox"), LAST_RESORT_PHRASE);
    expect(remove).toBeEnabled();

    await user.click(remove);
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it("asks for no sentence on a slot that is not the last resort", () => {
    const { remove } = setup({ slot: passwordSlot });
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(remove).toBeEnabled();
  });

  it("keeps the last slot unremovable however the dialog is filled in", async () => {
    const user = userEvent.setup();
    const refusal = "This is the only way into this vault.";
    const { onConfirm, remove } = setup({ refusal });

    expect(screen.getByText(refusal)).toBeInTheDocument();
    // The sentence field is not even offered: there is no answer that unlocks
    // this button, and a field implying otherwise would be a lie.
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(remove).toBeDisabled();

    await user.click(remove);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("shows the core's message when the removal fails", () => {
    setup({
      failure: {
        code: "vault.last-slot",
        message: "This is the only slot left on this vault.",
        detail: "Removing it would leave a file nobody can open.",
        actions: ["Add another slot first"],
      },
    });

    expect(screen.getByText("This is the only slot left on this vault.")).toBeInTheDocument();
    expect(screen.getByText("Add another slot first")).toBeInTheDocument();
  });
});
