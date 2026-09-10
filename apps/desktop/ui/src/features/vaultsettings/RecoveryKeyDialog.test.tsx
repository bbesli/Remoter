/**
 * The transcription check on a rotated recovery key.
 *
 * A rotated key is shown exactly once and nothing can reissue it, so the two
 * behaviours pinned here are the ones that prevent the loss: the way out stays
 * shut until the nominated group has been retyped, and Escape does not close
 * the dialog — it answers instead. Everywhere else in the application Escape
 * cancels a modal, which is exactly why this exception needs a test.
 */

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { RecoveryKey } from "@/lib/ipc";

import { RecoveryKeyDialog } from "./RecoveryKeyDialog";

const key: RecoveryKey = {
  slotIndex: 1,
  recoveryKeyGroups: [
    "A1B2",
    "C3D4",
    "E5F6",
    "G7H8",
    "J9K0",
    "M1N2",
    "P3Q4",
    "R5S6",
    "T7V8",
    "W9X0",
    "Y1Z2",
    "A3B4",
    "C5D6",
    "E7F8",
  ],
  confirmGroupIndex: 2,
};

function setup() {
  const onDone = vi.fn();
  render(
    <RecoveryKeyDialog
      recoveryKey={key}
      vaultPath="/home/alex/vaults/acme.rvault"
      kdfSummary="Argon2id, 256 MiB, t=3"
      onDone={onDone}
    />,
  );
  return { onDone };
}

describe("RecoveryKeyDialog", () => {
  it("holds the way out shut until the nominated group is retyped", async () => {
    const user = userEvent.setup();
    const { onDone } = setup();

    const done = screen.getByRole("button", { name: /i have saved it/i });
    expect(done).toBeDisabled();

    // The wrong group: it is on screen, so a user who is not reading could
    // easily type it.
    await user.type(screen.getByRole("textbox"), "A1B2");
    expect(done).toBeDisabled();

    await user.clear(screen.getByRole("textbox"));
    // Case and the presentation hyphen are forgiven; the group is not.
    await user.type(screen.getByRole("textbox"), "e5f6");
    expect(screen.getByRole("button", { name: /i have saved it/i })).toBeEnabled();

    await user.click(screen.getByRole("button", { name: /i have saved it/i }));
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it("does not close on Escape, and says why", async () => {
    const user = userEvent.setup();
    const { onDone } = setup();

    await user.keyboard("{Escape}");

    expect(onDone).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    // The dialog's own answer to the press, not the panel's standing warning:
    // both say "shown once", and only one of them is the refusal.
    expect(screen.getByText(/closing without recording it/i)).toBeInTheDocument();
  });

  it("shows every group of the key", () => {
    setup();
    for (const group of key.recoveryKeyGroups) {
      expect(screen.getByText(group)).toBeInTheDocument();
    }
  });
});
