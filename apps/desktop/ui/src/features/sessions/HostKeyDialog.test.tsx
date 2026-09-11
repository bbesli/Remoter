/**
 * The one rule this dialog exists to keep: a changed host key is not an
 * unknown one, and no path through the interface can make it look like one.
 *
 * The core refuses `accept` on a changed prompt, so a dialog that offered the
 * button would produce a refusal the user cannot act on — and, worse, would
 * train them that the alarming dialog is answered with the same click as the
 * calm one. These tests pin that the two renderings differ in the ways that
 * matter: the control, the friction, and the information.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import type { HostKeyPrompt } from "@/lib/ipc";
import { HostKeyDialog } from "./HostKeyDialog";

const OFFERED = "SHA256:8bNc3Xv1QmL6pRt0wZkE9jYdH2sGaF7uT4iO5xP1qA";
const TRUSTED = "SHA256:4tRw9Kp2LmX7bQ0vZnE5cJdHy3sGaF6uT8iO1xP2wM";

const RANDOMART = ["+--[ED25519 256]--+", "|   .o+=*B        |", "+----[SHA256]-----+"].join("\n");

function unknownPrompt(): HostKeyPrompt {
  return {
    promptId: 7,
    host: "10.0.0.5:2222",
    algorithm: "ssh-ed25519",
    fingerprint: OFFERED,
    randomart: RANDOMART,
    status: "unknown",
    previouslyTrusted: null,
    confirmationLen: null,
  };
}

function changedPrompt(): HostKeyPrompt {
  return {
    promptId: 9,
    host: "db-01.internal:22",
    algorithm: "ssh-ed25519",
    fingerprint: OFFERED,
    randomart: RANDOMART,
    status: "changed",
    previouslyTrusted: {
      fingerprint: TRUSTED,
      randomart: RANDOMART,
      firstTrustedAtMs: Date.UTC(2026, 2, 12),
    },
    confirmationLen: 8,
  };
}

function renderDialog(prompt: HostKeyPrompt, handlers: Partial<Record<string, () => void>> = {}) {
  const onAccept = vi.fn();
  const onReplace = vi.fn();
  const onReject = vi.fn();
  render(
    <HostKeyDialog
      prompt={prompt}
      sessionName="db-01"
      busy={false}
      failure={null}
      onAccept={handlers.onAccept ?? onAccept}
      onReplace={onReplace}
      onReject={handlers.onReject ?? onReject}
    />,
  );
  return { onAccept, onReplace, onReject };
}

describe("the unknown host key dialog", () => {
  it("shows the fingerprint, the randomart and the algorithm", () => {
    renderDialog(unknownPrompt());

    expect(screen.getByText(OFFERED)).toBeInTheDocument();
    expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
    expect(screen.getByText(/ED25519 256/)).toBeInTheDocument();
  });

  it("accepts with one explicit press, and asks for nothing typed", async () => {
    const user = userEvent.setup();
    const { onAccept } = renderDialog(unknownPrompt());

    expect(screen.queryByRole("textbox")).toBeNull();
    await user.click(screen.getByRole("button", { name: /trust this key/i }));
    expect(onAccept).toHaveBeenCalledTimes(1);
  });
});

describe("the changed host key dialog", () => {
  it("offers no way to accept it the way an unknown key is accepted", () => {
    renderDialog(changedPrompt());

    // The word the calm dialog uses must not appear on this one at all.
    expect(screen.queryByRole("button", { name: /trust this key/i })).toBeNull();
    for (const button of screen.getAllByRole("button")) {
      expect(button.textContent ?? "").not.toMatch(/^Trust/);
    }
    expect(screen.getByRole("button", { name: /replace the key/i })).toBeInTheDocument();
  });

  it("announces itself as an alert, not as an ordinary dialog", () => {
    renderDialog(changedPrompt());
    expect(screen.getByRole("alertdialog")).toBeInTheDocument();
  });

  it("shows both fingerprints and when the old one was trusted", () => {
    renderDialog(changedPrompt());

    expect(screen.getByText(TRUSTED)).toBeInTheDocument();
    expect(screen.getByText(OFFERED)).toBeInTheDocument();
    expect(screen.getByText(/Verified/)).toBeInTheDocument();
  });

  it("says plainly that this may be interception or a rebuilt server", () => {
    renderDialog(changedPrompt());
    expect(screen.getByText(/intercepting this connection/i)).toBeInTheDocument();
    expect(screen.getByText(/rebuilt/i)).toBeInTheDocument();
  });

  it("keeps replace refused until the confirmation is the length the core asked for", async () => {
    const user = userEvent.setup();
    const { onReplace } = renderDialog(changedPrompt());

    const replace = screen.getByRole("button", { name: /replace the key/i });
    expect(replace).toBeDisabled();

    const field = screen.getByRole("textbox");
    await user.type(field, "8bNc");
    expect(replace).toBeDisabled();

    await user.type(field, "3Xv1");
    expect(replace).toBeEnabled();
    await user.click(replace);
    expect(onReplace).toHaveBeenCalledWith("8bNc3Xv1");
  });

  it("never pre-fills the confirmation from the prompt", () => {
    renderDialog(changedPrompt());
    expect(screen.getByRole("textbox")).toHaveValue("");
  });
});

describe("both dialogs", () => {
  it("take Escape as a rejection", async () => {
    const user = userEvent.setup();
    const { onReject } = renderDialog(changedPrompt());

    await user.keyboard("{Escape}");
    expect(onReject).toHaveBeenCalledTimes(1);
  });

  it("move focus inside on open", () => {
    renderDialog(unknownPrompt());
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("register as a modal so global shortcuts stand down", async () => {
    const { useApp } = await import("@/stores/app");
    renderDialog(unknownPrompt());
    expect(useApp.getState().openModals.size).toBeGreaterThan(0);
  });
});
