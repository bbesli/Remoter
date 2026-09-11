/**
 * Randomart is a picture, and a picture that mirrors is a different picture.
 *
 * The art is drawn entirely from bidi-neutral characters — `+`, `-`, `|`, `.`,
 * `o`, `E`, space — so it has no direction of its own and inherits the
 * paragraph's. Inside `dir="rtl"` that reverses every row and right-aligns the
 * box, and the result still looks like plausible randomart. That is precisely
 * the danger: the only thing the user is asked to do with this art is recognise
 * whether it is the same shape they saw last time. If Arabic changes the shape,
 * a changed host key and a rendering artefact become indistinguishable, and the
 * habit the dialog teaches is to ignore the difference.
 *
 * So the assertion is not "the art looks right" — it is that the direction is
 * pinned on the element rather than inherited from whatever is above it.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";

import type { HostKeyPrompt } from "@/lib/ipc";
import { HostKeyDialog } from "./HostKeyDialog";

const OFFERED = "SHA256:8bNc3Xv1QmL6pRt0wZkE9jYdH2sGaF7uT4iO5xP1qA";
const TRUSTED = "SHA256:4tRw9Kp2LmX7bQ0vZnE5cJdHy3sGaF6uT8iO1xP2wM";

const RANDOMART = ["+--[ED25519 256]--+", "|   .o+=*B        |", "+----[SHA256]-----+"].join("\n");

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
    // The changed dialog is the one that matters most here: it puts the two
    // pictures side by side and asks the user to compare them.
    confirmationLen: 8,
  };
}

function renderDialog(prompt: HostKeyPrompt) {
  render(
    <HostKeyDialog
      prompt={prompt}
      sessionName="db-01"
      busy={false}
      failure={null}
      onAccept={vi.fn()}
      onReplace={vi.fn()}
      onReject={vi.fn()}
    />,
  );
}

beforeEach(() => {
  document.documentElement.setAttribute("dir", "rtl");
});

afterEach(() => {
  document.documentElement.removeAttribute("dir");
});

describe("the host key dialog in a right-to-left interface", () => {
  it("keeps every randomart box left-to-right", () => {
    renderDialog(changedPrompt());

    // The dialog itself is mirrored — that part is correct and stays correct.
    // A changed key is an `alertdialog`; see HostKeyDialog.test.tsx for why.
    const dialog = screen.getByRole("alertdialog");
    expect(getComputedStyle(dialog).direction).toBe("rtl");

    // Both boxes: the key offered now and the one trusted before it. Comparing
    // a mirrored picture against an unmirrored one would be worse than
    // mirroring neither.
    const boxes = screen.getAllByText(/ED25519 256/);
    expect(boxes.length).toBe(2);
    for (const box of boxes) {
      expect(getComputedStyle(box).direction).toBe("ltr");
      // `pre` stops the rows re-wrapping; `direction` stops them re-ordering.
      // Neither implies the other, so a regression in either is a regression.
      expect(getComputedStyle(box).whiteSpace).toBe("pre");
    }
  });

  it("keeps both fingerprints left-to-right", () => {
    renderDialog(changedPrompt());

    // Base64 is strongly LTR, so the digits survive on content alone; the
    // `SHA256:` colon and any `=` padding are neutral and do not.
    for (const text of [OFFERED, TRUSTED]) {
      expect(getComputedStyle(screen.getByText(text)).direction).toBe("ltr");
    }
  });
});
