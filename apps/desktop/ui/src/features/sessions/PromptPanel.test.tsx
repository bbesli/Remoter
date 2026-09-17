/**
 * The two dialogs a connect attempt can stop at: a certificate decision, and a
 * question answered by typing.
 *
 * The certificate dialog is the one an RDP session against a default Windows
 * host stops at.
 *
 * Before this existed the certificate question had one control on it — Cancel —
 * so the protocol worked, the picture worked, and nobody could open a session.
 * These tests pin the two halves of the fix, and they are not the same half:
 *
 * - there **is** a way to say yes to a first use, and
 * - there is **no** way to say yes to anything else.
 *
 * The second is the one that rots. A later change that made the accept button
 * unconditional would pass every test about the first and would quietly turn
 * this into a dialog that trusts whatever answered the port.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import type { SessionPrompt } from "@/lib/ipc";
import { PromptPanel } from "./PromptPanel";
import { newTabId, useSessions, type SessionRecord } from "./store";

const decideHostKey = vi.fn();
const cancelConnect = vi.fn();
const answerPrompt = vi.fn();

vi.mock("./manager", () => ({
  decideHostKey: (...args: unknown[]) => decideHostKey(...args),
  cancelConnect: (...args: unknown[]) => cancelConnect(...args),
  answerPrompt: (...args: unknown[]) => answerPrompt(...args),
}));

const FINGERPRINT = "SHA256:8bNc3Xv1QmL6pRt0wZkE9jYdH2sGaF7uT4iO5xP1qA";

function certificate(overrides: Partial<SessionPrompt> = {}): SessionPrompt {
  return {
    promptId: 4,
    kind: "certificate",
    text: "10.0.0.5:3389",
    echo: true,
    fingerprint: FINGERPRINT,
    reason: "self-signed",
    instruction: null,
    ...overrides,
  };
}

function recordFor(prompt: SessionPrompt): SessionRecord {
  const tabId = newTabId();
  useSessions.getState().open({
    tabId,
    nodeId: "node-1",
    name: "ts-01",
    colour: null,
    protocol: "rdp",
    target: "10.0.0.5:3389",
  });
  useSessions.getState().patch(tabId, { sessionId: 1, phase: "verifying", prompt });
  const record = useSessions.getState().byId[tabId];
  if (record === undefined) throw new Error("the seeded tab was not in the store");
  return record;
}

beforeEach(() => {
  decideHostKey.mockClear();
  cancelConnect.mockClear();
  answerPrompt.mockClear();
});

describe("a first-use certificate", () => {
  it("can be accepted, which is the whole reason this dialog exists", async () => {
    const user = userEvent.setup();
    render(<PromptPanel record={recordFor(certificate())} />);

    await user.click(screen.getByRole("button", { name: /trust this certificate/i }));
    expect(decideHostKey).toHaveBeenCalledTimes(1);
    expect(decideHostKey.mock.calls[0]?.[1]).toEqual({ decision: "accept", promptId: 4 });
  });

  it("shows the fingerprint it is asking to be compared", () => {
    render(<PromptPanel record={recordFor(certificate())} />);
    expect(screen.getByText(FINGERPRINT)).toBeInTheDocument();
  });

  it("declines through the core rather than by abandoning the tab", async () => {
    // A rejection is an answer: the core is suspended on the question and the
    // adapter reads anything that is not `yes` as a no, which ends the attempt
    // with a certificate failure the user can read. Killing the tab instead
    // would leave the far end waiting.
    const user = userEvent.setup();
    render(<PromptPanel record={recordFor(certificate())} />);

    await user.click(screen.getByRole("button", { name: /do not connect/i }));
    expect(decideHostKey.mock.calls[0]?.[1]).toEqual({ decision: "reject", promptId: 4 });
    expect(cancelConnect).not.toHaveBeenCalled();
  });
});

describe("a certificate that is not a first use", () => {
  it("offers no accept when the core sent no fingerprint to compare", () => {
    render(<PromptPanel record={recordFor(certificate({ fingerprint: null }))} />);

    expect(screen.queryByRole("button", { name: /trust this certificate/i })).toBeNull();
    expect(screen.getByRole("button", { name: /do not connect/i })).toBeInTheDocument();
  });

  it("offers no accept for one that contradicts a pinned certificate", () => {
    // This should never arrive here at all — the adapter raises a changed
    // certificate as a host key prompt, which is the shape that can show both
    // fingerprints. If it ever did, it must not be acceptable the way a first
    // use is.
    render(<PromptPanel record={recordFor(certificate({ reason: "changed" }))} />);
    expect(screen.queryByRole("button", { name: /trust this certificate/i })).toBeNull();
  });

  it("offers no accept for a revoked certificate", () => {
    render(<PromptPanel record={recordFor(certificate({ reason: "revoked" }))} />);
    expect(screen.queryByRole("button", { name: /trust this certificate/i })).toBeNull();
  });

  it("offers no accept for a reason this build has no sentence for", () => {
    render(<PromptPanel record={recordFor(certificate({ reason: "some-new-problem" }))} />);

    expect(screen.queryByRole("button", { name: /trust this certificate/i })).toBeNull();
    // Named rather than hidden, so a bug report can quote it.
    expect(screen.getByText(/some-new-problem/)).toBeInTheDocument();
  });
});

function typed(overrides: Partial<SessionPrompt> = {}): SessionPrompt {
  return {
    promptId: 2,
    kind: "password",
    text: "10.0.0.5:3389",
    echo: false,
    fingerprint: null,
    reason: null,
    instruction: null,
    ...overrides,
  };
}

describe("a question answered by typing", () => {
  it("sends what was typed for a password, and keeps nothing of it on screen", async () => {
    const user = userEvent.setup();
    const record = recordFor(typed());
    render(<PromptPanel record={record} />);

    const field = screen.getByLabelText("Password");
    // The server marked it secret, so it is a password field.
    expect(field).toHaveAttribute("type", "password");
    expect(screen.getByRole("button", { name: "Continue" })).toBeDisabled();

    await user.type(field, "zzq-typed-secret");
    await user.click(screen.getByRole("button", { name: "Continue" }));

    expect(answerPrompt).toHaveBeenCalledWith(record.tabId, 2, {
      response: "answer",
      value: "zzq-typed-secret",
    });
    expect(field).toHaveValue("");
    // Nothing offers a trust decision on a password question.
    expect(screen.queryByRole("button", { name: /trust/i })).toBeNull();
    expect(decideHostKey).not.toHaveBeenCalled();
  });

  it("reveals a secret answer only when asked, and submits on Enter", async () => {
    const user = userEvent.setup();
    const record = recordFor(typed({ kind: "key_passphrase", text: "" }));
    render(<PromptPanel record={record} />);

    expect(screen.getByRole("heading", { name: "Unlock the private key" })).toBeInTheDocument();
    const field = screen.getByLabelText("Passphrase");
    await user.click(screen.getByRole("button", { name: "Show" }));
    expect(field).toHaveAttribute("type", "text");

    await user.type(field, "correct horse{Enter}");
    expect(answerPrompt).toHaveBeenCalledWith(record.tabId, 2, {
      response: "answer",
      value: "correct horse",
    });
  });

  it("shows a keyboard-interactive question and its instruction as the server's words", async () => {
    const user = userEvent.setup();
    const record = recordFor(
      typed({
        kind: "keyboard_interactive",
        text: "Verification code:",
        echo: true,
        instruction: "<b>Two-factor</b> required",
      }),
    );
    render(<PromptPanel record={record} />);

    // Text, not markup: the angle brackets are on screen as they were sent.
    expect(screen.getByText(/<b>Two-factor<\/b> required/)).toBeInTheDocument();
    expect(screen.getByText(/Verification code:/)).toBeInTheDocument();
    const field = screen.getByLabelText("Answer");
    expect(field).toHaveAttribute("type", "text");
    expect(screen.queryByRole("button", { name: "Show" })).toBeNull();

    await user.type(field, "482913");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    expect(answerPrompt).toHaveBeenCalledWith(record.tabId, 2, {
      response: "answer",
      value: "482913",
    });
  });

  it("cancels through the core, from the button and from Escape", async () => {
    const user = userEvent.setup();
    const record = recordFor(typed());
    render(<PromptPanel record={record} />);

    await user.click(screen.getByRole("button", { name: /cancel the attempt/i }));
    expect(answerPrompt).toHaveBeenLastCalledWith(record.tabId, 2, { response: "cancel" });

    await user.keyboard("{Escape}");
    expect(answerPrompt).toHaveBeenCalledTimes(2);
    expect(cancelConnect).not.toHaveBeenCalled();
  });
});
