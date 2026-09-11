/**
 * The warnings, on screen.
 *
 * `store.ts` collected these from the day the session feature was written and
 * nothing drew them. These tests are what stops that happening again: the most
 * important one asserts that a warning saying a session is unauthenticated
 * cannot be folded out of sight.
 */

import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { SessionWarnings } from "./SessionWarnings";
import type { SessionRecord, SessionWarning } from "./store";

function record(warnings: SessionWarning[]): SessionRecord {
  return {
    tabId: "t1",
    nodeId: "n1",
    name: "ctso-dc01",
    colour: null,
    protocol: "vnc",
    target: "ctso-dc01.internal:5900",
    sessionId: 1,
    phase: "running",
    opened: null,
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    inputError: null,
    warnings,
    metrics: { bytesIn: 0, bytesOut: 0, cols: 0, rows: 0, echoMs: null },
    renderer: null,
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
  };
}

function warning(kind: string, detail: string | null = null): SessionWarning {
  return { kind, detail, at: 0 };
}

afterEach(cleanup);

describe("SessionWarnings", () => {
  it("draws nothing when the session warned about nothing", () => {
    const { container } = render(<SessionWarnings record={record([])} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders what the adapter actually raised", () => {
    render(<SessionWarnings record={record([warning("other", "vnc.security.none")])} />);
    expect(screen.getByText(/asked for no authentication at all/i)).toBeInTheDocument();
  });

  it("will not let an unauthenticated session be folded away", () => {
    // A warning hidden behind a control the user pressed once is a warning that
    // was not shown.
    render(<SessionWarnings record={record([warning("other", "vnc.security.none")])} />);
    expect(screen.queryByRole("button", { name: /hide/i })).toBeNull();
  });

  it("folds the unremarkable ones away on request", async () => {
    const user = userEvent.setup();
    render(<SessionWarnings record={record([warning("other", "vnc.bell")])} />);

    expect(screen.getByText(/rang its bell/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /hide/i }));
    expect(screen.queryByText(/rang its bell/i)).toBeNull();
  });

  it("shows a login banner as the server's own text, not as part of a sentence", () => {
    const banner = "Authorised users only\nAll access is logged";
    render(<SessionWarnings record={record([warning("banner", banner)])} />);

    const block = screen.getByText(/Authorised users only/);
    // A <pre>, so the server's own line breaks survive and nothing in it is
    // interpreted. It is not spliced into the introducing sentence.
    expect(block.tagName).toBe("PRE");
    expect(block.textContent).toBe(banner);
  });

  it("names a warning it has no wording for rather than swallowing it", () => {
    render(<SessionWarnings record={record([warning("other", "rdp.something.new")])} />);
    expect(screen.getByText(/rdp\.something\.new/)).toBeInTheDocument();
  });

  it("counts them, and puts the newest first", () => {
    render(
      <SessionWarnings
        record={record([warning("other", "vnc.bell"), warning("output_throttled")])}
      />,
    );
    expect(screen.getByText(/2 notices from this session/i)).toBeInTheDocument();
    const texts = screen.getAllByRole("listitem").map((item) => item.textContent ?? "");
    expect(texts[0]).toMatch(/sending faster/i);
  });
});
