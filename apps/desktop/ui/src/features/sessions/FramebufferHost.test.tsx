/**
 * What the graphical session surface promises, and what it admits.
 *
 * The assertions that matter most here are the negative ones. This build
 * renders a remote desktop and cannot send anything to it, so the one thing the
 * surface must never do is look like a session the user is driving. A test that
 * only checked the scale buttons would pass on an interface that quietly
 * swallowed every keystroke.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import type { SessionOpened } from "@/lib/ipc";
import { FramebufferHost } from "./FramebufferHost";
import { useSessions, type SessionRecord } from "./store";

vi.mock("./manager", () => ({ requestDesktopSize: vi.fn() }));

function opened(resizable: boolean): SessionOpened {
  return {
    sessionId: 1,
    nodeId: "n1",
    name: "ctso-dc01",
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    username: "svc-deploy",
    authMethod: "password",
    via: [],
    capabilities: {
      kind: "framebuffer",
      resizable,
      clipboard: "none",
      fileTransfer: false,
      audio: false,
      printing: false,
      multiMonitor: false,
      recordable: true,
    },
    startedAtMs: Date.now(),
    recording: "never",
  };
}

function record(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    tabId: "t1",
    nodeId: "n1",
    name: "ctso-dc01",
    colour: null,
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    sessionId: 1,
    phase: "running",
    opened: opened(true),
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    inputError: null,
    warnings: [],
    metrics: { bytesIn: 0, bytesOut: 0, cols: 0, rows: 0, echoMs: null },
    renderer: null,
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
    ...overrides,
  };
}

beforeEach(() => {
  useSessions.setState({ order: ["t1"], byId: { t1: record() }, activeTabId: "t1" });
});

afterEach(() => {
  cleanup();
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("the framebuffer surface", () => {
  it("says plainly that nothing typed or clicked reaches the desktop", () => {
    render(<FramebufferHost record={record()} active />);
    expect(screen.getByText(/nothing you type or click reaches this desktop/i)).toBeInTheDocument();
    expect(screen.getByText(/no way to send keyboard or pointer events/i)).toBeInTheDocument();
  });

  it("says the picture is live, so the surface does not read as frozen", () => {
    render(<FramebufferHost record={record()} active />);
    expect(screen.getByText(/the picture is live/i)).toBeInTheDocument();
  });

  it("gives the remote screen an accessible name", () => {
    render(<FramebufferHost record={record()} active />);
    expect(screen.getByRole("img", { name: /remote screen for/i })).toBeInTheDocument();
  });

  it("looks view-only, not merely labelled view-only, when it is", () => {
    render(<FramebufferHost record={record({ viewOnly: true })} active />);
    expect(screen.getByText("view only")).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /remote screen for/i })).toHaveAttribute(
      "data-view-only",
      "true",
    );
  });

  it("does not claim view-only on a session it has not read the setting for", () => {
    render(<FramebufferHost record={record({ viewOnly: null })} active />);
    expect(screen.queryByText("view only")).toBeNull();
  });

  it("offers smart resize only where the session says it is resizable", async () => {
    render(<FramebufferHost record={record()} active />);
    expect(screen.getByRole("button", { name: "Smart" })).toBeInTheDocument();
    cleanup();

    // A server that never opened the Display Control channel: the button would
    // do nothing, so it is not drawn.
    render(<FramebufferHost record={record({ opened: opened(false) })} active />);
    expect(screen.queryByRole("button", { name: "Smart" })).toBeNull();
    await Promise.resolve();
  });

  it("says which scale is in force, in words a screen reader gets too", async () => {
    const user = userEvent.setup();
    render(<FramebufferHost record={record()} active />);

    expect(screen.getByRole("button", { name: "Fit" })).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("button", { name: "1:1" }));
    expect(useSessions.getState().byId.t1?.scale).toEqual({ mode: "actual", zoom: 2 });
  });

  it("offers whole-number magnifications only", () => {
    render(<FramebufferHost record={record()} active />);
    // 2x, 3x, 4x and nothing between: a fractional zoom mixes each glyph's stem
    // across two output pixels, which is the mush this refuses to produce.
    for (const factor of ["2×", "3×", "4×"]) {
      expect(screen.getByRole("button", { name: factor })).toBeInTheDocument();
    }
    expect(screen.queryByRole("button", { name: "1.5×" })).toBeNull();
  });

  it("says it is waiting rather than showing an unexplained empty rectangle", () => {
    render(<FramebufferHost record={record()} active />);
    expect(screen.getByText(/waiting for the first frame/i)).toBeInTheDocument();
  });

  it("draws no chrome on a tab that is not in front", () => {
    // The canvas stays laid out — it is measured — but a background tab must
    // not put a second set of scale controls in the accessibility tree.
    render(<FramebufferHost record={record()} active={false} />);
    expect(screen.queryByRole("button", { name: "Fit" })).toBeNull();
  });
});
