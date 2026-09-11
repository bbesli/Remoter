/**
 * The route into the file manager for a session that already has a shell.
 *
 * The whole SFTP file manager shipped as zero bytes once, because it was
 * exported and never imported: there was no control anywhere that reached it.
 * These tests pin the control — that it exists, that it is enabled exactly
 * where a pane can actually be opened, that a refusal says which refusal it is,
 * and that pressing it records the tab so the window mounts a dock for it.
 *
 * They do not test what the pane then draws; `filePanes.test.ts` covers the
 * rule and `RemotePane.rtl.test.tsx` covers the listing. What is pinned here is
 * reachability.
 */

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useSessions, type SessionRecord } from "@/features/sessions";
import type { Capabilities, SessionOpened } from "@/lib/ipc";
import { useApp } from "@/stores/app";

// The strip is what is under test. Closing and reconnecting reach the core, and
// focusing reaches an xterm instance; neither belongs in this test.
vi.mock("@/features/sessions/manager", () => ({
  closeTab: vi.fn(),
  reconnect: vi.fn(),
}));
vi.mock("@/features/sessions/terminals", () => ({
  focusTerminal: vi.fn(),
  isTerminalFocused: () => false,
  applyTerminalAppearance: vi.fn(),
}));

import { TabStrip } from "./TabStrip";

const SSH: Capabilities = {
  kind: "terminal",
  resizable: true,
  clipboard: "text",
  fileTransfer: true,
  audio: false,
  printing: false,
  multiMonitor: false,
  recordable: true,
};

const SFTP: Capabilities = { ...SSH, kind: "file_transfer", resizable: false, clipboard: "none" };

const VNC: Capabilities = { ...SSH, kind: "framebuffer", fileTransfer: false };

function opened(capabilities: Capabilities): SessionOpened {
  return {
    sessionId: 11,
    nodeId: "n1",
    name: "web-01",
    protocol: capabilities.kind === "file_transfer" ? "sftp" : "ssh",
    target: "10.0.4.12:22",
    username: "deploy",
    authMethod: "publickey",
    via: [],
    capabilities,
    startedAtMs: 1_757_500_000_000,
    recording: "never",
  };
}

/** Opens a tab in the sessions store and brings it to the front. */
function seed(patch: Partial<SessionRecord>): string {
  const tabId = "tab-1";
  act(() => {
    useSessions.getState().open({
      tabId,
      nodeId: "n1",
      name: "web-01",
      colour: null,
      protocol: "ssh",
      target: "10.0.4.12:22",
    });
    useSessions.getState().patch(tabId, patch);
  });
  return tabId;
}

function filesButton(): HTMLElement {
  const found = screen
    .getAllByRole("button")
    .find((button) => (button.getAttribute("aria-label") ?? "").toLowerCase().includes("file"));
  if (found === undefined) throw new Error("the tab strip drew no Files control");
  return found;
}

beforeEach(() => {
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useApp.setState({ filePaneTabs: new Set<string>() });
});

describe("the Files control", () => {
  it("says which reason it is refusing for, rather than only being dead", () => {
    render(<TabStrip />);

    const button = filesButton();
    expect(button).toBeDisabled();
    // "Unavailable" is not a reason. The sentence names the next move.
    expect(button).toHaveAttribute(
      "aria-label",
      "Browsing files needs an open session. Double-click a connection to start one.",
    );
  });

  it("refuses a session whose protocol carries no files, and says why", () => {
    seed({ phase: "running", sessionId: 11, opened: opened(VNC) });
    render(<TabStrip />);

    expect(filesButton()).toBeDisabled();
    expect(filesButton()).toHaveAttribute(
      "aria-label",
      "This session carries no files. SFTP runs over SSH; an RDP or VNC session has no file channel.",
    );
  });

  it("refuses a tab that is already a file session", () => {
    // An `sftp` connection's tab *is* the file manager. Docking a second pane
    // under it would be offering the screen the user is looking at.
    seed({ phase: "running", sessionId: 11, opened: opened(SFTP) });
    render(<TabStrip />);

    expect(filesButton()).toBeDisabled();
    expect(filesButton()).toHaveAttribute("aria-label", "This tab is already a file session.");
  });

  it("opens and closes the pane for the session in front", async () => {
    const user = userEvent.setup();
    const tabId = seed({ phase: "running", sessionId: 11, opened: opened(SSH) });
    render(<TabStrip />);

    const button = filesButton();
    expect(button).toBeEnabled();
    expect(button).toHaveAttribute("aria-pressed", "false");

    await user.click(button);
    // The tab, not the session: the pane follows the tab across a reconnect.
    expect(useApp.getState().filePaneTabs.has(tabId)).toBe(true);
    expect(filesButton()).toHaveAttribute("aria-pressed", "true");
    expect(filesButton()).toHaveAttribute("aria-label", "Close the file pane");

    await user.click(filesButton());
    expect(useApp.getState().filePaneTabs.has(tabId)).toBe(false);
  });
});
