/**
 * The corner countdown.
 *
 * Pinned: it draws nothing until the core has said a window is open — a value
 * left in the store from before a lock must not put a countdown on screen —
 * it disappears when the time is up, and "End now" ends the core's window, not
 * just the drawing of it.
 */

import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useApp } from "@/stores/app";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      revealWindow: vi.fn(),
      endRevealWindow: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { RevealWindowBadge } from "./RevealWindowBadge";

const revealWindow = vi.mocked(ipc.revealWindow);
const endRevealWindow = vi.mocked(ipc.endRevealWindow);

beforeEach(() => {
  useApp.setState({ revealUntil: null });
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("RevealWindowBadge", () => {
  it("draws nothing when the core has no window open, whatever the store remembered", async () => {
    useApp.setState({ revealUntil: Date.now() + 120_000 });
    revealWindow.mockResolvedValue({ remainingMs: null });
    const { container } = render(<RevealWindowBadge />);
    await act(async () => {});
    expect(container).toBeEmptyDOMElement();
    expect(useApp.getState().revealUntil).toBeNull();
  });

  it("counts down the core's window and goes when it is over", async () => {
    vi.useFakeTimers();
    revealWindow.mockResolvedValue({ remainingMs: 61_500 });
    render(<RevealWindowBadge />);
    await act(async () => {});

    expect(screen.getByText("Passwords shown without asking")).toBeInTheDocument();
    expect(screen.getByText("01:01 left")).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(30_000);
    });
    expect(screen.getByText("00:31 left")).toBeInTheDocument();

    await act(async () => {
      vi.advanceTimersByTime(32_000);
    });
    expect(screen.queryByText("Passwords shown without asking")).toBeNull();
    expect(useApp.getState().revealUntil).toBeNull();
  });

  it("ends the core's window on request", async () => {
    const user = userEvent.setup();
    revealWindow.mockResolvedValue({ remainingMs: 300_000 });
    endRevealWindow.mockResolvedValue(undefined);
    render(<RevealWindowBadge />);
    await act(async () => {});

    await user.click(screen.getByRole("button", { name: "End now" }));
    expect(endRevealWindow).toHaveBeenCalledTimes(1);
    expect(screen.queryByText("Passwords shown without asking")).toBeNull();
    expect(useApp.getState().revealUntil).toBeNull();
  });
});
