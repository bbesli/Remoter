/**
 * The bottom inline-end corner of the window, and the sentence it puts there.
 *
 * `locksInSeconds` is null in two situations that have nothing to do with each
 * other: auto-lock is switched off, and the vault is locked. The footer read
 * the null and printed "auto-lock is off" for both — so the moment a vault
 * locked itself after fifteen idle minutes, the one corner of the window still
 * saying anything announced that auto-lock was off. The owner read it beside a
 * badge saying "Locked".
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { VaultState } from "@/lib/ipc";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: { listTunnels: vi.fn() } };
});

import { ipc } from "@/lib/ipc";
import { useSessions } from "@/features/sessions";

import { Footer } from "./Footer";

const listTunnels = vi.mocked(ipc.listTunnels);

const OPEN: VaultState = {
  unlocked: true,
  path: "/vaults/work.rvault",
  label: "Work",
  connectionCount: 3,
  credentialCount: 2,
  locksInSeconds: 900,
  kdfUpgradeAvailable: false,
};

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
  listTunnels.mockResolvedValue([]);
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("the auto-lock corner", () => {
  it("counts down while the vault is open and auto-lock is on", () => {
    render(wrap(<Footer vault={OPEN} onShowPanels={() => undefined} />));
    expect(screen.getByText("vault locks in 15:00")).toBeInTheDocument();
  });

  it("says auto-lock is off only when it is off", () => {
    render(
      wrap(
        <Footer
          vault={{ ...OPEN, locksInSeconds: null }}
          onShowPanels={() => undefined}
        />,
      ),
    );
    expect(screen.getByText("auto-lock is off")).toBeInTheDocument();
  });

  it("does not claim auto-lock is off while the vault is locked", () => {
    // What `vault_state` reports after the idle timeout fires: no vault open,
    // and therefore no countdown — which is not the same fact at all.
    render(
      wrap(
        <Footer
          vault={{ ...OPEN, unlocked: false, connectionCount: 0, credentialCount: 0, locksInSeconds: null }}
          onShowPanels={() => undefined}
        />,
      ),
    );
    expect(screen.queryByText("auto-lock is off")).toBeNull();
    expect(screen.getByText("vault locked")).toBeInTheDocument();
  });

  it("says nothing at all before the first answer arrives", () => {
    // "Not known yet" is not "off" either, and guessing would put a sentence
    // on screen that the next render contradicts.
    render(wrap(<Footer vault={undefined} onShowPanels={() => undefined} />));
    expect(screen.queryByText("auto-lock is off")).toBeNull();
    expect(screen.queryByText("vault locked")).toBeNull();
  });
});
