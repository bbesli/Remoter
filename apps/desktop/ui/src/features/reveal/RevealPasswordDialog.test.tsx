/**
 * The "show password" dialog's behaviour.
 *
 * What is pinned is the part that would look right while being wrong: that
 * nothing is shown before the vault password is confirmed unless the core
 * says the window is open; that a window the store only believes is open
 * falls back to asking; that a wrong password leaves the question standing
 * with the field emptied; and that the deadline the core reports reaches the
 * corner countdown.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { IpcFailure, RevealedSecret, TreeNode } from "@/lib/ipc";
import { useApp } from "@/stores/app";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      listNodes: vi.fn(),
      revealSecret: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { RevealPasswordDialog } from "./RevealPasswordDialog";

const listNodes = vi.mocked(ipc.listNodes);
const revealSecret = vi.mocked(ipc.revealSecret);

const WEB = { id: "c-web", name: "web-01", kind: "connection" } as TreeNode;

const SECRET: RevealedSecret = {
  nodeId: "c-web",
  credentialName: "web-01",
  shared: false,
  username: "deploy",
  password: "zq-server-pw-7731",
  windowRemainingMs: 600_000,
};

function failure(code: string, message = "refused"): IpcFailure {
  return { code, message, detail: null, actions: [] };
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  listNodes.mockResolvedValue([WEB]);
  useApp.setState({ revealUntil: null, openModals: new Set() });
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("RevealPasswordDialog", () => {
  it("asks for the vault password before showing anything", async () => {
    const user = userEvent.setup();
    revealSecret.mockResolvedValue(SECRET);
    render(<RevealPasswordDialog nodeId="c-web" onClose={() => {}} />, { wrapper });

    expect(screen.getByRole("dialog", { name: "Show password" })).toBeInTheDocument();
    expect(revealSecret).not.toHaveBeenCalled();
    expect(screen.queryByTestId("revealed-password")).toBeNull();
    expect(screen.getByText("Every password shown is recorded in the audit log.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Vault password"), "the vault password");
    await user.click(screen.getByRole("button", { name: "Show password" }));

    expect(revealSecret).toHaveBeenCalledWith("c-web", "the vault password");
    expect(await screen.findByTestId("revealed-password")).toHaveTextContent("zq-server-pw-7731");
    expect(screen.getByText("deploy")).toBeInTheDocument();
    const until = useApp.getState().revealUntil;
    expect(until).not.toBeNull();
    expect((until ?? 0) - Date.now()).toBeGreaterThan(590_000);
  });

  it("keeps asking after a wrong password, with the field emptied", async () => {
    const user = userEvent.setup();
    revealSecret.mockRejectedValue(
      failure("secret.reveal-refused", "That is not this vault's password, so nothing was shown."),
    );
    render(<RevealPasswordDialog nodeId="c-web" onClose={() => {}} />, { wrapper });

    const field = screen.getByLabelText("Vault password");
    await user.type(field, "wrong");
    await user.click(screen.getByRole("button", { name: "Show password" }));

    expect(
      await screen.findByText("That is not this vault's password, so nothing was shown."),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Vault password")).toHaveValue("");
    expect(screen.queryByTestId("revealed-password")).toBeNull();
    expect(useApp.getState().revealUntil).toBeNull();
  });

  it("shows without asking while the window is open", async () => {
    useApp.setState({ revealUntil: Date.now() + 300_000 });
    revealSecret.mockResolvedValue({ ...SECRET, windowRemainingMs: 300_000 });
    render(<RevealPasswordDialog nodeId="c-web" onClose={() => {}} />, { wrapper });

    expect(await screen.findByTestId("revealed-password")).toHaveTextContent("zq-server-pw-7731");
    expect(revealSecret).toHaveBeenCalledTimes(1);
    expect(revealSecret).toHaveBeenCalledWith("c-web", null);
    expect(screen.queryByLabelText("Vault password")).toBeNull();
  });

  it("asks after all when the core says the window has closed", async () => {
    useApp.setState({ revealUntil: Date.now() + 300_000 });
    revealSecret.mockRejectedValue(failure("secret.reveal-confirm"));
    render(<RevealPasswordDialog nodeId="c-web" onClose={() => {}} />, { wrapper });

    expect(await screen.findByLabelText("Vault password")).toBeInTheDocument();
    expect(useApp.getState().revealUntil).toBeNull();
  });

  it("says why when there is nothing to show", async () => {
    const user = userEvent.setup();
    revealSecret.mockRejectedValue(
      failure("secret.reveal-nothing", "There is no password to show here."),
    );
    render(<RevealPasswordDialog nodeId="c-web" onClose={() => {}} />, { wrapper });

    await user.type(screen.getByLabelText("Vault password"), "the vault password");
    await user.click(screen.getByRole("button", { name: "Show password" }));

    expect(await screen.findByText("The password could not be shown")).toBeInTheDocument();
    expect(screen.queryByLabelText("Vault password")).toBeNull();
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<RevealPasswordDialog nodeId="c-web" onClose={onClose} />, { wrapper });
    await user.keyboard("{Escape}");
    await waitFor(() => expect(onClose).toHaveBeenCalledTimes(1));
  });
});
