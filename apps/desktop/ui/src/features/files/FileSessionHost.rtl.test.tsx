/**
 * An `sftp` connection's tab, end to end from the tab's point of view.
 *
 * `session_open` accepts an `sftp` node and the core answers with
 * `capabilities.kind === "file_transfer"` — `an_sftp_connection_opens_a_file_session_of_its_own`
 * in `crates/remoter-ipc/src/live_tests.rs` pins that half. For a long time the
 * other half was missing: the session surface had no branch for that kind, so
 * such a tab drew a terminal that could never print a byte, and the finished
 * file manager was unreachable.
 *
 * So what is pinned here is the join. Given a tab with a file session on it,
 * this host opens a pane **on that session id** — not a second connection — and
 * draws the browser and its transfer queue.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { withoutBidi } from "@/test/bidi";
import type { DirectoryEntry, SftpPane } from "@/lib/ipc";

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      openPane: vi.fn(),
      closePane: vi.fn(),
      listDirectory: vi.fn(),
      listTransfers: vi.fn(),
    },
  };
});

import { ipc } from "@/lib/ipc";

import { FileSessionHost } from "./FileSessionHost";

const openPane = vi.mocked(ipc.openPane);
const closePane = vi.mocked(ipc.closePane);
const listDirectory = vi.mocked(ipc.listDirectory);
const listTransfers = vi.mocked(ipc.listTransfers);

const PANE: SftpPane = {
  paneId: 3,
  sessionId: 42,
  home: "/home/deploy",
  homeDisplay: "/home/deploy",
};

function file(name: string): DirectoryEntry {
  return {
    name,
    path: `/home/deploy/${name}`,
    displayName: name,
    displayPath: `/home/deploy/${name}`,
    kind: "file",
    size: 2048,
    permissions: null,
    mode: null,
    uid: null,
    user: null,
    gid: null,
    group: null,
    modified: null,
    risks: { control: false, bidi: false, invisible: false, separator: false },
  };
}

function wrap(children: ReactNode) {
  // Retries off: a test that waits out three backoffs for a rejected query is a
  // test nobody runs.
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
  openPane.mockResolvedValue(PANE);
  closePane.mockResolvedValue(undefined);
  listDirectory.mockResolvedValue([file("deploy.log")]);
  listTransfers.mockResolvedValue([]);
});

describe("a file session's tab", () => {
  it("browses on the session the tab already has, rather than connecting again", async () => {
    render(wrap(<FileSessionHost sessionId={42} name="web-01" active />));

    await waitFor(() => {
      expect(openPane).toHaveBeenCalledWith(42);
    });
    // One channel on one session. There is one place in this application where
    // a host key is checked and a credential is used, and it is not here.
    expect(openPane).toHaveBeenCalledTimes(1);

    // The listing draws every server-supplied name inside a bidi isolate, so the
    // query has to see past the invisible characters.
    expect(await screen.findByText("deploy.log", { normalizer: withoutBidi })).toBeInTheDocument();
    // The queue is beside the buttons that fill it, on the same screen.
    expect(screen.getByText("Transfers")).toBeInTheDocument();
  });

  it("opens nothing until the session has authenticated, and says so", () => {
    render(wrap(<FileSessionHost sessionId={null} name="web-01" active />));

    expect(openPane).not.toHaveBeenCalled();
    expect(screen.getByText("Not connected yet")).toBeInTheDocument();
  });

  it("stays in the accessibility tree only while its tab is in front", async () => {
    const { rerender } = render(wrap(<FileSessionHost sessionId={42} name="web-01" active />));
    await waitFor(() => {
      expect(openPane).toHaveBeenCalledWith(42);
    });

    rerender(wrap(<FileSessionHost sessionId={42} name="web-01" active={false} />));
    expect(screen.getByLabelText("Files on web-01", { normalizer: withoutBidi })).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    // Hidden, not closed: the pane keeps its channel and its queue, so a
    // transfer survives the user switching to another tab.
    expect(closePane).not.toHaveBeenCalled();
  });
});
