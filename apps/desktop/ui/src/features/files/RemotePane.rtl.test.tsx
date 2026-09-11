/**
 * What a listing row is allowed to draw.
 *
 * Every string in a row was chosen by a machine this application does not
 * control, and the core sends each of them twice for that reason: the raw form
 * to address with and the escaped form to read. These tests pin that the pane
 * draws the second and never the first, that a flagged name is marked rather
 * than hidden, and that a name the core will not build a path from offers no
 * action at all.
 *
 * They also pin the formatting, because the alternative to `Intl` here is not
 * "slightly wrong" — `String(2048)` is a byte count nobody reads and
 * `String(1772000000)` is not a date in any language.
 */

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { formatBytes, formatDateTime } from "@/i18n";
import { withoutBidi } from "@/test/bidi";
import type { DirectoryEntry, EntryKind } from "@/lib/ipc";

import { RemotePane } from "./RemotePane";
import { DEFAULT_SORT } from "./sort";
import type { DirectoryView } from "./useDirectory";

/** A name carrying a right-to-left override, written as an escape. */
const HOSTILE_RAW = "annex\u202Etxt.exe";
/** What the core sends back for it, with the override written out. */
const HOSTILE_SHOWN = "annex\\u{202E}txt.exe";

function entry(over: Partial<DirectoryEntry> & { displayName: string }): DirectoryEntry {
  const kind: EntryKind = over.kind ?? "file";
  return {
    name: over.displayName,
    path: `/srv/${over.displayName}`,
    displayPath: `/srv/${over.displayName}`,
    kind,
    size: null,
    permissions: null,
    mode: null,
    uid: null,
    user: null,
    gid: null,
    group: null,
    modified: null,
    risks: { control: false, bidi: false, invisible: false, separator: false },
    ...over,
  };
}

function viewOf(entries: DirectoryEntry[]): DirectoryView {
  return {
    entries,
    visible: entries,
    matched: entries.length,
    total: entries.length,
    capped: false,
    loading: false,
    problem: null,
    refresh: vi.fn(),
    order: DEFAULT_SORT,
    chooseColumn: vi.fn(),
    setFoldersFirst: vi.fn(),
    filter: "",
    setFilter: vi.fn(),
  };
}

function renderPane(entries: DirectoryEntry[], overrides: Partial<Parameters<typeof RemotePane>[0]> = {}) {
  const onNavigate = vi.fn();
  const onRename = vi.fn();
  const onDelete = vi.fn();
  render(
    <RemotePane
      view={viewOf(entries)}
      path="/srv"
      displayPath="/srv"
      home="/home/deploy"
      homeDisplay="/home/deploy"
      selection={new Set()}
      onSelectionChange={vi.fn()}
      onNavigate={onNavigate}
      onNewFolder={vi.fn()}
      onRename={onRename}
      onDelete={onDelete}
      onDownload={vi.fn()}
      onUploadDropped={vi.fn()}
      busy={false}
      {...overrides}
    />,
  );
  return { onNavigate, onRename, onDelete };
}

describe("a hostile name", () => {
  it("is drawn escaped and never raw", () => {
    renderPane([entry({ name: HOSTILE_RAW, displayName: HOSTILE_SHOWN, path: `/srv/${HOSTILE_RAW}` })]);

    expect(screen.getByText(HOSTILE_SHOWN, { normalizer: withoutBidi })).toBeInTheDocument();
    // The raw form, which draws itself as `annexexe.txt` in every toolkit that
    // honours bidi, must be nowhere in the document.
    expect(screen.queryByText(HOSTILE_RAW, { normalizer: withoutBidi })).toBeNull();
  });

  it("is marked rather than hidden", () => {
    // A file called `annex` + U+202E + `txt.exe` exists and the user may well
    // want it. What they may not have is a row that looks ordinary.
    renderPane([
      entry({
        name: HOSTILE_RAW,
        displayName: HOSTILE_SHOWN,
        risks: { control: false, bidi: true, invisible: false, separator: false },
      }),
    ]);
    expect(screen.getByText("Name disguised")).toBeInTheDocument();
  });
});

describe("a name that is not a single path component", () => {
  it("offers no rename and no delete", async () => {
    // The core refuses to build a path from it, so there is nothing to offer.
    // A button that produced a refusal every time would be a button that does
    // not work.
    const { onRename, onDelete } = renderPane([
      entry({
        displayName: "..%2Fetc",
        risks: { control: false, bidi: false, invisible: false, separator: true },
      }),
    ]);
    expect(screen.queryByRole("button", { name: "Rename" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete" })).toBeNull();
    expect(onRename).not.toHaveBeenCalled();
    expect(onDelete).not.toHaveBeenCalled();
    await Promise.resolve();
  });

  it("is not navigable even when the server called it a directory", async () => {
    const { onNavigate } = renderPane([
      entry({
        displayName: "trap",
        kind: "directory",
        risks: { control: false, bidi: false, invisible: false, separator: true },
      }),
    ]);
    // It is drawn as plain text rather than as the button a folder gets.
    expect(screen.queryByRole("button", { name: "trap" })).toBeNull();
    await userEvent.dblClick(screen.getByText("trap", { normalizer: withoutBidi }));
    expect(onNavigate).not.toHaveBeenCalled();
  });
});

describe("a folder", () => {
  it("navigates by the raw path and is labelled by the escaped one", async () => {
    const { onNavigate } = renderPane([
      entry({
        name: "log\u202Es",
        displayName: "log\\u{202E}s",
        path: "/srv/log\u202Es",
        displayPath: "/srv/log\\u{202E}s",
        kind: "directory",
      }),
    ]);
    await userEvent.click(screen.getByRole("button", { name: /log/ }));
    expect(onNavigate).toHaveBeenCalledWith({ path: "/srv/log\u202Es", displayPath: "/srv/log\\u{202E}s" });
  });

  it("cannot be queued for transfer, and says why", () => {
    // Expanding a folder into one transfer per file is a walk that is not
    // built. The checkbox is disabled and carries the reason rather than
    // appearing to work.
    renderPane([entry({ displayName: "logs", kind: "directory" })]);
    const box = screen.getByRole("checkbox", { name: "logs" });
    expect(box).toBeDisabled();
    expect(box).toHaveAttribute("title", "Only files can be transferred in this build.");
  });
});

describe("the columns", () => {
  it("puts sizes and dates through the locale formatter", () => {
    renderPane([
      entry({
        displayName: "build.tar.gz",
        size: 2048,
        mode: "-rw-r--r--",
        user: "deploy",
        // 2026-03-11, as seconds since the epoch.
        modified: 1_773_187_200,
      }),
    ]);

    // The two assertions that matter are the negative ones: `String(2048)` is a
    // number rather than a size, and `String(1773187200)` is not a date in any
    // language. The positive half compares against the shared formatter rather
    // than against a literal, because the literal would be a snapshot of one
    // ICU version's idea of a short date in one locale.
    expect(screen.queryByText("2048")).toBeNull();
    // `withoutBidi` on both sides: a formatted byte count holds a non-breaking
    // space, which the query normaliser collapses in the DOM text but not in a
    // literal handed to it.
    expect(
      screen.getByText(withoutBidi(formatBytes("en", 2048)), { normalizer: withoutBidi }),
    ).toBeInTheDocument();
    expect(screen.queryByText("1773187200")).toBeNull();
    expect(
      screen.getByText(withoutBidi(formatDateTime("en", 1_773_187_200_000, "short")), {
        normalizer: withoutBidi,
      }),
    ).toBeInTheDocument();
    // The mode string is the core's, rendered as sent: it is ASCII by
    // construction and is never translated.
    expect(screen.getByText("-rw-r--r--")).toBeInTheDocument();
    expect(screen.getByText("deploy", { normalizer: withoutBidi })).toBeInTheDocument();
  });

  it("says a value was not reported rather than inventing one", () => {
    renderPane([entry({ displayName: "socket" })]);
    // Four unreported fields: size, modified, permissions, owner.
    expect(screen.getAllByText("Not reported")).toHaveLength(4);
  });
});
