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
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { formatBytes, formatDateTime } from "@/i18n";
import { withoutBidi } from "@/test/bidi";
import type { DirectoryEntry, EntryKind } from "@/lib/ipc";

import { REMOTE_DRAG_TYPE, decodePaths } from "./dragTypes";
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
  const onSelectionChange = vi.fn();
  const onDownload = vi.fn();
  const onUploadDropped = vi.fn();
  const onBack = vi.fn();
  const onForward = vi.fn();
  const onGoToTyped = vi.fn();
  const onProperties = vi.fn();
  render(
    <RemotePane
      view={viewOf(entries)}
      path="/srv"
      displayPath="/srv"
      home="/home/deploy"
      homeDisplay="/home/deploy"
      selection={new Set()}
      onSelectionChange={onSelectionChange}
      onNavigate={onNavigate}
      canGoBack={false}
      canGoForward={false}
      onBack={onBack}
      onForward={onForward}
      onGoToTyped={onGoToTyped}
      resolving={false}
      resolveProblem={null}
      onNewFolder={vi.fn()}
      onRename={onRename}
      onDelete={onDelete}
      onProperties={onProperties}
      onDownload={onDownload}
      onUploadDropped={onUploadDropped}
      busy={false}
      {...overrides}
    />,
  );
  return {
    onNavigate,
    onRename,
    onDelete,
    onProperties,
    onSelectionChange,
    onDownload,
    onBack,
    onForward,
    onGoToTyped,
  };
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

  it("can be queued for transfer", () => {
    // The core walks a folder and queues one transfer per file underneath it,
    // so the row takes part in a selection like any other. This used to be a
    // disabled checkbox, which made the commonest real job — copy this
    // directory down — impossible.
    renderPane([entry({ displayName: "logs", kind: "directory" })]);
    expect(screen.getByRole("checkbox", { name: "logs" })).toBeEnabled();
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

/**
 * The listing is a grid, so it has to behave like one.
 *
 * Every assertion below is about an *effect* — where the focus went, what was
 * handed to the selection callback, what the drag payload contained — rather
 * than about an internal being called. A test that asserted "the key handler
 * ran" would pass over a handler that moved the focus to the wrong row.
 */
describe("the keyboard", () => {
  const three = () => [
    entry({ displayName: "alpha.txt", path: "/srv/alpha.txt" }),
    entry({ displayName: "beta.txt", path: "/srv/beta.txt" }),
    entry({ displayName: "gamma.txt", path: "/srv/gamma.txt" }),
  ];

  /** The rows, in the order the grid draws them. */
  function rows(): HTMLElement[] {
    return screen.getAllByRole("row").filter((row) => row.hasAttribute("data-row"));
  }

  /**
   * Puts the keyboard on one row, the way tabbing into the grid would.
   *
   * Wrapped in `act` because focusing a row moves the roving tabindex, which is
   * React state: an unwrapped `focus()` updates it outside a render pass and
   * the warning is React saying the next assertion may read a stale tree.
   */
  function focusRow(index: number) {
    act(() => {
      rows()[index]?.focus();
    });
  }

  it("puts exactly one row in the tab order and moves it with the arrows", async () => {
    renderPane(three());
    // A roving tabindex: tabbing into the grid lands on one row, not on three
    // hundred.
    expect(rows().filter((row) => row.tabIndex === 0)).toHaveLength(1);

    focusRow(0);
    await userEvent.keyboard("{ArrowDown}");
    expect(rows()[1]).toHaveFocus();
    await userEvent.keyboard("{ArrowDown}");
    expect(rows()[2]).toHaveFocus();
    // Clamped at the end rather than wrapping: a list that wraps on the arrow
    // keys is a list that loses your place.
    await userEvent.keyboard("{ArrowDown}");
    expect(rows()[2]).toHaveFocus();
    await userEvent.keyboard("{Home}");
    expect(rows()[0]).toHaveFocus();
    await userEvent.keyboard("{End}");
    expect(rows()[2]).toHaveFocus();
  });

  it("selects with Space and takes a range with Shift", async () => {
    const { onSelectionChange } = renderPane(three());
    focusRow(0);
    await userEvent.keyboard(" ");
    expect(onSelectionChange).toHaveBeenLastCalledWith(new Set(["/srv/alpha.txt"]));

    onSelectionChange.mockClear();
    await userEvent.keyboard("{Shift>}{ArrowDown}{/Shift}");
    // The range from the anchor to the new row, both ends included.
    expect(onSelectionChange).toHaveBeenLastCalledWith(
      new Set(["/srv/alpha.txt", "/srv/beta.txt"]),
    );
  });

  it("opens a folder with Enter and goes up with Backspace", async () => {
    const { onNavigate } = renderPane([
      entry({ displayName: "logs", path: "/srv/logs", displayPath: "/srv/logs", kind: "directory" }),
    ]);
    focusRow(0);
    await userEvent.keyboard("{Enter}");
    expect(onNavigate).toHaveBeenCalledWith({ path: "/srv/logs", displayPath: "/srv/logs" });

    onNavigate.mockClear();
    await userEvent.keyboard("{Backspace}");
    // `/srv` has one segment, so the folder above it is the root.
    expect(onNavigate).toHaveBeenCalledWith({ path: "/", displayPath: "/" });
  });

  it("renames with F2 and removes with Delete", async () => {
    const { onRename, onDelete } = renderPane(three());
    focusRow(1);
    await userEvent.keyboard("{F2}");
    expect(onRename).toHaveBeenCalledWith(expect.objectContaining({ path: "/srv/beta.txt" }));
    await userEvent.keyboard("{Delete}");
    expect(onDelete).toHaveBeenCalledWith(expect.objectContaining({ path: "/srv/beta.txt" }));
  });

  it("jumps to a name when letters are typed", async () => {
    renderPane(three());
    focusRow(0);
    await userEvent.keyboard("g");
    expect(rows()[2]).toHaveFocus();
  });

  it("folds the typed letters invariantly, the way the filter does", async () => {
    // A file name is a byte string a machine chose, not language — so `B`
    // finds `beta.txt`, and the Turkish fold is kept away from it for the
    // reason `sort.ts` sets out at length.
    //
    // Its own test rather than a second keystroke in the one above: successive
    // keystrokes inside the type-ahead window are a *prefix*, which is the
    // behaviour that test is not about.
    renderPane(three());
    focusRow(0);
    await userEvent.keyboard("B");
    expect(rows()[1]).toHaveFocus();
  });
});

describe("the mouse", () => {
  const two = () => [
    entry({ displayName: "one.txt", path: "/srv/one.txt" }),
    entry({ displayName: "two.txt", path: "/srv/two.txt" }),
  ];

  it("replaces the selection on a plain click and adds on Ctrl", async () => {
    const { onSelectionChange } = renderPane(two(), { selection: new Set(["/srv/two.txt"]) });
    const rows = screen.getAllByRole("row").filter((row) => row.hasAttribute("data-row"));

    await userEvent.click(rows[0] as HTMLElement);
    // Replaced, not added: a plain click on a row means "this one".
    expect(onSelectionChange).toHaveBeenLastCalledWith(new Set(["/srv/one.txt"]));

    onSelectionChange.mockClear();
    // `fireEvent` rather than `userEvent`, because the modifier has to be on
    // the click itself: `userEvent.keyboard("{Control>}")` and a separate
    // `click` are two interactions, and the second does not carry the first's
    // modifier state.
    fireEvent.click(rows[0] as HTMLElement, { ctrlKey: true });
    // Added to what was already chosen, not replacing it. The selection prop
    // is fixed in this test, so this is the callback's own arithmetic.
    expect(onSelectionChange).toHaveBeenLastCalledWith(
      new Set(["/srv/two.txt", "/srv/one.txt"]),
    );
  });
});

describe("a drag out of this pane", () => {
  it("carries the rows that were dragged, not whatever happens to be selected", () => {
    // The defect this pins: both panes ignored the payload and re-ran the bulk
    // action, so dropping one row fetched the whole selection.
    renderPane(
      [
        entry({ displayName: "one.txt", path: "/srv/one.txt" }),
        entry({ displayName: "two.txt", path: "/srv/two.txt" }),
      ],
      { selection: new Set(["/srv/two.txt"]) },
    );
    const rows = screen.getAllByRole("row").filter((row) => row.hasAttribute("data-row"));

    const stored = new Map<string, string>();
    const dataTransfer = {
      setData: (type: string, value: string) => stored.set(type, value),
      effectAllowed: "none",
    };

    // A row outside the selection drags itself alone.
    fireEvent.dragStart(rows[0] as HTMLElement, { dataTransfer });
    expect(decodePaths(stored.get(REMOTE_DRAG_TYPE) ?? "")).toEqual(["/srv/one.txt"]);

    // A row inside it drags the whole selection, which is what dragging a
    // chosen row means everywhere else.
    stored.clear();
    fireEvent.dragStart(rows[1] as HTMLElement, { dataTransfer });
    expect(decodePaths(stored.get(REMOTE_DRAG_TYPE) ?? "")).toEqual(["/srv/two.txt"]);
  });
});

describe("the path box", () => {
  it("accepts a relative path instead of silently disabling its button", async () => {
    // It used to refuse anything that did not begin with a slash by disabling
    // the button and saying nothing, so `..` and `logs` both looked broken.
    const { onGoToTyped } = renderPane([]);
    await userEvent.type(screen.getByLabelText("Folder path"), "..");
    const go = screen.getByRole("button", { name: "Go" });
    expect(go).toBeEnabled();
    await userEvent.click(go);
    expect(onGoToTyped).toHaveBeenCalledWith("..");
  });
});

describe("an entry's properties", () => {
  it("are reachable from the row and from the keyboard", async () => {
    // `sftp_stat`, `sftp_read_link` and `sftp_set_permissions` were on the
    // command surface with no way to reach any of them. This pins that there
    // now is one, by both routes.
    const { onProperties } = renderPane([entry({ displayName: "deploy.sh", path: "/srv/deploy.sh" })]);

    await userEvent.click(screen.getByRole("button", { name: "Properties" }));
    expect(onProperties).toHaveBeenCalledWith(expect.objectContaining({ path: "/srv/deploy.sh" }));

    onProperties.mockClear();
    const row = screen.getAllByRole("row").filter((one) => one.hasAttribute("data-row"))[0];
    act(() => {
      row?.focus();
    });
    // Alt+Enter, which is what every desktop file manager binds it to. Plain
    // Enter still opens.
    await userEvent.keyboard("{Alt>}{Enter}{/Alt}");
    expect(onProperties).toHaveBeenCalledTimes(1);
  });
});
