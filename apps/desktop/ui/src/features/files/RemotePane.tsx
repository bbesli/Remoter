/**
 * The remote half of the browser.
 *
 * # Every string in a row came from the far end
 *
 * A file name, a path, an owner and a group are all chosen by the machine at
 * the other end of the connection, and a hostile one is a legal one. So:
 *
 *   - the row draws `displayName`, `displayPath`, `user` and `group`, every one
 *     of which the core has already escaped, and never the raw twin. The raw
 *     `path` travels back to the core and is never drawn;
 *   - each of those values is wrapped in a Unicode isolate where it sits inside
 *     interface copy, so an Arabic file name cannot reorder the sentence it is
 *     interpolated into;
 *   - a name the core flagged carries a visible badge saying so. The row is
 *     never hidden for it — a file called `report` + U+202E + `fdp.exe` exists
 *     and the user may well want it — but it does not get to look ordinary;
 *   - a name carrying `risks.separator` is not navigable and offers no actions.
 *     The core refuses to build a path from it, so there is nothing to offer,
 *     and the row says which.
 *
 * # The grid, and what it is not
 *
 * Five columns on a CSS grid repeated across the header and every row, the same
 * shape the audit log uses and for the same reason: the columns line up without
 * a table layout pass. It is **not** virtualised, which the audit log is — see
 * `useDirectory.ts` for what that costs and what is said on screen about it.
 *
 * # It is a grid, so it behaves like one
 *
 * The listing used to be reachable by mouse only: rows were not focusable, the
 * grid had no key handler, and the only way to choose several files was to
 * click a checkbox each. A file manager is a keyboard instrument for anyone who
 * administers servers, so the grid now carries a roving tabindex and the map
 * every file manager has — arrows move, Enter opens, Space selects, Shift
 * extends, Backspace goes up, F2 renames, Delete removes, and typing jumps to a
 * name. The map is said once on screen (`nav.keyboardHint`) rather than left to
 * be discovered.
 *
 * The pointer gained the other half of the same vocabulary: a plain click
 * selects one row, Ctrl (or Cmd) adds, and Shift takes the range from the last
 * row touched. The checkboxes stay — they are the only affordance that is
 * discoverable without being told — but they are no longer the only way.
 */

import { useId, useRef, useState, type DragEvent, type KeyboardEvent, type MouseEvent } from "react";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon, type IconName } from "@/components/Icon";
import { SkeletonRows } from "@/components/Busy";
import { TextInput } from "@/components/TextInput";
import { formatBytes, formatDateTime, formatList, foldInvariant, isolate, useLocale, useT } from "@/i18n";
import type { DirectoryEntry, EntryKind, IpcFailure, NameRisks } from "@/lib/ipc";

import { LOCAL_DRAG_TYPE, REMOTE_DRAG_TYPE, decodePaths, encodePaths } from "./dragTypes";
import { breadcrumbs, parentPath, ROOT } from "./path";
import type { SortColumn } from "./sort";
import type { DirectoryView } from "./useDirectory";

import s from "./RemotePane.module.css";

const KIND_ICON = {
  file: "file",
  directory: "folder",
  symlink: "arrow-right",
  other: "settings",
} as const satisfies Record<EntryKind, IconName>;

const KIND_KEY = {
  file: "kind.file",
  directory: "kind.directory",
  symlink: "kind.symlink",
  other: "kind.other",
} as const satisfies Record<EntryKind, string>;

const COLUMN_KEY = {
  name: "columns.name",
  size: "columns.size",
  modified: "columns.modified",
  permissions: "columns.permissions",
  owner: "columns.owner",
} as const satisfies Record<SortColumn, string>;

const COLUMNS: readonly SortColumn[] = ["name", "size", "modified", "permissions", "owner"];

/**
 * How long a type-ahead prefix survives between keystrokes.
 *
 * The same window every desktop list uses. Held in a ref and compared against
 * the keyboard event's own timestamp rather than kept alive by a timer: a timer
 * would be one more thing to clear on unmount, and the only question this
 * answers is "was the last keystroke recent".
 */
const TYPE_AHEAD_MS = 800;

/**
 * Whether a row can be chosen or transferred at all.
 *
 * Folders can, now that the core expands one into a transfer per file beneath
 * it. What still cannot: an entry whose name is not a single path component,
 * because the core refuses to build a path from it; and a socket, device or
 * named pipe, because there is nothing in one to copy.
 */
function isTransferable(entry: DirectoryEntry): boolean {
  return !entry.risks.separator && entry.kind !== "other";
}

interface RemotePaneProps {
  view: DirectoryView;
  /** Where the pane is, raw and escaped. */
  path: string;
  displayPath: string;
  home: string;
  homeDisplay: string;
  /** Raw paths of the chosen rows. */
  selection: ReadonlySet<string>;
  onSelectionChange: (next: ReadonlySet<string>) => void;
  /**
   * Both forms travel together. The raw one addresses the folder; the escaped
   * one is what the trail draws next, and deriving it here would mean a second
   * implementation of the core's escaping rules.
   */
  onNavigate: (location: { path: string; displayPath: string }) => void;
  /** Whether this pane has anywhere to go back to, or forward to. */
  canGoBack: boolean;
  canGoForward: boolean;
  onBack: () => void;
  onForward: () => void;
  /**
   * A path typed into the box, absolute or relative.
   *
   * Resolved by the caller through the server rather than here: `..`, `.` and
   * a bare folder name all mean whatever the server says they mean, and
   * resolving them in the frontend would be a second implementation of a
   * question `sftp_canonicalize` already answers.
   */
  onGoToTyped: (typed: string) => void;
  /** True while a typed path is being resolved. */
  resolving: boolean;
  /** Why a typed path could not be resolved. */
  resolveProblem: IpcFailure | null;
  onNewFolder: () => void;
  onRename: (entry: DirectoryEntry) => void;
  onDelete: (entry: DirectoryEntry) => void;
  /** Shows what the entry is, and lets its mode be changed. */
  onProperties: (entry: DirectoryEntry) => void;
  /** Copies these entries to this computer. */
  onDownload: (entries: readonly DirectoryEntry[]) => void;
  /** Sends these local paths to the folder on screen. */
  onUploadDropped: (localPaths: readonly string[]) => void;
  busy: boolean;
}

export function RemotePane({
  view,
  path,
  displayPath,
  home,
  homeDisplay,
  selection,
  onSelectionChange,
  onNavigate,
  canGoBack,
  canGoForward,
  onBack,
  onForward,
  onGoToTyped,
  resolving,
  resolveProblem,
  onNewFolder,
  onRename,
  onDelete,
  onProperties,
  onDownload,
  onUploadDropped,
  busy,
}: RemotePaneProps) {
  const t = useT("files");
  const { code: locale } = useLocale();
  const filterId = useId();

  const parent = parentPath(path);
  const parentDisplay = parentPath(displayPath);
  const crumbs = breadcrumbs(path, displayPath);
  const [typed, setTyped] = useState("");
  // Whether a staged local file is hovering over this pane. A drop target that
  // says nothing until the drop is a drop target nobody finds.
  const [dropping, setDropping] = useState(false);

  const rows = view.visible;
  // Only rows that can actually be addressed take part in a selection.
  const selectable = rows.filter(isTransferable);
  const allSelected = selectable.length > 0 && selectable.every((entry) => selection.has(entry.path));

  // Which row has the keyboard. A roving tabindex: exactly one row is in the
  // tab order, and the arrows move which. Clamped on every render rather than
  // synchronised in an effect, because the listing changes underneath it — a
  // refresh, a filter, a new sort — and an effect that chased it would be a
  // second source of truth for the same number.
  const [focusIndex, setFocusIndex] = useState(0);
  const focused = Math.min(Math.max(focusIndex, 0), Math.max(rows.length - 1, 0));
  const gridRef = useRef<HTMLDivElement>(null);
  // Where a Shift-extended range starts. A ref because nothing renders from it.
  const anchor = useRef(0);
  const typeAhead = useRef({ prefix: "", at: 0 });

  const goUp = () => {
    if (parent !== null) onNavigate({ path: parent, displayPath: parentDisplay ?? parent });
  };

  /** Moves the keyboard to a row and takes the DOM focus with it. */
  const focusRow = (index: number) => {
    const clamped = Math.min(Math.max(index, 0), Math.max(rows.length - 1, 0));
    setFocusIndex(clamped);
    // Queried rather than held in a ref array: the rows are a map over a list
    // that changes length, and a ref per row would be a parallel structure to
    // keep in step with it.
    const row = gridRef.current?.querySelectorAll<HTMLElement>("[data-row]")[clamped];
    row?.focus();
  };

  const selectOnly = (entry: DirectoryEntry) => {
    onSelectionChange(isTransferable(entry) ? new Set([entry.path]) : new Set());
  };

  const toggle = (entry: DirectoryEntry) => {
    if (!isTransferable(entry)) return;
    const next = new Set(selection);
    if (next.has(entry.path)) next.delete(entry.path);
    else next.add(entry.path);
    onSelectionChange(next);
  };

  /** Everything between the anchor and `index`, added to what is chosen. */
  const extendTo = (index: number) => {
    const from = Math.min(anchor.current, index);
    const to = Math.max(anchor.current, index);
    const next = new Set(selection);
    for (const entry of rows.slice(from, to + 1)) {
      if (isTransferable(entry)) next.add(entry.path);
    }
    onSelectionChange(next);
  };

  const open = (entry: DirectoryEntry) => {
    if (entry.kind === "directory" && !entry.risks.separator) {
      onNavigate({ path: entry.path, displayPath: entry.displayPath });
    }
  };

  /**
   * Jumps to the next row whose name starts with what has been typed.
   *
   * Folded invariantly, exactly as the filter is and for the reason `sort.ts`
   * sets out: a file name is a byte string a machine chose, not language, so
   * the Turkish fold would turn the `I` in `IMG_0431.JPG` into a letter the
   * name does not contain.
   */
  const typeAheadTo = (character: string, now: number) => {
    const prefix =
      now - typeAhead.current.at < TYPE_AHEAD_MS ? typeAhead.current.prefix + character : character;
    typeAhead.current = { prefix, at: now };
    const needle = foldInvariant(prefix);
    // From the row after the focused one, wrapping, so typing the same letter
    // repeatedly walks through the names that start with it.
    for (let step = 1; step <= rows.length; step += 1) {
      const index = (focused + step) % rows.length;
      const candidate = rows[index];
      if (candidate !== undefined && foldInvariant(candidate.displayName).startsWith(needle)) {
        focusRow(index);
        return;
      }
    }
  };

  const onGridKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const entry = rows[focused];
    switch (event.key) {
      case "ArrowDown":
      case "ArrowUp": {
        event.preventDefault();
        const next = focused + (event.key === "ArrowDown" ? 1 : -1);
        if (event.shiftKey) extendTo(Math.min(Math.max(next, 0), rows.length - 1));
        else anchor.current = Math.min(Math.max(next, 0), Math.max(rows.length - 1, 0));
        focusRow(next);
        return;
      }
      case "Home":
        event.preventDefault();
        if (event.shiftKey) extendTo(0);
        else anchor.current = 0;
        focusRow(0);
        return;
      case "End":
        event.preventDefault();
        if (event.shiftKey) extendTo(rows.length - 1);
        else anchor.current = rows.length - 1;
        focusRow(rows.length - 1);
        return;
      case "Enter":
        if (entry === undefined) return;
        event.preventDefault();
        // Alt+Enter is what every desktop file manager binds properties to,
        // and a plain Enter opens.
        if (event.altKey) onProperties(entry);
        else open(entry);
        return;
      case " ":
        if (entry === undefined) return;
        event.preventDefault();
        anchor.current = focused;
        toggle(entry);
        return;
      case "Backspace":
        event.preventDefault();
        goUp();
        return;
      case "F2":
        if (entry === undefined || entry.risks.separator) return;
        event.preventDefault();
        onRename(entry);
        return;
      case "Delete":
        if (entry === undefined || entry.risks.separator) return;
        event.preventDefault();
        onDelete(entry);
        return;

      default:
        break;
    }
    // Type-ahead last, and only for a bare printable key: Ctrl+A and the rest
    // belong to the application and to the browser, not to a name search.
    if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      event.preventDefault();
      // The event's own clock, not `Date.now()`: it is the right measurement —
      // "was the last keystroke recent" — and it keeps this out of the impure
      // calls a render may not make.
      typeAheadTo(event.key, event.timeStamp);
    }
  };

  const onRowClick = (event: MouseEvent<HTMLElement>, index: number, entry: DirectoryEntry) => {
    setFocusIndex(index);
    if (event.shiftKey) {
      extendTo(index);
      return;
    }
    anchor.current = index;
    // `metaKey` as well as `ctrlKey`: Cmd is the additive modifier on macOS,
    // and a list that only honours Ctrl there is a list that cannot multi-select.
    if (event.ctrlKey || event.metaKey) toggle(entry);
    else selectOnly(entry);
  };

  /** What a drag from this row carries: the selection, or just this row. */
  const dragPayload = (entry: DirectoryEntry): DirectoryEntry[] => {
    if (!selection.has(entry.path)) return [entry];
    return rows.filter((row) => selection.has(row.path));
  };

  const carriesLocalFile = (e: DragEvent<HTMLElement>) => e.dataTransfer.types.includes(LOCAL_DRAG_TYPE);

  const onDrop = (e: DragEvent<HTMLElement>) => {
    setDropping(false);
    if (!carriesLocalFile(e)) return;
    e.preventDefault();
    // What was dragged, not what happens to be staged. A drop that sent the
    // whole staging list regardless of the payload is what this replaces.
    const dropped = decodePaths(e.dataTransfer.getData(LOCAL_DRAG_TYPE));
    if (dropped.length > 0) onUploadDropped(dropped);
  };

  return (
    <section
      className={s.pane}
      aria-label={t("pane.remote.title")}
      onDragOver={(e) => {
        if (!carriesLocalFile(e)) return;
        e.preventDefault();
        setDropping(true);
      }}
      onDragLeave={(e) => {
        // Only when the pointer has left the pane itself, not when it crosses
        // from one row to the next.
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropping(false);
      }}
      onDrop={onDrop}
    >
      {dropping && (
        <p className={s.dropHint} role="status">
          {t("drop.toRemote")}
        </p>
      )}
      <header className={s.head}>
        <h3 className={s.title}>{t("pane.remote.title")}</h3>
        <div className={s.spacer} />
        <Button
          size="sm"
          variant="ghost"
          onClick={onBack}
          disabled={!canGoBack}
          title={canGoBack ? t("nav.back") : t("nav.noBack")}
        >
          {t("nav.back")}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={onForward}
          disabled={!canGoForward}
          title={canGoForward ? t("nav.forward") : t("nav.noForward")}
        >
          {t("nav.forward")}
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            onNavigate({ path: home, displayPath: homeDisplay });
          }}
          ariaLabel={t("nav.home")}
          title={t("nav.home")}
        >
          <Icon name="folder" size={14} />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={goUp}
          disabled={parent === null}
          ariaLabel={t("nav.up")}
          title={parent === null ? t("nav.atRoot") : t("nav.up")}
        >
          <Icon name="arrow-left" size={14} />
        </Button>
        {/* A word rather than a glyph: the icon vocabulary in
            `components/Icon.tsx` is a closed set and has no refresh mark, and
            borrowing one that means something else is how an icon language
            stops meaning anything. */}
        <Button size="sm" variant="ghost" onClick={view.refresh} title={t("nav.refresh")}>
          {t("nav.refresh")}
        </Button>
      </header>

      <nav className={s.crumbs} aria-label={t("nav.breadcrumb")}>
        <button
          type="button"
          className={s.crumb}
          onClick={() => {
            onNavigate({ path: ROOT, displayPath: ROOT });
          }}
        >
          {/* A path separator, not a word. Never translated. */}
          <span aria-hidden="true">/</span>
          <span className={s.visuallyHidden}>{t("nav.home")}</span>
        </button>
        {crumbs.map((crumb) => (
          <button
            key={crumb.path}
            type="button"
            className={s.crumb}
            onClick={() => {
              onNavigate({ path: crumb.path, displayPath: crumb.displayPath });
            }}
          >
            {isolate(crumb.label)}
          </button>
        ))}
      </nav>

      {/* Typing a path is how anyone reaches /var/log without eight clicks.
          What is typed here is the user's own text, not the server's, so it is
          its own display form — there is nothing to escape.

          The button used to be disabled for anything that did not begin with a
          slash, which refused `..` and `logs` silently: a control that looks
          broken and says nothing. Both are now sent to the server, which is the
          only thing that knows what they mean from here. */}
      <form
        className={s.goto}
        onSubmit={(e) => {
          e.preventDefault();
          const wanted = typed.trim();
          if (wanted === "") return;
          onGoToTyped(wanted);
          setTyped("");
        }}
      >
        <TextInput
          value={typed}
          onChange={setTyped}
          mono
          ariaLabel={t("nav.pathLabel")}
          placeholder={path}
        />
        <Button size="sm" type="submit" disabled={typed.trim() === "" || resolving}>
          {t("nav.go")}
        </Button>
      </form>
      <p className={s.foldNote}>{t("nav.goHint")}</p>

      {resolveProblem !== null && (
        <div className={s.notice}>
          <FailureNotice failure={resolveProblem} title={t("pane.remote.listFailed")} />
        </div>
      )}

      <div className={s.tools}>
        <label className={s.visuallyHidden} htmlFor={filterId}>
          {t("filter.label")}
        </label>
        <TextInput
          id={filterId}
          value={view.filter}
          onChange={view.setFilter}
          placeholder={t("filter.placeholder")}
          ariaLabel={t("filter.label")}
        />
        {view.filter !== "" && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              view.setFilter("");
            }}
            ariaLabel={t("filter.clear")}
            title={t("filter.clear")}
          >
            <Icon name="x" size={14} />
          </Button>
        )}
        <label className={s.toggle}>
          <input
            type="checkbox"
            checked={view.order.foldersFirst}
            onChange={(e) => {
              view.setFoldersFirst(e.target.checked);
            }}
          />
          {t("sort.foldersFirst")}
        </label>
        <div className={s.spacer} />
        <Button size="sm" onClick={onNewFolder} disabled={busy}>
          {t("action.newFolder")}
        </Button>
        <Button
          size="sm"
          variant="primary"
          onClick={() => {
            onDownload(rows.filter((entry) => selection.has(entry.path)));
          }}
          disabled={busy || selection.size === 0}
        >
          {t("action.download")}
        </Button>
      </div>

      <p className={s.counts}>
        {t("filter.matches", { count: view.matched, total: view.total })}
        {selection.size > 0 && <span className={s.selected}>{t("action.selected", { count: selection.size })}</span>}
      </p>

      {view.capped && <Callout tone="info">{t("pane.remote.tooMany", { shown: view.visible.length, total: view.total })}</Callout>}

      {view.problem !== null && (
        <div className={s.notice}>
          <FailureNotice failure={view.problem} title={t("pane.remote.listFailed")} onRetry={view.refresh} />
        </div>
      )}

      <div
        className={s.grid}
        role="grid"
        aria-label={t("pane.remote.title")}
        aria-busy={view.loading}
        aria-multiselectable="true"
        ref={gridRef}
        onKeyDown={onGridKeyDown}
      >
        <div className={s.headRow} role="row">
          <span className={s.check} role="columnheader">
            <input
              type="checkbox"
              checked={allSelected}
              disabled={selectable.length === 0}
              onChange={() => {
                onSelectionChange(allSelected ? new Set() : new Set(selectable.map((entry) => entry.path)));
              }}
              aria-label={allSelected ? t("action.clearSelection") : t("action.selectAll")}
            />
          </span>
          {COLUMNS.map((column) => {
            const active = view.order.column === column;
            return (
              <span
                key={column}
                role="columnheader"
                aria-sort={active ? (view.order.direction === "asc" ? "ascending" : "descending") : "none"}
                className={s[column]}
              >
                <button
                  type="button"
                  className={active ? s.sortActive : s.sort}
                  onClick={() => {
                    view.chooseColumn(column);
                  }}
                  title={
                    active
                      ? view.order.direction === "asc"
                        ? t("sort.ascending")
                        : t("sort.descending")
                      : t("sort.inactive")
                  }
                >
                  {t(COLUMN_KEY[column])}
                  {/* One glyph, turned over for the other direction. A
                      chevron-right would have done the job in English and
                      pointed the wrong way in Arabic, because directional
                      icons mirror and a sort indicator is not directional. */}
                  {active && (
                    <span className={view.order.direction === "asc" ? s.sortUp : s.sortDown}>
                      <Icon name="chevron-down" size={12} />
                    </span>
                  )}
                </button>
              </span>
            );
          })}
          <span className={s.actions} role="columnheader" />
        </div>

        {view.loading && (
          <div className={s.skeleton}>
            {/* The skeleton is shape without meaning to a screen reader, so the
                wait is also said in words. */}
            <p className={s.visuallyHidden} role="status">
              {t("pane.remote.loading")}
            </p>
            <SkeletonRows count={8} />
          </div>
        )}

        {!view.loading &&
          rows.map((entry, index) => (
            <Row
              key={entry.path}
              entry={entry}
              locale={locale}
              selected={selection.has(entry.path)}
              tabbable={index === focused}
              onClick={(event) => {
                onRowClick(event, index, entry);
              }}
              onFocus={() => {
                setFocusIndex(index);
              }}
              onDragStart={(event) => {
                const payload = dragPayload(entry);
                // The raw paths, because they are what the core takes back.
                // They never reach the DOM as text.
                event.dataTransfer.setData(REMOTE_DRAG_TYPE, encodePaths(payload.map((one) => one.path)));
                event.dataTransfer.effectAllowed = "copy";
              }}
              onToggle={() => {
                anchor.current = index;
                toggle(entry);
              }}
              onOpen={() => {
                open(entry);
              }}
              onRename={() => {
                onRename(entry);
              }}
              onDelete={() => {
                onDelete(entry);
              }}
              onProperties={() => {
                onProperties(entry);
              }}
            />
          ))}
      </div>

      {!view.loading && view.problem === null && view.total === 0 && (
        <p className={s.empty}>{t("pane.remote.empty")}</p>
      )}
      {!view.loading && view.problem === null && view.total > 0 && view.matched === 0 && (
        <p className={s.empty}>{t("filter.none")}</p>
      )}
      <p className={s.foldNote}>{t("nav.keyboardHint")}</p>
      <p className={s.foldNote}>{t("filter.note")}</p>
    </section>
  );
}

interface RowProps {
  entry: DirectoryEntry;
  locale: string;
  selected: boolean;
  /** True for the one row in the tab order. See the roving tabindex above. */
  tabbable: boolean;
  onClick: (event: MouseEvent<HTMLElement>) => void;
  onFocus: () => void;
  onDragStart: (event: DragEvent<HTMLElement>) => void;
  onToggle: () => void;
  onOpen: () => void;
  onRename: () => void;
  onDelete: () => void;
  onProperties: () => void;
}

function Row({
  entry,
  locale,
  selected,
  tabbable,
  onClick,
  onFocus,
  onDragStart,
  onToggle,
  onOpen,
  onRename,
  onDelete,
  onProperties,
}: RowProps) {
  const t = useT("files");
  const unaddressable = entry.risks.separator;
  const transferable = isTransferable(entry);

  return (
    <div
      className={selected ? s.rowSelected : s.row}
      role="row"
      aria-selected={selected}
      data-row=""
      tabIndex={tabbable ? 0 : -1}
      draggable={transferable}
      onDragStart={onDragStart}
      onDoubleClick={onOpen}
      onClick={onClick}
      onFocus={onFocus}
    >
      <span className={s.check} role="gridcell">
        <input
          type="checkbox"
          checked={selected}
          disabled={!transferable}
          onChange={onToggle}
          // Not in the tab order: the row is, and a checkbox per row would
          // make tabbing through a hundred-file listing a hundred stops.
          tabIndex={-1}
          aria-label={entry.displayName}
          title={transferable ? undefined : t("action.filesOnly")}
        />
      </span>

      <span className={s.name} role="gridcell">
        <span className={s.kindIcon}>
          <Icon name={KIND_ICON[entry.kind]} size={14} title={t(KIND_KEY[entry.kind])} />
        </span>
        {entry.kind === "directory" && !unaddressable ? (
          <button type="button" className={s.nameButton} onClick={onOpen} tabIndex={-1} title={entry.displayPath}>
            {isolate(entry.displayName)}
          </button>
        ) : (
          <span className={s.nameText} title={entry.displayPath}>
            {isolate(entry.displayName)}
          </span>
        )}
        {hasRisk(entry.risks) && <RiskBadge risks={entry.risks} />}
      </span>

      <span className={s.size} role="gridcell">
        {entry.size === null ? <span className={s.unknown}>{t("value.unknown")}</span> : formatBytes(locale, entry.size)}
      </span>

      <span className={s.modified} role="gridcell">
        {entry.modified === null ? (
          <span className={s.unknown}>{t("value.unknown")}</span>
        ) : (
          formatDateTime(locale, entry.modified * 1000, "short")
        )}
      </span>

      <span className={s.permissions} role="gridcell">
        {/* `drwxr-xr-x` is produced by the core, is ASCII by construction, and
            is never translated. */}
        {entry.mode ?? <span className={s.unknown}>{t("value.unknown")}</span>}
      </span>

      <span className={s.owner} role="gridcell">
        {entry.user === null || entry.user === "" ? (
          <span className={s.unknown}>{t("value.unknown")}</span>
        ) : (
          isolate(entry.user)
        )}
      </span>

      <span className={s.actions} role="gridcell">
        {unaddressable ? (
          <span className={s.refused} title={t("risk.separatorNote")}>
            <Icon name="alert" size={13} title={t("risk.separatorNote")} />
          </span>
        ) : (
          <>
            {/* A word, not a glyph — the same rule the refresh control
                follows. `components/Icon.tsx` is a closed vocabulary with no
                mark for "tell me about this", and borrowing one that means
                something else is how an icon language stops meaning anything.

                The three commands behind it — stat, read-link and
                set-permissions — were on the command surface and reachable
                from nowhere at all. */}
            <Button size="sm" variant="ghost" onClick={onProperties} title={t("action.properties")}>
              {t("action.properties")}
            </Button>
            <Button size="sm" variant="ghost" onClick={onRename} ariaLabel={t("action.rename")} title={t("action.rename")}>
              <Icon name="settings" size={13} />
            </Button>
            <Button size="sm" variant="ghost" onClick={onDelete} ariaLabel={t("action.delete")} title={t("action.delete")}>
              <Icon name="trash" size={13} />
            </Button>
          </>
        )}
      </span>
    </div>
  );
}

function hasRisk(risks: NameRisks): boolean {
  return risks.control || risks.bidi || risks.invisible || risks.separator;
}

/**
 * The mark on a name that is not what it appears to be.
 *
 * Text as well as colour, per `docs/ui/design-system.md`: nothing in this
 * interface is communicated by colour alone, and least of all this.
 */
function RiskBadge({ risks }: { risks: NameRisks }) {
  const t = useT("files");
  const { code: locale } = useLocale();

  const reasons: string[] = [];
  if (risks.control) reasons.push(t("risk.control"));
  if (risks.bidi) reasons.push(t("risk.bidi"));
  if (risks.invisible) reasons.push(t("risk.invisible"));
  if (risks.separator) reasons.push(t("risk.separator"));

  return (
    <Badge tone="warning" title={t("risk.explain", { reasons: formatList(locale, reasons) })}>
      {t("risk.badge")}
    </Badge>
  );
}
