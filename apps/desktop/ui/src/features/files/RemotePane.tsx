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
 */

import { useId, useState, type DragEvent } from "react";

import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon, type IconName } from "@/components/Icon";
import { SkeletonRows } from "@/components/Busy";
import { TextInput } from "@/components/TextInput";
import { formatBytes, formatDateTime, formatList, isolate, useLocale, useT } from "@/i18n";
import type { DirectoryEntry, EntryKind, NameRisks } from "@/lib/ipc";

import { LOCAL_DRAG_TYPE, REMOTE_DRAG_TYPE } from "./dragTypes";
import { breadcrumbs, isAbsolute, parentPath, ROOT } from "./path";
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
  onNewFolder: () => void;
  onRename: (entry: DirectoryEntry) => void;
  onDelete: (entry: DirectoryEntry) => void;
  onDownload: () => void;
  /** Called when local files are dropped onto this pane. */
  onUploadDropped: () => void;
  /** True while something from the local pane is being dragged. */
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
  onNewFolder,
  onRename,
  onDelete,
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

  // Only rows that can actually be addressed take part in a selection. A row
  // the core will refuse to build a path from is not a candidate for anything.
  const selectable = view.visible.filter((entry) => !entry.risks.separator && entry.kind !== "directory");
  const allSelected = selectable.length > 0 && selectable.every((entry) => selection.has(entry.path));

  const toggle = (entry: DirectoryEntry) => {
    const next = new Set(selection);
    if (next.has(entry.path)) next.delete(entry.path);
    else next.add(entry.path);
    onSelectionChange(next);
  };

  const carriesLocalFile = (e: DragEvent<HTMLElement>) => e.dataTransfer.types.includes(LOCAL_DRAG_TYPE);

  const onDrop = (e: DragEvent<HTMLElement>) => {
    setDropping(false);
    if (!carriesLocalFile(e)) return;
    e.preventDefault();
    onUploadDropped();
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
          onClick={() => {
            if (parent !== null) onNavigate({ path: parent, displayPath: parentDisplay ?? parent });
          }}
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
          its own display form — there is nothing to escape. */}
      <form
        className={s.goto}
        onSubmit={(e) => {
          e.preventDefault();
          const wanted = typed.trim();
          if (!isAbsolute(wanted)) return;
          onNavigate({ path: wanted, displayPath: wanted });
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
        <Button size="sm" type="submit" disabled={!isAbsolute(typed.trim())}>
          {t("nav.go")}
        </Button>
      </form>

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
        <Button size="sm" variant="primary" onClick={onDownload} disabled={busy || selection.size === 0}>
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

      <div className={s.grid} role="grid" aria-label={t("pane.remote.title")} aria-busy={view.loading}>
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
          view.visible.map((entry) => (
            <Row
              key={entry.path}
              entry={entry}
              locale={locale}
              selected={selection.has(entry.path)}
              onToggle={() => {
                toggle(entry);
              }}
              onOpen={() => {
                if (entry.kind === "directory" && !entry.risks.separator) {
                  onNavigate({ path: entry.path, displayPath: entry.displayPath });
                }
              }}
              onRename={() => {
                onRename(entry);
              }}
              onDelete={() => {
                onDelete(entry);
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
      <p className={s.foldNote}>{t("filter.note")}</p>
    </section>
  );
}

interface RowProps {
  entry: DirectoryEntry;
  locale: string;
  selected: boolean;
  onToggle: () => void;
  onOpen: () => void;
  onRename: () => void;
  onDelete: () => void;
}

function Row({ entry, locale, selected, onToggle, onOpen, onRename, onDelete }: RowProps) {
  const t = useT("files");
  const unaddressable = entry.risks.separator;
  const risky = hasRisk(entry.risks);

  return (
    <div
      className={selected ? s.rowSelected : s.row}
      role="row"
      draggable={!unaddressable && entry.kind !== "directory"}
      onDragStart={(e) => {
        // The raw path, because it is what the core takes back. It never
        // reaches the DOM as text.
        e.dataTransfer.setData(REMOTE_DRAG_TYPE, entry.path);
        e.dataTransfer.effectAllowed = "copy";
      }}
      onDoubleClick={onOpen}
    >
      <span className={s.check} role="gridcell">
        <input
          type="checkbox"
          checked={selected}
          disabled={unaddressable || entry.kind === "directory"}
          onChange={onToggle}
          aria-label={entry.displayName}
          title={entry.kind === "directory" ? t("action.filesOnly") : undefined}
        />
      </span>

      <span className={s.name} role="gridcell">
        <span className={s.kindIcon}>
          <Icon name={KIND_ICON[entry.kind]} size={14} title={t(KIND_KEY[entry.kind])} />
        </span>
        {entry.kind === "directory" && !unaddressable ? (
          <button type="button" className={s.nameButton} onClick={onOpen} title={entry.displayPath}>
            {isolate(entry.displayName)}
          </button>
        ) : (
          <span className={s.nameText} title={entry.displayPath}>
            {isolate(entry.displayName)}
          </span>
        )}
        {risky && <RiskBadge risks={entry.risks} />}
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
