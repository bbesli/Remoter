/**
 * The command palette.
 *
 * Ctrl/Cmd+K from anywhere; Escape closes. The binding is declared to the
 * keyboard registry rather than installed as a listener here, because the
 * palette has to open while focus is in a session, a form, or nothing at all —
 * and because one listener that knows every binding is what stopped the
 * settings table drifting away from what the application actually does.
 *
 * Matching happens in the core (`tree_search`), which is also where the prefix
 * filters are understood. The palette sends the raw query and renders what
 * comes back — including the matched ranges, so the highlight always agrees
 * with the ranking.
 *
 * Search never reaches a secret. It cannot: secrets are encrypted per field,
 * and indexing them would mean decrypting the vault into memory. The footer
 * says so, because a search box that silently excludes something should say
 * what it excludes.
 *
 * This component is also where the editor overlay is mounted. It is the one
 * piece of the feature that is always on screen, and the editor has to survive
 * the sidebar being collapsed.
 */

import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import type { TFunction } from "i18next";

import { Badge } from "@/components/Badge";
import { BusyStatus, SkeletonRows } from "@/components/Busy";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon, type IconName } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { TextInput } from "@/components/TextInput";
import { foldForSearch, foldInvariant, isolate, useLocale, useT } from "@/i18n";
import { asFailure, ipc, type SearchHit } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import {
  acceleratorCaps,
  resolveShortcuts,
  useKeyboardSettings,
  useShortcutGroup,
} from "@/hooks/keyboard";
import { isConnectable, openSession } from "@/features/sessions";

import { ConnectionEditor, useConnectionEditor } from "./ConnectionEditor";
import { useFocusTrap } from "./focusTrap";
import { nodeGlyph, protocolClass } from "./NodeRow";
import s from "./CommandPalette.module.css";

/** The prefix filters the core understands, offered as one-click chips. */
const PREFIXES = ["tag:", "proto:", "host:", "user:"] as const;

interface PaletteAction {
  id: string;
  label: string;
  glyph: IconName;
  shortcut?: string;
  run: () => void;
  /** Set while the action's command is in flight; the row then refuses a click. */
  busy?: boolean;
  /** What it is doing, shown in place of the label. */
  busyLabel?: string;
}

type Item =
  | { kind: "hit"; key: string; hit: SearchHit }
  | { kind: "action"; key: string; action: PaletteAction };

/**
 * Match ranges arrive from the core. They are clamped and ordered here rather
 * than trusted, so a malformed range can only lose a highlight, never throw
 * during render.
 */
function highlight(name: string, ranges: readonly [number, number][]) {
  const clean = ranges
    .map(([start, end]): [number, number] => [
      Math.max(0, Math.min(start, name.length)),
      Math.max(0, Math.min(end, name.length)),
    ])
    .filter(([start, end]) => end > start)
    .sort((a, b) => a[0] - b[0]);

  const parts: { text: string; hit: boolean }[] = [];
  let cursor = 0;
  for (const [start, end] of clean) {
    if (start < cursor) continue;
    if (start > cursor) parts.push({ text: name.slice(cursor, start), hit: false });
    parts.push({ text: name.slice(start, end), hit: true });
    cursor = end;
  }
  if (cursor < name.length) parts.push({ text: name.slice(cursor), hit: false });

  return parts.map((part, i) =>
    part.hit ? (
      <span key={i} className={s.hit}>
        {part.text}
      </span>
    ) : (
      <span key={i}>{part.text}</span>
    ),
  );
}

export function CommandPalette() {
  const open = useApp((st) => st.paletteOpen);
  const setPaletteOpen = useApp((st) => st.setPaletteOpen);
  const close = useCallback(() => setPaletteOpen(false), [setPaletteOpen]);

  /*
   * The palette's one binding.
   *
   * It reads the store at fire time rather than closing over `open`, so it can
   * never go stale. The two guards this used to carry now belong to the
   * dispatcher and apply to every binding at once: a focused terminal reaches
   * an application binding through the prefix (the palette is universal, so
   * either form works), and no binding fires while a modal has the keyboard —
   * opening the palette under a focus trap put two traps on one document and
   * rendered the palette invisibly behind the first.
   */
  useShortcutGroup("palette", {
    "palette.open": () => {
      const store = useApp.getState();
      store.setPaletteOpen(!store.paletteOpen);
    },
  });

  return (
    <>
      {open && <PaletteSheet onClose={close} />}
      <ConnectionEditor />
    </>
  );
}

/**
 * The second line of a search hit.
 *
 * Three of the five node shapes answer with a value — an address, a login,
 * nothing — and those render as they stand: they are not language. The other
 * two answer with a count, and the core used to send that as a finished
 * English phrase ("1 item", "12 members"), hand-pluralised with English rules
 * and written in ASCII digits. The palette printed it verbatim, so a reader
 * who had chosen Russian got English prose with the wrong plural category, and
 * a reader who had chosen Arabic or Hindi got the wrong digits as well.
 *
 * Now the core sends `subtitleKind` and `subtitleCount`, and the phrase is an
 * ICU plural from this catalogue — which is the only place that can know that
 * Russian has four categories and Arabic six. `hit.subtitle` stays as the
 * fallback for a kind this build has not learned yet, exactly as an
 * `IpcFailure`'s `message` is the fallback for an unknown code.
 */
export function subtitleText(t: TFunction<"connections">, hit: SearchHit): string {
  if (hit.subtitleKind === null) return hit.subtitle;
  // Absent rather than zero would be a core that sent a kind and forgot the
  // number; "0 items" is the honest reading of that and beats an empty line.
  const count = hit.subtitleCount ?? 0;
  switch (hit.subtitleKind) {
    case "items":
      return t("palette.subtitle.items", { count });
    case "members":
      return t("palette.subtitle.members", { count });
    default:
      return hit.subtitle;
  }
}

function PaletteSheet({ onClose }: { onClose: () => void }) {
  const t = useT("connections");
  const tCommon = useT("common");
  // The action filter folds translated labels, so it needs the language they
  // were translated into. See the `foldForSearch` call below.
  const { code: locale } = useLocale();
  const select = useApp((st) => st.select);
  const go = useApp((st) => st.go);
  const openExport = useApp((st) => st.openExport);
  const openKnownHosts = useApp((st) => st.openKnownHosts);
  const openEditor = useConnectionEditor((st) => st.open);
  const queryClient = useQueryClient();

  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement | null>(null);

  const sheetRef = useRef<HTMLDivElement | null>(null);

  const searchQuery = useQuery({
    queryKey: qk.search(query),
    queryFn: () => ipc.search(query),
  });
  const nodesQuery = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });

  const total = useMemo(
    () => (nodesQuery.data ?? []).filter((n) => n.kind === "connection").length,
    [nodesQuery.data],
  );

  const lockMutation = useMutation({
    mutationFn: () => ipc.lockVault(),
    onSuccess: () => {
      // Nothing that was read from the unlocked vault may outlive it.
      queryClient.clear();
      onClose();
      go({ name: "picker" });
    },
  });

  // `mutate` is stable across renders; the mutation object is not, and the
  // action list must not be rebuilt on every keystroke of an unrelated field.
  const lock = lockMutation.mutate;
  const locking = lockMutation.isPending;

  /*
   * The key cap on the row is read from the map, not typed here.
   *
   * It used to be the string "Ctrl L", which stayed "Ctrl L" after the binding
   * was changed. A shortcut hint that disagrees with the shortcut is worse than
   * no hint: it teaches a key that does nothing. Focus is in the palette, never
   * in a terminal, so the unprefixed form is the one to show.
   */
  const { overrides } = useKeyboardSettings();
  const lockShortcut = useMemo(() => {
    const entry = resolveShortcuts(overrides).find((one) => one.action.id === "vault.lock");
    return entry === undefined ? undefined : acceleratorCaps(entry.accelerator).join(" ");
  }, [overrides]);

  const hits = useMemo(() => searchQuery.data ?? [], [searchQuery.data]);

  const actions = useMemo<PaletteAction[]>(() => {
    const all: PaletteAction[] = [
      {
        id: "lock-vault",
        label: t("palette.actionLockVault"),
        glyph: "lock",
        ...(lockShortcut === undefined ? {} : { shortcut: lockShortcut }),
        run: () => lock(),
        // Locking writes and zeroises before the palette closes, so the row
        // has to stop accepting the second and third press.
        busy: locking,
        busyLabel: t("palette.actionLocking"),
      },
      {
        id: "new-connection",
        label: t("palette.actionNewConnection"),
        glyph: "plus",
        run: () => {
          onClose();
          openEditor({ mode: "create", parentId: null, kind: "connection" });
        },
      },
      {
        id: "new-folder",
        label: t("palette.actionNewFolder"),
        glyph: "folder",
        run: () => {
          onClose();
          openEditor({ mode: "create", parentId: null, kind: "folder" });
        },
      },
      {
        id: "import",
        label: t("palette.actionImport"),
        glyph: "download",
        run: () => {
          onClose();
          go({ name: "import" });
        },
      },
      {
        id: "known-hosts",
        label: t("palette.actionImportKnownHosts"),
        glyph: "shield",
        run: () => {
          onClose();
          openKnownHosts();
        },
      },
      {
        id: "export",
        label: t("palette.actionExport"),
        glyph: "upload",
        run: () => {
          onClose();
          openExport(null);
        },
      },
      {
        id: "audit",
        label: t("palette.actionAudit"),
        glyph: "file",
        run: () => {
          onClose();
          go({ name: "audit" });
        },
      },
      {
        id: "vault-settings",
        label: t("palette.actionVaultSettings"),
        glyph: "shield",
        run: () => {
          onClose();
          go({ name: "vault-settings" });
        },
      },
      {
        id: "settings",
        label: t("palette.actionSettings"),
        glyph: "settings",
        run: () => {
          onClose();
          go({ name: "settings" });
        },
      },
    ];
    const typed = query.trim();
    // A prefix filter is a question about connections; it is not about actions.
    // The prefixes are ASCII the core defines, not words in anyone's language,
    // so they are recognised through the invariant fold.
    if (PREFIXES.some((p) => foldInvariant(typed).startsWith(p))) return [];
    if (typed === "") return all;
    // The labels are translated, so they fold under the reader's own casing
    // rules — `toLowerCase()` applied English ones to every language, and a
    // Turkish reader filtering on a label containing a capital I was told
    // there was no such action.
    const needle = foldForSearch(typed, locale);
    return all.filter((a) => foldForSearch(a.label, locale).includes(needle));
  }, [
    query,
    locale,
    lock,
    locking,
    lockShortcut,
    onClose,
    openEditor,
    go,
    openExport,
    openKnownHosts,
    t,
  ]);

  const items = useMemo<Item[]>(
    () => [
      ...hits.map((hit): Item => ({ kind: "hit", key: `hit:${hit.node.id}`, hit })),
      ...actions.map((action): Item => ({ kind: "action", key: `act:${action.id}`, action })),
    ],
    [hits, actions],
  );

  useEffect(() => setActive(0), [query]);

  useEffect(() => {
    const item = items[active];
    if (item === undefined) return;
    listRef.current?.querySelector(`[data-key="${CSS.escape(item.key)}"]`)?.scrollIntoView({
      block: "nearest",
    });
  }, [active, items]);

  const activate = (item: Item, withEditor: boolean) => {
    if (item.kind === "action") {
      // Enter repeats as readily as a mouse does; a running action ignores it.
      if (item.action.busy === true) return;
      item.action.run();
      return;
    }
    if (withEditor) {
      onClose();
      openEditor({ mode: "edit", nodeId: item.hit.node.id });
      return;
    }
    // Enter on a connection opens a session, which is what the palette is for:
    // type three letters of a hostname and be in a shell. A folder or a
    // credential has nothing to connect to, so it is selected in the tree.
    select(item.hit.node.id);
    if (isConnectable(item.hit.node)) openSession(item.hit.node);
    onClose();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    switch (e.key) {
      case "Escape":
        e.preventDefault();
        e.stopPropagation();
        onClose();
        return;
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => (items.length === 0 ? 0 : Math.min(items.length - 1, i + 1)));
        return;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        return;
      case "Enter": {
        const item = items[active];
        if (item === undefined) return;
        e.preventDefault();
        activate(item, e.ctrlKey || e.metaKey);
        return;
      }
      default:
    }
  };

  /*
   * The node list feeds the counter, and a failure there used to be invisible:
   * the count simply read zero. It joins the other two failures here so a total
   * that could not be read is said out loud rather than guessed at.
   */
  const failure =
    searchQuery.error !== null
      ? asFailure(searchQuery.error)
      : lockMutation.error !== null
        ? asFailure(lockMutation.error)
        : nodesQuery.error !== null
          ? asFailure(nodesQuery.error)
          : null;
  const failureTitle =
    searchQuery.error !== null
      ? t("palette.searchFailed")
      : lockMutation.error !== null
        ? t("palette.lockFailed")
        : t("palette.countFailed");
  const retryFailed =
    searchQuery.error !== null
      ? () => void searchQuery.refetch()
      : lockMutation.error === null && nodesQuery.error !== null
        ? () => void nodesQuery.refetch()
        : undefined;

  const countLabel = nodesQuery.isPending
    ? t("palette.countPending", { shown: hits.length })
    : nodesQuery.error !== null
      ? t("palette.countUnknown", { count: hits.length })
      : t("palette.count", { shown: hits.length, total });

  // `aria-modal` says the tree behind the sheet is inert; without a trap, Tab
  // walks straight into it and proves otherwise.
  useFocusTrap(true, sheetRef);
  useModalRegistration("palette", true);

  return (
    <div
      className={s.backdrop}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      {/* Key handling lives on the sheet so it applies whether focus is in the
          input or on a result row. */}
      <div
        ref={sheetRef}
        className={s.sheet}
        role="dialog"
        aria-modal="true"
        aria-label={t("palette.label")}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        <div className={s.inputRow}>
          <span className={s.inputGlyph}>
            <Icon name="search" size={16} />
          </span>
          <span className={s.inputField}>
            <TextInput
              value={query}
              onChange={setQuery}
              placeholder={t("palette.placeholder")}
              ariaLabel={t("palette.inputLabel")}
              mono
              autoFocus
            />
          </span>
          {/* Typing re-runs the search against the core. Without this the
              counter simply sits on a stale number. */}
          {searchQuery.isFetching && !searchQuery.isPending ? (
            <span className={s.count} title={t("palette.refining")}>
              <Spinner size={13} label={t("palette.refining")} />
            </span>
          ) : (
            <span
              className={s.count}
              {...(nodesQuery.error === null ? {} : { title: t("palette.countFailed") })}
            >
              {countLabel}
            </span>
          )}
        </div>

        <div className={s.results} ref={listRef} role="listbox" aria-label={t("palette.label")}>
          {failure !== null && (
            <div className={s.state}>
              <FailureNotice
                failure={failure}
                title={failureTitle}
                onRetry={retryFailed}
                retryLabel={tCommon("action.retry")}
              />
            </div>
          )}

          {/* The sheet opens onto its first search. Rows in outline beat an
              empty panel that reads as "nothing matches". */}
          {searchQuery.isPending && (
            <div className={s.state}>
              <BusyStatus label={t("palette.searching")} size={14} />
              <div className={s.stateSkeleton}>
                <SkeletonRows count={4} height="var(--space-6)" />
              </div>
            </div>
          )}

          {hits.length > 0 && <div className={s.groupLabel}>{t("palette.groupConnections")}</div>}
          {hits.map((hit, i) => {
            const item = items[i];
            const key = item?.key ?? `hit:${hit.node.id}`;
            return (
              <button
                key={key}
                type="button"
                role="option"
                data-key={key}
                aria-selected={active === i}
                className={clsx(s.item, active === i && s.active)}
                onMouseEnter={() => setActive(i)}
                onClick={(e) => activate({ kind: "hit", key, hit }, e.ctrlKey || e.metaKey)}
              >
                <span
                  className={clsx(
                    s.itemGlyph,
                    hit.node.kind === "connection" && protocolClass(hit.node.protocol),
                  )}
                >
                  <Icon name={nodeGlyph(hit.node)} size={14} />
                </span>
                <span className={s.itemName}>{highlight(hit.node.name, hit.nameMatches)}</span>
                <span className={s.subtitle}>{subtitleText(t, hit)}</span>
                {hit.node.tags.length > 0 && (
                  <Badge tone="neutral" mono>
                    {hit.node.tags[0]}
                  </Badge>
                )}
                <span className={s.itemSpacer} />
                <span className={s.path}>{hit.path}</span>
                {active === i && <span className={s.shortcut}>↵</span>}
              </button>
            );
          })}

          {hits.length > 0 && actions.length > 0 && <div className={s.groupRule} />}
          {actions.length > 0 && <div className={s.groupLabel}>{t("palette.groupActions")}</div>}
          {actions.map((action, i) => {
            const index = hits.length + i;
            const key = `act:${action.id}`;
            const busy = action.busy === true;
            const busyLabel = action.busyLabel ?? action.label;
            return (
              <button
                key={key}
                type="button"
                role="option"
                data-key={key}
                aria-selected={active === index}
                className={clsx(s.item, active === index && s.active)}
                disabled={busy}
                {...(busy ? { title: busyLabel } : {})}
                onMouseEnter={() => setActive(index)}
                onClick={() => activate({ kind: "action", key, action }, false)}
              >
                {/* The spinner replaces the action's own glyph, so the row
                    keeps its height and the label keeps its position. */}
                <span className={s.itemGlyph}>
                  {busy ? (
                    <Spinner size={14} label={busyLabel} />
                  ) : (
                    <Icon name={action.glyph} size={14} />
                  )}
                </span>
                <span className={s.itemName}>{busy ? busyLabel : action.label}</span>
                <span className={s.itemSpacer} />
                {action.shortcut !== undefined && !busy && (
                  <span className={s.shortcut}>{action.shortcut}</span>
                )}
              </button>
            );
          })}

          {searchQuery.isSuccess && items.length === 0 && (
            <div className={s.state}>{t("palette.noResults", { query: isolate(query) })}</div>
          )}
        </div>

        <div className={s.footer}>
          <span className={s.hint}>
            <span className={s.key}>↵</span> {t("palette.hintSelect")}
          </span>
          <span className={s.hint}>
            {/* eslint-disable-next-line remoter-i18n/no-literal-jsx-text --
                key names. A keycap says Ctrl whatever the interface language
                is (docs/features/i18n.md, "What is never translated"). */}
            <span className={s.key}>Ctrl ↵</span> {t("palette.hintEdit")}
          </span>
          <span className={s.chips}>
            {PREFIXES.map((prefix) => (
              <button
                key={prefix}
                type="button"
                className={s.chip}
                onClick={() => setQuery((q) => (q.startsWith(prefix) ? q : prefix))}
              >
                {prefix}
              </button>
            ))}
            <span>{t("palette.hintFilter")}</span>
          </span>
          <span className={s.footerSpacer} />
          <span className={s.assurance}>{t("palette.assurance")}</span>
        </div>
      </div>
    </div>
  );
}
