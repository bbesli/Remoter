/**
 * The application's home: title bar, tree, session area, inspector, footer.
 *
 * The chrome budget is fixed — 38 + 36 + 28 + 26 vertically, 268 and 320
 * horizontally — because the session is the content and everything else has
 * to justify the pixels it takes. The layout is a flex column of fixed-height
 * bars around one `min-height: 0` row; that is what lets the session area,
 * the tree and the inspector each scroll independently instead of pushing the
 * footer off the bottom of the window.
 */

import { memo, useCallback, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { isolate, isolateLtr, useT } from "@/i18n";
import { asFailure, ipc, type IpcFailure, type TreeNode } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import {
  StatusBarPrefixRow,
  useShortcutDispatcher,
  useShortcutGroup,
} from "@/hooks/keyboard";
import { ConnectionTree } from "@/features/connections/ConnectionTree";
import { CommandPalette } from "@/features/connections/CommandPalette";
import {
  SessionPanels,
  SessionSurface,
  closeAllSessions,
  isTerminalFocused,
  useSessions,
  type SessionRecord,
} from "@/features/sessions";
import { FilePane } from "@/features/files";
import { TitleBar } from "./TitleBar";
import { TabStrip } from "./TabStrip";
import { StatusBar } from "./StatusBar";
import { Footer } from "./Footer";
import { Inspector } from "./Inspector";
import { EmptyVault } from "./EmptyVault";
import { KdfUpgradeBar } from "./KdfUpgradeBar";
import { canDockFilePane } from "./filePanes";
import { useConnectionEditor } from "@/features/connections/ConnectionEditor";
import s from "./MainWindow.module.css";

/** How often the core is asked for the vault's state, including auto-lock. */
const VAULT_POLL_MS = 30_000;



/** TanStack reports "no error" as `null`; a rejected query can also be `undefined`. */
function failureOf(error: unknown): IpcFailure | null {
  return error === null || error === undefined ? null : asFailure(error);
}

/**
 * What fills the session area when no session is open.
 *
 * It names what is selected and how to open it, rather than drawing an empty
 * terminal: a terminal with nothing behind it is read as a bug the first time
 * a keystroke does nothing.
 */
function SessionPlaceholder({ node }: { node: TreeNode | undefined }) {
  const t = useT("shell");

  if (node === undefined) {
    return (
      <div className={s.placeholder}>
        <p className={s.placeholderTitle}>{t("main.nothingSelected")}</p>
        <p className={s.placeholderBody}>{t("main.nothingSelectedBody")}</p>
      </div>
    );
  }

  const target =
    node.host === null || node.host === ""
      ? null
      : node.port === null
        ? node.host
        : `${node.host}:${String(node.port)}`;

  return (
    <div className={s.placeholder}>
      <p className={s.placeholderKind}>
        {node.kind === "connection"
          ? // A protocol name — SSH, RDP, VNC, SFTP — is never translated.
            (node.protocol ?? t("main.noProtocol"))
          : t(`main.nodeKind.${node.kind}`)}
      </p>
      {/* Name, address and description are the user's own text and a remote
          machine's, in whatever script they wrote them. Isolated so they
          cannot reorder the layout around them. */}
      <p className={s.placeholderTitle}>{isolate(node.name)}</p>
      {target !== null && <p className={s.placeholderTarget}>{isolateLtr(target)}</p>}
      {node.description !== "" && (
        <p className={s.placeholderBody}>{isolate(node.description)}</p>
      )}
      <p className={s.placeholderBody}>
        {node.kind === "connection" ? t("main.connectHint") : t("main.folderSelected")}
      </p>
    </div>
  );
}

/**
 * One file pane, docked under the session it belongs to.
 *
 * Memoised, and its props are four primitives, for a reason that is not
 * premature: this window re-renders on every session metrics flush — once a
 * second, per open session — and the pane below it can be drawing a thousand
 * listing rows. Without the memo those rows are reconciled every second for a
 * byte counter in the status bar. The close handler is built here rather than
 * passed in so that it is stable across those renders, which is what lets the
 * memo hold.
 */
const DockedFilePane = memo(function DockedFilePane({
  tabId,
  sessionId,
  name,
  active,
}: {
  tabId: string;
  sessionId: number | null;
  name: string;
  active: boolean;
}) {
  const toggleFilePane = useApp((st) => st.toggleFilePane);
  const onClose = useCallback(() => {
    toggleFilePane(tabId);
  }, [toggleFilePane, tabId]);

  return (
    <div className={s.filesDock} hidden={!active}>
      <FilePane sessionId={sessionId} name={name} onClose={onClose} />
    </div>
  );
});

export function MainWindow() {
  const t = useT("shell");
  const tCommon = useT("common");
  const queryClient = useQueryClient();
  const [panelsOpen, setPanelsOpen] = useState(false);

  const go = useApp((st) => st.go);
  const select = useApp((st) => st.select);
  const selectedNodeId = useApp((st) => st.selectedNodeId);
  const sidebarOpen = useApp((st) => st.sidebarOpen);
  const toggleSidebar = useApp((st) => st.toggleSidebar);
  const inspectorOpen = useApp((st) => st.inspectorOpen);
  const toggleInspector = useApp((st) => st.toggleInspector);

  // The session in front. The status bar describes what fills the session
  // area, and when a session does, that is what it describes.
  const activeTabId = useSessions((st) => st.activeTabId);
  const sessionsById = useSessions((st) => st.byId);
  const sessionOrder = useSessions((st) => st.order);
  const sessionCount = sessionOrder.length;
  const activeSession = activeTabId === null ? undefined : sessionsById[activeTabId];

  /*
   * The file panes docked under a shell, one per tab that asked for one.
   *
   * Every one of them is mounted whenever its session is running — not only the
   * tab in front — and the ones behind are hidden with `hidden` rather than
   * unmounted. A pane is an open SFTP channel with a transfer queue draining
   * through it, and unmounting closes it, which cancels whatever it is copying.
   * "Switch to another tab while that downloads" has to be true, and this is
   * what makes it true.
   *
   * A tab whose session has ended drops out on its own: the record stops being
   * dockable, the pane unmounts and `sftp_close` runs. The tab id stays in the
   * store, so a reconnect brings the pane back rather than making the user ask
   * for it twice.
   */
  const filePaneTabs = useApp((st) => st.filePaneTabs);
  const dockedPanes = useMemo(
    () =>
      sessionOrder
        .filter((tabId) => filePaneTabs.has(tabId))
        .map((tabId) => sessionsById[tabId])
        .filter((record): record is SessionRecord => canDockFilePane(record)),
    [sessionOrder, sessionsById, filePaneTabs],
  );

  /** Set when the window manager refused a full-screen toggle. */
  const [windowFailure, setWindowFailure] = useState<string | null>(null);

  // Keys come from lib/queryKeys.ts, never from a literal here. This shell and
  // the connection editor were reading the same data under different keys, so a
  // saved edit updated the tree and left the status bar and inspector showing
  // the host, port and username the connection had before it.
  const vaultQuery = useQuery({
    queryKey: qk.vaultState(),
    queryFn: () => ipc.vaultState(),
    refetchInterval: VAULT_POLL_MS,
  });
  const vault = vaultQuery.data;

  const treeQuery = useQuery({
    queryKey: qk.nodes(),
    queryFn: () => ipc.listNodes(),
    enabled: vault?.unlocked === true,
  });
  const nodes = useMemo(() => treeQuery.data ?? [], [treeQuery.data]);

  const selectedNode = useMemo(
    () => (selectedNodeId === null ? undefined : nodes.find((n) => n.id === selectedNodeId)),
    [nodes, selectedNodeId],
  );

  // Resolution is per-connection and comparatively expensive on a deep tree,
  // so it is asked for only when something can actually consume it.
  const resolveEnabled =
    selectedNode !== undefined &&
    selectedNode.kind === "connection" &&
    vault?.unlocked === true;

  const resolveQuery = useQuery({
    queryKey: qk.resolve(selectedNode?.id ?? ""),
    queryFn: () => ipc.resolveNode(selectedNode?.id ?? ""),
    enabled: resolveEnabled,
  });

  const resolveError = failureOf(resolveQuery.error);
  const vaultError = failureOf(vaultQuery.error);
  const treeError = failureOf(treeQuery.error);

  /**
   * Locking clears the query cache as well as the core's keys. Everything
   * cached here was decrypted from the vault; leaving it in memory behind a
   * locked vault would defeat the lock for anything that can read the heap.
   *
   * A refused lock leaves the vault open, so the failure has to be seen: it is
   * shown beside whichever control asked for it, which is what `destination`
   * identifies — the title bar's lock button, or the empty-vault card's "open
   * a different vault".
   */
  const lock = useMutation({
    // Sessions go before the vault does. Locking from here is a deliberate
    // "I am leaving this machine", and leaving live shells attached to a
    // locked vault would keep credentials in a process nobody is watching.
    // The vault's own idle policy is a different question and stays the
    // core's; this is only the button.
    mutationFn: (destination: "unlock" | "picker") =>
      closeAllSessions()
        .then(() => ipc.lockVault())
        .then(() => destination),
    onSuccess: (destination) => {
      const path = vault?.path ?? null;
      queryClient.clear();
      select(null);
      go(destination === "picker" || path === null ? { name: "picker" } : { name: "unlock", path });
    },
  });

  const lockError = failureOf(lock.error);
  const lockErrorFrom = lockError === null ? null : lock.variables ?? "unlock";


  const openEditor = useConnectionEditor((st) => st.open);

  const onLock = useCallback(() => {
    lock.mutate("unlock");
  }, [lock]);

  const onOpenAnother = useCallback(() => {
    lock.mutate("picker");
  }, [lock]);

  const onCreateConnection = useCallback(() => {
    openEditor({ mode: "create", parentId: null, kind: "connection" });
  }, [openEditor]);

  const onSettings = useCallback(() => {
    go({ name: "settings" });
  }, [go]);

  const onCreateFolder = useCallback(() => {
    openEditor({ mode: "create", parentId: null, kind: "folder" });
  }, [openEditor]);

  const selectedId = selectedNode?.id;
  const onEditSelected = useCallback(() => {
    if (selectedId === undefined) return;
    openEditor({ mode: "edit", nodeId: selectedId });
  }, [openEditor, selectedId]);

  /**
   * Full screen is the window's, not a CSS class: the session is meant to fill
   * the display, and a "full screen" that stayed inside a windowed frame would
   * be a control that does not do what it says.
   */
  const onToggleFullscreen = useCallback(() => {
    void (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const win = getCurrentWindow();
        await win.setFullscreen(!(await win.isFullscreen()));
        setWindowFailure(null);
      } catch {
        // Outside the Tauri shell — a browser preview or a test — there is no
        // window to resize. Saying so beats a key that appears to do nothing.
        setWindowFailure(t("main.fullscreenFailedBody"));
      }
    })();
  }, [t]);

  /*
   * Every binding the shell owns, in one declaration.
   *
   * `null` means "not right now", and the keystroke is left alone rather than
   * swallowed: F11 with no session open, or Ctrl+L with no vault, must reach
   * whatever else wants them. The record is exhaustive by type — an action
   * added to the catalogue with `owner: "shell"` fails the build until it has
   * a handler here, which is what stops the settings table documenting a key
   * nothing implements.
   */
  useShortcutGroup("shell", {
    "vault.lock": vault?.unlocked === true && !lock.isPending ? onLock : null,
    "connection.new": onCreateConnection,
    "folder.new": onCreateFolder,
    "node.edit": selectedId === undefined ? null : onEditSelected,
    "sidebar.toggle": toggleSidebar,
    "inspector.toggle": toggleInspector,
    "session.fullscreen": sessionCount === 0 ? null : onToggleFullscreen,
  });

  // The one window-level listener. Everything above only declares handlers.
  useShortcutDispatcher(isTerminalFocused);

  const vaultEmpty = vault?.unlocked === true && treeQuery.isSuccess && nodes.length === 0;

  // What fills the session area when no session is open. It is passed to
  // the surface rather than chosen against it, so a live terminal is never
  // unmounted to show a vault notice — a locked vault with the policy set to
  // keep sessions running still has sessions to draw.
  const sessionFallback = (
    vaultError !== null ? (
                <div className={s.sessionNotice}>
                  <FailureNotice
                    failure={vaultError}
                    title={t("main.vaultStateFailed")}
                    onRetry={() => void vaultQuery.refetch()}
                    retryLabel={tCommon("action.retry")}
                  />
                </div>
              ) : treeError !== null ? (
                <div className={s.sessionNotice}>
                  <FailureNotice
                    failure={treeError}
                    title={t("main.treeFailed")}
                    onRetry={() => void treeQuery.refetch()}
                    retryLabel={tCommon("action.retry")}
                  />
                </div>
              ) : vaultQuery.isPending ? (
                // Neither "empty" nor "locked" is known yet. Saying so beats
                // flashing one of them and then correcting it.
                <div className={s.sessionNotice}>
                  <BusyStatus label={t("main.checkingVault")} size={16} />
                </div>
              ) : vault !== undefined && !vault.unlocked ? (
                // The core can lock the vault without the interface asking —
                // the idle timeout does exactly that. Left unsaid, the window
                // simply stops having any content in it.
                <div className={s.sessionNotice}>
                  <Callout tone="warning" title={t("main.lockedTitle")}>
                    <p className={s.noticeBody}>{t("main.lockedBody")}</p>
                    <div className={s.noticeActions}>
                      <Button
                        variant="primary"
                        size="sm"
                        onClick={() =>
                          go(
                            vault.path === null
                              ? { name: "picker" }
                              : { name: "unlock", path: vault.path },
                          )
                        }
                      >
                        {vault.path === null ? t("main.lockedNoPath") : t("main.lockedAction")}
                      </Button>
                    </div>
                  </Callout>
                </div>
              ) : treeQuery.isPending ? (
                // The shape of what is coming, rather than a blank panel that
                // reads as "this vault has nothing in it".
                <div className={s.placeholder}>
                  <BusyStatus label={t("main.readingTree")} size={16} />
                  <div className={s.placeholderSkeleton}>
                    <SkeletonRows count={3} height="var(--space-5)" />
                  </div>
                </div>
              ) : vaultEmpty ? (
                <EmptyVault
                  vaultPath={vault?.path ?? null}
                  onCreateConnection={onCreateConnection}
                  onOpenAnother={onOpenAnother}
                  openingAnother={lock.isPending}
                  openAnotherFailure={lockErrorFrom === "picker" ? lockError : null}
                />
              ) : (
                <SessionPlaceholder node={selectedNode} />
              )
  );

  return (
    <div className={s.window}>
      <TitleBar
        vault={vault}
        onLock={onLock}
        locking={lock.isPending}
        onSettings={onSettings}
      />

      {/* Directly under the button that was pressed: a lock that did not
          happen is the one failure the title bar must not keep to itself. */}
      {lockError !== null && lockErrorFrom === "unlock" && (
        <div className={s.notice}>
          <FailureNotice
            failure={lockError}
            title={t("main.lockFailed")}
            onRetry={onLock}
            retryLabel={tCommon("action.retry")}
          >
            <Button variant="ghost" size="sm" onClick={() => lock.reset()}>
              {tCommon("action.dismiss")}
            </Button>
          </FailureNotice>
        </div>
      )}

      {/* A shortcut that appears to do nothing is the failure this application
          keeps shipping. If the window manager refused the toggle, say so. */}
      {windowFailure !== null && (
        <div className={s.notice}>
          <Callout tone="warning" title={t("main.fullscreenFailedTitle")}>
            <p className={s.noticeBody}>{windowFailure}</p>
            <div className={s.noticeActions}>
              <Button variant="ghost" size="sm" onClick={() => setWindowFailure(null)}>
                {tCommon("action.dismiss")}
              </Button>
            </div>
          </Callout>
        </div>
      )}

      {/* Above the body, below a failed lock: the vault opened, so this is a
          suggestion rather than a failure and must not take the session area.
          It renders nothing unless the core says a slot is below the floor. */}
      <KdfUpgradeBar vault={vault} />

      <div className={s.body}>
        {sidebarOpen && (
          <nav className={s.sidebar} aria-label={t("main.sidebarLabel")}>
            <ConnectionTree />
          </nav>
        )}

        <main className={s.centre}>
          <TabStrip />

          <div className={s.session}>
            <div className={s.sessionPrimary}>
              <SessionSurface empty={sessionFallback} />
            </div>

            {/* Under the session rather than over it: the terminal keeps the
                keyboard and stays readable, which is the point of browsing
                files on a host you are working on. Hidden — not unmounted —
                when its tab is not the one in front. */}
            {dockedPanes.map((record) => (
              <DockedFilePane
                key={record.tabId}
                tabId={record.tabId}
                sessionId={record.sessionId}
                name={record.name}
                active={record.tabId === activeTabId}
              />
            ))}
          </div>

          {/* The bar describes the session; the hint beside it describes the
              keyboard, which changes shape while a terminal has focus. */}
          <StatusBarPrefixRow isTerminalFocused={isTerminalFocused}>
            <StatusBar
              session={activeSession}
              node={selectedNode}
              effective={resolveQuery.data}
              resolving={resolveEnabled && resolveQuery.isPending}
              error={resolveError}
              onShowDetail={inspectorOpen ? null : toggleInspector}
            />
          </StatusBarPrefixRow>
        </main>

        {inspectorOpen && (
          <Inspector
            node={selectedNode}
            effective={resolveQuery.data}
            loading={resolveEnabled && resolveQuery.isPending}
            enabled={resolveEnabled}
            error={resolveError}
            onRetry={() => void resolveQuery.refetch()}
            onClose={toggleInspector}
          />
        )}
      </div>

      <Footer vault={vault} onShowPanels={() => setPanelsOpen(true)} />

      {panelsOpen && <SessionPanels onClose={() => setPanelsOpen(false)} />}

      <CommandPalette />
    </div>
  );
}
