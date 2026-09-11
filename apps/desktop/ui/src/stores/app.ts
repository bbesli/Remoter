/**
 * Application-level UI state.
 *
 * Backend data lives in TanStack Query. This store holds only what the
 * interface itself owns: which screen is showing, which node is selected, and
 * the shell's layout.
 */

import { create } from "zustand";
import type { CreateVaultResult, ThemeName } from "@/lib/ipc";
import type { RelockNotice } from "@/features/vault/lock";

export type Screen =
  | { name: "picker" }
  | { name: "create" }
  /**
   * Asking for the password of a known vault.
   *
   * `relock` is what distinguishes the two ways of arriving here, and it is
   * required rather than optional so that every caller has to answer the
   * question. `null` is a cold open — the user picked this file and is opening
   * it. Non-null means the vault was already open and locked under them, and
   * the screen owes them two sentences it cannot otherwise know to write: why
   * it locked, and what happened to the sessions they had running.
   */
  | { name: "unlock"; path: string; relock: RelockNotice | null }
  /** Shown once, immediately after creation, before the vault opens. */
  | { name: "recovery"; result: CreateVaultResult }
  | { name: "main" }
  /** Reached from the title bar and the palette; leaves by going back. */
  | { name: "settings" }
  /**
   * The open vault's own settings: key slots, auto-lock, backups. Distinct from
   * `settings`, which is this machine's preferences and travels with the
   * installation rather than with the vault file.
   */
  | { name: "vault-settings" }
  /** The audit log of the open vault. */
  | { name: "audit" }
  /**
   * The import wizard. Reached from the title bar, the palette, and the
   * empty-vault card — which is where most people meet it.
   */
  | { name: "import" };

interface AppStore {
  screen: Screen;
  /**
   * Where the user was before the current screen, so settings has somewhere to
   * return to. Null on the first screen of the session.
   */
  previousScreen: Screen | null;
  go: (screen: Screen) => void;
  /** Escape and the Back control. Falls back to the picker when there is no history. */
  goBack: () => void;

  theme: ThemeName;
  setTheme: (t: ThemeName) => void;

  locale: string;
  setLocale: (l: string) => void;

  selectedNodeId: string | null;
  select: (id: string | null) => void;

  expanded: Set<string>;
  toggleExpanded: (id: string) => void;

  sidebarOpen: boolean;
  toggleSidebar: () => void;

  inspectorOpen: boolean;
  toggleInspector: () => void;

  paletteOpen: boolean;
  setPaletteOpen: (open: boolean) => void;

  /**
   * The session tabs that have a file pane docked under them.
   *
   * A set rather than a single id, because a docked pane is not a view of the
   * tab in front — it is a live SFTP channel with a transfer queue draining
   * through it. Closing it cancels what it is copying. So a pane opened on
   * `web-01` stays open while the user works in `db-01`'s shell, and the shell
   * mounts every one of them, hiding the ones whose tab is not in front.
   *
   * Tab ids, not session ids: the pane follows the tab across a reconnect, and
   * the tab is what the user closes. An id whose tab has gone matches nothing
   * and mounts nothing — ids are unique for the life of the process, so a stale
   * one can never be reused by a later tab.
   */
  filePaneTabs: ReadonlySet<string>;
  toggleFilePane: (tabId: string) => void;

  /**
   * Which modal surfaces are currently open.
   *
   * There is one registry because there were none, and the gaps showed: the
   * command palette's Ctrl+K guard knew about the connection editor but not
   * about the delete confirmation, so the palette could open on top of it with
   * two focus traps fighting over Tab and the palette rendered invisibly
   * behind. F4 toggled the inspector underneath all three. Anything that takes
   * over the keyboard registers here, and anything with a global shortcut asks
   * before acting.
   */
  openModals: ReadonlySet<string>;
  pushModal: (id: string) => void;
  popModal: (id: string) => void;

  /**
   * Modals that must not be dismissed, and what is at stake if one is.
   *
   * A rotated recovery key is returned exactly once and can never be asked for
   * again. Its dialog therefore refuses Escape, refuses a backdrop click and
   * disables its own close button — but none of that stops the user closing
   * the WINDOW, which loses the key just as permanently. The window controls
   * ask before closing while one of these is open, and say what would be lost.
   */
  blockingModals: ReadonlyMap<string, string>;
  pushBlockingModal: (id: string, atStake: string) => void;
  popBlockingModal: (id: string) => void;
}

export const useApp = create<AppStore>((set) => ({
  screen: { name: "picker" },
  previousScreen: null,
  // Navigating to the screen you are already on would otherwise make Back a
  // no-op that looks like a dead control.
  go: (screen) =>
    set((s) => (s.screen.name === screen.name ? { screen } : { screen, previousScreen: s.screen })),
  goBack: () =>
    set((s) => ({ screen: s.previousScreen ?? { name: "picker" }, previousScreen: null })),

  theme: "system",
  setTheme: (theme) => set({ theme }),

  locale: "en",
  setLocale: (locale) => set({ locale }),

  selectedNodeId: null,
  select: (selectedNodeId) => set({ selectedNodeId }),

  expanded: new Set<string>(),
  toggleExpanded: (id) =>
    set((s) => {
      const next = new Set(s.expanded);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return { expanded: next };
    }),

  sidebarOpen: true,
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

  // Closed by default: open-by-default costs 320px of session width permanently.
  inspectorOpen: false,
  toggleInspector: () => set((s) => ({ inspectorOpen: !s.inspectorOpen })),

  paletteOpen: false,
  setPaletteOpen: (paletteOpen) => set({ paletteOpen }),

  filePaneTabs: new Set<string>(),
  toggleFilePane: (tabId) =>
    set((s) => {
      const next = new Set(s.filePaneTabs);
      if (next.has(tabId)) next.delete(tabId);
      else next.add(tabId);
      return { filePaneTabs: next };
    }),

  blockingModals: new Map<string, string>(),
  pushBlockingModal: (id, atStake) =>
    set((s) => {
      if (s.blockingModals.get(id) === atStake) return {};
      const next = new Map(s.blockingModals);
      next.set(id, atStake);
      return { blockingModals: next };
    }),
  popBlockingModal: (id) =>
    set((s) => {
      if (!s.blockingModals.has(id)) return {};
      const next = new Map(s.blockingModals);
      next.delete(id);
      return { blockingModals: next };
    }),

  openModals: new Set<string>(),
  pushModal: (id) =>
    set((s) => {
      if (s.openModals.has(id)) return {};
      const next = new Set(s.openModals);
      next.add(id);
      return { openModals: next };
    }),
  popModal: (id) =>
    set((s) => {
      if (!s.openModals.has(id)) return {};
      const next = new Set(s.openModals);
      next.delete(id);
      return { openModals: next };
    }),
}));
