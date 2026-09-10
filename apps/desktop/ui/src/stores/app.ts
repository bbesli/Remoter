/**
 * Application-level UI state.
 *
 * Backend data lives in TanStack Query. This store holds only what the
 * interface itself owns: which screen is showing, which node is selected, and
 * the shell's layout.
 */

import { create } from "zustand";
import type { CreateVaultResult, ThemeName } from "@/lib/ipc";

export type Screen =
  | { name: "picker" }
  | { name: "create" }
  | { name: "unlock"; path: string }
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
