/**
 * The window's own title bar.
 *
 * The Tauri window is created with `decorations: false`, so dragging,
 * maximising and closing are ours to provide. Dragging is delegated to the
 * compositor through `data-tauri-drag-region` rather than tracked in
 * JavaScript — a JS drag loop fights the window manager on Wayland and on
 * tiling compositors, and loses.
 *
 * Control placement follows the platform: right on Linux and Windows, which
 * are the v0.1 targets.
 *
 * This bar draws the window controls itself, in the flow of the bar, so it is
 * the one header that does not reserve `--window-controls-w`: the main window
 * does not render the `WindowControls` overlay over it. Every other screen
 * does, and must reserve that width or its rightmost control sits under the
 * close button.
 *
 * The three vault screens are reached from here through the store rather than
 * through props. They are navigation and nothing else — no shell state to
 * coordinate, no mutation to run — and the prop contract belongs to
 * `MainWindow`, which is not this agent's file to widen.
 */

import { useCallback, useEffect, useState } from "react";

import { Mark } from "@/components/Mark";
import { Icon, type IconName } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import type { VaultState } from "@/lib/ipc";
import { useApp, type Screen } from "@/stores/app";
import s from "./TitleBar.module.css";

const TEXT = {
  appName: "Remoter",
  unlocked: "unlocked",
  locked: "locked",
  lock: "Lock the vault",
  lockAlreadyLocked: "There is no unlocked vault to lock.",
  lockInProgress: "Locking the vault…",
  /** Short enough for a 38px bar; the tooltip carries the full sentence. */
  lockingShort: "Locking…",
  settings: "Settings",
  vaultSettings: "Vault settings",
  audit: "Audit log",
  importer: "Import connections",
  /**
   * All three read or write the open vault. A button that refuses a click
   * without saying why reads as a broken button, so the tooltip carries the
   * reason rather than the bare label.
   */
  needsVault: (action: string) => `${action} needs an unlocked vault.`,
  minimise: "Minimise",
  maximise: "Maximise",
  restore: "Restore",
  close: "Close",
  noVault: "No vault open",

  /**
   * The window controls are the one place where doing nothing is
   * indistinguishable from being broken — that is exactly how the missing
   * controls were found in the first place. So a refusal says so.
   */
  controlFailed: (action: string) => `${action} was refused by the window manager.`,
  noWindow:
    "This page is not running inside the Remoter window, so the window controls do nothing here.",
} as const;

/** The slice of the Tauri window this bar drives. */
interface WindowHandle {
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  close(): Promise<void>;
}

interface TitleBarProps {
  vault: VaultState | undefined;
  onLock: () => void;
  locking?: boolean | undefined;
  onSettings: () => void;
}

/** The vault-scoped screens this bar reaches, in the order they are shown. */
const VAULT_SCREENS: readonly { screen: Screen; label: string; glyph: IconName }[] = [
  { screen: { name: "import" }, label: TEXT.importer, glyph: "download" },
  { screen: { name: "audit" }, label: TEXT.audit, glyph: "file" },
  { screen: { name: "vault-settings" }, label: TEXT.vaultSettings, glyph: "shield" },
];

export function TitleBar({ vault, onLock, locking = false, onSettings }: TitleBarProps) {
  const go = useApp((st) => st.go);
  const [maximised, setMaximised] = useState(false);
  // Null until a control is actually pressed and refused; the bar stays clean
  // in the normal case.
  const [controlFailure, setControlFailure] = useState<string | null>(null);

  // The window can be maximised by a double-click on the drag region or by the
  // compositor itself, so the glyph tracks the window rather than our clicks.
  useEffect(() => {
    let cancelled = false;
    let stop: (() => void) | undefined;

    void (async () => {
      try {
        const { getCurrentWindow } = await import("@tauri-apps/api/window");
        const win = getCurrentWindow();
        const initial = await win.isMaximized();
        if (!cancelled) setMaximised(initial);
        const unlisten = await win.onResized(() => {
          void win.isMaximized().then(
            (v) => {
              if (!cancelled) setMaximised(v);
            },
            () => {
              // Nothing to say: this is a passive observation of the window,
              // not an action the user took. The glyph keeps its last value.
            },
          );
        });
        if (cancelled) unlisten();
        else stop = unlisten;
      } catch {
        // Running outside the Tauri shell — a browser dev server or a test.
        // The controls stay inert rather than throwing on every render.
      }
    })();

    return () => {
      cancelled = true;
      stop?.();
    };
  }, []);

  const withWindow = useCallback(
    (action: string, fn: (win: WindowHandle) => Promise<void>) => {
      void (async () => {
        let win: WindowHandle;
        try {
          const { getCurrentWindow } = await import("@tauri-apps/api/window");
          win = getCurrentWindow();
        } catch {
          // A browser dev server or a test. Distinguished from a refusal
          // below, because the two need different words.
          setControlFailure(TEXT.noWindow);
          return;
        }
        try {
          await fn(win);
          setControlFailure(null);
        } catch {
          setControlFailure(TEXT.controlFailed(action));
        }
      })();
    },
    [],
  );

  const onMinimise = useCallback(() => {
    withWindow(TEXT.minimise, (win) => win.minimize());
  }, [withWindow]);

  const onToggleMaximise = useCallback(() => {
    withWindow(maximised ? TEXT.restore : TEXT.maximise, (win) => win.toggleMaximize());
  }, [withWindow, maximised]);

  const onClose = useCallback(() => {
    withWindow(TEXT.close, (win) => win.close());
  }, [withWindow]);

  const unlocked = vault?.unlocked === true;
  const label = vault?.label ?? null;
  const lockTitle = locking
    ? TEXT.lockInProgress
    : unlocked
      ? TEXT.lock
      : TEXT.lockAlreadyLocked;

  return (
    <header className={s.bar} data-tauri-drag-region>
      <Mark size={18} />
      <span className={s.app} data-tauri-drag-region>
        {TEXT.appName}
      </span>
      <span className={s.dash} data-tauri-drag-region aria-hidden="true">
        —
      </span>
      <span className={s.vaultLabel} data-tauri-drag-region title={label ?? TEXT.noVault}>
        {label ?? TEXT.noVault}
      </span>

      <div className={s.spacer} data-tauri-drag-region />

      {controlFailure !== null && (
        <span className={s.controlFailure} role="alert" title={controlFailure}>
          <Icon name="alert" size={12} />
          <span className={s.controlFailureText}>{controlFailure}</span>
        </span>
      )}

      <span className={unlocked ? s.pillUnlocked : s.pillLocked}>
        <Icon name={unlocked ? "unlock" : "lock"} size={11} />
        <span className={s.pillText}>{unlocked ? TEXT.unlocked : TEXT.locked}</span>
      </span>

      {/* A lock takes a moment and the pill above it does not change until it
          lands, so the bar says what is happening in words as well. */}
      {locking && (
        <span className={s.busy} role="status">
          {TEXT.lockingShort}
        </span>
      )}

      {/* The tooltip carries the reason rather than the bare label whenever
          the button refuses a click; "why not?" is the only question a
          disabled control raises. */}
      <button
        type="button"
        className={s.iconButton}
        title={lockTitle}
        aria-label={lockTitle}
        onClick={onLock}
        disabled={locking || !unlocked}
      >
        {locking ? (
          <Spinner size={14} label={TEXT.lockInProgress} />
        ) : (
          <Icon name="lock" size={15} />
        )}
      </button>

      {/* The vault's own screens sit beside the lock, because that is the part
          of the bar that is about the vault rather than about the window. */}
      {VAULT_SCREENS.map((entry) => (
        <button
          key={entry.screen.name}
          type="button"
          className={s.iconButton}
          title={unlocked ? entry.label : TEXT.needsVault(entry.label)}
          aria-label={entry.label}
          onClick={() => go(entry.screen)}
          disabled={!unlocked}
        >
          <Icon name={entry.glyph} size={15} />
        </button>
      ))}

      <button
        type="button"
        className={s.iconButton}
        title={TEXT.settings}
        aria-label={TEXT.settings}
        onClick={onSettings}
      >
        <Icon name="settings" size={15} />
      </button>

      <div className={s.controls}>
        <button
          type="button"
          className={s.control}
          title={TEXT.minimise}
          aria-label={TEXT.minimise}
          onClick={onMinimise}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M6 12h12" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
          </svg>
        </button>
        <button
          type="button"
          className={s.control}
          title={maximised ? TEXT.restore : TEXT.maximise}
          aria-label={maximised ? TEXT.restore : TEXT.maximise}
          onClick={onToggleMaximise}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            {maximised ? (
              <g stroke="currentColor" strokeWidth="2">
                <rect x="4" y="8" width="11" height="11" rx="1.5" />
                <path d="M9 8V6.5A1.5 1.5 0 0 1 10.5 5H18a1.5 1.5 0 0 1 1.5 1.5V14a1.5 1.5 0 0 1-1.5 1.5h-1.5" />
              </g>
            ) : (
              <rect
                x="6"
                y="6"
                width="12"
                height="12"
                rx="1.5"
                stroke="currentColor"
                strokeWidth="2"
              />
            )}
          </svg>
        </button>
        <button
          type="button"
          className={[s.control, s.closeControl].join(" ")}
          title={TEXT.close}
          aria-label={TEXT.close}
          onClick={onClose}
        >
          <svg width="13" height="13" viewBox="0 0 24 24" aria-hidden="true">
            <path
              d="M7 7l10 10M17 7L7 17"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
            />
          </svg>
        </button>
      </div>
    </header>
  );
}
