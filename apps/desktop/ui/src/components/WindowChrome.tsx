/**
 * Minimise, maximise and close for the frameless window.
 *
 * The window is created with `decorations: false`, so nothing outside the page
 * draws these — without them the window cannot be minimised, maximised or
 * closed at all, which is exactly what happened the first time this
 * application was run.
 *
 * It renders as an overlay pinned to the top-right rather than as a bar,
 * because every screen already draws its own title bar and a second one
 * stacked above it looked like a mistake. Dragging comes from
 * `data-tauri-drag-region` on those existing bars.
 *
 * `MainWindow` has its own controls in `TitleBar` and does not use this.
 */

import { useCallback, useEffect, useState } from "react";

import { useBlockingReason } from "@/hooks/useModalRegistration";
import s from "./WindowChrome.module.css";

const TEXT = {
  /** Shown when closing the window would destroy something unrecoverable. */
  confirmClose: (atStake: string) =>
    `Close Remoter and lose ${atStake}? This cannot be undone.`,
  minimise: "Minimise",
  maximise: "Maximise",
  restore: "Restore",
  close: "Close",

  /**
   * These three buttons are the whole of the window's chrome. If one refuses
   * and says nothing, the window looks stuck — which is how the missing
   * controls were noticed in the first place.
   */
  controlFailed: (action: string) => `${action} was refused by the window manager.`,
  noWindow:
    "This page is not running inside the Remoter window, so the window controls do nothing here.",
} as const;

interface WindowHandle {
  minimize(): Promise<void>;
  toggleMaximize(): Promise<void>;
  close(): Promise<void>;
}

export function WindowControls() {
  const [maximised, setMaximised] = useState(false);
  const atStake = useBlockingReason();
  const [failure, setFailure] = useState<string | null>(null);

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
          // See above: there is no window to drive. Said out loud, because a
          // control that silently does nothing reads as a defect.
          setFailure(TEXT.noWindow);
          return;
        }
        try {
          await fn(win);
          setFailure(null);
        } catch {
          setFailure(TEXT.controlFailed(action));
        }
      })();
    },
    [],
  );

  return (
    <div className={s.controls}>
      {failure !== null && (
        <span className={s.failure} role="alert" title={failure}>
          {failure}
        </span>
      )}
      <button
        type="button"
        className={s.control}
        onClick={() => withWindow(TEXT.minimise, (w) => w.minimize())}
        aria-label={TEXT.minimise}
        title={TEXT.minimise}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
            <path d="M0 5h10" stroke="currentColor" strokeWidth="1.2" />
          </svg>
      </button>
      <button
        type="button"
        className={s.control}
        onClick={() =>
          withWindow(maximised ? TEXT.restore : TEXT.maximise, (w) => w.toggleMaximize())
        }
        aria-label={maximised ? TEXT.restore : TEXT.maximise}
        title={maximised ? TEXT.restore : TEXT.maximise}
        >
          {maximised ? (
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <path
                d="M2.5 2.5V0.6h6.9v6.9H7.5M0.6 2.5h6.9v6.9H0.6z"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.1"
              />
            </svg>
          ) : (
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <rect
                x="0.6"
                y="0.6"
                width="8.8"
                height="8.8"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.1"
              />
            </svg>
          )}
      </button>
      <button
        type="button"
        className={`${s.control} ${s.close}`}
        onClick={() => {
          // A dialog can refuse Escape, refuse a backdrop click and disable its
          // own close button, and still be defeated by this control. That
          // matters for exactly one thing today, and it is the worst thing to
          // lose: a recovery key is shown once and cannot be asked for again.
          if (atStake !== null && !window.confirm(TEXT.confirmClose(atStake))) return;
          withWindow(TEXT.close, (w) => w.close());
        }}
        aria-label={TEXT.close}
        title={TEXT.close}
        >
          <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
            <path d="M0.7 0.7l8.6 8.6M9.3 0.7L0.7 9.3" stroke="currentColor" strokeWidth="1.2" />
          </svg>
      </button>
    </div>
  );
}
