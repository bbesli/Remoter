/**
 * The screen an RDP or VNC session is seen on.
 *
 * The canvas underneath belongs to `surfaces.ts`, for the same reason a
 * terminal belongs to `terminals.ts`: it holds the only copy of the remote
 * screen that exists anywhere, and a component that could unmount it could
 * throw that copy away with no way to ask for it back. This component appends
 * it, sizes it, and draws the chrome around it.
 *
 * # What this surface can and cannot do, and why it says so
 *
 * It renders. Keyframes, deltas, copy-rects, both pixel formats, the cursor
 * shape, dropped-frame detection, fit, 1:1, integer zoom, and smart resize on a
 * server that opened the channel for it — all of that is live, because the
 * commands behind it exist.
 *
 * **It does not send keyboard or pointer input, and it says so on screen.** The
 * command surface in `crates/remoter-ipc` carries `session_input`, which takes
 * *bytes* and maps to `InputEvent::Bytes` — the terminal path. The RDP adapter
 * drops that variant and the VNC adapter refuses it, because a framebuffer
 * protocol needs `InputEvent::Key` and `InputEvent::Pointer`, and no Tauri
 * command constructs either. So there is no key handler and no pointer handler
 * on this element: a surface that swallowed keystrokes and dropped them would
 * be a control that does nothing, which is the one thing this interface is not
 * allowed to ship. `keymap.ts` is the translation those commands will need,
 * finished and tested, and `keymap.test.ts` walks a Turkish Q layout through it.
 *
 * The remote cursor shape is decoded and shown as a labelled swatch rather than
 * painted under the local pointer, and that is the same rule. A CSS cursor made
 * from the server's shape follows the *local* pointer; with no input on the
 * wire the remote pointer is not where the local one is, so an I-beam appearing
 * over a text field the user is not really hovering would be a claim about the
 * remote screen that is false.
 */

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";

import { Badge } from "@/components/Badge";
import { Icon } from "@/components/Icon";
import { isolate, useLocale, useT } from "@/i18n";
import { formatSize } from "./format";
import { frameDecodeKey } from "./frames";
import { requestDesktopSize } from "./manager";
import { cursorDataUrl } from "./presenter";
import { layoutFor, ZOOM_STEPS, type ScaleMode, type Size } from "./scaling";
import { useSessions, type SessionRecord } from "./store";
import { attachSurface, subscribeSurface, surfaceElement, surfaceStatus, surfaceUnavailable } from "./surfaces";

import s from "./FramebufferHost.module.css";

/**
 * How long the tab must stop changing size before a resizable server is asked
 * to follow it.
 *
 * A window drag produces a resize event per frame, and each one is a capability
 * exchange and a full repaint at the far end. Waiting for the drag to stop is
 * the difference between a resize and a denial of service.
 */
const SMART_RESIZE_SETTLE_MS = 350;

/** The label for each scale mode. A record, so a new mode is a compile error. */
const MODE_KEYS = {
  smart: "surface.framebuffer.scale.smart",
  fit: "surface.framebuffer.scale.fit",
  actual: "surface.framebuffer.scale.actual",
  zoom: "surface.framebuffer.scale.zoom",
} as const satisfies Record<ScaleMode, string>;

function useViewport(ref: React.RefObject<HTMLDivElement | null>): Size {
  const [viewport, setViewport] = useState<Size>({ width: 0, height: 0 });

  useEffect(() => {
    const element = ref.current;
    if (element === null || typeof ResizeObserver !== "function") return;
    const observer = new ResizeObserver(() => {
      setViewport({ width: element.clientWidth, height: element.clientHeight });
    });
    observer.observe(element);
    setViewport({ width: element.clientWidth, height: element.clientHeight });
    return () => observer.disconnect();
  }, [ref]);

  return viewport;
}

/**
 * The scaling controls, as a segmented set of toggles.
 *
 * Native buttons rather than `<Button>` so that each one can carry
 * `aria-pressed`: these are a set of states, not a row of actions, and a screen
 * reader that is told "Fit, button" four times cannot say which one is in
 * force. The visual weight comes from the module's own rules.
 */
function ScaleControls({ record }: { record: SessionRecord }) {
  const t = useT("sessions");
  const setScale = useSessions((st) => st.setScale);
  const { mode, zoom } = record.scale;
  // Smart resize is offered only where the adapter says the channel that
  // performs it is open. Drawing it on a server that refused would be a button
  // that does nothing.
  const resizable = record.opened?.capabilities.resizable === true;

  const choose = (next: ScaleMode, nextZoom = zoom) => {
    setScale(record.tabId, { mode: next, zoom: nextZoom });
  };

  const option = (
    key: string,
    pressed: boolean,
    label: string,
    help: string,
    onClick: () => void,
  ) => (
    <button
      key={key}
      type="button"
      className={s.option}
      aria-pressed={pressed}
      title={help}
      onClick={onClick}
    >
      {label}
    </button>
  );

  return (
    <div className={s.controls} role="group" aria-label={t("surface.framebuffer.scale.label")}>
      {resizable &&
        option("smart", mode === "smart", t(MODE_KEYS.smart), t("surface.framebuffer.scale.smartHelp"), () =>
          choose("smart"),
        )}
      {option("fit", mode === "fit", t(MODE_KEYS.fit), t("surface.framebuffer.scale.fitHelp"), () =>
        choose("fit"),
      )}
      {option(
        "actual",
        mode === "actual",
        t(MODE_KEYS.actual),
        t("surface.framebuffer.scale.actualHelp"),
        () => choose("actual"),
      )}
      {ZOOM_STEPS.map((step) =>
        option(
          `zoom-${String(step)}`,
          mode === "zoom" && zoom === step,
          t("surface.framebuffer.scale.zoomStep", { factor: step }),
          t("surface.framebuffer.scale.zoomHelp"),
          () => choose("zoom", step),
        ),
      )}
    </div>
  );
}

export function FramebufferHost({ record, active }: { record: SessionRecord; active: boolean }) {
  const t = useT("sessions");
  const { code: locale } = useLocale();
  const tabId = record.tabId;
  const ref = useRef<HTMLDivElement>(null);
  const viewport = useViewport(ref);

  useEffect(() => {
    const container = ref.current;
    if (container === null) return;
    return attachSurface(tabId, container);
  }, [tabId]);

  // The presenter notifies on structural change only — a size, a dropped
  // frame, a new cursor shape, a malformed message. Frames themselves are
  // counted and flushed on a timer, because re-rendering the shell thirty times
  // a second for a byte count nobody is reading is how a session stops being
  // interactive.
  const subscribe = useCallback(
    (listener: () => void) => subscribeSurface(tabId, listener),
    [tabId],
  );
  const status = useSyncExternalStore(
    subscribe,
    () => surfaceStatus(tabId),
    () => surfaceStatus(tabId),
  );

  const desktop = { width: status.width, height: status.height };
  const dpr = typeof window === "undefined" ? 1 : window.devicePixelRatio;
  const layout = layoutFor({
    mode: record.scale.mode,
    zoom: record.scale.zoom,
    desktop,
    viewport,
    devicePixelRatio: dpr,
  });

  // The element's CSS size is the scale; its backing store is always the remote
  // desktop's own size. `image-rendering` is the whole answer to "a zoom that
  // does not resample text into mush": at or above one device pixel per remote
  // pixel the compositor replicates whole pixels instead of interpolating them.
  useEffect(() => {
    const canvas = surfaceElement(tabId);
    if (canvas === null) return;
    canvas.style.width = `${String(layout.width)}px`;
    canvas.style.height = `${String(layout.height)}px`;
    canvas.style.imageRendering = layout.crisp ? "pixelated" : "auto";
  }, [tabId, layout.width, layout.height, layout.crisp]);

  // Smart resize, debounced. Only the active tab asks: a background tab has the
  // size it had when it was last in front, and making every open session
  // renegotiate its desktop on a window drag is a lot of far-end work for a
  // screen nobody is looking at.
  const smart = record.scale.mode === "smart";
  useEffect(() => {
    if (!smart || !active) return;
    if (viewport.width === 0 || viewport.height === 0) return;
    const timer = window.setTimeout(() => {
      requestDesktopSize(tabId, viewport, dpr);
    }, SMART_RESIZE_SETTLE_MS);
    return () => window.clearTimeout(timer);
  }, [smart, active, tabId, viewport, dpr]);

  const cursorUrl = useMemo(
    () => (status.cursor === null ? null : cursorDataUrl(status.cursor)),
    [status.cursor],
  );

  const unavailable = surfaceUnavailable(tabId);
  const viewOnly = record.viewOnly === true;
  const hasPixels = status.width > 0 && status.height > 0;

  return (
    <div
      className={active ? s.host : [s.host, s.hidden].join(" ")}
      aria-hidden={active ? undefined : true}
      data-tab={tabId}
    >
      <div
        ref={ref}
        className={s.stage}
        data-view-only={viewOnly ? "true" : undefined}
        role="img"
        aria-label={t("surface.framebuffer.label", { name: isolate(record.name) })}
      />

      {active && (
        <>
          <div className={s.topBar}>
            <ScaleControls record={record} />
          </div>

          <div className={s.notices}>
            {viewOnly && (
              <Badge tone="warning" title={t("surface.framebuffer.viewOnlyHelp")}>
                <Icon name="shield" size={12} />
                {t("surface.framebuffer.viewOnly")}
              </Badge>
            )}

            {/* Not a hint, not a tooltip: a standing statement, because the
                alternative is a user typing into a window that looks live. */}
            <p className={s.inputNotice}>
              <Icon name="alert" size={13} />
              <span>
                <strong className={s.inputTitle}>
                  {t("surface.framebuffer.inputUnavailable")}
                </strong>{" "}
                {t("surface.framebuffer.inputUnavailableWhy")}
              </span>
            </p>

            {unavailable && (
              <p className={s.problem}>{t("surface.framebuffer.noContext")}</p>
            )}

            {status.stale && (
              <p className={s.problem} role="status">
                {t("surface.framebuffer.stale")}
              </p>
            )}

            {status.decodeError !== null && (
              <p className={s.problem} role="status">
                {t(frameDecodeKey(status.decodeError))}
              </p>
            )}

            {!hasPixels && !unavailable && (
              <p className={s.waiting}>{t("surface.framebuffer.awaitingFirstFrame")}</p>
            )}
          </div>

          <div className={s.bottomBar}>
            <span className={s.meta}>
              {hasPixels
                ? t("surface.framebuffer.desktop", {
                    size: formatSize(locale, status.width, status.height),
                  })
                : t("surface.framebuffer.desktopUnknown")}
            </span>
            {cursorUrl !== null && status.cursor !== null && (
              <span className={s.cursorChip} title={t("surface.framebuffer.pointerShapeHelp")}>
                <img
                  className={s.cursorImage}
                  src={cursorUrl}
                  alt=""
                  width={status.cursor.width}
                  height={status.cursor.height}
                />
                {t("surface.framebuffer.pointerShape")}
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}
