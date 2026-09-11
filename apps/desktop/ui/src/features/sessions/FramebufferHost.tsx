/**
 * The screen an RDP or VNC session is seen on, and driven from.
 *
 * The canvas underneath belongs to `surfaces.ts`, for the same reason a
 * terminal belongs to `terminals.ts`: it holds the only copy of the remote
 * screen that exists anywhere, and a component that could unmount it could
 * throw that copy away with no way to ask for it back. This component appends
 * it, sizes it, draws the chrome around it, and carries the user's keyboard and
 * pointer to the far end.
 *
 * # Input
 *
 * `session_key` and `session_pointer` construct `InputEvent::Key` and
 * `InputEvent::Pointer`, which is what a framebuffer protocol's input actually
 * is — `session_input` carries *bytes*, which the RDP adapter drops and the VNC
 * adapter refuses. `keymap.ts` turns a browser `KeyboardEvent` into the
 * scancode RDP wants *and* the keysym VNC wants, because neither can be derived
 * from the other without the keyboard layout and the layout exists only here.
 * `remotePoint` in `scaling.ts` divides the tab's scale back out of a pointer
 * position, because only this side knows what it drew.
 *
 * Three rules this file keeps, each of them a bug someone has shipped before:
 *
 * - **Order.** Every send is chained onto the one before it. Two `invoke`
 *   calls in flight at once are two promises with no ordering between them,
 *   and a keyboard that can deliver "ab" as "ba" is not a keyboard.
 * - **Nothing stays down.** Every key this surface pressed is released when it
 *   loses focus or the window does. Otherwise Alt+Tab leaves Alt held at the
 *   far end for ever, and every later keystroke is an Alt chord.
 * - **A view-only session sends nothing.** Not "sends and is refused": no
 *   handler is attached at all, and the surface says so and looks it.
 *
 * # Who gets the keystroke
 *
 * The same rule a focused terminal has, because a user should not have to learn
 * two: while the remote screen has focus the keys are the remote host's, and
 * Remoter's own shortcuts are reached through the terminal prefix (`Ctrl+Alt`
 * unless it has been changed). Universal bindings — the command palette,
 * locking the vault — still answer to their plain form, so the vault is always
 * one chord away.
 *
 * A chord with no Ctrl, Alt or Meta is never taken: it is a character someone
 * is typing, and an interface that opened its own cheat sheet when a user typed
 * `?` into a remote text editor would be unusable.
 *
 * Two combinations can never be captured, because the local machine takes them
 * first: Alt+Tab and Ctrl+Alt+Delete. They are also the two people ask for by
 * name, so they are buttons — see `chordFor` in `keymap.ts`.
 *
 * # Where the chrome goes
 *
 * **Nothing of ours is drawn over the picture.** A remote desktop uses all four
 * of its edges and all four corners — Windows puts a taskbar along one and the
 * minimise/maximise/close buttons in another, macOS has a menu bar and a dock,
 * a Linux panel can be anywhere — so there is no safe place to float a control
 * over someone else's screen. This shipped as a defect: the send-keys and scale
 * buttons floated over the top inline-end corner, on top of a maximised remote
 * window's own controls, and the desktop size and keyboard hint floated over
 * the bottom inline-start corner, on top of the Start button.
 *
 * So the host is a flex column: a toolbar row, then any notices, then the
 * stage. Each has its own height and the picture gets the rest. `.stage` is
 * what `useViewport` measures, so `fit` and `smart` follow the smaller
 * viewport with no extra bookkeeping.
 *
 * The desktop size is not here at all any more. The status bar under the
 * session already shows it — see `SessionStatus` — so the overlay was covering
 * the Start button to repeat a figure that was on screen anyway.
 *
 * # Why Fit leaves a band, and where that is said
 *
 * `Fit` scales by `min(1, vw/dw, vh/dh)` on both axes — see `scaling.ts` — so a
 * 16:9 desktop in a wider tab is drawn whole with space beside it. That is the
 * arithmetic working, not failing, and the only thing that removes the band is
 * a remote desktop shaped like the tab: either the server agreeing to resize
 * (`Smart`), or the connection being made at a matching resolution. Ignoring
 * the aspect ratio is not on the list — it stretches rasterised remote text
 * into a smear, which is why no serious client offers it.
 *
 * On a server that will not resize, `Smart` is withdrawn — `manager.ts`
 * `revokeResize` — and the user is then looking at a band with every control
 * that could have removed it gone from the row. The warning that explains it
 * exists, but it is a line in the session's notices, folded behind a count, and
 * the question is asked *here*, at the scale controls. So {@link ScaleControls}
 * is followed by one chip that answers it in the place it is asked. It is drawn
 * only while there is actually a band: on a desktop that fills the tab, or one
 * larger than it, the same sentence would be an answer to nothing.
 */

import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";

import { Badge } from "@/components/Badge";
import { Icon } from "@/components/Icon";
import {
  acceleratorFromEvent,
  acceleratorLabel,
  handlerFor,
  isRegistryOwned,
  matchesChord,
  resolveShortcuts,
  useKeyboardSettings,
} from "@/hooks/keyboard";
import { isolate, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import { frameDecodeKey } from "./frames";
import { buttonsFrom, chordFor, keyInputFrom, wheelFrom, type KeyInput } from "./keymap";
import { requestDesktopSize } from "./manager";
import { cursorCssValue, cursorDataUrl } from "./presenter";
import { layoutFor, remotePoint, ZOOM_STEPS, type Layout, type ScaleMode, type Size } from "./scaling";
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

/**
 * The two chords the local machine takes before any application sees them.
 *
 * Physical key names, not characters: `chordFor` places them by position, so
 * these are the same three keys on a Turkish, German or US keyboard.
 */
const CTRL_ALT_DEL = ["ControlLeft", "AltLeft", "Delete"] as const;
const ALT_TAB = ["AltLeft", "Tab"] as const;

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

/** What the surface's handlers need to reach the far end. */
interface InputTarget {
  tabId: string;
  /** Null while the core has not named the session, or it has ended. */
  sessionId: number | null;
  layout: Layout;
  desktop: Size;
  /** False for a view-only session, a background tab, or one still connecting. */
  live: boolean;
  /** The scrolling stage, for the one listener React cannot attach. */
  stage: React.RefObject<HTMLDivElement | null>;
}

/**
 * Everything that carries a keystroke or a pointer state to the session.
 *
 * A hook rather than free functions because the queue, the set of keys this
 * surface has pressed, and the coalesced pointer position are all per-tab state
 * that has to survive a re-render and be cleaned up when the tab goes.
 */
function useFramebufferInput(target: InputTarget) {
  const { tabId, sessionId, layout, desktop, live, stage } = target;

  /**
   * The tail of the send queue.
   *
   * Input is a *sequence*. Two `invoke` calls in flight concurrently are two
   * independent promises, and nothing in Tauri promises that the first one to
   * be called is the first one to arrive — so a fast typist could send "ab" and
   * type "ba". Chaining every send onto the previous one costs a round trip per
   * event on a local IPC boundary and buys an ordering guarantee that a
   * keyboard cannot do without.
   */
  const queue = useRef<Promise<void>>(Promise.resolve());
  /** The scancodes this surface has pressed and not yet released. */
  const down = useRef<Set<number>>(new Set());
  /** The latest pointer state, waiting for the next frame. */
  const pendingMove = useRef<{ x: number; y: number; buttons: number } | null>(null);
  const moveFrame = useRef<number | null>(null);

  // Read through refs by the handlers below, which are attached once: a
  // native listener that closed over the first render's layout would send
  // coordinates from a scale the user changed a minute ago.
  const latest = useRef({ sessionId, layout, desktop, live });
  useEffect(() => {
    latest.current = { sessionId, layout, desktop, live };
  });

  /**
   * Runs one send, in order, and reports the outcome on the tab.
   *
   * A rejection is almost always the vault locking under a `freeze_input`
   * policy. A surface that stopped accepting input without saying why reads as
   * a hung session, and the user's next move is to kill a tab that is in fact
   * still connected — so the failure goes on the record, where
   * `SessionSurface` shows it, and is cleared by the first send that succeeds.
   */
  const enqueue = useCallback(
    (send: (sessionId: number) => Promise<void>) => {
      const id = latest.current.sessionId;
      if (id === null) return;
      queue.current = queue.current
        .then(() => send(id))
        .then(
          () => {
            if (useSessions.getState().byId[tabId]?.inputError !== null) {
              useSessions.getState().patch(tabId, { inputError: null });
            }
          },
          (error: unknown) => {
            useSessions.getState().patch(tabId, { inputError: asFailure(error) });
          },
        );
    },
    [tabId],
  );

  const sendKey = useCallback(
    (key: KeyInput) => {
      enqueue((id) => ipc.sendKey(id, key));
    },
    [enqueue],
  );

  const sendPointer = useCallback(
    (pointer: { x: number; y: number; buttons: number; wheel: number; wheelX: number }) => {
      enqueue((id) => ipc.sendPointer(id, pointer));
    },
    [enqueue],
  );

  /** The pointer position in remote pixels, from a position in the window. */
  const pointAt = useCallback(
    (clientX: number, clientY: number) => {
      const canvas = surfaceElement(tabId);
      if (canvas === null) return null;
      // Before the first frame the desktop has no size, so there is no such
      // place as "where the user clicked". Sending 0,0 would put the remote
      // pointer in the corner for every click until the picture arrived.
      const { desktop: size } = latest.current;
      if (size.width <= 0 || size.height <= 0) return null;
      const box = canvas.getBoundingClientRect();
      // Against the canvas rather than the stage: the stage is letterboxed
      // around it, and a click in the letterbox has to clamp to the edge of the
      // desktop rather than report a negative coordinate.
      return remotePoint(
        latest.current.layout,
        latest.current.desktop,
        clientX - box.left,
        clientY - box.top,
      );
    },
    [tabId],
  );

  /**
   * Sends the coalesced pointer position, at most once a frame.
   *
   * A pointer moving across a 4K desktop produces several hundred events a
   * second and the far end can use sixty of them. Only *movement* is coalesced:
   * a button transition and a wheel notch are events in their own right and go
   * immediately, and they carry their own position, which is at least as recent
   * as the one waiting — so the pending move is dropped rather than sent after
   * them, which would move the pointer backwards.
   */
  const flushMove = useCallback(() => {
    moveFrame.current = null;
    const move = pendingMove.current;
    pendingMove.current = null;
    if (move === null) return;
    sendPointer({ ...move, wheel: 0, wheelX: 0 });
  }, [sendPointer]);

  const onPointerMove = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      if (!latest.current.live) return;
      const point = pointAt(event.clientX, event.clientY);
      if (point === null) return;
      pendingMove.current = { ...point, buttons: buttonsFrom(event.buttons) };
      if (moveFrame.current !== null) return;
      moveFrame.current =
        typeof window.requestAnimationFrame === "function"
          ? window.requestAnimationFrame(flushMove)
          : window.setTimeout(flushMove, 16);
    },
    [flushMove, pointAt],
  );

  const onPointerButton = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      if (!latest.current.live) return;
      const point = pointAt(event.clientX, event.clientY);
      if (point === null) return;
      pendingMove.current = null;
      sendPointer({ ...point, buttons: buttonsFrom(event.buttons), wheel: 0, wheelX: 0 });
    },
    [pointAt, sendPointer],
  );

  const onPointerDown = useCallback(
    (event: React.PointerEvent<HTMLDivElement>) => {
      if (!latest.current.live) return;
      // The keyboard follows the mouse into the screen: a user who clicks a
      // remote window and then types expects the typing to land there.
      event.currentTarget.focus();
      // A drag that leaves the surface is still this session's drag — that is
      // how a window is dragged to the edge of the remote desktop, and how the
      // release is seen at all when it happens over the chrome.
      if (typeof event.currentTarget.setPointerCapture === "function") {
        try {
          event.currentTarget.setPointerCapture(event.pointerId);
        } catch {
          // Some WebViews refuse capture for a pointer that has already been
          // released. The click itself is unaffected.
        }
      }
      onPointerButton(event);
    },
    [onPointerButton],
  );

  /**
   * Releases every key this surface pressed.
   *
   * The bug it prevents: the user presses Alt, the window manager takes
   * Alt+Tab, the keyup never arrives, and the far end believes Alt is held for
   * the rest of the session — so every subsequent keystroke is an Alt chord and
   * nothing the user types works. Lock states cannot stick the same way,
   * because every key event carries the current latch state with it.
   */
  const releaseAll = useCallback(() => {
    for (const scancode of down.current) {
      sendKey({ scancode, keysym: null, modifiers: 0, pressed: false });
    }
    down.current.clear();
  }, [sendKey]);

  /** Sends a chord the local machine would otherwise swallow. */
  const sendChord = useCallback(
    (codes: readonly string[]) => {
      const events = chordFor(codes);
      if (events === null) return;
      for (const event of events) sendKey(event);
    },
    [sendKey],
  );

  /**
   * The wheel, on both axes.
   *
   * A native listener because React attaches `wheel` passively at its root, and
   * a passive listener cannot call `preventDefault` — so the stage would scroll
   * the picture locally at the same moment the remote window scrolled, and a
   * zoomed session would drift away under the pointer.
   *
   * The wheel is the remote host's. Panning a desktop larger than the tab is
   * what the scrollbars and the scale controls are for.
   */
  useEffect(() => {
    const element = stage.current;
    if (element === null || !live) return;
    const onWheel = (event: WheelEvent) => {
      const point = pointAt(event.clientX, event.clientY);
      if (point === null) return;
      event.preventDefault();
      const { wheel, wheelX } = wheelFrom(event);
      // The position rides with the notch rather than being sent separately:
      // both protocols carry a wheel event as a pointer event that happens to
      // have a rotation, and a stale pending move would put it in the wrong
      // place.
      pendingMove.current = null;
      sendPointer({ ...point, buttons: buttonsFrom(event.buttons), wheel, wheelX });
    };
    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [live, pointAt, sendPointer, stage]);

  // The window losing focus is not the element losing focus: the element keeps
  // it, so `blur` on the element never fires, and the keyup for whatever was
  // held goes to the desktop that took the focus.
  useEffect(() => {
    if (!live) return;
    const onWindowBlur = () => {
      releaseAll();
    };
    window.addEventListener("blur", onWindowBlur);
    return () => {
      window.removeEventListener("blur", onWindowBlur);
      releaseAll();
    };
  }, [live, releaseAll]);

  // A pointer move waiting for the next frame when the tab closes has nowhere
  // to go: the callback would run against a session that is gone and a canvas
  // that has been zero-sized.
  useEffect(
    () => () => {
      if (moveFrame.current === null) return;
      if (typeof window.cancelAnimationFrame === "function") {
        window.cancelAnimationFrame(moveFrame.current);
      } else {
        window.clearTimeout(moveFrame.current);
      }
    },
    [],
  );

  return { sendKey, sendChord, releaseAll, down, onPointerMove, onPointerButton, onPointerDown };
}

export function FramebufferHost({ record, active }: { record: SessionRecord; active: boolean }) {
  const t = useT("sessions");
  const tabId = record.tabId;
  const ref = useRef<HTMLDivElement>(null);
  const viewport = useViewport(ref);
  const [focused, setFocused] = useState(false);
  /**
   * Whether this screen has ever had the keyboard.
   *
   * "Click the screen to type into it" is orientation, not a control: it
   * answers one question once. Kept on screen for the rest of the session it
   * would be a permanent line of chrome saying something the user has already
   * done — so it is shown until the first focus and never again on this tab.
   */
  const [everFocused, setEverFocused] = useState(false);

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

  const unavailable = surfaceUnavailable(tabId);
  const viewOnly = record.viewOnly === true;
  const hasPixels = status.width > 0 && status.height > 0;

  /**
   * Whether the picture leaves empty tab beside or below it, and nothing here
   * can change that.
   *
   * Two facts, and the chip needs both. `fixedSize` is the session's: the
   * remote desktop's size is not ours to set — a VNC server, which cannot be
   * asked at all, or an RDP one that never opened MS-RDPEDISP, in which case
   * `revokeResize` has already taken Smart out of the row above. `banded` is
   * the geometry's: the drawn picture is smaller than the stage on at least one
   * axis. Without the second, the sentence would be shown to someone who is not
   * looking at a band and has not asked the question.
   */
  const fixedSize = record.opened !== null && !record.opened.capabilities.resizable;
  const banded =
    hasPixels &&
    viewport.width > 0 &&
    viewport.height > 0 &&
    (layout.width < viewport.width || layout.height < viewport.height);
  const explainBands = record.phase === "running" && fixedSize && banded;
  // Nothing is sent from a view-only session, from a tab that is not in front,
  // or before the core has named the session. `live` gates the handlers
  // themselves, not a refusal inside them — a view-only session has no key
  // handler to swallow a keystroke and no pointer handler to drop a click.
  //
  // Not gated on a frame having arrived. A login screen that has not painted
  // yet still takes a password, and the keyboard is exactly what it is waiting
  // for. The *pointer* is gated on it, one layer down: a click has to land
  // somewhere, and "somewhere" is a desktop whose size is not yet known.
  //
  // It *is* gated on the phase. A failed or closed tab keeps its last picture
  // so the user can read what happened, and a picture is all it is: typing at
  // it would raise "that session is not open any more" over the failure that
  // actually matters.
  const live = active && !viewOnly && record.phase === "running" && record.sessionId !== null;

  const input = useFramebufferInput({
    tabId,
    sessionId: record.sessionId,
    layout,
    desktop,
    live,
    stage: ref,
  });

  const { prefix, overrides } = useKeyboardSettings();
  // The prefix is modifiers only, so it has no key of its own to name. A
  // throwaway key is appended and its cap dropped, which is what
  // `PrefixIndicator` does with the same value for the same reason: an
  // accelerator with no key does not parse, and the label would come out as
  // the stored spelling — "ctrl+alt", in lower case, which is not how it is
  // written anywhere else in the interface.
  const prefixLabel = useMemo(
    () => acceleratorLabel(`${prefix}+space`).split("+").slice(0, -1).join("+"),
    [prefix],
  );
  // Resolved once per change rather than per keystroke: the list is the whole
  // shortcut map, and rebuilding it on every keydown of a fast typist is work
  // done hundreds of times a second for an answer that did not change.
  const shortcuts = useMemo(
    () => resolveShortcuts(overrides).filter((entry) => isRegistryOwned(entry.action)),
    [overrides],
  );

  /**
   * Whether this keystroke belongs to Remoter rather than to the remote host.
   *
   * The terminal's rule, applied to a screen: inside a focused session the keys
   * are the far end's, and an application binding is reached through the
   * prefix — except a universal one, which answers to its plain form as well so
   * that locking the vault is never more than one chord away.
   *
   * A chord with no Ctrl, Alt or Meta is never taken. It is a character the
   * user is typing, and `?` is bound to the cheat sheet: a remote text editor
   * in which question marks opened a help panel would be unusable.
   *
   * An action nothing can perform right now does not count either. The key
   * would be swallowed by a handler that does nothing, which is worse than
   * either outcome.
   */
  const applicationOwns = useCallback(
    (event: KeyboardEvent): boolean => {
      if (!event.ctrlKey && !event.altKey && !event.metaKey) return false;
      const chord = acceleratorFromEvent(event);
      if (chord === null) return false;
      return shortcuts.some(
        (entry) =>
          matchesChord(entry, chord, true, prefix).matched &&
          handlerFor(entry.action.owner, entry.action.id) !== null,
      );
    },
    [prefix, shortcuts],
  );

  const { sendKey, down } = input;
  const onKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (!live) return;
      // Left alone deliberately: not calling `preventDefault` is what lets the
      // one window-level listener in `hooks/keyboard` see it, which is where
      // every application shortcut fires from.
      if (applicationOwns(event.nativeEvent)) return;
      const key = keyInputFrom(event.nativeEvent, true);
      // A key `keymap.ts` cannot place physically, or one an IME has taken.
      // Neither is ours to swallow.
      if (key === null) return;
      down.current.add(key.scancode);
      event.preventDefault();
      sendKey(key);
    },
    [applicationOwns, down, live, sendKey],
  );

  const onKeyUp = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (!live) return;
      const key = keyInputFrom(event.nativeEvent, false);
      if (key === null) return;
      // Only for a key this surface actually pressed. A keyup whose keydown
      // went to a dialog or to an application shortcut is not this session's to
      // report, and sending it alone tells the far end a key was released that
      // it never saw pressed.
      if (!down.current.delete(key.scancode)) return;
      event.preventDefault();
      sendKey(key);
    },
    [down, live, sendKey],
  );

  const { sendChord, releaseAll, onPointerMove, onPointerButton, onPointerDown } = input;

  /**
   * Sends a chord and gives the keyboard back to the screen.
   *
   * Without the second half the button keeps the focus it took on the click,
   * and the next thing the user types goes to the application instead of to
   * the desktop they just sent Ctrl+Alt+Delete to — which is exactly the moment
   * they are about to type a password.
   */
  const sendFromButton = useCallback(
    (codes: readonly string[]) => {
      sendChord(codes);
      ref.current?.focus();
    },
    [sendChord],
  );

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

  /**
   * The remote pointer shape, as this window's own cursor.
   *
   * Only while input is live, and that condition is the whole point: the shape
   * arrives with no position, and its position is wherever the client last put
   * the pointer. On a session that sends nothing the remote pointer is not
   * where the local one is, so painting the server's I-beam under a local
   * cursor that controls nothing would be a claim about the remote screen that
   * is false. There it is shown as a labelled swatch instead.
   */
  const cursorCss = useMemo(() => {
    if (!live || status.cursor === null) return null;
    // The server asked for no pointer at all — a full-screen video player, or a
    // game that draws its own. Hiding the local one is what honours that.
    if (status.cursor.width === 0 || status.cursor.height === 0) return "none";
    return cursorCssValue(status.cursor, "default");
  }, [live, status.cursor]);

  const cursorUrl = useMemo(
    () => (status.cursor === null || cursorCss !== null ? null : cursorDataUrl(status.cursor)),
    [cursorCss, status.cursor],
  );

  useEffect(() => {
    const canvas = surfaceElement(tabId);
    if (canvas === null) return;
    canvas.style.cursor = cursorCss ?? "";
  }, [cursorCss, tabId]);

  /**
   * The one line of orientation about the keyboard, or nothing.
   *
   * Three states, not two. While the screen has focus it says so and says how
   * to reach Remoter's own shortcuts anyway — a user who cannot find the way
   * back reads the application as hung. Before the first click it says how to
   * start. Afterwards it says nothing: the instruction has been followed, and
   * repeating it for the rest of the session is chrome that earns no row.
   */
  const keyboardHint = !live
    ? null
    : focused
      ? t("surface.framebuffer.input.capturing", { prefix: prefixLabel })
      : everFocused
        ? null
        : t("surface.framebuffer.input.clickToType");

  /**
   * Whether the sentence-length notices have anything to say.
   *
   * Checked here so the block is not drawn as an empty bordered strip above the
   * picture. "Waiting for the first frame" is deliberately not one of them: it
   * is true of every session for its first moment, and a strip that appeared
   * and vanished would change the stage's height twice at connect — which on a
   * smart-resize session is two desktop renegotiations at the far end. It is a
   * chip in the toolbar, whose height does not move.
   */
  const hasNotices = viewOnly || unavailable || status.stale || status.decodeError !== null;

  return (
    <div
      className={active ? s.host : [s.host, s.hidden].join(" ")}
      aria-hidden={active ? undefined : true}
      data-tab={tabId}
    >
      {/* The toolbar and the notices come FIRST in the flow and the stage last,
          which is the fix: they are rows above the picture rather than boxes
          floating on it. Nothing here is positioned. */}
      {active && (
        <div
          className={s.toolbar}
          role="group"
          aria-label={t("surface.framebuffer.toolbarLabel")}
        >
          {live && (
            <div
              className={s.controls}
              role="group"
              aria-label={t("surface.framebuffer.input.sendKeys")}
            >
              <button
                type="button"
                className={s.option}
                title={t("surface.framebuffer.input.ctrlAltDelHelp")}
                onClick={() => sendFromButton(CTRL_ALT_DEL)}
              >
                {t("surface.framebuffer.input.ctrlAltDel")}
              </button>
              <button
                type="button"
                className={s.option}
                title={t("surface.framebuffer.input.altTabHelp")}
                onClick={() => sendFromButton(ALT_TAB)}
              >
                {t("surface.framebuffer.input.altTab")}
              </button>
            </div>
          )}

          <ScaleControls record={record} />

          {/* Beside the controls, because that is where the question is asked:
              the user reaches for Fit, sees a band, and concludes Fit is
              broken. The tooltip carries the rest of the answer — that a
              matching resolution is what fills the tab, and that stretching the
              picture is not on offer because it would blur the remote text. */}
          {explainBands && (
            <span className={s.fixedSize} title={t("surface.framebuffer.scale.fixedSizeHelp")}>
              {t("surface.framebuffer.scale.fixedSize")}
            </span>
          )}

          {viewOnly && (
            <Badge tone="warning" title={t("surface.framebuffer.viewOnlyHelp")}>
              <Icon name="shield" size={12} />
              {t("surface.framebuffer.viewOnly")}
            </Badge>
          )}

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

          {!hasPixels && !unavailable && (
            <span className={s.waiting}>{t("surface.framebuffer.awaitingFirstFrame")}</span>
          )}

          <span className={s.spacer} />

          {keyboardHint !== null && <span className={s.capture}>{keyboardHint}</span>}
        </div>
      )}

      {active && hasNotices && (
        <div className={s.notices}>
          {viewOnly && (
            <p className={s.inputNotice}>
              <Icon name="alert" size={13} />
              <span>{t("surface.framebuffer.viewOnlyNotice")}</span>
            </p>
          )}

          {unavailable && <p className={s.problem}>{t("surface.framebuffer.noContext")}</p>}

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
        </div>
      )}

      <div
        ref={ref}
        className={s.stage}
        data-view-only={viewOnly ? "true" : undefined}
        data-input={live ? "live" : undefined}
        // `application` tells a screen reader to stop intercepting keys and
        // hand them to the page, which is exactly what a remote desktop needs.
        // A session that sends nothing is a picture, and says so.
        role={live ? "application" : "img"}
        tabIndex={live ? 0 : undefined}
        aria-label={t("surface.framebuffer.label", { name: isolate(record.name) })}
        onKeyDown={live ? onKeyDown : undefined}
        onKeyUp={live ? onKeyUp : undefined}
        onPointerDown={live ? onPointerDown : undefined}
        onPointerMove={live ? onPointerMove : undefined}
        onPointerUp={live ? onPointerButton : undefined}
        onPointerCancel={live ? onPointerButton : undefined}
        // The WebView's own menu would cover the remote screen, and a right
        // click is the far end's: it opens the remote menu instead.
        onContextMenu={live ? (event) => event.preventDefault() : undefined}
        onFocus={
          live
            ? () => {
                setFocused(true);
                setEverFocused(true);
              }
            : undefined
        }
        onBlur={
          live
            ? () => {
                setFocused(false);
                releaseAll();
              }
            : undefined
        }
      />
    </div>
  );
}
