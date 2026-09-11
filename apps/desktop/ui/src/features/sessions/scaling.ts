/**
 * How a remote desktop is fitted into a tab.
 *
 * `docs/architecture/rendering.md` names four modes. All four are here, and
 * each one is only offered where the behaviour behind it exists:
 *
 * | Mode | What it does | What it needs |
 * |---|---|---|
 * | `smart` | Asks the remote host to make its desktop the size of the tab | `capabilities.resizable` |
 * | `fit` | Scales the desktop down to the tab, aspect preserved | nothing |
 * | `actual` | One remote pixel per device pixel, with scrollbars | nothing |
 * | `zoom` | An integer magnification, for reading small text | nothing |
 *
 * **`smart` is the default where the session says it is resizable, and `fit`
 * otherwise.** That is rendering.md's own ordering — smart resize is the best
 * experience where supported and the default for RDP — and it is honest here
 * because the resize genuinely happens: `session_resize` reaches
 * MS-RDPEDISP for RDP and `SetDesktopSize` for VNC, and `capabilities.resizable`
 * is the adapter's report of whether the channel is actually open, not a guess.
 * A server that refuses raises a warning, which the surface shows.
 *
 * `fit` is the fallback rather than `actual` because a remote desktop is nearly
 * always larger than the tab it is shown in. At 1:1 the first thing a user sees
 * of a 1920x1080 desktop in a 1200px tab is its top-left corner, with the task
 * bar, the window controls and half the screen behind scrollbars.
 *
 * # Why zoom is integer-only
 *
 * A remote desktop is a grid of pixels carrying text that was already
 * rasterised and hinted for that grid. Resampling it by a non-integer factor
 * mixes each glyph's stem across two output pixels, and 8pt text becomes a grey
 * smear — the exact failure this module exists to avoid. An integer factor with
 * nearest-neighbour sampling replicates whole pixels, so a stem stays a stem.
 *
 * So zoom is 2x, 3x, 4x and nothing between, and `crisp` on the returned layout
 * is what tells the surface to ask the compositor for nearest-neighbour
 * sampling rather than the smooth default. Zooming *out* is what `fit` is for,
 * and there smoothing is right: a downscale without it aliases.
 */

/** The four modes. `smart` is only selectable on a resizable session. */
export type ScaleMode = "smart" | "fit" | "actual" | "zoom";

/** The magnifications `zoom` offers. Integers only — see the file comment. */
export const ZOOM_STEPS = [2, 3, 4] as const;

/** A size in pixels. */
export interface Size {
  width: number;
  height: number;
}

/** Where and how large the surface is drawn, in CSS pixels. */
export interface Layout {
  /** Remote pixels to CSS pixels. */
  scale: number;
  /** The element's size, `scale` applied. */
  width: number;
  height: number;
  /**
   * Whether one remote pixel covers at least one device pixel, so the
   * compositor should replicate pixels rather than interpolate them.
   */
  crisp: boolean;
  /** Whether the surface is larger than the viewport and has to scroll. */
  scrolls: boolean;
}

/**
 * MS-RDPEDISP's limits (MS-RDPBCGR §2.2.2.2.1): at least 200, at most 8192,
 * and an even width. The core clamps too, but a request that has already been
 * clamped saves a round trip that would come back as a size nobody asked for.
 */
const MIN_DESKTOP = 200;
const MAX_DESKTOP = 8192;

/**
 * The layout for a desktop in a viewport.
 *
 * `smart` shares `fit`'s arithmetic: asking the server to resize is a separate
 * action with its own round trip, and until it lands — or if the server refuses
 * — the frame that is actually on the wire still has to be shown whole.
 */
export function layoutFor(input: {
  mode: ScaleMode;
  zoom: number;
  desktop: Size;
  viewport: Size;
  devicePixelRatio: number;
}): Layout {
  const { desktop, viewport } = input;
  const dpr = input.devicePixelRatio > 0 ? input.devicePixelRatio : 1;

  if (desktop.width <= 0 || desktop.height <= 0) {
    return { scale: 1, width: 0, height: 0, crisp: true, scrolls: false };
  }

  let scale: number;
  switch (input.mode) {
    case "actual":
      scale = 1;
      break;
    case "zoom":
      // Guarded rather than trusted: a zoom that arrived as 1.5 from somewhere
      // is exactly the resampling this module refuses to do.
      scale = Math.max(1, Math.round(input.zoom));
      break;
    case "smart":
    case "fit": {
      if (viewport.width <= 0 || viewport.height <= 0) {
        scale = 1;
        break;
      }
      // Never magnified by fitting. A desktop smaller than the tab is centred
      // at 1:1: blowing it up to fill the window is the mush case, and nobody
      // asked for a magnifier by making their window large.
      scale = Math.min(1, viewport.width / desktop.width, viewport.height / desktop.height);
      break;
    }
  }

  const width = Math.round(desktop.width * scale);
  const height = Math.round(desktop.height * scale);
  return {
    scale,
    width,
    height,
    // Against *device* pixels, not CSS ones. On a 2x display a half-scale
    // surface is still one remote pixel per device pixel, and asking for
    // smoothing there would blur a picture that is already exact.
    crisp: scale * dpr >= 1,
    scrolls: width > viewport.width || height > viewport.height,
  };
}

/**
 * The desktop size to ask a resizable server for, in remote pixels.
 *
 * Physical pixels, not logical ones: rendering.md asks for a framebuffer at the
 * device's pixel size so that text on a 4K display is rendered sharp by the
 * remote host rather than upscaled here.
 *
 * Returns null when the viewport is not worth asking about — a tab that has not
 * been laid out yet, or one collapsed below what the protocol permits.
 */
export function smartResizeRequest(viewport: Size, devicePixelRatio: number): Size | null {
  const dpr = devicePixelRatio > 0 ? devicePixelRatio : 1;
  const width = Math.round(viewport.width * dpr);
  const height = Math.round(viewport.height * dpr);
  if (width < MIN_DESKTOP || height < MIN_DESKTOP) return null;
  return {
    // Even, because the protocol requires it and an odd width comes back
    // rounded to a size the interface did not choose.
    width: Math.min(MAX_DESKTOP, width - (width % 2)),
    height: Math.min(MAX_DESKTOP, height),
  };
}

/**
 * A point in the tab, in remote display coordinates.
 *
 * `InputEvent::Pointer` is documented as carrying remote pixels "after the
 * tab's zoom and the device pixel ratio have been divided out", and says the
 * division belongs in the frontend because only the frontend knows what it
 * drew. This is that division.
 *
 * Clamped to the desktop and to `u16`, which is what both protocols carry: a
 * pointer dragged past the edge of the surface reports the edge rather than a
 * coordinate that wraps to the opposite side of the screen.
 */
export function remotePoint(
  layout: Layout,
  desktop: Size,
  offsetX: number,
  offsetY: number,
): { x: number; y: number } {
  const scale = layout.scale > 0 ? layout.scale : 1;
  const clamp = (value: number, limit: number) =>
    Math.max(0, Math.min(Math.min(limit, 0xffff), Math.floor(value / scale)));
  return {
    x: clamp(offsetX, Math.max(0, desktop.width - 1)),
    y: clamp(offsetY, Math.max(0, desktop.height - 1)),
  };
}

/** The mode a session starts in. See the file comment for why. */
export function defaultScaleMode(resizable: boolean): ScaleMode {
  return resizable ? "smart" : "fit";
}
