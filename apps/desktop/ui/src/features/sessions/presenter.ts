/**
 * The presenter: decoded frames onto a surface.
 *
 * `docs/architecture/rendering.md` puts the presenter behind an interface that
 * may differ per platform, and ADR-0010 leaves the choice between a WebView
 * presenter and a native one open until the end of v0.2. This is the WebView
 * one, and it is **Canvas 2D rather than WebGL2** for one reason that is worth
 * stating: copy-rect.
 *
 * A copy-rect carries no pixels. It says "this region of the surface you
 * already hold now also appears here", which is what makes scrolling and window
 * drags almost free in both protocols. A 2D context can serve that from the
 * canvas itself — `drawImage(canvas, sx, sy, …)` is defined to read a snapshot
 * of the source, so a self-copy of overlapping regions is well defined — while
 * a WebGL2 presenter needs a second texture and a blit pass to avoid sampling
 * the pixels it is in the middle of writing. Raw and RLE rectangles go through
 * `putImageData`, which is a straight upload with no compositing, and JPEG
 * rectangles through `createImageBitmap`.
 *
 * **Scaling is not done here.** The canvas backing store is always exactly the
 * remote desktop's size and every rectangle lands at 1:1; the element is scaled
 * by CSS. That keeps the per-frame cost proportional to the dirty area rather
 * than to the window, and it puts the resampling on the compositor, which is
 * where `image-rendering: pixelated` can keep an upscaled desktop crisp. See
 * `scaling.ts`.
 *
 * **Order is preserved across an await.** A JPEG rectangle decodes
 * asynchronously, and a rectangle applied out of order corrupts everything a
 * later copy-rect reads. So messages queue, each message decodes all of its
 * images *before* any of its rectangles are applied, and the apply pass itself
 * is synchronous.
 */

import {
  copySource,
  cursorIsHidden,
  decodeFrameMessage,
  expandRle,
  keyframeExtent,
  toRgba,
  type CursorUpdate,
  type FrameDecodeReason,
  type FrameMessage,
  type FrameRect,
  type FrameUpdate,
  type Rect,
} from "./frames";

/**
 * The surface the presenter draws on.
 *
 * An interface rather than a canvas, because everything above it — sequence
 * gaps, keyframe handling, copy-rect ordering, RLE expansion — is logic that
 * has to be testable, and jsdom has no 2D context to test it against.
 */
export interface FrameTarget {
  /** Resize the surface. Its contents are undefined afterwards. */
  resize(width: number, height: number): void;
  /** Upload RGBA pixels at `rect`. */
  putPixels(rect: Rect, rgba: Uint8ClampedArray<ArrayBuffer>): void;
  /** Copy an area of the surface to another place on the same surface. */
  copyRect(rect: Rect, sourceX: number, sourceY: number): void;
  /** Draw a decoded image over `rect`. */
  drawImage(rect: Rect, image: CanvasImageSource): void;
}

/** Turns JPEG bytes into something a canvas can draw. Injected, for tests. */
export type ImageDecoder = (bytes: Uint8Array) => Promise<CanvasImageSource>;

/** The cursor shape the server set, ready to be turned into a CSS cursor. */
export interface CursorShape {
  hotspotX: number;
  hotspotY: number;
  width: number;
  height: number;
  /** RGBA, straight alpha, row-major. */
  rgba: Uint8ClampedArray<ArrayBuffer>;
}

/** Everything the surface's chrome reads off the presenter. */
export interface PresenterStatus {
  /** The remote desktop's size in pixels, or zero before the first frame. */
  width: number;
  height: number;
  /** Framebuffer messages applied since the tab opened. */
  frames: number;
  /** Bytes of encoded frame data received. */
  bytes: number;
  /**
   * True after a gap in the sequence, until a keyframe repairs the surface.
   *
   * A gap means the encoder dropped a stale frame under load, so what is on
   * screen is no longer what the remote screen shows. Saying so is the honest
   * thing: the alternative is a desktop that is quietly wrong in one corner.
   */
  stale: boolean;
  /** The last malformed message, if one arrived. Never silently dropped. */
  decodeError: FrameDecodeReason | null;
  /** The cursor shape the server last set. Null means it asked for none. */
  cursor: CursorShape | null;
}

const EMPTY_STATUS: PresenterStatus = {
  width: 0,
  height: 0,
  frames: 0,
  bytes: 0,
  stale: false,
  decodeError: null,
  cursor: null,
};

/** The default decoder. `createImageBitmap` is the only synchronous-enough one. */
async function decodeJpeg(bytes: Uint8Array): Promise<CanvasImageSource> {
  // `slice` rather than the subarray the decoder was handed: `Blob` keeps a
  // reference to the buffer, and that buffer is the whole message, which is
  // about to be reused.
  const blob = new Blob([bytes.slice()], { type: "image/jpeg" });
  return createImageBitmap(blob);
}

export class FramebufferPresenter {
  private readonly target: FrameTarget;
  private readonly decodeImage: ImageDecoder;
  private readonly onChange: () => void;

  private state: PresenterStatus = { ...EMPTY_STATUS };

  /** The sequence number the next message should carry. Null before the first. */
  private expectedSeq: number | null = null;

  private queue: FrameMessage[] = [];
  private draining = false;
  private disposed = false;

  constructor(options: {
    target: FrameTarget;
    /** Called when something structural changed: size, staleness, cursor, error. */
    onChange: () => void;
    decodeImage?: ImageDecoder;
  }) {
    this.target = options.target;
    this.onChange = options.onChange;
    this.decodeImage = options.decodeImage ?? decodeJpeg;
  }

  /** A snapshot for the chrome. Cheap: the object is rebuilt only on change. */
  status(): PresenterStatus {
    return this.state;
  }

  /**
   * The size the remote desktop reported through `SessionEvent::Resized`.
   *
   * Authoritative, and separate from what a keyframe's rectangles imply: the
   * server announces a resize before the pixels for it arrive, and a surface
   * left at the old size would crop the first frame of the new one.
   */
  setDesktopSize(width: number, height: number): void {
    if (width <= 0 || height <= 0) return;
    if (this.state.width === width && this.state.height === height) return;
    this.target.resize(width, height);
    // Resizing discards the surface, so what is on it is no longer the remote
    // screen until a keyframe arrives.
    this.state = { ...this.state, width, height, stale: true };
    this.onChange();
  }

  /** Takes one encoded message off the session channel. */
  accept(bytes: Uint8Array): void {
    if (this.disposed) return;
    this.state = { ...this.state, bytes: this.state.bytes + bytes.byteLength };

    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok) {
      this.state = { ...this.state, decodeError: decoded.reason };
      this.onChange();
      return;
    }

    this.queue.push(decoded.value);
    void this.drain();
  }

  /** Stops applying anything further. The surface is left as it stands. */
  dispose(): void {
    this.disposed = true;
    this.queue = [];
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      for (;;) {
        const next = this.queue.shift();
        if (next === undefined || this.disposed) return;
        await this.applyMessage(next);
      }
    } finally {
      this.draining = false;
    }
  }

  private async applyMessage(message: FrameMessage): Promise<void> {
    this.trackSequence(message.seq, message.message === "framebuffer" && message.keyframe);

    if (message.message === "cursor") {
      this.applyCursor(message);
      return;
    }
    await this.applyFramebuffer(message);
  }

  /**
   * Notices a dropped frame.
   *
   * The sequence counter is shared by framebuffer and cursor messages — one
   * stream, one sequence — so a gap in either means the surface may be wrong.
   * A keyframe clears it, because a keyframe depends on nothing before it.
   */
  private trackSequence(seq: number, keyframe: boolean): void {
    const expected = this.expectedSeq;
    // u32, so it wraps. A wrap is not a gap.
    this.expectedSeq = (seq + 1) >>> 0;
    if (expected === null) return;
    if (seq !== expected && !keyframe && !this.state.stale) {
      this.state = { ...this.state, stale: true };
      this.onChange();
    }
  }

  private applyCursor(update: CursorUpdate): void {
    if (cursorIsHidden(update)) {
      if (this.state.cursor === null) return;
      this.state = { ...this.state, cursor: null };
      this.onChange();
      return;
    }
    const expected = update.width * update.height * 4;
    // A short image would read past the end of the buffer into whatever the
    // channel handed over next. Dropping it costs one pointer shape.
    if (update.image.byteLength < expected) return;
    this.state = {
      ...this.state,
      cursor: {
        hotspotX: update.hotspotX,
        hotspotY: update.hotspotY,
        width: update.width,
        height: update.height,
        rgba: toRgba(update.format, update.image.subarray(0, expected)),
      },
    };
    this.onChange();
  }

  private async applyFramebuffer(update: FrameUpdate): Promise<void> {
    let structural = false;

    // A keyframe covers the whole desktop, so it is also the moment the size
    // can be learned when no `Resized` event preceded it.
    const extent = keyframeExtent(update);
    if (extent !== null && (extent.width !== this.state.width || extent.height !== this.state.height)) {
      this.target.resize(extent.width, extent.height);
      this.state = { ...this.state, width: extent.width, height: extent.height };
      structural = true;
    }

    // Every image in the message is decoded before any rectangle is applied.
    // Decoding between rectangles would let a later copy-rect read a region an
    // earlier rectangle had not written yet.
    const images = new Map<number, CanvasImageSource>();
    for (const [index, rect] of update.rects.entries()) {
      if (rect.encoding !== "jpeg") continue;
      try {
        images.set(index, await this.decodeImage(rect.payload));
      } catch {
        // One unreadable region, not a dead session. It stays as it was, and
        // the next keyframe repairs it — which is what `stale` announces.
        if (!this.state.stale) {
          this.state = { ...this.state, stale: true };
          structural = true;
        }
      }
    }
    if (this.disposed) return;

    for (const [index, rect] of update.rects.entries()) {
      this.applyRect(rect, images.get(index));
    }

    this.state = { ...this.state, frames: this.state.frames + 1 };
    if (update.keyframe && this.state.stale) {
      this.state = { ...this.state, stale: false };
      structural = true;
    }
    if (structural) this.onChange();
  }

  private applyRect(rect: FrameRect, image: CanvasImageSource | undefined): void {
    if (rect.rect.width === 0 || rect.rect.height === 0) return;

    switch (rect.encoding) {
      case "raw": {
        const expected = rect.rect.width * rect.rect.height * 4;
        if (rect.payload.byteLength < expected) return;
        this.target.putPixels(rect.rect, toRgba(rect.format, rect.payload.subarray(0, expected)));
        return;
      }
      case "rle": {
        const raw = expandRle(rect.rect, rect.payload);
        if (raw === null) return;
        this.target.putPixels(rect.rect, toRgba(rect.format, raw));
        return;
      }
      case "jpeg": {
        if (image === undefined) return;
        this.target.drawImage(rect.rect, image);
        return;
      }
      case "copyRect": {
        const source = copySource(rect);
        if (source === null) return;
        this.target.copyRect(rect.rect, source.x, source.y);
        return;
      }
    }
  }
}

/**
 * A `FrameTarget` backed by a real canvas, or null where there is no 2D
 * context — jsdom, and a WebView that has run out of them.
 *
 * `alpha: true` is deliberate: where nothing has been painted the element's own
 * background shows through, which is how the session ground stays the colour
 * the token says rather than canvas black.
 */
export function canvasTarget(canvas: HTMLCanvasElement): FrameTarget | null {
  const context = canvas.getContext("2d", { alpha: true });
  if (context === null) return null;

  return {
    resize(width, height) {
      canvas.width = width;
      canvas.height = height;
    },
    putPixels(rect, rgba) {
      context.putImageData(new ImageData(rgba, rect.width, rect.height), rect.x, rect.y);
    },
    copyRect(rect, sourceX, sourceY) {
      // Defined behaviour even when the regions overlap: the specification says
      // the source is a snapshot taken before anything is drawn, which is
      // exactly the semantics RFB CopyRect and the RDP scrblt order have.
      context.drawImage(
        canvas,
        sourceX,
        sourceY,
        rect.width,
        rect.height,
        rect.x,
        rect.y,
        rect.width,
        rect.height,
      );
    },
    drawImage(rect, image) {
      context.drawImage(image, rect.x, rect.y, rect.width, rect.height);
    },
  };
}

/**
 * The cursor shape as a PNG data URL, or null where one cannot be built.
 *
 * The size limit is the browsers': a cursor image larger than 128 x 128 is
 * refused outright as a CSS cursor by Firefox and Chromium, and a shape that
 * cannot become a cursor is not worth carrying to the one place that wants it.
 */
export function cursorDataUrl(shape: CursorShape): string | null {
  if (shape.width === 0 || shape.height === 0) return null;
  if (shape.width > 128 || shape.height > 128) return null;
  if (typeof document === "undefined") return null;

  const canvas = document.createElement("canvas");
  canvas.width = shape.width;
  canvas.height = shape.height;
  const context = canvas.getContext("2d", { alpha: true });
  if (context === null) return null;
  try {
    context.putImageData(new ImageData(shape.rgba, shape.width, shape.height), 0, 0);
    return canvas.toDataURL("image/png");
  } catch {
    // Some WebViews refuse `toDataURL` on a canvas they consider tainted, and
    // one refused pointer shape is not worth an error on screen.
    return null;
  }
}

/**
 * The cursor shape as a CSS `cursor` value.
 *
 * A CSS cursor rather than a sprite drawn over the canvas: the browser moves it
 * at the display's refresh rate without a repaint, which is the whole reason
 * the shape is a separate message in the first place — the pointer moves far
 * more often than it changes shape.
 *
 * **Only correct while the local pointer is driving the remote one.** The shape
 * arrives with no position; its position is wherever the client put the pointer
 * last. A session that is not sending pointer events has a remote pointer that
 * is not where the local one is, and painting the server's I-beam under a local
 * cursor that controls nothing would be a claim about the remote screen that is
 * not true. The caller decides; this function only builds the value.
 */
export function cursorCssValue(shape: CursorShape, fallback: string): string | null {
  const url = cursorDataUrl(shape);
  if (url === null) return null;
  return `url(${url}) ${String(shape.hotspotX)} ${String(shape.hotspotY)}, ${fallback}`;
}
