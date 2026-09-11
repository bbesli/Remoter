/**
 * The framebuffer wire format, read.
 *
 * `crates/remoter-proto/src/framebuffer.rs` is the normative description; this
 * is the other end of it. A graphical session pushes its pixels down the same
 * channel a terminal pushes its bytes — `SessionEvent::Data`, forwarded by
 * `remoter-ipc` as a raw byte payload rather than JSON — so what arrives at
 * `sessionChannel`'s `onData` for an RDP or VNC tab is one whole encoded
 * message per push.
 *
 * ```text
 * header, 16 bytes
 *   0  u64  session
 *   8  u32  seq            a gap means the encoder dropped a frame
 *  12  u8   message        0 = framebuffer, 1 = cursor
 *  13  u8   flags          bit 0 = keyframe
 *  14  u16  rect_count
 *
 * then rect_count x 14 bytes
 *   0  u16  x        2  u16 y       4  u16 width    6  u16 height
 *   8  u8   encoding       0 raw, 1 RLE, 2 JPEG, 3 copy-rect
 *   9  u8   pixel_format   0 BGRX8888, 1 RGBA8888
 *  10  u32  byte_length
 *
 * then the payloads, concatenated, in descriptor order
 * ```
 *
 * Three things about this module are deliberate.
 *
 * **It allocates nothing per rectangle.** A `DataView` reads the header and
 * the descriptors in place, and each payload is a `subarray` — a view onto the
 * bytes the channel already handed over, not a copy of them. At 1080p30 a copy
 * per rectangle is megabytes a second of garbage on the one thread that has a
 * 30 ms budget (`docs/architecture/rendering.md`).
 *
 * **It validates exactly as strictly as the Rust decoder does.** Every length
 * is checked against what is present; the payloads must account for the buffer
 * exactly, because trailing bytes mean the message is not the message it claims
 * to be. A short read here would be a presenter parsing a header out of the
 * middle of a JPEG.
 *
 * **It reports a failure rather than throwing one.** A malformed message is
 * something the user is told about — see `frameDecodeKey` — not an exception
 * that unwinds the channel handler and takes the session's remaining frames
 * with it.
 */

/** Bytes in a message header. */
export const FRAME_HEADER_BYTES = 16;

/** Bytes in one rectangle descriptor. */
export const FRAME_RECT_BYTES = 14;

/** A message carrying dirty rectangles of the desktop. */
export const MESSAGE_FRAMEBUFFER = 0;

/** A message carrying the cursor shape the server set. */
export const MESSAGE_CURSOR = 1;

/** Header flag: this update depends on nothing before it. */
export const FLAG_KEYFRAME = 1 << 0;

/** Bytes in a copy-rect payload: a source x and a source y, little-endian. */
export const COPY_RECT_PAYLOAD_BYTES = 4;

/** Bytes per pixel in every format the wire carries. Four, by design. */
export const BYTES_PER_PIXEL = 4;

/** A rectangle of the remote display, in remote pixels. */
export interface Rect {
  x: number;
  y: number;
  width: number;
  height: number;
}

/**
 * How the bytes of a rectangle's pixels are arranged.
 *
 * `bgrx8888` is what an RDP 32bpp surface and `vnc-rs`'s `PixelFormat::bgra()`
 * deliver, and its fourth byte is **padding, not alpha** — a presenter that
 * believes it is alpha renders a transparent desktop. `rgba8888` has a real
 * mask and is what a cursor image uses.
 */
export type PixelFormat = "bgrx8888" | "rgba8888";

/** How a rectangle's payload is compressed. */
export type FrameEncoding = "raw" | "rle" | "jpeg" | "copyRect";

/** One rectangle and the bytes that fill it. */
export interface FrameRect {
  rect: Rect;
  encoding: FrameEncoding;
  /** Ignored for `jpeg` (which carries its own) and `copyRect` (no pixels). */
  format: PixelFormat;
  /** A view onto the message buffer. Valid for as long as that buffer is. */
  payload: Uint8Array;
}

/** A batch of dirty rectangles. */
export interface FrameUpdate {
  message: "framebuffer";
  sessionId: number;
  seq: number;
  /**
   * Whether this update is self-sufficient: it covers the whole desktop and
   * depends on nothing before it, so a presenter may discard what it holds.
   */
  keyframe: boolean;
  /**
   * The rectangles, **in the order they must be applied**. Reordering is not a
   * permitted optimisation: a copy-rect reads what the rectangles before it
   * wrote.
   */
  rects: FrameRect[];
}

/** The cursor shape the server set. */
export interface CursorUpdate {
  message: "cursor";
  sessionId: number;
  seq: number;
  /** The hot spot's offset from the top-left of the image. */
  hotspotX: number;
  hotspotY: number;
  /** Zero width and height hide the pointer. */
  width: number;
  height: number;
  format: PixelFormat;
  image: Uint8Array;
}

export type FrameMessage = FrameUpdate | CursorUpdate;

/**
 * Why a message could not be read.
 *
 * A code rather than a sentence, for the same reason `renderer.ts` uses one:
 * the sentence is read by a user and therefore lives in the catalogue.
 */
export type FrameDecodeReason =
  | "shortHeader"
  | "shortDescriptors"
  | "unknownEncoding"
  | "unknownFormat"
  | "payloadMismatch"
  | "unknownMessage"
  | "cursorShape";

export type FrameDecode =
  | { ok: true; value: FrameMessage }
  | { ok: false; reason: FrameDecodeReason };

/**
 * The catalogue key for a decode failure.
 *
 * Typed as the union of the keys it can return, not as `string`: the catalogue
 * is typed, so a reason with no sentence written for it is a compile error
 * rather than a humanised key on screen.
 */
export type FrameDecodeKey = `framebuffer.decode.${FrameDecodeReason}`;

export function frameDecodeKey(reason: FrameDecodeReason): FrameDecodeKey {
  return `framebuffer.decode.${reason}`;
}

function pixelFormat(wire: number): PixelFormat | null {
  if (wire === 0) return "bgrx8888";
  if (wire === 1) return "rgba8888";
  return null;
}

function frameEncoding(wire: number): FrameEncoding | null {
  switch (wire) {
    case 0:
      return "raw";
    case 1:
      return "rle";
    case 2:
      return "jpeg";
    case 3:
      return "copyRect";
    default:
      return null;
  }
}

/**
 * Reads one encoded message.
 *
 * `bytes` must be exactly one message. The core writes them through
 * `FrameMessage::emit`, which never coalesces or re-chunks — that is the
 * terminal path, and two framed messages run together would be parsed as one
 * with a header in the middle of it.
 */
export function decodeFrameMessage(bytes: Uint8Array): FrameDecode {
  if (bytes.byteLength < FRAME_HEADER_BYTES) return { ok: false, reason: "shortHeader" };

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  // Little-endian throughout: every platform Remoter builds for is
  // little-endian, and a DataView takes the endianness as an argument anyway.
  //
  // The session id is 64 bits on the wire. It is a counter that starts at zero,
  // and `SessionOpened.sessionId` already crosses the IPC boundary as a JSON
  // number, so narrowing it here matches the identifier the rest of the
  // interface holds rather than inventing a second kind of session id.
  const sessionId = Number(view.getBigUint64(0, true));
  const seq = view.getUint32(8, true);
  const message = view.getUint8(12);
  const flags = view.getUint8(13);
  const count = view.getUint16(14, true);

  const descriptorsEnd = FRAME_HEADER_BYTES + count * FRAME_RECT_BYTES;
  if (bytes.byteLength < descriptorsEnd) return { ok: false, reason: "shortDescriptors" };

  // Descriptors first, payloads second: the payload of rectangle n starts where
  // the payloads of every rectangle before it end, so the whole table has to be
  // read before any payload can be located.
  const descriptors: { rect: Rect; encoding: FrameEncoding; format: PixelFormat; length: number }[] =
    [];
  let payloadTotal = 0;
  for (let index = 0; index < count; index += 1) {
    const at = FRAME_HEADER_BYTES + index * FRAME_RECT_BYTES;
    const encoding = frameEncoding(view.getUint8(at + 8));
    if (encoding === null) return { ok: false, reason: "unknownEncoding" };
    const format = pixelFormat(view.getUint8(at + 9));
    if (format === null) return { ok: false, reason: "unknownFormat" };
    const length = view.getUint32(at + 10, true);
    payloadTotal += length;
    descriptors.push({
      rect: {
        x: view.getUint16(at, true),
        y: view.getUint16(at + 2, true),
        width: view.getUint16(at + 4, true),
        height: view.getUint16(at + 6, true),
      },
      encoding,
      format,
      length,
    });
  }

  // Exactly, not at least. Trailing bytes mean this is not the message its
  // header describes, and reading it anyway is how a desynchronised stream
  // keeps producing plausible-looking rectangles.
  if (bytes.byteLength !== descriptorsEnd + payloadTotal) {
    return { ok: false, reason: "payloadMismatch" };
  }

  let cursor = descriptorsEnd;
  const rects: FrameRect[] = [];
  for (const descriptor of descriptors) {
    rects.push({
      rect: descriptor.rect,
      encoding: descriptor.encoding,
      format: descriptor.format,
      payload: bytes.subarray(cursor, cursor + descriptor.length),
    });
    cursor += descriptor.length;
  }

  if (message === MESSAGE_FRAMEBUFFER) {
    return {
      ok: true,
      value: {
        message: "framebuffer",
        sessionId,
        seq,
        keyframe: (flags & FLAG_KEYFRAME) !== 0,
        rects,
      },
    };
  }

  if (message === MESSAGE_CURSOR) {
    const only = rects[0];
    if (rects.length !== 1 || only === undefined) return { ok: false, reason: "cursorShape" };
    return {
      ok: true,
      value: {
        message: "cursor",
        sessionId,
        seq,
        // A cursor message is one rectangle whose x/y are the hot spot rather
        // than a position on the desktop.
        hotspotX: only.rect.x,
        hotspotY: only.rect.y,
        width: only.rect.width,
        height: only.rect.height,
        format: only.format,
        image: only.payload,
      },
    };
  }

  return { ok: false, reason: "unknownMessage" };
}

/** Whether a cursor update asks for no pointer at all. */
export function cursorIsHidden(update: CursorUpdate): boolean {
  return update.width === 0 || update.height === 0;
}

/**
 * Expands a run-length payload into raw pixels.
 *
 * The format is a repeated `u32` little-endian run length followed by one pixel
 * of the declared format. Returns `null` when the runs do not fill the
 * rectangle exactly — under-filling would leave a band of whatever the buffer
 * held before, and over-filling is a payload describing a different rectangle.
 */
export function expandRle(rect: Rect, payload: Uint8Array): Uint8Array | null {
  const pixels = rect.width * rect.height;
  const out = new Uint8Array(pixels * BYTES_PER_PIXEL);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  let read = 0;
  let written = 0;

  while (read + 4 + BYTES_PER_PIXEL <= payload.byteLength) {
    const run = view.getUint32(read, true);
    read += 4;
    const at = read;
    read += BYTES_PER_PIXEL;
    if (written + run * BYTES_PER_PIXEL > out.byteLength) return null;
    for (let n = 0; n < run; n += 1) {
      out[written] = payload[at] as number;
      out[written + 1] = payload[at + 1] as number;
      out[written + 2] = payload[at + 2] as number;
      out[written + 3] = payload[at + 3] as number;
      written += BYTES_PER_PIXEL;
    }
  }

  if (read !== payload.byteLength || written !== out.byteLength) return null;
  return out;
}

/**
 * Raw pixels as a canvas wants them: RGBA, straight alpha.
 *
 * The `x` in BGRX is padding and **must** be forced opaque. It arrives as
 * whatever the server left in it — frequently zero — and a presenter that
 * passes it through as alpha draws an invisible desktop. That is not a
 * hypothetical: it is the first thing that goes wrong with a 32bpp RDP surface.
 */
export function toRgba(format: PixelFormat, raw: Uint8Array): Uint8ClampedArray<ArrayBuffer> {
  const out = new Uint8ClampedArray(new ArrayBuffer(raw.byteLength));
  if (format === "rgba8888") {
    out.set(raw);
    return out;
  }
  for (let at = 0; at + 3 < raw.byteLength; at += BYTES_PER_PIXEL) {
    out[at] = raw[at + 2] as number;
    out[at + 1] = raw[at + 1] as number;
    out[at + 2] = raw[at] as number;
    out[at + 3] = 255;
  }
  return out;
}

/** Where a copy-rect reads from, or `null` for a payload that is not one. */
export function copySource(rect: FrameRect): { x: number; y: number } | null {
  if (rect.encoding !== "copyRect" || rect.payload.byteLength !== COPY_RECT_PAYLOAD_BYTES) {
    return null;
  }
  const view = new DataView(rect.payload.buffer, rect.payload.byteOffset, COPY_RECT_PAYLOAD_BYTES);
  return { x: view.getUint16(0, true), y: view.getUint16(2, true) };
}

/**
 * The desktop size a keyframe implies.
 *
 * A keyframe covers the whole desktop by definition, so the far corner of its
 * rectangles is the far corner of the display. This is the only place the size
 * is learned from pixels; `SessionEvent::Resized` is the authoritative one and
 * arrives separately.
 */
export function keyframeExtent(update: FrameUpdate): { width: number; height: number } | null {
  if (!update.keyframe || update.rects.length === 0) return null;
  let width = 0;
  let height = 0;
  for (const rect of update.rects) {
    width = Math.max(width, rect.rect.x + rect.rect.width);
    height = Math.max(height, rect.rect.y + rect.rect.height);
  }
  if (width === 0 || height === 0) return null;
  return { width, height };
}
