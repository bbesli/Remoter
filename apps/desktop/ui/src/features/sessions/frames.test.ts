/**
 * The wire format, from the other side.
 *
 * These tests build bytes the way `FrameMessage::encode` builds them — by hand,
 * field by field, little-endian — rather than by calling the decoder's own
 * helpers. A test that used the parser to build its input would agree with the
 * parser about a format they were both wrong about.
 */

import { describe, expect, it } from "vitest";

import {
  COPY_RECT_PAYLOAD_BYTES,
  copySource,
  decodeFrameMessage,
  expandRle,
  FLAG_KEYFRAME,
  FRAME_HEADER_BYTES,
  FRAME_RECT_BYTES,
  keyframeExtent,
  MESSAGE_CURSOR,
  MESSAGE_FRAMEBUFFER,
  toRgba,
  type FrameUpdate,
} from "./frames";

interface RectSpec {
  x: number;
  y: number;
  width: number;
  height: number;
  encoding: number;
  format: number;
  payload: number[];
}

function encode(spec: {
  session?: number;
  seq?: number;
  message?: number;
  flags?: number;
  rects: RectSpec[];
}): Uint8Array {
  const payloadBytes = spec.rects.reduce((total, rect) => total + rect.payload.length, 0);
  const total = FRAME_HEADER_BYTES + spec.rects.length * FRAME_RECT_BYTES + payloadBytes;
  const bytes = new Uint8Array(total);
  const view = new DataView(bytes.buffer);

  view.setBigUint64(0, BigInt(spec.session ?? 1), true);
  view.setUint32(8, spec.seq ?? 0, true);
  view.setUint8(12, spec.message ?? MESSAGE_FRAMEBUFFER);
  view.setUint8(13, spec.flags ?? 0);
  view.setUint16(14, spec.rects.length, true);

  spec.rects.forEach((rect, index) => {
    const at = FRAME_HEADER_BYTES + index * FRAME_RECT_BYTES;
    view.setUint16(at, rect.x, true);
    view.setUint16(at + 2, rect.y, true);
    view.setUint16(at + 4, rect.width, true);
    view.setUint16(at + 6, rect.height, true);
    view.setUint8(at + 8, rect.encoding);
    view.setUint8(at + 9, rect.format);
    view.setUint32(at + 10, rect.payload.length, true);
  });

  let cursor = FRAME_HEADER_BYTES + spec.rects.length * FRAME_RECT_BYTES;
  for (const rect of spec.rects) {
    bytes.set(rect.payload, cursor);
    cursor += rect.payload.length;
  }
  return bytes;
}

function raw(width: number, height: number, fill: number[]): RectSpec {
  const payload: number[] = [];
  for (let n = 0; n < width * height; n += 1) payload.push(...fill);
  return { x: 0, y: 0, width, height, encoding: 0, format: 0, payload };
}

describe("decodeFrameMessage", () => {
  it("reads a keyframe with several rectangles, in order", () => {
    const bytes = encode({
      seq: 7,
      flags: FLAG_KEYFRAME,
      rects: [
        { ...raw(2, 1, [1, 2, 3, 0]), x: 0, y: 0 },
        { ...raw(1, 1, [4, 5, 6, 0]), x: 8, y: 9 },
      ],
    });

    const decoded = decodeFrameMessage(bytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    const update = decoded.value as FrameUpdate;

    expect(update.message).toBe("framebuffer");
    expect(update.seq).toBe(7);
    expect(update.keyframe).toBe(true);
    expect(update.rects).toHaveLength(2);
    expect(update.rects[0]?.rect).toEqual({ x: 0, y: 0, width: 2, height: 1 });
    expect(update.rects[1]?.rect).toEqual({ x: 8, y: 9, width: 1, height: 1 });
    // Payload boundaries are derived from the descriptor table, so getting the
    // second one right is the whole point of reading the table first.
    expect([...(update.rects[1]?.payload ?? [])]).toEqual([4, 5, 6, 0]);
  });

  it("carries the session id whole", () => {
    // A 32-bit header would truncate this to 1 and two tabs would become one.
    const bytes = encode({ session: 0x1_0000_0001, rects: [] });
    const decoded = decodeFrameMessage(bytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect(decoded.value.sessionId).toBe(0x1_0000_0001);
  });

  it("does not treat a batch of rectangles as a keyframe on its own", () => {
    const bytes = encode({ flags: 0, rects: [raw(4, 4, [0, 0, 0, 0])] });
    const decoded = decodeFrameMessage(bytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok) return;
    expect((decoded.value as FrameUpdate).keyframe).toBe(false);
  });

  it("reads a cursor message as a hot spot and an image", () => {
    const bytes = encode({
      message: MESSAGE_CURSOR,
      seq: 3,
      rects: [{ x: 2, y: 3, width: 1, height: 1, encoding: 0, format: 1, payload: [9, 8, 7, 255] }],
    });
    const decoded = decodeFrameMessage(bytes);
    expect(decoded.ok).toBe(true);
    if (!decoded.ok || decoded.value.message !== "cursor") throw new Error("not a cursor");
    expect(decoded.value.hotspotX).toBe(2);
    expect(decoded.value.hotspotY).toBe(3);
    expect(decoded.value.width).toBe(1);
    expect(decoded.value.format).toBe("rgba8888");
  });

  it("reads a cursor of zero size as one that hides the pointer", () => {
    const bytes = encode({
      message: MESSAGE_CURSOR,
      rects: [{ x: 0, y: 0, width: 0, height: 0, encoding: 0, format: 1, payload: [] }],
    });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "cursor") throw new Error("not a cursor");
    expect(decoded.value.width).toBe(0);
  });

  it("refuses a buffer shorter than a header", () => {
    expect(decodeFrameMessage(new Uint8Array(8))).toEqual({ ok: false, reason: "shortHeader" });
  });

  it("refuses a descriptor table that is not there", () => {
    const bytes = encode({ rects: [] });
    const view = new DataView(bytes.buffer);
    view.setUint16(14, 4, true);
    expect(decodeFrameMessage(bytes)).toEqual({ ok: false, reason: "shortDescriptors" });
  });

  it("refuses an encoding and a pixel format it does not know", () => {
    const unknownEncoding = encode({ rects: [{ ...raw(1, 1, [0, 0, 0, 0]), encoding: 9 }] });
    expect(decodeFrameMessage(unknownEncoding)).toEqual({ ok: false, reason: "unknownEncoding" });

    const unknownFormat = encode({ rects: [{ ...raw(1, 1, [0, 0, 0, 0]), format: 9 }] });
    expect(decodeFrameMessage(unknownFormat)).toEqual({ ok: false, reason: "unknownFormat" });
  });

  it("refuses trailing bytes rather than ignoring them", () => {
    // Exactly, not at least: a message with something after it is not the
    // message its header describes, and reading it anyway is how a
    // desynchronised stream keeps producing plausible rectangles.
    const bytes = encode({ rects: [raw(1, 1, [0, 0, 0, 0])] });
    const padded = new Uint8Array(bytes.byteLength + 1);
    padded.set(bytes);
    expect(decodeFrameMessage(padded)).toEqual({ ok: false, reason: "payloadMismatch" });
  });

  it("refuses a message kind it does not know", () => {
    expect(decodeFrameMessage(encode({ message: 42, rects: [] }))).toEqual({
      ok: false,
      reason: "unknownMessage",
    });
  });

  it("refuses a cursor message with other than one rectangle", () => {
    const bytes = encode({
      message: MESSAGE_CURSOR,
      rects: [raw(1, 1, [0, 0, 0, 0]), raw(1, 1, [0, 0, 0, 0])],
    });
    expect(decodeFrameMessage(bytes)).toEqual({ ok: false, reason: "cursorShape" });
  });

  it("reads a payload as a view rather than a copy", () => {
    const bytes = encode({ rects: [raw(1, 1, [1, 2, 3, 4])] });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "framebuffer") throw new Error("not a frame");
    expect(decoded.value.rects[0]?.payload.buffer).toBe(bytes.buffer);
  });
});

describe("copySource", () => {
  it("reads the source of a copy-rect", () => {
    const bytes = encode({
      rects: [
        {
          x: 10,
          y: 20,
          width: 4,
          height: 4,
          encoding: 3,
          format: 0,
          // 300 little-endian is 0x2c 0x01; a big-endian read would give 11265.
          payload: [0x2c, 0x01, 0x40, 0x00],
        },
      ],
    });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "framebuffer") throw new Error("not a frame");
    const rect = decoded.value.rects[0];
    if (rect === undefined) throw new Error("no rect");
    expect(rect.payload.byteLength).toBe(COPY_RECT_PAYLOAD_BYTES);
    expect(copySource(rect)).toEqual({ x: 300, y: 64 });
  });

  it("returns nothing for an encoding that is not a copy-rect", () => {
    const bytes = encode({ rects: [raw(1, 1, [0, 0, 0, 0])] });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "framebuffer") throw new Error("not a frame");
    const rect = decoded.value.rects[0];
    if (rect === undefined) throw new Error("no rect");
    expect(copySource(rect)).toBeNull();
  });
});

describe("expandRle", () => {
  it("expands runs into raw pixels", () => {
    // Three of one pixel, then one of another: four pixels for a 2x2 rect.
    const payload = new Uint8Array([3, 0, 0, 0, 10, 20, 30, 0, 1, 0, 0, 0, 40, 50, 60, 0]);
    const out = expandRle({ x: 0, y: 0, width: 2, height: 2 }, payload);
    expect(out).not.toBeNull();
    expect([...(out ?? [])]).toEqual([
      10, 20, 30, 0, 10, 20, 30, 0, 10, 20, 30, 0, 40, 50, 60, 0,
    ]);
  });

  it("refuses runs that do not fill the rectangle exactly", () => {
    const short = new Uint8Array([1, 0, 0, 0, 1, 2, 3, 0]);
    expect(expandRle({ x: 0, y: 0, width: 2, height: 2 }, short)).toBeNull();

    const long = new Uint8Array([9, 0, 0, 0, 1, 2, 3, 0]);
    expect(expandRle({ x: 0, y: 0, width: 2, height: 2 }, long)).toBeNull();
  });
});

describe("toRgba", () => {
  it("forces the padding byte of a BGRX pixel opaque", () => {
    // The defect this prevents: the fourth byte of a BGRX pixel is padding, not
    // alpha. Servers frequently leave it at zero, and a presenter that passes
    // it through draws a completely invisible desktop.
    const out = toRgba("bgrx8888", new Uint8Array([30, 20, 10, 0]));
    expect([...out]).toEqual([10, 20, 30, 255]);
  });

  it("leaves an RGBA pixel alone, alpha included", () => {
    const out = toRgba("rgba8888", new Uint8Array([10, 20, 30, 128]));
    expect([...out]).toEqual([10, 20, 30, 128]);
  });
});

describe("keyframeExtent", () => {
  it("takes the desktop size from the far corner of a keyframe", () => {
    const bytes = encode({
      flags: FLAG_KEYFRAME,
      rects: [
        { ...raw(2, 2, [0, 0, 0, 0]), x: 0, y: 0 },
        { ...raw(2, 2, [0, 0, 0, 0]), x: 1918, y: 1078 },
      ],
    });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "framebuffer") throw new Error("not a frame");
    expect(keyframeExtent(decoded.value)).toEqual({ width: 1920, height: 1080 });
  });

  it("takes nothing from a delta, however large", () => {
    const bytes = encode({ flags: 0, rects: [raw(64, 64, [0, 0, 0, 0])] });
    const decoded = decodeFrameMessage(bytes);
    if (!decoded.ok || decoded.value.message !== "framebuffer") throw new Error("not a frame");
    expect(keyframeExtent(decoded.value)).toBeNull();
  });
});
