/**
 * The presenter, against a surface that records rather than draws.
 *
 * jsdom has no 2D context, which is exactly why `FrameTarget` is an interface:
 * everything worth testing here — keyframes, deltas, copy-rect ordering,
 * dropped-frame detection, the pixel conversion — is logic above the canvas,
 * and a test that needed a GPU would be a test nobody runs.
 */

import { describe, expect, it, vi } from "vitest";

import { FLAG_KEYFRAME, FRAME_HEADER_BYTES, FRAME_RECT_BYTES, MESSAGE_CURSOR } from "./frames";
import { FramebufferPresenter, type FrameTarget } from "./presenter";

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
  seq: number;
  keyframe?: boolean;
  message?: number;
  rects: RectSpec[];
}): Uint8Array {
  const payloadBytes = spec.rects.reduce((total, rect) => total + rect.payload.length, 0);
  const bytes = new Uint8Array(
    FRAME_HEADER_BYTES + spec.rects.length * FRAME_RECT_BYTES + payloadBytes,
  );
  const view = new DataView(bytes.buffer);
  view.setBigUint64(0, 1n, true);
  view.setUint32(8, spec.seq, true);
  view.setUint8(12, spec.message ?? 0);
  view.setUint8(13, spec.keyframe === true ? FLAG_KEYFRAME : 0);
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

function rawRect(x: number, y: number, width: number, height: number, pixel: number[]): RectSpec {
  const payload: number[] = [];
  for (let n = 0; n < width * height; n += 1) payload.push(...pixel);
  return { x, y, width, height, encoding: 0, format: 0, payload };
}

function copyRect(x: number, y: number, width: number, height: number, sx: number, sy: number) {
  return {
    x,
    y,
    width,
    height,
    encoding: 3,
    format: 0,
    payload: [sx & 0xff, sx >> 8, sy & 0xff, sy >> 8],
  };
}

type Call =
  | { op: "resize"; width: number; height: number }
  | { op: "put"; x: number; y: number; first: number[] }
  | { op: "copy"; x: number; y: number; sourceX: number; sourceY: number }
  | { op: "image"; x: number; y: number };

function recorder(): { target: FrameTarget; calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    target: {
      resize: (width, height) => calls.push({ op: "resize", width, height }),
      putPixels: (rect, rgba) =>
        calls.push({ op: "put", x: rect.x, y: rect.y, first: [...rgba.slice(0, 4)] }),
      copyRect: (rect, sourceX, sourceY) =>
        calls.push({ op: "copy", x: rect.x, y: rect.y, sourceX, sourceY }),
      drawImage: (rect) => calls.push({ op: "image", x: rect.x, y: rect.y }),
    },
  };
}

describe("FramebufferPresenter", () => {
  it("sizes the surface from a keyframe and paints its rectangles", async () => {
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });

    presenter.accept(
      encode({ seq: 0, keyframe: true, rects: [rawRect(0, 0, 2, 2, [30, 20, 10, 0])] }),
    );
    await vi.waitFor(() => expect(calls).toHaveLength(2));

    expect(calls[0]).toEqual({ op: "resize", width: 2, height: 2 });
    // BGRX in, RGBA out, with the padding byte forced opaque.
    expect(calls[1]).toEqual({ op: "put", x: 0, y: 0, first: [10, 20, 30, 255] });
    expect(presenter.status()).toMatchObject({ width: 2, height: 2, frames: 1, stale: false });
  });

  it("applies rectangles in the order they arrived", async () => {
    // Not an optimisation to reorder: a copy-rect reads what the rectangles
    // before it wrote, so a presenter that hoisted the cheap one corrupts the
    // surface.
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });

    presenter.accept(
      encode({
        seq: 0,
        keyframe: true,
        rects: [
          rawRect(0, 0, 1, 1, [1, 1, 1, 0]),
          copyRect(4, 4, 1, 1, 0, 0),
          rawRect(8, 8, 1, 1, [2, 2, 2, 0]),
        ],
      }),
    );
    await vi.waitFor(() => expect(calls).toHaveLength(4));

    expect(calls.slice(1).map((call) => call.op)).toEqual(["put", "copy", "put"]);
    expect(calls[2]).toEqual({ op: "copy", x: 4, y: 4, sourceX: 0, sourceY: 0 });
  });

  it("keeps rectangle order across an asynchronous image decode", async () => {
    // The JPEG rectangle decodes on a promise. If it were applied when its
    // promise settled rather than in descriptor order, the raw rectangle after
    // it would already have been drawn and the JPEG would paint over it.
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({
      target,
      onChange: () => undefined,
      decodeImage: () =>
        new Promise((resolve) => {
          setTimeout(() => resolve({} as CanvasImageSource), 0);
        }),
    });

    presenter.accept(
      encode({
        seq: 0,
        keyframe: true,
        rects: [
          { x: 0, y: 0, width: 4, height: 4, encoding: 2, format: 0, payload: [0xff, 0xd8] },
          rawRect(0, 0, 1, 1, [3, 3, 3, 0]),
        ],
      }),
    );

    await vi.waitFor(() => expect(calls).toHaveLength(3));
    expect(calls.slice(1).map((call) => call.op)).toEqual(["image", "put"]);
  });

  it("applies whole messages in arrival order even when one of them awaits", async () => {
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({
      target,
      onChange: () => undefined,
      decodeImage: () =>
        new Promise((resolve) => {
          setTimeout(() => resolve({} as CanvasImageSource), 5);
        }),
    });

    presenter.accept(
      encode({
        seq: 0,
        keyframe: true,
        rects: [{ x: 0, y: 0, width: 2, height: 2, encoding: 2, format: 0, payload: [0xff] }],
      }),
    );
    presenter.accept(encode({ seq: 1, rects: [rawRect(0, 0, 1, 1, [4, 4, 4, 0])] }));

    await vi.waitFor(() => expect(calls).toHaveLength(3));
    expect(calls.map((call) => call.op)).toEqual(["resize", "image", "put"]);
  });

  it("notices a gap in the sequence and says the picture may be wrong", async () => {
    const { target } = recorder();
    const changes = vi.fn();
    const presenter = new FramebufferPresenter({ target, onChange: changes });

    presenter.accept(encode({ seq: 10, keyframe: true, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }));
    await vi.waitFor(() => expect(presenter.status().frames).toBe(1));
    expect(presenter.status().stale).toBe(false);

    // 11 was dropped by the encoder under load.
    presenter.accept(encode({ seq: 12, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }));
    await vi.waitFor(() => expect(presenter.status().stale).toBe(true));

    // A keyframe depends on nothing before it, so it repairs the surface.
    presenter.accept(encode({ seq: 13, keyframe: true, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }));
    await vi.waitFor(() => expect(presenter.status().stale).toBe(false));
  });

  it("treats the sequence counter wrapping as continuous", async () => {
    const { target } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });

    presenter.accept(
      encode({ seq: 0xffff_ffff, keyframe: true, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }),
    );
    await vi.waitFor(() => expect(presenter.status().frames).toBe(1));
    presenter.accept(encode({ seq: 0, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }));
    await vi.waitFor(() => expect(presenter.status().frames).toBe(2));
    expect(presenter.status().stale).toBe(false);
  });

  it("records a malformed message rather than dropping it silently", () => {
    const { target } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });
    presenter.accept(new Uint8Array(4));
    expect(presenter.status().decodeError).toBe("shortHeader");
  });

  it("keeps the cursor shape the server set, and forgets it when hidden", async () => {
    const { target } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });

    presenter.accept(
      encode({
        seq: 0,
        message: MESSAGE_CURSOR,
        rects: [{ x: 3, y: 4, width: 1, height: 1, encoding: 0, format: 1, payload: [1, 2, 3, 255] }],
      }),
    );
    await vi.waitFor(() => expect(presenter.status().cursor).not.toBeNull());
    expect(presenter.status().cursor).toMatchObject({ hotspotX: 3, hotspotY: 4, width: 1 });

    presenter.accept(
      encode({
        seq: 1,
        message: MESSAGE_CURSOR,
        rects: [{ x: 0, y: 0, width: 0, height: 0, encoding: 0, format: 1, payload: [] }],
      }),
    );
    await vi.waitFor(() => expect(presenter.status().cursor).toBeNull());
  });

  it("resizes the surface when the core reports the desktop changed size", () => {
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });

    presenter.setDesktopSize(1280, 800);
    expect(calls).toEqual([{ op: "resize", width: 1280, height: 800 }]);
    // The surface is discarded by a resize, so what is on it is no longer the
    // remote screen until a keyframe arrives.
    expect(presenter.status().stale).toBe(true);

    presenter.setDesktopSize(1280, 800);
    expect(calls).toHaveLength(1);
  });

  it("applies nothing once disposed", async () => {
    const { target, calls } = recorder();
    const presenter = new FramebufferPresenter({ target, onChange: () => undefined });
    presenter.dispose();
    presenter.accept(encode({ seq: 0, keyframe: true, rects: [rawRect(0, 0, 1, 1, [0, 0, 0, 0])] }));
    await Promise.resolve();
    expect(calls).toHaveLength(0);
  });

  /*
   * A decoded `ImageBitmap` owns pixels the collector cannot see — about eight
   * megabytes for a 1080p rectangle, held outside the JavaScript heap. A
   * JPEG-encoded stream left to the collector therefore grows for the life of
   * the tab, which is a problem measured in gigabytes on an all-day RDP
   * session and in nothing at all on a thirty-second one. Every path has to
   * close them, which is why there are three of these.
   */
  describe("decoded images", () => {
    /** A stand-in bitmap that records its own close. */
    function bitmap(): { image: CanvasImageSource; closed: () => number } {
      let count = 0;
      const image = {
        close: () => {
          count += 1;
        },
      } as unknown as CanvasImageSource;
      return { image, closed: () => count };
    }

    it("are closed once their rectangle has been drawn", async () => {
      const { target, calls } = recorder();
      const first = bitmap();
      const presenter = new FramebufferPresenter({
        target,
        onChange: () => undefined,
        decodeImage: () => Promise.resolve(first.image),
      });

      presenter.accept(
        encode({
          seq: 0,
          keyframe: true,
          rects: [{ x: 0, y: 0, width: 4, height: 4, encoding: 2, format: 0, payload: [0xff] }],
        }),
      );

      await vi.waitFor(() => expect(calls).toHaveLength(2));
      expect(first.closed()).toBe(1);
    });

    it("are closed even when the tab is disposed mid-decode", async () => {
      const { target } = recorder();
      const late = bitmap();
      const presenter = new FramebufferPresenter({
        target,
        onChange: () => undefined,
        decodeImage: () =>
          new Promise((resolve) => {
            setTimeout(() => resolve(late.image), 0);
          }),
      });

      presenter.accept(
        encode({
          seq: 0,
          keyframe: true,
          rects: [{ x: 0, y: 0, width: 4, height: 4, encoding: 2, format: 0, payload: [0xff] }],
        }),
      );
      // Closing the tab while a rectangle is in flight is the ordinary case,
      // not an edge one: a tab is usually closed while frames are arriving.
      presenter.dispose();

      await vi.waitFor(() => expect(late.closed()).toBe(1));
    });

    it("are closed for the rectangles that decoded when a later one did not", async () => {
      const { target, calls } = recorder();
      const good = bitmap();
      let nth = 0;
      const presenter = new FramebufferPresenter({
        target,
        onChange: () => undefined,
        decodeImage: () => {
          nth += 1;
          return nth === 1 ? Promise.resolve(good.image) : Promise.reject(new Error("truncated"));
        },
      });

      presenter.accept(
        encode({
          seq: 0,
          keyframe: true,
          rects: [
            { x: 0, y: 0, width: 4, height: 4, encoding: 2, format: 0, payload: [0xff] },
            { x: 4, y: 0, width: 4, height: 4, encoding: 2, format: 0, payload: [0xd8] },
          ],
        }),
      );

      await vi.waitFor(() => expect(good.closed()).toBe(1));
      // The unreadable region is skipped rather than ending the session, and
      // the readable one is still drawn — and still released.
      expect(calls.filter((call) => call.op === "image")).toHaveLength(1);
    });
  });
});
