import { describe, expect, it } from "vitest";

import {
  defaultScaleMode,
  layoutFor,
  remotePoint,
  smartResizeRequest,
  ZOOM_STEPS,
} from "./scaling";

const DESKTOP = { width: 1920, height: 1080 };

describe("layoutFor", () => {
  it("fits a desktop larger than the tab, proportions kept", () => {
    const layout = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 960, height: 900 },
      devicePixelRatio: 1,
    });
    expect(layout.scale).toBeCloseTo(0.5);
    expect(layout.width).toBe(960);
    expect(layout.height).toBe(540);
    expect(layout.scrolls).toBe(false);
  });

  it("never enlarges in fit", () => {
    // A desktop smaller than the tab is centred at its own size. Blowing it up
    // to fill the window is the resampling this module exists to avoid, and
    // nobody asked for a magnifier by making their window large.
    const layout = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: { width: 800, height: 600 },
      viewport: { width: 1600, height: 1200 },
      devicePixelRatio: 1,
    });
    expect(layout.scale).toBe(1);
    expect(layout.width).toBe(800);
  });

  it("scrolls at 1:1 when the desktop is larger than the tab", () => {
    const layout = layoutFor({
      mode: "actual",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 1200, height: 800 },
      devicePixelRatio: 1,
    });
    expect(layout.scale).toBe(1);
    expect(layout.scrolls).toBe(true);
  });

  it("magnifies by whole pixels only", () => {
    for (const step of ZOOM_STEPS) {
      const layout = layoutFor({
        mode: "zoom",
        zoom: step,
        desktop: { width: 100, height: 50 },
        viewport: { width: 1000, height: 1000 },
        devicePixelRatio: 1,
      });
      expect(layout.scale).toBe(step);
      expect(Number.isInteger(layout.scale)).toBe(true);
    }
  });

  it("rounds a fractional zoom rather than resampling by it", () => {
    // A 1.5x zoom mixes each glyph's stem across two output pixels, which is
    // the mush case. It cannot be reached through the interface; this is the
    // guard for a value that arrived from somewhere else.
    const layout = layoutFor({
      mode: "zoom",
      zoom: 1.5,
      desktop: { width: 100, height: 50 },
      viewport: { width: 1000, height: 1000 },
      devicePixelRatio: 1,
    });
    expect(Number.isInteger(layout.scale)).toBe(true);
  });

  it("asks for crisp sampling against device pixels, not CSS ones", () => {
    // A half-scale surface on a 2x display is still one remote pixel per
    // device pixel. Smoothing it would blur a picture that is already exact.
    const retina = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 960, height: 540 },
      devicePixelRatio: 2,
    });
    expect(retina.scale).toBeCloseTo(0.5);
    expect(retina.crisp).toBe(true);

    const ordinary = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 960, height: 540 },
      devicePixelRatio: 1,
    });
    expect(ordinary.crisp).toBe(false);
  });

  it("draws nothing before a desktop size is known", () => {
    const layout = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: { width: 0, height: 0 },
      viewport: { width: 800, height: 600 },
      devicePixelRatio: 1,
    });
    expect(layout.width).toBe(0);
    expect(layout.height).toBe(0);
  });

  it("shows the whole frame while a smart resize is still in flight", () => {
    // Smart resize asks the server for a new desktop and the answer takes a
    // round trip. Until then the frame actually on the wire is the old size,
    // and it still has to be shown whole rather than cropped.
    const layout = layoutFor({
      mode: "smart",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 800, height: 600 },
      devicePixelRatio: 1,
    });
    expect(layout.scrolls).toBe(false);
    expect(layout.width).toBeLessThanOrEqual(800);
  });
});

describe("smartResizeRequest", () => {
  it("asks for physical pixels, so a HiDPI desktop is rendered sharp remotely", () => {
    expect(smartResizeRequest({ width: 960, height: 540 }, 2)).toEqual({
      width: 1920,
      height: 1080,
    });
  });

  it("keeps the width even, as the protocol requires", () => {
    const request = smartResizeRequest({ width: 801, height: 600 }, 1);
    expect(request?.width).toBe(800);
  });

  it("asks for nothing when the tab is below what the protocol permits", () => {
    expect(smartResizeRequest({ width: 100, height: 100 }, 1)).toBeNull();
    expect(smartResizeRequest({ width: 0, height: 0 }, 1)).toBeNull();
  });

  it("clamps to the protocol's ceiling", () => {
    const request = smartResizeRequest({ width: 6000, height: 5000 }, 3);
    expect(request?.width).toBeLessThanOrEqual(8192);
    expect(request?.height).toBeLessThanOrEqual(8192);
  });
});

describe("remotePoint", () => {
  it("divides the tab's scale back out", () => {
    const layout = layoutFor({
      mode: "fit",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 960, height: 540 },
      devicePixelRatio: 1,
    });
    expect(remotePoint(layout, DESKTOP, 480, 270)).toEqual({ x: 960, y: 540 });
  });

  it("clamps to the desktop rather than wrapping", () => {
    // A pointer dragged past the edge must report the edge. A coordinate that
    // wrapped would put the remote pointer on the opposite side of the screen.
    const layout = layoutFor({
      mode: "actual",
      zoom: 2,
      desktop: DESKTOP,
      viewport: { width: 3000, height: 3000 },
      devicePixelRatio: 1,
    });
    expect(remotePoint(layout, DESKTOP, 99_999, -40)).toEqual({ x: 1919, y: 0 });
  });

  it("never exceeds what the protocols can carry", () => {
    const huge = { width: 70_000, height: 70_000 };
    const layout = layoutFor({
      mode: "actual",
      zoom: 2,
      desktop: huge,
      viewport: { width: 100, height: 100 },
      devicePixelRatio: 1,
    });
    expect(remotePoint(layout, huge, 69_000, 69_000)).toEqual({ x: 0xffff, y: 0xffff });
  });
});

describe("defaultScaleMode", () => {
  it("is smart resize where the session says it is resizable", () => {
    expect(defaultScaleMode(true)).toBe("smart");
  });

  it("is fit otherwise, not 1:1", () => {
    // At 1:1 the first thing a user sees of a 1920x1080 desktop in a 1200px tab
    // is its top-left corner, with the task bar behind a scrollbar.
    expect(defaultScaleMode(false)).toBe("fit");
  });
});
