/**
 * The renderer check, which exists because a WebGL2 context that initialises
 * successfully proves nothing (docs/architecture/rendering.md).
 */

import { describe, expect, it } from "vitest";

import { i18n, initI18n } from "@/i18n";
import { describeRenderer, isSoftwareRenderer } from "./renderer";

// English is bundled, so a real `t` is available without rendering anything.
initI18n();
const t = i18n().getFixedT("en", "sessions");

/** U+2068 and U+2069, the isolate an adapter name is wrapped in. */
const BIDI = /[\u2066-\u2069]/g;

describe("classifying a WebGL renderer string", () => {
  it("recognises the software rasterisers that matter", () => {
    // The three that actually turn up: Mesa's on Linux, Chromium's own, and
    // what Windows hands out inside a remote desktop session.
    expect(isSoftwareRenderer("Mesa/X.org llvmpipe (LLVM 17.0.6, 256 bits)")).toBe(true);
    expect(isSoftwareRenderer("Google SwiftShader")).toBe(true);
    expect(isSoftwareRenderer("Microsoft Basic Render Driver")).toBe(true);
    expect(isSoftwareRenderer("llvmpipe")).toBe(true);
  });

  it("treats a real adapter as hardware", () => {
    expect(isSoftwareRenderer("NVIDIA GeForce RTX 4070/PCIe/SSE2")).toBe(false);
    expect(isSoftwareRenderer("Apple M2")).toBe(false);
    expect(isSoftwareRenderer("AMD Radeon RX 7900 XTX (radeonsi, navi31)")).toBe(false);
  });

  it("treats an unknown or masked string as hardware", () => {
    // A masked string is the browser refusing to say, not a confession. Pushing
    // every unrecognised adapter onto the DOM renderer would be the worse
    // mistake by a wide margin.
    expect(isSoftwareRenderer("WebKit WebGL")).toBe(false);
    expect(isSoftwareRenderer(null)).toBe(false);
    expect(isSoftwareRenderer(undefined)).toBe(false);
    expect(isSoftwareRenderer("")).toBe(false);
  });
});

describe("describing what the terminal got", () => {
  it("names the adapter when there is one", () => {
    // The adapter name is wrapped in a bidi isolate before it goes into the
    // sentence, so the marks come off before the comparison. See src/test/bidi.ts.
    expect(
      describeRenderer(t, { kind: "webgl", renderer: "Apple M2", reason: null }).replace(BIDI, ""),
    ).toBe("WebGL · Apple M2");
  });

  it("says why it fell back, not merely that it did", () => {
    expect(
      describeRenderer(t, {
        kind: "dom",
        renderer: "llvmpipe",
        reason: "software",
      }),
    ).toBe("DOM renderer · the WebGL context is software-rasterised");
  });

  it("does not claim a renderer before a terminal exists", () => {
    expect(describeRenderer(t, null)).toBe("not started");
  });
});
