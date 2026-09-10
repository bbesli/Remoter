/**
 * Which renderer the terminal actually got.
 *
 * `docs/architecture/rendering.md`: "WebKitGTK can create a WebGL2 context
 * backed by a software rasteriser, so a context that initialises successfully
 * proves nothing." A terminal that silently falls back to `llvmpipe` looks
 * exactly like one on a GPU until the first `yes` scrolls past at four frames
 * a second, so the renderer string is read and classified rather than the
 * context's existence being taken as the answer.
 *
 * The classification is a pure function of that string so it can be tested
 * without a GPU — which is the only way it can be tested at all in jsdom.
 */

/** What the terminal is drawing with, and why. */
export interface RendererReport {
  /** What ended up being used. */
  kind: "webgl" | "dom";
  /** The unmasked renderer string, when the browser would give one. */
  renderer: string | null;
  /** Why the fallback happened. Null when WebGL was taken. */
  reason: string | null;
}

/**
 * Names that mean "this is a CPU pretending to be a GPU".
 *
 * SwiftShader is Chromium's, llvmpipe/softpipe/lavapipe are Mesa's, and
 * "Microsoft Basic Render Driver" is what Windows hands out when there is no
 * usable adapter — a remote desktop session, most often, which is precisely
 * the environment this application runs in.
 */
const SOFTWARE = [
  "swiftshader",
  "llvmpipe",
  "softpipe",
  "lavapipe",
  "software rasterizer",
  "microsoft basic render",
  "mesa offscreen",
  "generic renderer",
  "apple software renderer",
];

/**
 * Whether a WebGL renderer string names a software rasteriser.
 *
 * Unknown strings are treated as hardware. A false negative costs a slightly
 * slower terminal; a false positive would push every unrecognised GPU onto the
 * DOM renderer, which is the worse mistake by a wide margin.
 */
export function isSoftwareRenderer(renderer: string | null | undefined): boolean {
  if (renderer === null || renderer === undefined || renderer === "") return false;
  const lower = renderer.toLowerCase();
  return SOFTWARE.some((name) => lower.includes(name));
}

/** Human-readable, for the session panel. Never a raw driver string alone. */
export function describeRenderer(report: RendererReport | null): string {
  if (report === null) return "not started";
  if (report.kind === "webgl") {
    return report.renderer === null ? "WebGL" : `WebGL · ${report.renderer}`;
  }
  return report.reason === null ? "DOM renderer" : `DOM renderer · ${report.reason}`;
}

/**
 * Reads the WebGL2 renderer string, or null when there is no usable context.
 *
 * The probe canvas is thrown away immediately and its context explicitly lost:
 * a leaked WebGL context counts against a per-document limit that is as low as
 * 16 in some builds, and the terminal needs one of those.
 */
export function probeWebglRenderer(): { available: boolean; renderer: string | null } {
  let canvas: HTMLCanvasElement | null = null;
  try {
    canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl2");
    if (gl === null) return { available: false, renderer: null };

    // WEBGL_debug_renderer_info is the only way to the real adapter name;
    // without it `RENDERER` is a masked, generic string, which classifies as
    // hardware and is the right default.
    const debug = gl.getExtension("WEBGL_debug_renderer_info");
    const raw: unknown =
      debug === null
        ? gl.getParameter(gl.RENDERER)
        : gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
    const renderer = typeof raw === "string" && raw !== "" ? raw : null;

    gl.getExtension("WEBGL_lose_context")?.loseContext();
    return { available: true, renderer };
  } catch {
    // A context request can throw outright in a hardened WebView. That is a
    // "no", not a crash.
    return { available: false, renderer: null };
  } finally {
    canvas?.remove();
  }
}

/**
 * Decides what the terminal should draw with, before an addon is loaded.
 *
 * Deciding beforehand rather than loading the WebGL addon and unloading it on
 * failure matters: the addon takes the context, and taking then releasing one
 * on every tab is how a WebView runs out of them.
 */
export function chooseRenderer(): RendererReport {
  const probe = probeWebglRenderer();
  if (!probe.available) {
    return { kind: "dom", renderer: null, reason: "no WebGL2 context" };
  }
  if (isSoftwareRenderer(probe.renderer)) {
    return {
      kind: "dom",
      renderer: probe.renderer,
      reason: "the WebGL context is software-rasterised",
    };
  }
  return { kind: "webgl", renderer: probe.renderer, reason: null };
}
