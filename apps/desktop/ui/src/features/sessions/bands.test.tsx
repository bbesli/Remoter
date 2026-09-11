/**
 * Why the picture does not fill the tab, said where the question is asked.
 *
 * # The measurement that produced this file
 *
 * The report was "Fit does not fit": a 1920x1080 Windows desktop in a wider
 * pane, a band down each side, and the scale row reading `Fit | 1:1 | 2x | 3x |
 * 4x` with no Smart in it. Three readings of the code produced three different
 * theories. Rendering the real surface against a real RDP-shaped record settled
 * it in one run:
 *
 * - with `capabilities.resizable: true` on the record, the row is
 *   `Smart, Fit, 1:1, 2x, 3x, 4x` and the mode is `smart` — so
 *   `FramebufferHost`'s `record.opened?.capabilities.resizable === true` is not
 *   the broken link, and neither is `record.opened` being populated;
 * - after `handleMessage` takes one `rdp.display_control_unavailable` warning,
 *   the *same record* reads `resizable: false`, the mode has moved to `fit`,
 *   and the row is exactly what the owner is looking at.
 *
 * The link that is not what it looks like is therefore `record.opened`. It is
 * not "what `session_open` replied": `Adapter::Rdp.capabilities().resizable` is
 * `true` and arrives intact, and the assertion in `crates/remoter-ipc` that says
 * so is correct and beside the point. `manager.ts`'s `revokeResize` overwrites
 * the field on the record afterwards, when the adapter reports that the server
 * never opened MS-RDPEDISP — and the adapter only reports that because the
 * server genuinely refused (`crates/remoter-proto-rdp/src/session.rs`:
 * `encode_resize` returns `None`, so there is no channel to ask down).
 *
 * So the control was withdrawn correctly, the band is unavoidable on this
 * server, and the thing that was missing was not Smart — it was a sentence.
 * What these tests pin is that sentence: present exactly when the picture is
 * banded and nothing here can change the remote size, absent otherwise, and in
 * the flow above the picture like everything else in this component.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";

import type { SessionOpened } from "@/lib/ipc";
import { FramebufferHost } from "./FramebufferHost";
import { useSessions, type SessionRecord } from "./store";

const { surfaceMock } = vi.hoisted(() => ({
  surfaceMock: {
    // One object with a stable identity: `useSyncExternalStore` re-renders on
    // every change of the snapshot's identity, and a fresh object per read
    // spins for ever.
    status: {
      width: 1920,
      height: 1080,
      frames: 1,
      bytes: 1,
      stale: false,
      decodeError: null,
      cursor: null,
    },
  },
}));

vi.mock("./surfaces", () => {
  const canvas = document.createElement("canvas");
  return {
    attachSurface: (_tabId: string, container: HTMLElement) => {
      container.appendChild(canvas);
      return () => canvas.remove();
    },
    subscribeSurface: () => () => undefined,
    surfaceElement: () => canvas,
    surfaceUnavailable: () => false,
    surfaceStatus: () => surfaceMock.status,
  };
});

vi.mock("./manager", () => ({ requestDesktopSize: vi.fn() }));

/**
 * The stage's measured size.
 *
 * jsdom lays nothing out, so every element reports a client size of zero and
 * `useViewport` would report a viewport of nothing — in which there is no band
 * to explain. The size is stubbed on the prototype and a `ResizeObserver` is
 * provided, because `useViewport` gives up without one; between them the
 * component sees the same numbers a real window would give it.
 */
const stage = { width: 0, height: 0 };

function withViewport(width: number, height: number): void {
  stage.width = width;
  stage.height = height;
}

beforeEach(() => {
  withViewport(2400, 1000);
  surfaceMock.status = { ...surfaceMock.status, width: 1920, height: 1080 };
  Object.defineProperty(HTMLElement.prototype, "clientWidth", {
    configurable: true,
    get: () => stage.width,
  });
  Object.defineProperty(HTMLElement.prototype, "clientHeight", {
    configurable: true,
    get: () => stage.height,
  });
  vi.stubGlobal(
    "ResizeObserver",
    class {
      observe(): void {
        /* The size never changes inside one test; the initial read is enough. */
      }
      unobserve(): void {
        /* Nothing is held. */
      }
      disconnect(): void {
        /* Nothing is held. */
      }
    },
  );
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  Reflect.deleteProperty(HTMLElement.prototype, "clientWidth");
  Reflect.deleteProperty(HTMLElement.prototype, "clientHeight");
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

function opened(resizable: boolean): SessionOpened {
  return {
    sessionId: 1,
    nodeId: "n1",
    name: "ctso-dc01",
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    username: "svc-deploy",
    authMethod: "password",
    via: [],
    capabilities: {
      kind: "framebuffer",
      resizable,
      clipboard: "none",
      fileTransfer: false,
      audio: false,
      printing: false,
      multiMonitor: false,
      recordable: true,
    },
    startedAtMs: Date.now(),
    recording: "never",
  };
}

function record(overrides: Partial<SessionRecord> = {}): SessionRecord {
  return {
    tabId: "t1",
    nodeId: "n1",
    name: "ctso-dc01",
    colour: null,
    protocol: "rdp",
    target: "ctso-dc01.internal:3389",
    sessionId: 1,
    phase: "running",
    opened: opened(false),
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    inputError: null,
    warnings: [],
    metrics: { bytesIn: 0, bytesOut: 0, cols: 1920, rows: 1080, echoMs: null },
    renderer: null,
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
    ...overrides,
  };
}

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/** The chip, if it is drawn. */
function explanation(): HTMLElement | null {
  return screen.queryByText(/sets its own size/i);
}

const OUT_OF_FLOW = new Set(["absolute", "fixed", "sticky"]);

describe("the withdrawn Smart control", () => {
  it("is not drawn on a server that refused the resize channel", () => {
    render(wrap(<FramebufferHost record={record()} active />));

    // Measured, not assumed: this is the row the owner is looking at.
    const group = screen.getByRole("group", { name: /scale the remote screen/i });
    expect([...group.querySelectorAll("button")].map((b) => b.textContent)).toEqual([
      "Fit",
      "1:1",
      "2×",
      "3×",
      "4×",
    ]);
  });

  it("is drawn, and is the default, where the server has not refused", () => {
    render(
      wrap(
        <FramebufferHost
          record={record({ opened: opened(true), scale: { mode: "smart", zoom: 2 } })}
          active
        />,
      ),
    );

    const group = screen.getByRole("group", { name: /scale the remote screen/i });
    expect([...group.querySelectorAll("button")].map((b) => b.textContent)).toEqual([
      "Smart",
      "Fit",
      "1:1",
      "2×",
      "3×",
      "4×",
    ]);
    expect(screen.getByRole("button", { name: "Smart" })).toHaveAttribute("aria-pressed", "true");
  });
});

describe("the band Fit leaves", () => {
  it("is explained beside the scale controls, not left to be blamed on Fit", () => {
    // 1920x1080 fitted into a 2400x1000 tab: the height binds, the drawn width
    // is 1778, and 622 pixels of tab are empty. Exactly the owner's session.
    render(wrap(<FramebufferHost record={record()} active />));

    const note = explanation();
    expect(note).not.toBeNull();
    // Beside the controls, in the same row — the place the question is asked.
    const group = screen.getByRole("group", { name: /scale the remote screen/i });
    expect(group.parentElement?.contains(note as Node)).toBe(true);
    // And the rest of the answer is one hover away, including the part that
    // says stretching is not on offer.
    expect(note).toHaveAttribute(
      "title",
      expect.stringContaining("stretching the picture instead would blur the remote text"),
    );
  });

  it("says nothing when the picture already fills the tab", () => {
    withViewport(1920, 1080);
    render(wrap(<FramebufferHost record={record()} active />));

    // No band, no question, no sentence. A standing note about a band that is
    // not there is the chrome this component spent a defect learning to avoid.
    expect(explanation()).toBeNull();
  });

  it("says nothing when the desktop is larger than the tab at 1:1", () => {
    withViewport(1200, 800);
    render(wrap(<FramebufferHost record={record({ scale: { mode: "actual", zoom: 2 } })} active />));

    // The picture overflows and scrolls; there is no empty tab to explain.
    expect(explanation()).toBeNull();
  });

  it("says nothing on a server that can be asked to resize", () => {
    render(wrap(<FramebufferHost record={record({ opened: opened(true) })} active />));

    // The band is there, but Smart is in the row above and removing it is one
    // click away. Telling this user their server sets its own size would be
    // false.
    expect(explanation()).toBeNull();
  });

  it("says nothing before the first frame", () => {
    surfaceMock.status = { ...surfaceMock.status, width: 0, height: 0 };
    render(wrap(<FramebufferHost record={record()} active />));

    expect(explanation()).toBeNull();
  });

  it("is a row in the flow, never a thing on top of the remote screen", () => {
    const { container } = render(wrap(<FramebufferHost record={record()} active />));
    const host = container.firstElementChild;
    expect(host).not.toBeNull();
    expect(explanation()).not.toBeNull();

    // The same sweep `layout.test.tsx` runs, with this chip on screen: a
    // remote desktop uses all four of its own edges, and the last control that
    // floated over one covered the Start button.
    const floating = [...(host as Element).querySelectorAll("*")].filter((element) =>
      OUT_OF_FLOW.has(getComputedStyle(element).position),
    );
    expect(floating).toEqual([]);
    // And it is above the picture rather than inside it.
    const stageElement = screen.getByLabelText(/remote screen for/i);
    expect(stageElement.contains(explanation())).toBe(false);
  });
});
