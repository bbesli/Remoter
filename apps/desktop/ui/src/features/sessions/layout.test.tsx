/**
 * The rule this application shipped a defect for: nothing of ours is drawn over
 * the remote screen.
 *
 * The bug was not subtle and it was not caught, because nothing checked it. The
 * send-keys and scale controls floated over the top inline-end corner of the
 * picture — which on a maximised Windows session is the minimise, maximise and
 * close buttons — and the desktop size and keyboard hint floated over the bottom
 * inline-start corner, which is the Start button. The owner connected to a real
 * server and could not open the Start menu.
 *
 * The principle behind the fix is what these tests assert, rather than the
 * particular corners that were wrong: **a remote desktop uses all four of its
 * edges and all four of its corners.** Windows puts a taskbar along one edge and
 * window controls in a corner, macOS has a menu bar and a dock, a Linux desktop
 * can put a panel anywhere. There is no safe place to float our own chrome over
 * someone else's screen, so it is not floated anywhere: every control, notice
 * and hint is a row in the flow above the picture, with a height of its own.
 *
 * So the assertions are about *computed layout*, not about CSS text. Each one
 * renders the real component tree, reads `position` back through
 * `getComputedStyle` — Vitest is configured with `css: true`, so the real
 * stylesheets are in the document — and fails if anything but the session host
 * itself is taken out of the flow inside the session area.
 *
 * jsdom does not lay out, so this cannot measure rectangles. It does not need
 * to: an element in normal flow cannot overlap its siblings, and an element that
 * is `absolute`, `fixed` or `sticky` inside the session area is exactly the
 * thing that can. The one deliberate exception is a blocking question about the
 * session — the connect panel, the host key dialog, the ended notice — which is
 * meant to cover it and is absent while a session is simply running. These tests
 * therefore describe a running session.
 *
 * **Full screen is covered by the same sweep, and `fixed` is why.** Full screen
 * here is the window's, not a CSS mode — `MainWindow` calls the Tauri window's
 * `setFullscreen`, and nothing in the component tree or the stylesheets branches
 * on it. So the session area keeps exactly this shape and simply gets taller,
 * and the picture is at its largest. The hazard specific to that case is an
 * element positioned `fixed`, which is laid out against the viewport rather than
 * against any box here and would therefore land on the remote desktop however
 * the flow is arranged. `OUT_OF_FLOW` includes it for that reason.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";

import type { IpcFailure, SessionOpened } from "@/lib/ipc";
import { FramebufferHost } from "./FramebufferHost";
import { SessionSurface } from "./SessionSurface";
import { useSessions, type SessionRecord } from "./store";

const { surfaceMock } = vi.hoisted(() => ({
  surfaceMock: {
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

// The canvas belongs to `surfaces.ts` and needs a 2D context jsdom does not
// provide. What is under test here is where this component puts its chrome, so
// the surface is stubbed down to "a canvas appears inside the stage".
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

vi.mock("./manager", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./manager")>();
  return { ...actual, requestDesktopSize: vi.fn() };
});

vi.mock("./terminals", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./terminals")>();
  return { ...actual, hasTerminal: () => false, focusTerminal: vi.fn() };
});

/** Positions that take an element out of the flow, where it can cover a sibling. */
const OUT_OF_FLOW = new Set(["absolute", "fixed", "sticky"]);

/** Something to recognise an offending element by, when the assertion fails. */
function name(element: Element): string {
  const classes = element.className;
  const label = typeof classes === "string" && classes !== "" ? `.${classes}` : "";
  return `${element.tagName.toLowerCase()}${label} — ${(element.textContent ?? "").slice(0, 40)}`;
}

/**
 * Everything inside `root` that is drawn out of the flow, and so could sit on
 * top of something else.
 *
 * `allowed` is for the session hosts themselves: they *are* the picture, and
 * they are `position: absolute; inset: 0` over the box that holds them.
 */
function floating(root: Element, allowed: readonly Element[] = []): string[] {
  return [...root.querySelectorAll("*")]
    .filter((element) => !allowed.includes(element))
    .filter((element) => OUT_OF_FLOW.has(getComputedStyle(element).position))
    .map(name);
}

function opened(kind: "framebuffer" | "terminal"): SessionOpened {
  return {
    sessionId: 1,
    nodeId: "n1",
    name: "ctso-dc01",
    protocol: kind === "framebuffer" ? "rdp" : "ssh",
    target: "ctso-dc01.internal:3389",
    username: "svc-deploy",
    authMethod: "password",
    via: [],
    capabilities: {
      kind,
      resizable: true,
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
    opened: opened("framebuffer"),
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

const REFUSED: IpcFailure = {
  code: "vault_locked",
  message: "The vault is locked.",
  detail: null,
  actions: [],
};

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

/** The remote screen: the scrolling stage the canvas is drawn into. */
function picture(): HTMLElement {
  return screen.getByLabelText(/remote screen for/i);
}

beforeEach(() => {
  surfaceMock.status = { ...surfaceMock.status, width: 1920, height: 1080, stale: false };
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
});

describe("the graphical session's own chrome", () => {
  it("draws nothing over the picture", () => {
    const { container } = render(wrap(<FramebufferHost record={record()} active />));
    const host = container.firstElementChild;
    expect(host).not.toBeNull();

    // Not "the corners we know about are clear" — nothing at all is out of the
    // flow. A control added later cannot be floated back over the remote screen
    // without this failing.
    expect(floating(host as Element)).toEqual([]);
  });

  it("puts its controls above the picture, in the flow, and the picture last", () => {
    render(wrap(<FramebufferHost record={record()} active />));
    const stage = picture();
    const host = stage.parentElement;
    expect(host).not.toBeNull();

    // A column: the toolbar has a height, and the stage is what is left. That is
    // the whole difference between chrome that covers the remote desktop and
    // chrome that does not.
    expect(getComputedStyle(host as Element).flexDirection).toBe("column");

    const toolbar = screen.getByRole("button", { name: "Ctrl+Alt+Del" }).closest("[class]");
    expect(stage.contains(toolbar)).toBe(false);

    // Nothing follows the picture in the column either, so it reaches the
    // bottom edge of the tab.
    expect(stage.nextElementSibling).toBeNull();
  });

  it("keeps the two chords and the scale controls reachable and labelled", () => {
    render(wrap(<FramebufferHost record={record()} active />));
    // The local machine takes both of these before this window sees them, which
    // is why they are buttons at all. Moving the chrome must not cost them.
    for (const label of ["Ctrl+Alt+Del", "Alt+Tab", "Fit", "1:1", "Smart"]) {
      const button = screen.getByRole("button", { name: label });
      expect(button).toBeInTheDocument();
      expect(picture().contains(button)).toBe(false);
    }
    expect(screen.getByRole("group", { name: /remote screen controls/i })).toBeInTheDocument();
  });

  it("does not repeat the desktop size the status bar already shows", () => {
    render(wrap(<FramebufferHost record={record()} active />));
    // It used to be drawn over the bottom inline-start corner — on the Start
    // button — to say something that was on screen in the status bar anyway.
    expect(screen.queryByText(/1,920/)).toBeNull();
    expect(screen.queryByText(/size not yet known/i)).toBeNull();
  });

  it("still says it is waiting for a frame, without covering the frame", () => {
    surfaceMock.status = { ...surfaceMock.status, width: 0, height: 0 };
    const { container } = render(wrap(<FramebufferHost record={record()} active />));
    expect(screen.getByText(/waiting for the first frame/i)).toBeInTheDocument();
    expect(floating(container.firstElementChild as Element)).toEqual([]);
  });

  it("says a view-only session sends nothing, beside the picture rather than on it", () => {
    const { container } = render(wrap(<FramebufferHost record={record({ viewOnly: true })} active />));
    const notice = screen.getByText(/nothing you type or click is sent/i);
    expect(picture().contains(notice)).toBe(false);
    expect(floating(container.firstElementChild as Element)).toEqual([]);
  });
});

describe("the session area", () => {
  function showSurface(overrides: Partial<SessionRecord> = {}) {
    const tab = record(overrides);
    useSessions.setState({ order: [tab.tabId], byId: { [tab.tabId]: tab }, activeTabId: tab.tabId });
    return render(
      wrap(
        <div data-testid="area">
          <SessionSurface empty={<p>nothing open</p>} />
        </div>,
      ),
    );
  }

  it("draws the warnings and a refused keystroke in the chrome, not on the session", () => {
    showSurface({
      inputError: REFUSED,
      warnings: [{ kind: "other", detail: "rdp.network_level_authentication_disabled", at: 1 }],
    });

    const area = screen.getByTestId("area");
    const host = picture().closest("[data-tab]");
    expect(host).not.toBeNull();
    const stack = (host as Element).parentElement;
    expect(stack).not.toBeNull();

    // The count is in the chrome — outside the box the session hosts fill — and
    // it comes before that box, so it pushes the picture down instead of
    // sitting on the remote taskbar.
    const count = screen.getByText(/notices? from this session/i);
    expect((stack as Element).contains(count)).toBe(false);
    expect(area.contains(count)).toBe(true);
    expect(
      count.compareDocumentPosition(stack as Element) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    // Same for the one that says a keystroke was refused.
    const refused = screen.getByText(/did not reach the server/i);
    expect((stack as Element).contains(refused)).toBe(false);

    // And the sweep: the only thing taken out of the flow anywhere in the
    // session area is the session host itself, which IS the picture.
    expect(floating(area, [host as Element])).toEqual([]);
  });

  it("still tells the user a warning happened rather than hiding it", () => {
    showSurface({ warnings: [{ kind: "other", detail: "rdp.network_level_authentication_disabled", at: 1 }] });
    // Moving it out of the picture must not turn into silence. The count is
    // always drawn, and a danger-toned warning cannot even be folded.
    expect(screen.getByText(/1 notice from this session/i)).toBeInTheDocument();
    expect(screen.getByText(/Network Level Authentication/i)).toBeInTheDocument();
  });

  it("grows no chrome at all for a session with nothing to report", () => {
    // A terminal shares this tree and has no remote edges to protect. It must
    // not pay for the fix with an empty strip above it either.
    const { container } = showSurface({ opened: opened("terminal"), protocol: "ssh" });
    expect(screen.queryByText(/notices? from this session/i)).toBeNull();
    // One child of the area: the positioned box the terminal fills, and nothing
    // above it.
    expect(screen.getByTestId("area").children).toHaveLength(1);
    expect(container).toBeTruthy();
  });
});
