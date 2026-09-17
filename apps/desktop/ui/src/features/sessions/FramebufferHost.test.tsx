/**
 * What the graphical session surface does with a keystroke and a click.
 *
 * The assertions that matter are about what reaches the core. A surface that
 * captured input and dropped it would look identical on screen to one that
 * drives a desktop, and the previous version of this file could only assert
 * that the interface admitted it sent nothing. Now the interface sends, so the
 * tests follow the event all the way to `ipc.sendKey` and `ipc.sendPointer` —
 * with both halves of the key, because the two protocols want different halves
 * and neither can be derived from the other here.
 *
 * The negative assertions are still the sharpest ones, and they moved: a
 * view-only session must attach no handler at all, and a key the application
 * owns must not be swallowed on its way to the one window-level listener.
 */

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { useKeyboardRegistry } from "@/hooks/keyboard";
import type { SessionOpened } from "@/lib/ipc";
import { FramebufferHost } from "./FramebufferHost";
import { useSessions, type SessionRecord } from "./store";

const { ipcMock, surfaceMock, terminalsMock } = vi.hoisted(() => ({
  ipcMock: {
    // Typed with their arguments, not as bare spies: these assertions are
    // about *what* was sent, and `mock.calls[0][1]` on an untyped spy is a
    // zero-length tuple that no assertion can reach into.
    sendKey: vi.fn(
      (
        _sessionId: number,
        _key: { scancode: number; keysym: number | null; modifiers: number; pressed: boolean },
      ) => Promise.resolve(),
    ),
    sendPointer: vi.fn(
      (
        _sessionId: number,
        _pointer: { x: number; y: number; buttons: number; wheel: number; wheelX: number },
      ) => Promise.resolve(),
    ),
    syncClipboard: vi.fn((_sessionId: number) => Promise.resolve()),
    getSettings: vi.fn(() => Promise.resolve({ terminalPrefix: "ctrl+alt", shortcuts: {} })),
  },
  terminalsMock: {
    reportClipboardFailure: vi.fn((_tabId: string, _failure: { code: string }) => undefined),
  },
  surfaceMock: {
    /**
     * What the presenter reports, as one object whose identity is stable.
     *
     * `useSyncExternalStore` re-renders whenever the snapshot's identity
     * changes, so a mock that built a fresh object per read would spin for
     * ever — which is exactly what the real presenter avoids by caching its
     * status.
     */
    status: {
      width: 1920,
      height: 1080,
      frames: 1,
      bytes: 1,
      stale: false,
      decodeError: null,
      cursor: null,
    },
    /** Where the canvas sits in the window, for coordinate translation. */
    box: { left: 10, top: 20 },
  },
}));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

vi.mock("./manager", () => ({ requestDesktopSize: vi.fn() }));

// The terminals' module owns xterm, which jsdom cannot host. This file only
// needs to know that a clipboard failure was reported, and where.
vi.mock("./terminals", () => terminalsMock);

// The canvas is owned outside React by `surfaces.ts` and needs a 2D context,
// which jsdom does not provide. Mocked so that these tests are about what this
// component does with an event, which is what it is responsible for.
vi.mock("./surfaces", () => {
  const canvas = document.createElement("canvas");
  canvas.getBoundingClientRect = () =>
    ({
      left: surfaceMock.box.left,
      top: surfaceMock.box.top,
      right: 0,
      bottom: 0,
      width: 0,
      height: 0,
      x: surfaceMock.box.left,
      y: surfaceMock.box.top,
      toJSON: () => ({}),
    }) as DOMRect;
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

function opened(resizable: boolean, clipboard: "none" | "text" = "text"): SessionOpened {
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
      clipboard,
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
    opened: opened(true),
    failure: null,
    failedStage: null,
    retryable: false,
    closeReason: null,
    hostKey: null,
    hostKeyBusy: false,
    hostKeyError: null,
    prompt: null,
    promptBusy: false,
    promptError: null,
    inputError: null,
    warnings: [],
    clipboardFiles: { offer: null, transfer: null },
    metrics: { bytesIn: 0, bytesOut: 0, cols: 0, rows: 0, echoMs: null },
    renderer: null,
    scale: { mode: "fit", zoom: 2 },
    viewOnly: null,
    startedAt: Date.now(),
    stageAt: {},
    ...overrides,
  };
}

function show(overrides: Partial<SessionRecord> = {}, active = true) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <FramebufferHost record={record(overrides)} active={active} />
    </QueryClientProvider>,
  );
}

/** The remote screen itself — the element that takes the keyboard. */
function screenElement(): HTMLElement {
  return screen.getByLabelText(/remote screen for/i);
}

/**
 * Lets the queued input reach the core.
 *
 * Every send is chained onto the one before it so that two keystrokes cannot
 * arrive out of order, which means the first one leaves in a microtask rather
 * than in the call that produced it. A test that asserted immediately would be
 * asserting before the queue had run.
 */
async function delivered(): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
}

beforeEach(() => {
  surfaceMock.status = { ...surfaceMock.status, width: 1920, height: 1080 };
  surfaceMock.box = { left: 10, top: 20 };
  useSessions.setState({ order: ["t1"], byId: { t1: record() }, activeTabId: "t1" });
});

afterEach(async () => {
  // Unmounting releases whatever was still held, which is one more queued send
  // — and one that would otherwise be counted against the next test.
  cleanup();
  await new Promise((resolve) => setTimeout(resolve, 0));
  vi.clearAllMocks();
  useSessions.setState({ order: [], byId: {}, activeTabId: null });
  useKeyboardRegistry.getState().detach("shell");
});

describe("the keyboard", () => {
  it("sends the scancode RDP wants and the keysym VNC wants, from one keypress", async () => {
    show();
    // A Turkish Q keyboard: the physical key a US layout calls `KeyI` types a
    // dotless ı. The scancode is the position and the keysym is the character,
    // and a client that sent only one of them types the wrong letter on one of
    // the two protocols.
    fireEvent.keyDown(screenElement(), { code: "KeyI", key: "ı" });
    await delivered();
    expect(ipcMock.sendKey).toHaveBeenCalledWith(1, {
      scancode: 0x17,
      keysym: 0x0100_0131,
      modifiers: 0,
      pressed: true,
    });
  });

  it("carries the lock state, so the far end does not type in capitals", async () => {
    show();
    // jsdom's `getModifierState` answers for the four modifier flags and
    // nothing else, so the latch is stated directly. What is under test is
    // that this component asks — a client that read only `shiftKey` would miss
    // it entirely.
    const event = new KeyboardEvent("keydown", { bubbles: true, key: "A" });
    Object.defineProperty(event, "code", { value: "KeyA" });
    Object.defineProperty(event, "getModifierState", {
      value: (name: string) => name === "CapsLock",
    });
    fireEvent(screenElement(), event);
    await delivered();
    // Bit 5 is Caps Lock in `remoter_proto::Modifiers`. RDP synchronises
    // latches explicitly; a session that never says so types in the wrong case
    // until the user works out why.
    expect(ipcMock.sendKey.mock.calls[0]?.[1].modifiers).toBe(1 << 5);
  });

  it("sends the release only for a key it pressed", async () => {
    show();
    const element = screenElement();
    // A keyup whose keydown went somewhere else — a dialog that has just
    // closed, an application shortcut — is not this session's to report. Sending
    // it alone tells the far end a key was released that it never saw pressed.
    fireEvent.keyUp(element, { code: "KeyA", key: "a" });
    await delivered();
    expect(ipcMock.sendKey).not.toHaveBeenCalled();

    fireEvent.keyDown(element, { code: "KeyA", key: "a" });
    fireEvent.keyUp(element, { code: "KeyA", key: "a" });
    await delivered();
    expect(ipcMock.sendKey).toHaveBeenCalledTimes(2);
    expect(ipcMock.sendKey.mock.calls[1]?.[1].pressed).toBe(false);
  });

  it("releases what is still held when the screen loses focus", async () => {
    show();
    const element = screenElement();
    element.focus();
    fireEvent.keyDown(element, { code: "AltLeft", key: "Alt", altKey: true });
    await delivered();
    ipcMock.sendKey.mockClear();

    // The bug: the window manager takes Alt+Tab, the keyup never arrives, and
    // the far end believes Alt is held for the rest of the session — so every
    // later keystroke is an Alt chord and nothing the user types works.
    element.blur();
    await delivered();
    expect(ipcMock.sendKey).toHaveBeenCalledWith(1, {
      scancode: 0x38,
      keysym: null,
      modifiers: 0,
      pressed: false,
    });
  });

  it("sends a key it cannot place nowhere, and does not swallow it either", async () => {
    show();
    const prevented = !fireEvent.keyDown(screenElement(), {
      code: "AudioVolumeUp",
      key: "AudioVolumeUp",
    });
    await delivered();
    expect(ipcMock.sendKey).not.toHaveBeenCalled();
    expect(prevented).toBe(false);
  });
});

describe("who gets the keystroke", () => {
  it("keeps a character the user is typing, even one bound to a shortcut", async () => {
    // `?` opens the cheat sheet. A remote text editor in which question marks
    // opened a help panel would be unusable, so a chord with no Ctrl, Alt or
    // Meta is never taken from the remote host.
    show();
    fireEvent.keyDown(screenElement(), { code: "Slash", key: "?", shiftKey: true });
    await delivered();
    expect(ipcMock.sendKey).toHaveBeenCalledTimes(1);
  });

  it("lets a universal shortcut through to the application", async () => {
    // Locking the vault is one chord away from anywhere, including from inside
    // a session — that is what "universal" means. The key is not sent to the
    // remote host and, just as importantly, is not swallowed: the one
    // window-level listener is what fires it.
    useKeyboardRegistry.getState().attach("shell", (id) => (id === "vault.lock" ? vi.fn() : null));
    show();
    const prevented = !fireEvent.keyDown(screenElement(), {
      code: "KeyL",
      key: "l",
      ctrlKey: true,
    });
    await delivered();
    expect(ipcMock.sendKey).not.toHaveBeenCalled();
    expect(prevented).toBe(false);
  });

  it("sends an application shortcut to the remote host instead", async () => {
    // `Ctrl+W` closes a tab — but inside a focused session it is the remote
    // host's, exactly as it is inside a focused terminal. The prefix is how the
    // user reaches the local one.
    useKeyboardRegistry.getState().attach("shell", (id) => (id === "tab.close" ? vi.fn() : null));
    show();
    fireEvent.keyDown(screenElement(), { code: "KeyW", key: "w", ctrlKey: true });
    await delivered();
    expect(ipcMock.sendKey).toHaveBeenCalledTimes(1);
  });

  it("says which keys it is taking, and how to get one back", async () => {
    show();
    act(() => {
      screenElement().focus();
    });
    // The way out has to be on screen. A user who cannot find it reads the
    // application as hung.
    expect(screen.getByText(/keys go to the remote screen/i).textContent).toContain("Ctrl+Alt");
  });

  it("says how to start, before the screen has focus", async () => {
    show();
    expect(screen.getByText(/click the screen to type into it/i)).toBeInTheDocument();
  });

  it("retires the hint once the user has done it", async () => {
    // "Click the screen to type into it" is orientation, not a control: it
    // answers one question, once. Left on screen for the rest of the session it
    // is a permanent row of chrome telling the user to do something they have
    // already done — and every row of chrome here is height the remote desktop
    // does not get.
    show();
    const element = screenElement();
    act(() => {
      element.focus();
    });
    expect(screen.queryByText(/click the screen to type into it/i)).toBeNull();

    act(() => {
      element.blur();
    });
    await delivered();
    expect(screen.queryByText(/click the screen to type into it/i)).toBeNull();
    // The other half of the rule is untouched: while the screen has the
    // keyboard it still says so, and still says how to get a shortcut back.
    act(() => {
      element.focus();
    });
    expect(screen.getByText(/keys go to the remote screen/i)).toBeInTheDocument();
  });
});

describe("the combinations the local machine takes first", () => {
  it("sends Ctrl+Alt+Del as three keys down and three up, in order", async () => {
    const user = userEvent.setup();
    show();
    await user.click(screen.getByRole("button", { name: "Ctrl+Alt+Del" }));
    await delivered();

    const sent = ipcMock.sendKey.mock.calls.map(
      (call) => [call[1].scancode, call[1].pressed] as const,
    );
    // Down in order, up in reverse: a Control released before the key it
    // modified produces a bare Delete at the far end.
    expect(sent).toEqual([
      [0x1d, true],
      [0x38, true],
      [0x153, true],
      [0x153, false],
      [0x38, false],
      [0x1d, false],
    ]);
  });

  it("offers Alt+Tab, which no window can capture for itself", async () => {
    const user = userEvent.setup();
    show();
    await user.click(screen.getByRole("button", { name: "Alt+Tab" }));
    await delivered();
    expect(ipcMock.sendKey.mock.calls.map((call) => call[1].scancode)).toEqual([
      0x38, 0x0f, 0x0f, 0x38,
    ]);
  });
});

describe("the clipboard", () => {
  it("offers the local clipboard when the screen takes the keyboard", async () => {
    show();
    act(() => screenElement().focus());
    await delivered();
    expect(ipcMock.syncClipboard).toHaveBeenCalledWith(1);
  });

  it("offers nothing from a session that carries no clipboard", async () => {
    show({ opened: opened(true, "none") });
    act(() => screenElement().focus());
    fireEvent.keyDown(screenElement(), { code: "KeyV", key: "v", ctrlKey: true });
    await delivered();
    expect(ipcMock.syncClipboard).not.toHaveBeenCalled();
    expect(ipcMock.sendKey).toHaveBeenCalled();
  });

  it("offers the clipboard before a paste chord, not after it", async () => {
    // A Ctrl+V that reached the server before the offer would paste whatever
    // the remote clipboard held before the user copied.
    show();
    fireEvent.keyDown(screenElement(), { code: "KeyV", key: "v", ctrlKey: true });
    await delivered();
    expect(ipcMock.syncClipboard).toHaveBeenCalledTimes(1);
    const offered = ipcMock.syncClipboard.mock.invocationCallOrder[0] ?? Infinity;
    const pasted = ipcMock.sendKey.mock.invocationCallOrder.at(-1) ?? -Infinity;
    expect(offered).toBeLessThan(pasted);
  });

  it("offers again when the window comes back to a screen that kept the keyboard", async () => {
    // Copied in another application and switched back: the element never lost
    // focus, so only the window's own focus event can see it.
    show();
    act(() => screenElement().focus());
    await delivered();
    ipcMock.syncClipboard.mockClear();
    window.dispatchEvent(new Event("focus"));
    await delivered();
    expect(ipcMock.syncClipboard).toHaveBeenCalledTimes(1);
  });

  it("does not draw a clipboard failure as a keystroke that did not arrive", async () => {
    ipcMock.syncClipboard.mockImplementationOnce(() =>
      Promise.reject({ code: "clipboard.unavailable", message: "no clipboard" }),
    );
    show();
    act(() => screenElement().focus());
    await delivered();
    expect(useSessions.getState().byId.t1?.inputError).toBeNull();
    // Nobody asked for an offer made on focus, so nobody is told it failed.
    expect(terminalsMock.reportClipboardFailure).not.toHaveBeenCalled();

    ipcMock.syncClipboard.mockImplementationOnce(() =>
      Promise.reject({ code: "clipboard.too-large", message: "too large" }),
    );
    fireEvent.keyDown(screenElement(), { code: "KeyV", key: "v", ctrlKey: true });
    await delivered();
    expect(terminalsMock.reportClipboardFailure).toHaveBeenCalledWith(
      "t1",
      expect.objectContaining({ code: "clipboard.too-large" }),
    );
    expect(useSessions.getState().byId.t1?.inputError).toBeNull();
  });

  it("offers nothing from a view-only session", async () => {
    show({ viewOnly: true });
    fireEvent.focus(screenElement());
    await delivered();
    expect(ipcMock.syncClipboard).not.toHaveBeenCalled();
  });
});

describe("the pointer", () => {
  it("sends the position in remote pixels, not in canvas ones", async () => {
    show();
    fireEvent(
      screenElement(),
      new MouseEvent("pointerdown", { bubbles: true, clientX: 110, clientY: 70, buttons: 1 }),
    );
    await delivered();
    // The canvas sits at (10, 20) in the window and is drawn at 1:1 here, so a
    // click at (110, 70) is (100, 50) on the remote desktop. Nothing but this
    // side knows that translation, which is why the core does not attempt it.
    expect(ipcMock.sendPointer).toHaveBeenCalledWith(1, {
      x: 100,
      y: 50,
      buttons: 1,
      wheel: 0,
      wheelX: 0,
    });
  });

  it("carries the extra buttons, which most clients drop", async () => {
    show();
    fireEvent(
      screenElement(),
      new MouseEvent("pointerdown", { bubbles: true, clientX: 10, clientY: 20, buttons: 8 }),
    );
    await delivered();
    // Bit 3 is Back. RDP carries it as PTRXFLAGS_BUTTON1; a browser's `buttons`
    // has it at 8, which is a different bit, so this is a translation.
    expect(ipcMock.sendPointer.mock.calls[0]?.[1].buttons).toBe(1 << 3);
  });

  it("sends nothing before the desktop has a size", async () => {
    // A click has to land somewhere, and "somewhere" is a desktop whose size is
    // not yet known. Sending 0,0 would put the remote pointer in the corner.
    surfaceMock.status = { ...surfaceMock.status, width: 0, height: 0 };
    show();
    fireEvent(
      screenElement(),
      new MouseEvent("pointerdown", { bubbles: true, clientX: 110, clientY: 70, buttons: 1 }),
    );
    await delivered();
    expect(ipcMock.sendPointer).not.toHaveBeenCalled();
  });

  it("sends both wheel axes and does not scroll the picture as well", async () => {
    show();
    const scrolled = fireEvent.wheel(screenElement(), {
      clientX: 110,
      clientY: 70,
      deltaX: 3,
      deltaY: -3,
      deltaMode: 1,
    });
    await delivered();
    // One notch is 120, the vertical axis is inverted against the DOM's, and
    // the horizontal one is not. `preventDefault` is what stops the stage
    // scrolling locally at the same moment the remote window scrolls.
    expect(ipcMock.sendPointer).toHaveBeenCalledWith(1, {
      x: 100,
      y: 50,
      buttons: 0,
      wheel: 120,
      wheelX: 120,
    });
    expect(scrolled).toBe(false);
  });
});

describe("a view-only session", () => {
  it("attaches no handler at all — it does not send and get refused", async () => {
    show({ viewOnly: true });
    const element = screenElement();
    fireEvent.keyDown(element, { code: "KeyA", key: "a" });
    fireEvent(
      element,
      new MouseEvent("pointerdown", { bubbles: true, clientX: 110, clientY: 70, buttons: 1 }),
    );
    await delivered();
    expect(ipcMock.sendKey).not.toHaveBeenCalled();
    expect(ipcMock.sendPointer).not.toHaveBeenCalled();
  });

  it("looks view-only and says so, rather than only being labelled it", async () => {
    show({ viewOnly: true });
    expect(screen.getByText("view only")).toBeInTheDocument();
    expect(screen.getByText(/nothing you type or click is sent/i)).toBeInTheDocument();
    expect(screenElement()).toHaveAttribute("data-view-only", "true");
    // A picture, not an application: it takes no keyboard, so it is not in the
    // tab order and a screen reader is not told to hand it the keys.
    expect(screenElement()).not.toHaveAttribute("tabindex");
  });

  it("stops sending once the session has ended", async () => {
    // A failed tab keeps its last picture so the user can read what happened.
    // Typing at it would raise "that session is not open any more" over the
    // failure that actually matters.
    show({ phase: "closed" });
    fireEvent.keyDown(screenElement(), { code: "KeyA", key: "a" });
    await delivered();
    expect(ipcMock.sendKey).not.toHaveBeenCalled();
  });

  it("does not claim view-only on a session it has not read the setting for", async () => {
    show({ viewOnly: null });
    expect(screen.queryByText("view only")).toBeNull();
  });

  it("offers no send-keys buttons, which would have nothing behind them", async () => {
    show({ viewOnly: true });
    expect(screen.queryByRole("button", { name: "Ctrl+Alt+Del" })).toBeNull();
  });
});

describe("the surface itself", () => {
  it("takes the keyboard only while the tab is in front", async () => {
    show({}, false);
    // A background tab's canvas stays laid out — it is measured — but it must
    // not be typing into a session the user is not looking at.
    expect(screen.queryByRole("button", { name: "Fit" })).toBeNull();
    expect(screen.getByLabelText(/remote screen for/i)).not.toHaveAttribute("tabindex");
  });

  it("gives the remote screen an accessible name", async () => {
    show();
    expect(screen.getByRole("application", { name: /remote screen for/i })).toBeInTheDocument();
  });

  it("offers smart resize only where the session says it is resizable", async () => {
    show();
    expect(screen.getByRole("button", { name: "Smart" })).toBeInTheDocument();
    cleanup();

    // A server that never opened the Display Control channel: the button would
    // do nothing, so it is not drawn.
    show({ opened: opened(false) });
    expect(screen.queryByRole("button", { name: "Smart" })).toBeNull();
  });

  it("says which scale is in force, in words a screen reader gets too", async () => {
    const user = userEvent.setup();
    show();
    expect(screen.getByRole("button", { name: "Fit" })).toHaveAttribute("aria-pressed", "true");
    await user.click(screen.getByRole("button", { name: "1:1" }));
    expect(useSessions.getState().byId.t1?.scale).toEqual({ mode: "actual", zoom: 2 });
  });

  it("offers whole-number magnifications only", async () => {
    show();
    // 2x, 3x, 4x and nothing between: a fractional zoom mixes each glyph's stem
    // across two output pixels, which is the mush this refuses to produce.
    for (const factor of ["2×", "3×", "4×"]) {
      expect(screen.getByRole("button", { name: factor })).toBeInTheDocument();
    }
    expect(screen.queryByRole("button", { name: "1.5×" })).toBeNull();
  });

  it("says it is waiting rather than showing an unexplained empty rectangle", async () => {
    surfaceMock.status = { ...surfaceMock.status, width: 0, height: 0 };
    show();
    expect(screen.getByText(/waiting for the first frame/i)).toBeInTheDocument();
  });
});
