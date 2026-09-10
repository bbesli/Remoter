/**
 * The one listener, end to end.
 *
 * The behaviour worth pinning is the part that used to be spread across three
 * components with three different ideas of it: a focused terminal keeps the
 * keyboard, a modal keeps the keyboard, and an action nothing can perform
 * right now does not swallow the key on its way past.
 */

import { QueryClientProvider, QueryClient } from "@tanstack/react-query";
import { act, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useApp } from "@/stores/app";

import { useShortcutDispatcher, useShortcutGroup, type ShortcutEvent } from "./registry";

const { ipcMock } = vi.hoisted(() => ({ ipcMock: { getSettings: vi.fn() } }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: ipcMock };
});

/** Every handler the harness registers, so a test can say which one fired. */
interface Spies {
  lock: ReturnType<typeof vi.fn>;
  newConnection: ReturnType<typeof vi.fn>;
  newFolder: ReturnType<typeof vi.fn>;
  edit: ReturnType<typeof vi.fn>;
  sidebar: ReturnType<typeof vi.fn>;
  inspector: ReturnType<typeof vi.fn>;
  fullscreen: ReturnType<typeof vi.fn>;
  palette: ReturnType<typeof vi.fn>;
  closeTab: ReturnType<typeof vi.fn>;
  nextTab: ReturnType<typeof vi.fn>;
  previousTab: ReturnType<typeof vi.fn>;
  jump: ReturnType<typeof vi.fn>;
}

function makeSpies(): Spies {
  return {
    lock: vi.fn(),
    newConnection: vi.fn(),
    newFolder: vi.fn(),
    edit: vi.fn(),
    sidebar: vi.fn(),
    inspector: vi.fn(),
    fullscreen: vi.fn(),
    palette: vi.fn(),
    closeTab: vi.fn(),
    nextTab: vi.fn(),
    previousTab: vi.fn(),
    jump: vi.fn(),
  };
}

interface HarnessProps {
  spies: Spies;
  terminal: { focused: boolean };
  /** Registered as `null`, i.e. "nothing can do this right now". */
  unavailable?: boolean;
}

function Harness({ spies, terminal, unavailable = false }: HarnessProps) {
  useShortcutGroup("shell", {
    "vault.lock": spies.lock,
    "connection.new": spies.newConnection,
    "folder.new": spies.newFolder,
    "node.edit": spies.edit,
    "sidebar.toggle": unavailable ? null : spies.sidebar,
    "inspector.toggle": spies.inspector,
    "session.fullscreen": spies.fullscreen,
  });
  useShortcutGroup("palette", { "palette.open": spies.palette });
  useShortcutGroup("tabs", {
    "tab.close": spies.closeTab,
    "tab.next": spies.nextTab,
    "tab.previous": spies.previousTab,
    "tab.jump": (event: ShortcutEvent) => spies.jump(event.seriesIndex),
  });
  useShortcutDispatcher(() => terminal.focused);
  return null;
}

function mount(props: HarnessProps) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Harness {...props} />
    </QueryClientProvider>,
  );
}

/** Sends a keystroke the way the window would, and returns the event. */
function press(init: KeyboardEventInit): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { cancelable: true, ...init });
  act(() => {
    window.dispatchEvent(event);
  });
  return event;
}

beforeEach(() => {
  vi.clearAllMocks();
  ipcMock.getSettings.mockResolvedValue({
    theme: "system",
    locale: "en",
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    sidebarWidth: 268,
    inspectorOpen: false,
    updateCheckEnabled: false,
    updateChannel: "stable",
    updateLastCheckedAt: null,
    terminalPrefix: "ctrl+alt",
    shortcuts: {},
  });
  useApp.setState({ openModals: new Set<string>() });
});

afterEach(() => {
  useApp.setState({ openModals: new Set<string>() });
});

describe("outside a session", () => {
  it("fires an application binding on its plain chord", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: false } });

    const event = press({ key: "b", ctrlKey: true, code: "KeyB" });

    expect(spies.sidebar).toHaveBeenCalledTimes(1);
    expect(event.defaultPrevented).toBe(true);
  });

  it("tells a series binding which key was pressed", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: false } });

    press({ key: "3", altKey: true, code: "Digit3" });

    expect(spies.jump).toHaveBeenCalledWith(2);
  });
});

describe("inside a focused terminal", () => {
  it("leaves an application chord to the remote host", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: true } });

    const event = press({ key: "b", ctrlKey: true, code: "KeyB" });

    expect(spies.sidebar).not.toHaveBeenCalled();
    // Untouched, so it reaches the shell exactly as it was typed.
    expect(event.defaultPrevented).toBe(false);
  });

  it("reaches the same action through the prefix", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: true } });

    press({ key: "b", ctrlKey: true, altKey: true, code: "KeyB" });

    expect(spies.sidebar).toHaveBeenCalledTimes(1);
  });

  it("keeps the universal ones global", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: true } });

    press({ key: "k", ctrlKey: true, code: "KeyK" });
    press({ key: "l", ctrlKey: true, code: "KeyL" });

    expect(spies.palette).toHaveBeenCalledTimes(1);
    expect(spies.lock).toHaveBeenCalledTimes(1);
  });

  it("never takes the keys the remote host owns", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: true } });

    for (const init of [
      { key: "c", ctrlKey: true, code: "KeyC" },
      { key: "d", ctrlKey: true, code: "KeyD" },
      { key: "f", altKey: true, code: "KeyF" },
    ]) {
      expect(press(init).defaultPrevented).toBe(false);
    }
  });
});

describe("what stops a binding firing", () => {
  it("a modal, which owns the keyboard while it is up", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: false } });
    act(() => {
      useApp.getState().pushModal("some-dialog");
    });

    press({ key: "b", ctrlKey: true, code: "KeyB" });

    expect(spies.sidebar).not.toHaveBeenCalled();
  });

  it("a handler nearer the key having already dealt with it", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: false } });

    const event = new KeyboardEvent("keydown", {
      key: "b",
      ctrlKey: true,
      code: "KeyB",
      cancelable: true,
    });
    event.preventDefault();
    act(() => {
      window.dispatchEvent(event);
    });

    expect(spies.sidebar).not.toHaveBeenCalled();
  });

  it("nothing being able to perform it — and the key is not swallowed", () => {
    const spies = makeSpies();
    mount({ spies, terminal: { focused: false }, unavailable: true });

    const event = press({ key: "b", ctrlKey: true, code: "KeyB" });

    expect(spies.sidebar).not.toHaveBeenCalled();
    expect(event.defaultPrevented).toBe(false);
  });

  it("the owner having gone away with its component", () => {
    const spies = makeSpies();
    const view = mount({ spies, terminal: { focused: false } });
    view.unmount();

    press({ key: "b", ctrlKey: true, code: "KeyB" });

    expect(spies.sidebar).not.toHaveBeenCalled();
  });
});
