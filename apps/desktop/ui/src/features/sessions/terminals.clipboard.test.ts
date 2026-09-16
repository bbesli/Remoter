/**
 * The clipboard and the mouse, through a real xterm instance.
 *
 * `terminalInput.test.ts` checks the rules. This checks that they are wired:
 * that a key or a click on an actual terminal ends up as the bytes the far end
 * receives — pasted text where a paste was meant, `^V` where a shell was meant
 * to get `^V` — and that the WebView's own menu never opens. Every assertion is
 * on what reached `onInput` or the clipboard, never on a handler having run.
 *
 * The platform is fixed when `terminals.ts` loads, so each platform gets a
 * fresh copy of the module.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { Platform } from "@/lib/platform";

const clipboard = {
  readClipboardText: vi.fn<(selection: string) => Promise<string | null>>(),
  writeClipboardText: vi.fn<(selection: string, text: string) => Promise<void>>(),
};

let platform: Platform = "linux";

vi.mock("@/lib/platform", () => ({ currentPlatform: () => platform }));
vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return {
    ...actual,
    ipc: {
      ...clipboard,
      getSettings: () => Promise.reject(new Error("not in a test")),
    },
  };
});

const TAB = "tab-clipboard";

beforeAll(() => {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: () => ({
      matches: false,
      media: "",
      addListener: () => undefined,
      removeListener: () => undefined,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      dispatchEvent: () => false,
    }),
  });
  Object.defineProperty(globalThis, "ResizeObserver", {
    writable: true,
    value: class {
      observe(): void {}
      unobserve(): void {}
      disconnect(): void {}
    },
  });
});

beforeEach(() => {
  clipboard.readClipboardText.mockReset();
  clipboard.writeClipboardText.mockReset().mockResolvedValue(undefined);
});

afterEach(() => {
  document.body.replaceChildren();
});

async function open(on: Platform) {
  platform = on;
  vi.resetModules();
  const terminals = await import("./terminals");
  const sent: string[] = [];
  const decoder = new TextDecoder();
  const entry = terminals.ensureTerminal(TAB, {
    onInput: (bytes) => sent.push(decoder.decode(bytes)),
    onResize: () => undefined,
    onMetrics: () => undefined,
  });
  const container = document.createElement("div");
  document.body.appendChild(container);
  terminals.attachTerminal(TAB, container);
  const textarea = entry.term.textarea;
  if (textarea === undefined) throw new Error("xterm did not open");
  return { terminals, entry, sent, textarea, dispose: () => terminals.disposeTerminal(TAB) };
}

function write(entry: { term: { write: (data: string, done: () => void) => void } }, data: string) {
  return new Promise<void>((resolve) => entry.term.write(data, resolve));
}

function press(target: Element, init: KeyboardEventInit & { keyCode?: number }) {
  const event = new KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(event);
  return event;
}

function rightClick(target: Element, shiftKey = false) {
  const event = new MouseEvent("contextmenu", {
    bubbles: true,
    cancelable: true,
    button: 2,
    clientX: 40,
    clientY: 30,
    shiftKey,
  });
  target.dispatchEvent(event);
  return event;
}

const flush = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("on Linux", () => {
  it("opens the terminal's own menu on a right click, never the WebView's", async () => {
    const { terminals, entry, dispose } = await open("linux");
    const events: unknown[] = [];
    const unsubscribe = terminals.subscribeTerminalEvents((event) => events.push(event));

    const click = rightClick(entry.host);

    expect(click.defaultPrevented).toBe(true);
    expect(events).toEqual([{ kind: "menu", tabId: TAB, x: 40, y: 30, hasSelection: false }]);
    unsubscribe();
    dispose();
  });

  it("sends ^V to the shell on Ctrl+V, and pastes on Ctrl+Shift+V", async () => {
    const { textarea, sent, dispose } = await open("linux");
    clipboard.readClipboardText.mockResolvedValue("uptime");

    press(textarea, { key: "v", code: "KeyV", keyCode: 86, ctrlKey: true });
    expect(sent).toEqual(["\x16"]);
    expect(clipboard.readClipboardText).not.toHaveBeenCalled();

    press(textarea, { key: "V", code: "KeyV", keyCode: 86, ctrlKey: true, shiftKey: true });
    await flush();
    expect(clipboard.readClipboardText).toHaveBeenCalledWith("clipboard");
    expect(sent).toEqual(["\x16", "uptime"]);
    dispose();
  });

  it("pastes the PRIMARY selection with the middle button", async () => {
    const { entry, sent, dispose } = await open("linux");
    clipboard.readClipboardText.mockResolvedValue("/var/log/syslog");

    const middle = new MouseEvent("mousedown", { bubbles: true, cancelable: true, button: 1 });
    entry.host.dispatchEvent(middle);
    await flush();

    expect(middle.defaultPrevented).toBe(true);
    expect(clipboard.readClipboardText).toHaveBeenCalledWith("primary");
    expect(sent).toEqual(["/var/log/syslog"]);
    dispose();
  });

  it("leaves the buttons to a program that asked for the mouse, until Shift is held", async () => {
    const { terminals, entry, sent, dispose } = await open("linux");
    const events: unknown[] = [];
    const unsubscribe = terminals.subscribeTerminalEvents((event) => events.push(event));
    // DECSET 1000: the far end — `mc`, `htop`, `vim` with `mouse=a` — wants clicks.
    await write(entry, "\x1b[?1000h");
    clipboard.readClipboardText.mockResolvedValue("should not arrive");

    rightClick(entry.host);
    entry.host.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, button: 1 }));
    await flush();
    expect(events).toEqual([]);
    expect(clipboard.readClipboardText).not.toHaveBeenCalled();
    expect(sent.join("")).not.toContain("should not arrive");

    rightClick(entry.host, true);
    expect(events).toHaveLength(1);
    unsubscribe();
    dispose();
  });
});

describe("on Windows", () => {
  it("pastes on Ctrl+V instead of sending ^V", async () => {
    const { textarea, sent, dispose } = await open("windows");
    clipboard.readClipboardText.mockResolvedValue("Get-Service");

    const event = press(textarea, { key: "v", code: "KeyV", keyCode: 86, ctrlKey: true });
    await flush();

    expect(event.defaultPrevented).toBe(true);
    expect(sent).toEqual(["Get-Service"]);
    dispose();
  });

  it("copies on Ctrl+C when something is selected, and interrupts when nothing is", async () => {
    const { entry, textarea, sent, dispose } = await open("windows");
    await write(entry, "C:\\Users\\burak> dir");
    entry.term.select(0, 0, 8);

    press(textarea, { key: "c", code: "KeyC", keyCode: 67, ctrlKey: true });
    await flush();
    expect(clipboard.writeClipboardText).toHaveBeenCalledWith("clipboard", "C:\\Users");
    expect(sent).toEqual([]);
    // Windows Terminal lets go of the selection once it is copied.
    expect(entry.term.hasSelection()).toBe(false);

    press(textarea, { key: "c", code: "KeyC", keyCode: 67, ctrlKey: true });
    expect(sent).toEqual(["\x03"]);
    dispose();
  });

  it("pastes on a right click with nothing selected, and copies with a selection", async () => {
    const { terminals, entry, sent, dispose } = await open("windows");
    const events: unknown[] = [];
    const unsubscribe = terminals.subscribeTerminalEvents((event) => events.push(event));
    clipboard.readClipboardText.mockResolvedValue("whoami");

    expect(rightClick(entry.host).defaultPrevented).toBe(true);
    await flush();
    expect(sent).toEqual(["whoami"]);
    expect(events).toEqual([]);

    await write(entry, "\r\nhostname-01");
    entry.term.select(0, 1, 8);
    rightClick(entry.host);
    await flush();
    expect(clipboard.writeClipboardText).toHaveBeenCalledWith("clipboard", "hostname");
    unsubscribe();
    dispose();
  });
});

describe("on macOS", () => {
  it("copies with Cmd+C and leaves Ctrl+C an interrupt", async () => {
    const { entry, textarea, sent, dispose } = await open("macos");
    await write(entry, "ssh-ed25519 AAAA");
    entry.term.select(0, 0, 11);

    press(textarea, { key: "c", code: "KeyC", keyCode: 67, metaKey: true });
    await flush();
    expect(clipboard.writeClipboardText).toHaveBeenCalledWith("clipboard", "ssh-ed25519");
    // Terminal.app keeps the selection after a copy.
    expect(entry.term.hasSelection()).toBe(true);

    press(textarea, { key: "c", code: "KeyC", keyCode: 67, ctrlKey: true });
    expect(sent).toEqual(["\x03"]);
    dispose();
  });
});
