/**
 * The WebView's browser habits are off, and nothing the application itself
 * relies on went with them.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { installNativeFeel } from "./nativeFeel";

let uninstall: () => void;

beforeEach(() => {
  document.body.innerHTML = `
    <div id="label">Connections</div>
    <input id="field" />
    <div class="xterm"><textarea id="term"></textarea></div>
    <div draggable="true" id="file">report.pdf</div>
    <img id="logo" alt="" />
  `;
  uninstall = installNativeFeel();
});

afterEach(() => {
  uninstall();
  document.body.innerHTML = "";
});

function key(target: Element, init: KeyboardEventInit): KeyboardEvent {
  const event = new KeyboardEvent("keydown", { bubbles: true, cancelable: true, ...init });
  target.dispatchEvent(event);
  return event;
}

function byId(id: string): Element {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`#${id} missing`);
  return found;
}

describe("installNativeFeel", () => {
  it("stops the WebView reloading the interface, and every open session with it", () => {
    expect(key(byId("label"), { key: "F5" }).defaultPrevented).toBe(true);
    expect(key(byId("label"), { key: "r", ctrlKey: true }).defaultPrevented).toBe(true);
    expect(key(byId("label"), { key: "R", ctrlKey: true, shiftKey: true }).defaultPrevented).toBe(true);
    expect(key(byId("label"), { key: "r", metaKey: true }).defaultPrevented).toBe(true);
    expect(key(byId("label"), { key: "p", ctrlKey: true }).defaultPrevented).toBe(true);
  });

  it("leaves ordinary typing and the application's own chords alone", () => {
    expect(key(byId("field"), { key: "a" }).defaultPrevented).toBe(false);
    expect(key(byId("field"), { key: "a", ctrlKey: true }).defaultPrevented).toBe(false);
    expect(key(byId("label"), { key: "f", ctrlKey: true, shiftKey: true }).defaultPrevented).toBe(false);
    expect(key(byId("label"), { key: "t", ctrlKey: true, altKey: true }).defaultPrevented).toBe(false);
    // AltGr on a Windows keyboard is Ctrl+Alt; nothing typed with it is a shortcut.
    expect(key(byId("field"), { key: "r", ctrlKey: true, altKey: true }).defaultPrevented).toBe(false);
  });

  it("does not take the zoom and find keys from a focused terminal, which binds its own", () => {
    expect(key(byId("term"), { key: "-", ctrlKey: true }).defaultPrevented).toBe(false);
    expect(key(byId("term"), { key: "f", ctrlKey: true }).defaultPrevented).toBe(false);
    expect(key(byId("label"), { key: "-", ctrlKey: true }).defaultPrevented).toBe(true);
  });

  it("keeps the native editing menu in a text field and nowhere else", () => {
    const onLabel = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    byId("label").dispatchEvent(onLabel);
    expect(onLabel.defaultPrevented).toBe(true);

    const onField = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    byId("field").dispatchEvent(onField);
    expect(onField.defaultPrevented).toBe(false);

    // xterm's hidden textarea is a text field to the WebView and not to a
    // person: its menu is the terminal's, drawn by the application.
    const onTerminal = new MouseEvent("contextmenu", { bubbles: true, cancelable: true });
    byId("term").dispatchEvent(onTerminal);
    expect(onTerminal.defaultPrevented).toBe(true);
  });

  it("stops an image being dragged out of the window, but not a file that opted in", () => {
    const logo = new Event("dragstart", { bubbles: true, cancelable: true });
    byId("logo").dispatchEvent(logo);
    expect(logo.defaultPrevented).toBe(true);

    const file = new Event("dragstart", { bubbles: true, cancelable: true });
    byId("file").dispatchEvent(file);
    expect(file.defaultPrevented).toBe(false);
  });

  it("stops the middle button starting a page auto-scroll", () => {
    const press = new MouseEvent("mousedown", { bubbles: true, cancelable: true, button: 1 });
    byId("label").dispatchEvent(press);
    expect(press.defaultPrevented).toBe(true);
  });
});
