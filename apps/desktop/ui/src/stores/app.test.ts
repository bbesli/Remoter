/**
 * Navigation history, because settings depends on it being real.
 *
 * `AppSettings` hardcoded `go({ name: "main" })` for its close button and for
 * Escape. Reached from the vault picker — where a user may well want to change
 * the language or the theme before opening anything — that dropped them into a
 * main window with no vault behind it. These tests pin the two facts the fix
 * rests on: that `go` records where you were, and that `goBack` returns there.
 */

import { beforeEach, describe, expect, it } from "vitest";

import { useApp } from "./app";

const initial = useApp.getState();

beforeEach(() => {
  useApp.setState({ screen: { name: "picker" }, previousScreen: null }, false);
});

describe("screen history", () => {
  it("records the screen it left", () => {
    initial.go({ name: "settings" });
    expect(useApp.getState().previousScreen).toEqual({ name: "picker" });
  });

  it("returns to the picker when settings was opened from the picker", () => {
    initial.go({ name: "settings" });
    initial.goBack();
    expect(useApp.getState().screen).toEqual({ name: "picker" });
  });

  it("returns to the main window when settings was opened from the main window", () => {
    initial.go({ name: "main" });
    initial.go({ name: "settings" });
    initial.goBack();
    expect(useApp.getState().screen).toEqual({ name: "main" });
  });

  it("returns to the unlock screen with the path it was showing", () => {
    initial.go({ name: "unlock", path: "/vaults/work.rvault", relock: null });
    initial.go({ name: "settings" });
    initial.goBack();
    expect(useApp.getState().screen).toEqual({
      name: "unlock",
      path: "/vaults/work.rvault",
      relock: null,
    });
  });

  it("falls back to the picker when there is no history", () => {
    initial.goBack();
    expect(useApp.getState().screen).toEqual({ name: "picker" });
  });

  it("does not make Back a no-op when navigating to the screen already showing", () => {
    initial.go({ name: "main" });
    initial.go({ name: "settings" });
    // A second `go` to settings — the palette can fire while settings is open.
    initial.go({ name: "settings" });
    initial.goBack();
    expect(useApp.getState().screen).toEqual({ name: "main" });
  });
});
