/**
 * The three controls on the recovery-key step, tested for the one property
 * that matters about them: that they either work or say they did not.
 *
 * This screen shows a 256-bit key exactly once and then forgets it. Every
 * other screen in the application can be reopened; this one cannot, so a
 * control here that fails quietly does not inconvenience the user, it loses
 * their vault.
 *
 * Save used to be a browser download — a `Blob`, an `<a download>`, a
 * programmatic click — which is an idiom of a page inside a browser. Inside a
 * WebView nothing reports back whether the file was written, `anchor.click()`
 * returns successfully either way, and on Windows the file was never written.
 * The `try`/`catch` around it had nothing to catch. There was no test, and
 * there could not have been one: there was no result to assert against.
 *
 * So the assertions below are deliberately about the seam rather than about
 * the pixels — the command is called, the destination reaches it, the key
 * reaches it whole, and every failure arrives on screen.
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { CreateVaultResult } from "@/lib/ipc";

vi.mock("@tauri-apps/plugin-dialog", () => ({ save: vi.fn() }));

vi.mock("@/lib/ipc", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/ipc")>();
  return { ...actual, ipc: { writeRecoverySheet: vi.fn() } };
});

import { save } from "@tauri-apps/plugin-dialog";
import { ipc } from "@/lib/ipc";

import { RecoveryKeyPanel } from "./RecoveryKeyScreen";

const saveDialog = vi.mocked(save);
const writeRecoverySheet = vi.mocked(ipc.writeRecoverySheet);

/**
 * Fourteen groups, the shape `RecoveryKey::groups` produces.
 *
 * Not a real recovery key and not derived from one: no key material is
 * committed to this repository, and what is under test is the plumbing.
 */
const GROUPS = [
  "A1B2",
  "C3D4",
  "E5F6",
  "G7H8",
  "J9K0",
  "MNPQ",
  "RSTV",
  "WXYZ",
  "0123",
  "4567",
  "89AB",
  "CDEF",
  "GHJK",
  "MNPR",
];

const FULL_KEY = GROUPS.join("-");

const RESULT: CreateVaultResult = {
  // A Windows path on purpose: this is the platform the control failed on, and
  // the suggested file name has to survive a backslash separator.
  path: "C:\\Users\\you\\Documents\\Work.rvault",
  recoveryKeyGroups: GROUPS,
  confirmGroupIndex: 2,
  kdf: null,
};

function panel() {
  return render(<RecoveryKeyPanel result={RESULT} onConfirmedChange={() => undefined} />);
}

/** The engines that can print expose `window.print`; WKWebView does not. */
function givePrinter(fires: "beforeprint" | "nothing") {
  const print = vi.fn(() => {
    if (fires === "beforeprint") window.dispatchEvent(new Event("beforeprint"));
  });
  Object.defineProperty(window, "print", { value: print, configurable: true, writable: true });
  return print;
}

const originalPrint = window.print;

/**
 * Takes the async Clipboard API away, the way a WebView without a secure
 * context or a focused document does.
 */
function withoutClipboardApi() {
  Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });
}

beforeEach(() => {
  saveDialog.mockResolvedValue(null);
  writeRecoverySheet.mockResolvedValue({ path: "/home/you/recovery-key-Work.txt", bytes: 512 });
  givePrinter("beforeprint");
});

afterEach(() => {
  vi.clearAllMocks();
  Object.defineProperty(window, "print", {
    value: originalPrint,
    configurable: true,
    writable: true,
  });
  delete document.body.dataset["printing"];
});

describe("saving the recovery key", () => {
  it("writes through the core, at the path the dialog returned", async () => {
    const user = userEvent.setup();
    const chosen = "C:\\Users\\you\\Desktop\\recovery-key-Work.txt";
    saveDialog.mockResolvedValue(chosen);
    writeRecoverySheet.mockResolvedValue({ path: chosen, bytes: 512 });

    panel();
    await user.click(screen.getByRole("button", { name: /save as a text file/i }));

    await waitFor(() => expect(writeRecoverySheet).toHaveBeenCalledTimes(1));
    const request = writeRecoverySheet.mock.calls[0]?.[0];
    expect(request?.path).toBe(chosen);
    // The whole key, not the groups the grid happens to have rendered: a sheet
    // that is missing a group is worse than no sheet, because it looks whole.
    expect(request?.text).toContain(FULL_KEY);
    expect(request?.text).toContain(RESULT.path);

    // And the user is told where it landed, on a screen they cannot return to.
    expect(await screen.findByText(new RegExp(String.raw`Saved to`, "i"))).toBeInTheDocument();
    expect(screen.getByText(/outside the vault's encryption/i)).toBeInTheDocument();
  });

  it("offers a file name built from the vault's, with the .rvault dropped", async () => {
    const user = userEvent.setup();
    panel();
    await user.click(screen.getByRole("button", { name: /save as a text file/i }));

    await waitFor(() => expect(saveDialog).toHaveBeenCalledTimes(1));
    // The core refuses to write the sheet onto a `.rvault` name, so a suggested
    // name ending in one would be a trap rather than a suggestion.
    expect(saveDialog.mock.calls[0]?.[0]).toMatchObject({
      defaultPath: "recovery-key-Work.txt",
    });
  });

  it("shows the refusal when the write fails", async () => {
    const user = userEvent.setup();
    saveDialog.mockResolvedValue("C:\\Users\\you\\Desktop\\sheet.txt");
    writeRecoverySheet.mockRejectedValue({
      code: "path.unusable",
      message:
        "C:\\Users\\you\\Desktop\\sheet.txt cannot be used: that is the vault itself, and " +
        "writing the sheet over it would destroy the vault this key opens",
      detail: null,
      actions: ["Choose another location"],
    });

    panel();
    await user.click(screen.getByRole("button", { name: /save as a text file/i }));

    // The whole point of replacing the download: a failure is on the screen.
    expect(await screen.findByText(/The recovery key was not saved\./i)).toBeInTheDocument();
    expect(screen.getByText(/would destroy the vault this key opens/i)).toBeInTheDocument();
    expect(screen.queryByText(/Saved to/i)).not.toBeInTheDocument();
  });

  it("says so when the save dialog will not open at all", async () => {
    const user = userEvent.setup();
    saveDialog.mockRejectedValue(new Error("no file browser"));

    panel();
    await user.click(screen.getByRole("button", { name: /save as a text file/i }));

    expect(await screen.findByText(/did not open a save dialog/i)).toBeInTheDocument();
    expect(writeRecoverySheet).not.toHaveBeenCalled();
  });

  it("treats a cancelled dialog as a cancellation, not a failure", async () => {
    const user = userEvent.setup();
    saveDialog.mockResolvedValue(null);

    panel();
    await user.click(screen.getByRole("button", { name: /save as a text file/i }));

    await waitFor(() => expect(saveDialog).toHaveBeenCalled());
    expect(writeRecoverySheet).not.toHaveBeenCalled();
    // The standing security warning is the only alert on the screen; nothing
    // new was raised.
    expect(screen.queryByText(/was not saved/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/did not open a save dialog/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Saved to/i)).not.toBeInTheDocument();
  });
});

describe("printing the recovery key", () => {
  it("is not offered on a window that cannot print", async () => {
    // WKWebView has no `window.print` at all. A button that throws on click is
    // worse than a sentence saying the route is closed.
    Reflect.deleteProperty(window, "print");

    panel();
    expect(screen.queryByRole("button", { name: /^print$/i })).not.toBeInTheDocument();
    expect(screen.getByText(/cannot print from this window/i)).toBeInTheDocument();
  });

  it("reports a print that prepared nothing", async () => {
    const user = userEvent.setup();
    const print = givePrinter("nothing");

    panel();
    await user.click(screen.getByRole("button", { name: /^print$/i }));

    expect(print).toHaveBeenCalled();
    // `window.print()` returns undefined whether or not it printed, so the
    // absence of `beforeprint` is the only evidence there is.
    expect(await screen.findByText(/did not open a print dialog/i)).toBeInTheDocument();
    // And the page is not left dressed for a printer that never arrived.
    expect(document.body.dataset["printing"]).toBeUndefined();
  });

  it("stays quiet when the engine really did prepare a page", async () => {
    const user = userEvent.setup();
    givePrinter("beforeprint");

    panel();
    await user.click(screen.getByRole("button", { name: /^print$/i }));

    expect(screen.queryByText(/did not open a print dialog/i)).not.toBeInTheDocument();
    expect(document.body.dataset["printing"]).toBe("recovery");
  });
});

describe("copying the recovery key", () => {
  it("falls back to the selection route when the clipboard API is unavailable", async () => {
    const user = userEvent.setup();
    // `userEvent.setup()` installs a working `navigator.clipboard`, which is
    // the one thing the WebViews under test do not have.
    withoutClipboardApi();
    const execCommand = vi.fn(() => true);
    Object.defineProperty(document, "execCommand", {
      value: execCommand,
      configurable: true,
      writable: true,
    });

    panel();
    await user.click(screen.getByRole("button", { name: /^copy$/i }));

    await waitFor(() => expect(execCommand).toHaveBeenCalledWith("copy"));
    expect(await screen.findByText(/Copied to the clipboard\./i)).toBeInTheDocument();
    Reflect.deleteProperty(document, "execCommand");
  });

  it("never claims a copy it could not make", async () => {
    const user = userEvent.setup();
    // Neither route works: no Clipboard API, and `execCommand` refuses.
    withoutClipboardApi();
    Object.defineProperty(document, "execCommand", {
      value: vi.fn(() => false),
      configurable: true,
      writable: true,
    });

    panel();
    await user.click(screen.getByRole("button", { name: /^copy$/i }));

    expect(await screen.findByText(/did not allow copying/i)).toBeInTheDocument();
    expect(screen.queryByText(/Copied to the clipboard\./i)).not.toBeInTheDocument();
    Reflect.deleteProperty(document, "execCommand");
  });
});
