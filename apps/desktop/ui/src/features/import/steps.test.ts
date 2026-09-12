/**
 * The step gating.
 *
 * Every rule here exists to stop the wizard reaching a step that would act on
 * something it does not have — a parse with no password, a commit with no
 * preview, a second commit of a handle the core has already spent.
 */

import { describe, expect, it } from "vitest";

import {
  canGoTo,
  forwardBlock,
  GATE,
  jumpBlock,
  wantsDocumentPassword,
  type WizardFacts,
} from "./steps";
import type { IpcFailure } from "@/lib/ipc";

const READY: WizardFacts = {
  hasFile: true,
  format: "mremoteng",
  detected: true,
  passwordRequired: false,
  hasPassword: false,
  hasPreview: true,
  includedCount: 12,
  committed: false,
  busy: false,
};

const EMPTY: WizardFacts = {
  hasFile: false,
  format: null,
  detected: false,
  passwordRequired: false,
  hasPassword: false,
  hasPreview: false,
  includedCount: 0,
  committed: false,
  busy: false,
};

function failure(code: string): IpcFailure {
  return { code, message: "", detail: null, actions: [] };
}

describe("wantsDocumentPassword", () => {
  it("recognises the two refusals a document password answers", () => {
    expect(wantsDocumentPassword(failure("import.password-required"))).toBe(true);
    expect(wantsDocumentPassword(failure("import.wrong-password"))).toBe(true);
  });

  it("does not turn every failure into a password prompt", () => {
    expect(wantsDocumentPassword(null)).toBe(false);
    // A file that is not the format, a file that will not open, a file whose
    // XML is broken: none of these is fixed by typing a password.
    expect(wantsDocumentPassword(failure("import.unknown-format"))).toBe(false);
    expect(wantsDocumentPassword(failure("import.malformed-xml"))).toBe(false);
    expect(wantsDocumentPassword(failure("io.failed"))).toBe(false);
  });
});

describe("forwardBlock", () => {
  it("refuses to leave the source step without a file, and says why", () => {
    expect(forwardBlock(1, EMPTY)).toBe(GATE.noFile);
  });

  it("lets a path that has not been read yet through, because reading it is the action", () => {
    expect(forwardBlock(1, { ...EMPTY, hasFile: true })).toBeNull();
  });

  it("refuses a format it could not detect and the user has not chosen", () => {
    expect(forwardBlock(1, { ...EMPTY, hasFile: true, detected: true })).toBe(GATE.unknownFormat);
    expect(forwardBlock(1, { ...EMPTY, hasFile: true, detected: true, format: "csv" })).toBeNull();
  });

  it("refuses to parse an encrypted file without its password", () => {
    const encrypted = { ...READY, passwordRequired: true, hasPassword: false };
    expect(forwardBlock(2, encrypted)).toBe(GATE.noPassword);
    expect(forwardBlock(2, { ...encrypted, hasPassword: true })).toBeNull();
  });

  it("does not ask for a password the file does not need", () => {
    expect(forwardBlock(2, READY)).toBeNull();
  });

  it("refuses to move on from a preview with everything unticked", () => {
    expect(forwardBlock(4, { ...READY, includedCount: 0 })).toBe(GATE.nothingTicked);
    expect(forwardBlock(5, { ...READY, includedCount: 0 })).toBe(GATE.nothingTicked);
    expect(forwardBlock(6, { ...READY, includedCount: 0 })).toBe(GATE.nothingTicked);
  });

  it("blocks every step while work is in flight", () => {
    for (const step of [1, 2, 4, 5, 6] as const) {
      expect(forwardBlock(step, { ...READY, busy: true })).toBe(GATE.busy);
    }
  });

  it("has no forward action on the two work steps", () => {
    expect(forwardBlock(3, READY)).toBe(GATE.busy);
    expect(forwardBlock(7, READY)).toBe(GATE.busy);
  });
});

describe("canGoTo", () => {
  it("keeps the preview and everything after it closed until there is one", () => {
    for (const step of [4, 5, 6, 7] as const) {
      expect(canGoTo(step, { ...READY, hasPreview: false })).toBe(false);
      expect(canGoTo(step, READY)).toBe(true);
    }
  });

  it("never re-enters the parse step from the rail", () => {
    expect(canGoTo(3, READY)).toBe(false);
  });

  it("closes every step but the result once the import is committed", () => {
    const done = { ...READY, committed: true };
    expect(canGoTo(8, done)).toBe(true);
    for (const step of [1, 2, 3, 4, 5, 6, 7] as const) {
      expect(canGoTo(step, done)).toBe(false);
    }
  });

  it("does not reach the result before there is one", () => {
    expect(canGoTo(8, READY)).toBe(false);
  });

  it("refuses everything while work is in flight", () => {
    expect(canGoTo(1, { ...READY, busy: true })).toBe(false);
  });
});

describe("jumpBlock", () => {
  it("gives a refused jump a reason to show", () => {
    expect(jumpBlock(4, { ...READY, hasPreview: false })).toBe(GATE.noPreview);
    expect(jumpBlock(2, EMPTY)).toBe(GATE.noFile);
    expect(jumpBlock(1, { ...READY, committed: true })).toBe(GATE.committed);
    expect(jumpBlock(4, READY)).toBeNull();
  });
});
