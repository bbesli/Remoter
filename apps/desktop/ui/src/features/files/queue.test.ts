/**
 * What a transfer row says, and — for resume — what it refuses to say.
 *
 * The command surface is explicit that `resume_offset` declines more often than
 * a user expects, and that the interface must say so plainly rather than
 * silently restarting. These tests pin the three outcomes apart: continued,
 * declined for a reason, and nothing worth saying. The last of those is the one
 * most easily got wrong in the other direction — a notice that fires on every
 * first attempt is a notice people learn to ignore.
 */

import { describe, expect, it } from "vitest";

import type { TransferStart, TransferStatus } from "@/lib/ipc";

import { anyLive, failureOf, isLive, progressOf, refetchIntervalFor, resumeOutcome, summarise } from "./queue";

function base(): Omit<TransferStatus, "state"> & { state: "queued" } {
  return {
    transferId: 1,
    direction: "download",
    remote: "/srv/build.tar.gz",
    remoteDisplay: "/srv/build.tar.gz",
    local: "/home/me/build.tar.gz",
    localDisplay: "/home/me/build.tar.gz",
    resume: false,
    start: null,
    state: "queued",
  };
}

function withStart(start: Partial<TransferStart>): TransferStatus {
  return {
    ...base(),
    start: {
      resumeRequested: true,
      resumeFrom: 0,
      total: null,
      resumeDeclined: false,
      // The core's English. Nothing renders it; it is here because the DTO
      // carries it, and these tests assert that it stays unread.
      note: null,
      ...start,
    },
  };
}

describe("isLive", () => {
  it("is true only while a transfer can still change on its own", () => {
    expect(isLive({ ...base(), state: "queued" })).toBe(true);
    expect(isLive({ ...base(), state: "running", done: 1, total: 2 })).toBe(true);
    expect(isLive({ ...base(), state: "completed", bytes: 2 })).toBe(false);
    expect(isLive({ ...base(), state: "cancelled" })).toBe(false);
  });
});

describe("refetchIntervalFor", () => {
  it("stops polling once everything is terminal", () => {
    // A screen that keeps polling after the last transfer finished is a screen
    // that keeps a timer alive for the rest of the session.
    expect(refetchIntervalFor([{ ...base(), state: "completed", bytes: 9 }])).toBe(false);
    expect(refetchIntervalFor([])).toBe(false);
    expect(refetchIntervalFor(undefined)).toBe(false);
  });

  it("polls while anything is still moving", () => {
    const interval = refetchIntervalFor([
      { ...base(), state: "completed", bytes: 9 },
      { ...base(), transferId: 2, state: "running", done: 1, total: 9 },
    ]);
    expect(typeof interval).toBe("number");
    expect(anyLive([{ ...base(), state: "queued" }])).toBe(true);
  });
});

describe("progressOf", () => {
  it("has nothing to show for a transfer that has moved nothing", () => {
    expect(progressOf({ ...base(), state: "queued" })).toBeNull();
    expect(progressOf({ ...base(), state: "cancelled" })).toBeNull();
  });

  it("reports a ratio only when the total is known", () => {
    expect(progressOf({ ...base(), state: "running", done: 50, total: 200 })).toEqual({
      done: 50,
      total: 200,
      ratio: 0.25,
    });
    // A growing file, or a server that reports no size. An indeterminate bar is
    // the honest answer; a fabricated percentage is not.
    expect(progressOf({ ...base(), state: "running", done: 50, total: null })).toEqual({
      done: 50,
      total: null,
      ratio: null,
    });
  });

  it("never draws a bar past its own end", () => {
    // A server that under-reports a size would otherwise produce 140 %.
    const over = progressOf({ ...base(), state: "running", done: 300, total: 200 });
    expect(over?.ratio).toBe(1);
  });

  it("shows a finished transfer as finished", () => {
    expect(progressOf({ ...base(), state: "completed", bytes: 128 })).toEqual({
      done: 128,
      total: 128,
      ratio: 1,
    });
  });
});

describe("resumeOutcome", () => {
  it("says nothing when a resume was never asked for", () => {
    expect(resumeOutcome(base())).toBeNull();
    expect(resumeOutcome(withStart({ resumeRequested: false }))).toBeNull();
  });

  it("says nothing when a resume was allowed and had nothing to continue", () => {
    // The first attempt at a file. A notice here would fire on nearly every
    // transfer and teach the user to ignore the one that matters.
    expect(resumeOutcome(withStart({ resumeRequested: true, resumeFrom: 0 }))).toBeNull();
  });

  it("reports where a continued transfer began", () => {
    expect(resumeOutcome(withStart({ resumeFrom: 4096, total: 8192 }))).toEqual({
      kind: "continued",
      offset: 4096,
    });
  });

  it("distinguishes the two refusals", () => {
    // The destination is at least as long as the source: continuing could have
    // corrupted it.
    expect(resumeOutcome(withStart({ resumeDeclined: true, total: 8192 }))).toEqual({
      kind: "declined",
      reason: "notShorter",
    });
    // Nobody reported the source's size, so no offset could be justified.
    expect(resumeOutcome(withStart({ resumeDeclined: true, total: null }))).toEqual({
      kind: "declined",
      reason: "unknownSize",
    });
  });
});

describe("summarise", () => {
  it("counts the three groups the heading shows", () => {
    expect(
      summarise([
        { ...base(), state: "queued" },
        { ...base(), transferId: 2, state: "running", done: 1, total: 2 },
        { ...base(), transferId: 3, state: "completed", bytes: 2 },
        { ...base(), transferId: 4, state: "cancelled" },
      ]),
    ).toEqual({ live: 2, finished: 1, failed: 0 });
  });
});

describe("failureOf", () => {
  it("hands a failed transfer to the failure layer in its own shape", () => {
    const failed: TransferStatus = {
      ...base(),
      state: "failed",
      code: "sftp.transfer-failed",
      message: "The server closed the channel.",
      detail: null,
      actions: ["Try again"],
      stage: "run",
      retryable: true,
    };
    expect(failureOf(failed)).toEqual({
      code: "sftp.transfer-failed",
      message: "The server closed the channel.",
      detail: null,
      actions: ["Try again"],
    });
    expect(failureOf({ ...base(), state: "cancelled" })).toBeNull();
  });
});
