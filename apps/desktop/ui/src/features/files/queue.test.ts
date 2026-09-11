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

import {
  anyLive,
  failureOf,
  isLive,
  progressOf,
  refetchIntervalFor,
  remainingParts,
  resumeOutcome,
  STALL_AFTER_MS,
  summarise,
  timingOf,
} from "./queue";

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
    queuedAtMs: 1_000,
    startedAtMs: null,
    finishedAtMs: null,
    progressAtMs: null,
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

describe("timingOf", () => {
  it("says nothing about a transfer that has not started", () => {
    // It has been queued and nothing else. An elapsed time measured from the
    // moment it was queued would count the wait as work.
    const timing = timingOf(base(), 50_000);
    expect(timing.elapsedMs).toBeNull();
    expect(timing.bytesPerSecond).toBeNull();
    expect(timing.remainingMs).toBeNull();
    expect(timing.stalled).toBe(false);
  });

  it("measures the rate over this attempt, not over the whole file", () => {
    // A resumed transfer that continued from 900 MiB and has since moved 4 MiB
    // is moving at the speed of those 4 MiB. Counting the 900 it never fetched
    // reports a rate the link has never achieved — and an estimate built on it.
    const resumed: TransferStatus = {
      ...base(),
      state: "running",
      done: 904 * 1024 * 1024,
      total: 1_000 * 1024 * 1024,
      start: {
        resumeRequested: true,
        resumeFrom: 900 * 1024 * 1024,
        total: 1_000 * 1024 * 1024,
        resumeDeclined: false,
        note: null,
      },
      startedAtMs: 10_000,
      progressAtMs: 14_000,
    };
    const timing = timingOf(resumed, 14_000);
    // Four MiB in four seconds is one MiB a second, whatever the file's size.
    expect(timing.bytesPerSecond).toBeCloseTo(1024 * 1024, 0);
    // 96 MiB left at 1 MiB/s.
    expect(timing.remainingMs).toBeCloseTo(96_000, -2);
  });

  it("refuses to report a rate from a sample too short to be one", () => {
    const justBegun: TransferStatus = {
      ...base(),
      state: "running",
      done: 4_096,
      total: 1_000_000,
      startedAtMs: 10_000,
      progressAtMs: 10_100,
    };
    expect(timingOf(justBegun, 10_100).bytesPerSecond).toBeNull();
  });

  it("calls a transfer stalled only once it is running and has stopped moving", () => {
    const running: TransferStatus = {
      ...base(),
      state: "running",
      done: 1_000,
      total: 10_000,
      startedAtMs: 0,
      progressAtMs: 1_000,
    };
    expect(timingOf(running, 1_000 + STALL_AFTER_MS - 1).stalled).toBe(false);
    expect(timingOf(running, 1_000 + STALL_AFTER_MS + 1).stalled).toBe(true);

    // A queued transfer has not begun and a finished one will not move again.
    // Calling either stalled describes the ordinary state of a queue as a fault.
    expect(timingOf({ ...base(), startedAtMs: null }, 10_000_000).stalled).toBe(false);
    expect(
      timingOf(
        { ...base(), state: "completed", bytes: 10, startedAtMs: 0, finishedAtMs: 5 },
        10_000_000,
      ).stalled,
    ).toBe(false);
  });

  it("stops the elapsed clock where the transfer stopped", () => {
    const done: TransferStatus = {
      ...base(),
      state: "completed",
      bytes: 2_048,
      startedAtMs: 1_000,
      finishedAtMs: 3_000,
    };
    // Not "now minus started": a finished transfer's elapsed time must not keep
    // growing while its row is on screen.
    expect(timingOf(done, 9_999_999).elapsedMs).toBe(2_000);
  });

  it("never produces a negative duration from a clock that moved backwards", () => {
    const skewed: TransferStatus = {
      ...base(),
      state: "running",
      done: 1,
      total: 2,
      startedAtMs: 5_000,
    };
    expect(timingOf(skewed, 1_000).elapsedMs).toBe(0);
  });
});

describe("remainingParts", () => {
  it("rounds to the leading unit", () => {
    expect(remainingParts(45_000)).toEqual({ unit: "seconds", value: 45 });
    expect(remainingParts(4 * 60_000 + 12_000)).toEqual({ unit: "minutes", value: 4 });
    expect(remainingParts(3 * 3_600_000)).toEqual({ unit: "hours", value: 3 });
  });

  it("says nothing where an estimate would not be one", () => {
    expect(remainingParts(null)).toBeNull();
    // About to finish: a countdown adds nothing.
    expect(remainingParts(400)).toBeNull();
    // Past a day, a rate measured over the last minute is not evidence.
    expect(remainingParts(40 * 3_600_000)).toBeNull();
    expect(remainingParts(Number.POSITIVE_INFINITY)).toBeNull();
  });
});
