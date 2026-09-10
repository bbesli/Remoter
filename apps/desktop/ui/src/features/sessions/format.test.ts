import { describe, expect, it } from "vitest";

import { formatBytes, formatClock, formatElapsed, formatSize, formatUptime } from "./format";

describe("formatBytes", () => {
  it("uses SI multiples, as every network counter beside it does", () => {
    expect(formatBytes(1000)).toBe("1.0 kB");
    expect(formatBytes(2_100_000)).toBe("2.1 MB");
    expect(formatBytes(412_000_000)).toBe("412 MB");
  });

  it("never shows a fractional byte", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(340)).toBe("340 B");
  });

  it("does not throw on a counter that went wrong", () => {
    expect(formatBytes(-1)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
  });
});

describe("formatUptime", () => {
  it("shows two units at most, the design's own examples", () => {
    expect(formatUptime(30 * 3600_000 + 14 * 60_000)).toBe("1d 6h");
    expect(formatUptime(3 * 3600_000 + 12 * 60_000)).toBe("3h 12m");
    expect(formatUptime(41 * 60_000 + 22_000)).toBe("41m 22s");
    expect(formatUptime(9000)).toBe("9s");
  });
});

describe("formatElapsed", () => {
  it("keeps milliseconds below a second, where the difference matters", () => {
    expect(formatElapsed(28)).toBe("28 ms");
    expect(formatElapsed(310)).toBe("310 ms");
    expect(formatElapsed(4200)).toBe("4.2 s");
  });

  it("says nothing rather than zero when there is no measurement", () => {
    expect(formatElapsed(-1)).toBe("—");
  });
});

describe("formatClock", () => {
  it("drops the hour until there is one", () => {
    expect(formatClock(374_000)).toBe("06:14");
    expect(formatClock(11_524_000)).toBe("3:12:04");
  });
});

describe("formatSize", () => {
  it("writes a terminal size the way a terminal does", () => {
    expect(formatSize(80, 24)).toBe("80×24");
  });
});
