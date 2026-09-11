/**
 * Locale-aware formatting.
 *
 * The assertions avoid pinning exact CLDR output where a Node upgrade could
 * legitimately change it — a month abbreviation, a space that becomes
 * U+202F. What is pinned is the part that is wrong when it is wrong: which
 * character separates thousands from decimals, which order the date parts come
 * in, and whether the digits are Latin.
 */

import { beforeEach, describe, expect, it } from "vitest";

import {
  formatBytes,
  formatClock,
  formatDate,
  formatList,
  formatNumber,
  formatPercent,
  formatRate,
  formatRelativeTime,
  resetFormatCacheForTests,
} from "./format";

beforeEach(() => {
  resetFormatCacheForTests();
});

describe("numbers", () => {
  it("uses the locale's group and decimal separators", () => {
    expect(formatNumber("en", 1234.5, 1)).toBe("1,234.5");
    // The failure in the brief: a German user reading "1,234.5" sees one and a
    // bit, not twelve hundred.
    expect(formatNumber("de", 1234.5, 1)).toBe("1.234,5");
    expect(formatNumber("fr", 1234.5, 1)).toMatch(/^1.234,5$/u);
  });

  it("formats percentages the way the locale writes them", () => {
    expect(formatPercent("en", 0.42)).toBe("42%");
    expect(formatPercent("tr", 0.42)).toBe("%42");
  });
});

describe("file sizes", () => {
  it("scales in binary units, because that is what the transfer counts", () => {
    expect(formatBytes("en", 0)).toBe("0 B");
    expect(formatBytes("en", 512)).toBe("512 B");
    expect(formatBytes("en", 1024)).toBe("1.0 KiB");
    expect(formatBytes("en", 1024 * 1024)).toBe("1.0 MiB");
    expect(formatBytes("en", 1024 ** 4)).toBe("1.0 TiB");
  });

  it("puts the number through the locale and leaves the unit alone", () => {
    // IEC unit symbols are notation, not words — the same reason SSH is not
    // translated. Only the number moves.
    expect(formatBytes("de", 1024 * 1024 * 1.5)).toBe("1,5 MiB");
    expect(formatBytes("en", 1024 * 1024 * 1.5)).toBe("1.5 MiB");
  });

  it("drops the decimal once the figure is wide enough not to need it", () => {
    expect(formatBytes("en", 1024 * 999)).toBe("999 KiB");
    expect(formatBytes("en", 1024 * 100)).toBe("100 KiB");
    expect(formatBytes("en", 1024 * 99)).toBe("99.0 KiB");
  });

  it("does not overflow past the largest unit it knows", () => {
    expect(formatBytes("en", 1024 ** 8)).toContain("PiB");
  });

  it("survives a figure that is not a number", () => {
    expect(formatBytes("en", Number.NaN)).toBe("0 B");
    expect(formatBytes("en", Number.POSITIVE_INFINITY)).toBe("0 B");
  });

  it("formats a rate", () => {
    expect(formatRate("en", 1024 * 1024)).toBe("1.0 MiB/s");
  });
});

describe("dates", () => {
  const when = Date.UTC(2026, 8, 11, 14, 30, 0);

  it("uses the locale's field order rather than ours", () => {
    // 11 September 2026. American order puts the month first; British,
    // German and almost everyone else put the day first.
    const us = formatDate("en-US", when, "short");
    const gb = formatDate("en-GB", when, "short");
    expect(us).not.toBe(gb);
    expect(us.startsWith("9")).toBe(true);
    expect(gb.startsWith("11")).toBe(true);
  });

  it("uses the locale's own digits where it has them", () => {
    // Arabic-Indic digits. A date rendered in Latin digits inside an Arabic
    // interface is legible but wrong, in the way a comma for a decimal point
    // is wrong.
    expect(formatDate("ar-EG", when, "short")).toMatch(/[٠-٩]/u);
  });

  it("falls back rather than throwing on a tag Intl will not take", () => {
    expect(() => formatDate("not a locale", when)).not.toThrow();
  });
});

describe("relative time", () => {
  const now = Date.UTC(2026, 8, 11, 12, 0, 0);

  it("picks the largest unit that fits", () => {
    expect(formatRelativeTime("en", now - 45_000, now)).toBe("45 seconds ago");
    expect(formatRelativeTime("en", now - 3 * 60_000, now)).toBe("3 minutes ago");
    expect(formatRelativeTime("en", now - 5 * 3_600_000, now)).toBe("5 hours ago");
  });

  it("uses the word the language has, where it has one", () => {
    expect(formatRelativeTime("en", now - 86_400_000, now)).toBe("yesterday");
    expect(formatRelativeTime("de", now - 86_400_000, now)).toBe("gestern");
  });

  it("handles the future", () => {
    expect(formatRelativeTime("en", now + 2 * 86_400_000, now)).toBe("in 2 days");
  });

  it("says something for zero rather than nothing", () => {
    expect(formatRelativeTime("en", now, now)).toBe("now");
  });
});

describe("lists", () => {
  it("joins the way the locale joins", () => {
    expect(formatList("en", ["a", "b", "c"])).toBe("a, b, and c");
    expect(formatList("de", ["a", "b", "c"])).toBe("a, b und c");
  });

  it("handles one and none", () => {
    expect(formatList("en", ["only"])).toBe("only");
    expect(formatList("en", [])).toBe("");
  });
});

describe("clock durations", () => {
  it("pads to two digits and grows an hour field when it needs one", () => {
    expect(formatClock("en", 0)).toBe("00:00");
    expect(formatClock("en", 59)).toBe("00:59");
    expect(formatClock("en", 61)).toBe("01:01");
    expect(formatClock("en", 3661)).toBe("1:01:01");
  });

  it("never shows a negative countdown", () => {
    expect(formatClock("en", -5)).toBe("00:00");
  });

  it("uses the locale's digits", () => {
    expect(formatClock("ar-EG", 61)).toMatch(/[٠-٩]/u);
  });
});
