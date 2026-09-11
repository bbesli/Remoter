/**
 * The session formatters, and the two properties that survive localisation.
 *
 * The units are asserted against English because English is the source
 * catalogue, but the assertions that matter are the ones about *shape*: two
 * units at most, milliseconds below a second, SI multiples rather than binary
 * ones. A German build renders the same shapes with `,` for the decimal and a
 * translated `d`/`h`/`m`/`s`, which is exactly what moving those letters into
 * the catalogue bought.
 */

import { describe, expect, it } from "vitest";

import { i18n, initI18n } from "@/i18n";
import { formatBytes, formatClock, formatElapsed, formatSize, formatUptime } from "./format";

// English is bundled and the backend answers for it synchronously, so a real
// `t` is available here without awaiting anything or rendering a component.
initI18n();
const t = i18n().getFixedT("en", "sessions");

/** The non-breaking space `formatBytes` puts between a number and its unit. */
const NBSP = "\u00A0";

describe("formatBytes", () => {
  it("uses SI multiples, as every network counter beside it does", () => {
    expect(formatBytes("en", 1000)).toBe(`1.0${NBSP}kB`);
    expect(formatBytes("en", 2_100_000)).toBe(`2.1${NBSP}MB`);
    expect(formatBytes("en", 412_000_000)).toBe(`412${NBSP}MB`);
  });

  it("never shows a fractional byte", () => {
    expect(formatBytes("en", 0)).toBe(`0${NBSP}B`);
    expect(formatBytes("en", 340)).toBe(`340${NBSP}B`);
  });

  it("does not throw on a counter that went wrong", () => {
    expect(formatBytes("en", -1)).toBe(`0${NBSP}B`);
    expect(formatBytes("en", Number.NaN)).toBe(`0${NBSP}B`);
  });

  it("writes the number the way the locale writes numbers", () => {
    // The whole reason the locale is a parameter: `toFixed()` would show a
    // German reader `2.1 MB`, which they read as two thousand one hundred.
    expect(formatBytes("de", 2_100_000)).toBe(`2,1${NBSP}MB`);
  });
});

describe("formatUptime", () => {
  it("shows two units at most, the design's own examples", () => {
    expect(formatUptime(t, "en", 30 * 3600_000 + 14 * 60_000)).toBe("1d 6h");
    expect(formatUptime(t, "en", 3 * 3600_000 + 12 * 60_000)).toBe("3h 12m");
    expect(formatUptime(t, "en", 41 * 60_000 + 22_000)).toBe("41m 22s");
    expect(formatUptime(t, "en", 9000)).toBe("9s");
  });
});

describe("formatElapsed", () => {
  it("keeps milliseconds below a second, where the difference matters", () => {
    expect(formatElapsed(t, "en", 28)).toBe("28 ms");
    expect(formatElapsed(t, "en", 310)).toBe("310 ms");
    expect(formatElapsed(t, "en", 4200)).toBe("4.2 s");
  });

  it("says nothing rather than zero when there is no measurement", () => {
    expect(formatElapsed(t, "en", -1)).toBe("—");
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
    expect(formatSize("en", 80, 24)).toBe("80×24");
  });
});
