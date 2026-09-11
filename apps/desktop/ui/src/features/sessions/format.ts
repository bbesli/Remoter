/**
 * The small formatters the session surfaces share.
 *
 * They live in one file because the status bar, the tab strip and the session
 * panel all show the same quantities, and three independent "MB" functions is
 * how a session reads 2.1 MB in one place and 2.05 MiB in another.
 *
 * Byte counts use SI multiples, not binary ones: the numbers stand next to a
 * network address and a transfer rate, and every other tool a network engineer
 * reads those beside — `ip -s link`, `iftop`, a switch counter — is decimal.
 * That is why these are here rather than reusing `formatBytes` from `@/i18n`,
 * which scales in binary units because it counts a file transfer.
 *
 * **Two shapes of argument, and the signature says which is needed.** A
 * function that only has to place digits takes the locale and puts them through
 * `Intl` — a German reader expects `2,1 MB`, and `toFixed()` cannot give them
 * that. A function whose output contains a *word* takes `t` instead, because
 * `d`, `h`, `m` and `s` are abbreviations of day, hour, minute and second, and
 * those are English. Unit *symbols* — `B`, `kB`, `MB`, `ms` — are neither: they
 * are standardised and are not translated in any language, so they stay here.
 *
 * **There is no clock here.** `hh:mm:ss` — a recording clock, a stage timer —
 * is `formatClock(locale, seconds)` from `@/i18n`, which takes the locale and
 * puts the digits through `Intl` so a reader whose language has its own
 * numerals gets them. This file used to carry a second one that took no locale
 * and padded the digits by hand with `String.padStart`, which is how the same
 * duration reads in Arabic-Indic numerals in the footer and in Latin ones in a
 * session. Convert the milliseconds at the call site: `ms / 1000`.
 */

import { formatNumber } from "@/i18n";
import type { TFunction } from "i18next";

/** SI steps. `B` has no decimal place; a fractional byte does not exist. */
const BYTE_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"] as const;

/**
 * A byte count as the interface shows it.
 *
 * Negative and non-finite inputs return `0 B` rather than throwing: these are
 * counters read from a live session, and a display formatter is the wrong
 * place to discover that one went wrong.
 */
export function formatBytes(locale: string, bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return join(formatNumber(locale, 0), BYTE_UNITS[0]);
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < BYTE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const label = BYTE_UNITS[unit] ?? "B";
  // One decimal below 100, none above: "9.4 MB" and "412 MB" are both three
  // significant characters, which keeps the status bar from reflowing.
  const digits = unit === 0 ? 0 : value < 100 ? 1 : 0;
  return join(formatNumber(locale, value, digits), label);
}

/**
 * Number and unit, with a non-breaking space between them.
 *
 * Written as an escape rather than pasted: it is invisible, and this repository
 * has twice shipped a file that tooling stopped reading because of a character
 * nobody could see. It is there so a narrow column never wraps `412` onto one
 * line and `MB` onto the next.
 */
function join(value: string, unit: string): string {
  return `${value}\u00A0${unit}`;
}

/**
 * An elapsed duration, coarse enough to read at a glance.
 *
 * The design's own examples are `1d 6h`, `3h 12m`, `41m`, `2m` — two units at
 * most, and the smaller unit dropped once the larger one is big enough that
 * nobody is counting it. Which of the four shapes is used is decided here; what
 * each one looks like is in `locales/en/sessions.json`, because the letters are
 * shortened words and a Turkish reader expects `41d 22sn`.
 */
export function formatUptime(t: TFunction<"sessions">, locale: string, ms: number): string {
  const n = (value: number) => formatNumber(locale, value);
  if (!Number.isFinite(ms) || ms < 0) return t("duration.seconds", { seconds: n(0) });
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return t("duration.daysHours", { days: n(days), hours: n(hours) });
  if (hours > 0) return t("duration.hoursMinutes", { hours: n(hours), minutes: n(minutes) });
  if (minutes > 0) {
    return t("duration.minutesSeconds", { minutes: n(minutes), seconds: n(seconds) });
  }
  return t("duration.seconds", { seconds: n(seconds) });
}

/**
 * A short elapsed time for a pipeline stage: `28 ms`, `310 ms`, `4.2 s`.
 *
 * Milliseconds below a second, because the difference between 28 ms and 310 ms
 * of DNS is the whole point of showing it. The em dash for an impossible
 * interval is punctuation rather than copy, and stays here.
 */
export function formatElapsed(t: TFunction<"sessions">, locale: string, ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) {
    return t("duration.milliseconds", { milliseconds: formatNumber(locale, Math.round(ms)) });
  }
  const seconds = ms / 1000;
  // The rounding rule stays here rather than in the message: a stage over a
  // hundred seconds has stopped being interesting to a tenth, and that is a
  // decision about this panel, not about English.
  return t("duration.elapsedSeconds", {
    seconds: formatNumber(locale, seconds, seconds < 100 ? 1 : 0),
  });
}

/**
 * A terminal's size, as the status bar writes it.
 *
 * The multiplication sign is mathematical notation, not a word. The two numbers
 * are not: a locale with its own digits writes them in its own digits.
 */
export function formatSize(locale: string, cols: number, rows: number): string {
  return `${formatNumber(locale, cols)}×${formatNumber(locale, rows)}`;
}
