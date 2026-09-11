/**
 * Every date, time, number, byte count and duration the interface shows.
 *
 * `Intl` does all of it. There is no hand-rolled formatting here and there
 * must be none anywhere else (docs/features/i18n.md), because every shortcut
 * is wrong somewhere: `toFixed(1) + " MB"` shows a German user `1,234.5 MB`
 * when they read `1.234,5 MB`, `toLocaleDateString()` with no locale follows
 * whatever the operating system happens to be set to rather than the language
 * the user chose in this application, and `new Date().toISOString().slice(0,10)`
 * shows an American date order to everyone.
 *
 * The functions take the locale explicitly rather than reading a module-level
 * "current locale". A formatter that reads hidden state is a formatter that
 * cannot be tested against six locales in one file, and these are.
 *
 * `Intl.*Format` objects are expensive to build and cheap to reuse, so they are
 * memoised on the arguments that define them. The cache is unbounded on
 * purpose: its key space is (locale × a handful of option sets), which is
 * bounded by the ten shipped languages.
 */

const cache = new Map<string, unknown>();

function memo<T>(key: string, build: () => T): T {
  const hit = cache.get(key);
  if (hit !== undefined) return hit as T;
  const made = build();
  cache.set(key, made);
  return made;
}

/**
 * A locale the `Intl` constructors will accept.
 *
 * A settings file can name a language this build does not ship, and every
 * `Intl` constructor throws a RangeError on a malformed tag. Falling back to
 * English beats a white window.
 */
function safeLocale(locale: string): string {
  try {
    return Intl.DateTimeFormat.supportedLocalesOf([locale]).length > 0 ? locale : "en";
  } catch {
    return "en";
  }
}

// ------------------------------------------------------------- dates ----

export type DateStyle = "short" | "medium" | "long";

/**
 * A date on its own. `short` for tables, `medium` for prose.
 *
 * Order, separators and month names all come from the locale: 11/09/2026 in
 * the United States, 09.11.2026 in Germany, and the Hijri-aware ordering in
 * Arabic.
 */
export function formatDate(locale: string, value: Date | number, style: DateStyle = "medium") {
  const key = `d:${locale}:${style}`;
  return memo(key, () => new Intl.DateTimeFormat(safeLocale(locale), { dateStyle: style })).format(
    value,
  );
}

/** A time of day. Seconds only where they carry information. */
export function formatTime(locale: string, value: Date | number, withSeconds = false) {
  const key = `t:${locale}:${withSeconds ? "s" : "m"}`;
  return memo(
    key,
    () =>
      new Intl.DateTimeFormat(safeLocale(locale), {
        timeStyle: withSeconds ? "medium" : "short",
      }),
  ).format(value);
}

/**
 * A timestamp. The audit log and the update check both show these, and both
 * need the 12/24-hour convention of the reader's locale rather than ours.
 */
export function formatDateTime(locale: string, value: Date | number, style: DateStyle = "medium") {
  const key = `dt:${locale}:${style}`;
  return memo(
    key,
    () =>
      new Intl.DateTimeFormat(safeLocale(locale), {
        dateStyle: style,
        timeStyle: style === "short" ? "short" : "medium",
      }),
  ).format(value);
}

/**
 * "3 minutes ago", "in 2 days" — picking the largest unit that fits.
 *
 * `numeric: "auto"` is what produces "yesterday" rather than "1 day ago" in
 * the languages that have a word for it, which is most of them.
 */
export function formatRelativeTime(locale: string, from: Date | number, now: Date | number = Date.now()) {
  const fromMs = typeof from === "number" ? from : from.getTime();
  const nowMs = typeof now === "number" ? now : now.getTime();
  const seconds = Math.round((fromMs - nowMs) / 1000);

  const units: readonly [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31_536_000],
    ["month", 2_592_000],
    ["week", 604_800],
    ["day", 86_400],
    ["hour", 3600],
    ["minute", 60],
    ["second", 1],
  ];

  const fmt = memo(
    `r:${locale}`,
    () => new Intl.RelativeTimeFormat(safeLocale(locale), { numeric: "auto" }),
  );

  const magnitude = Math.abs(seconds);
  for (const [unit, size] of units) {
    if (magnitude >= size) return fmt.format(Math.trunc(seconds / size), unit);
  }
  return fmt.format(0, "second");
}

// ----------------------------------------------------------- numbers ----

export function formatNumber(locale: string, value: number, fractionDigits?: number): string {
  const key = `n:${locale}:${fractionDigits ?? "auto"}`;
  return memo(
    key,
    () =>
      new Intl.NumberFormat(
        safeLocale(locale),
        fractionDigits === undefined
          ? {}
          : { minimumFractionDigits: fractionDigits, maximumFractionDigits: fractionDigits },
      ),
  ).format(value);
}

/** A ratio already in 0..1. Used by the transfer progress and the contrast check. */
export function formatPercent(locale: string, ratio: number, fractionDigits = 0): string {
  const key = `p:${locale}:${fractionDigits}`;
  return memo(
    key,
    () =>
      new Intl.NumberFormat(safeLocale(locale), {
        style: "percent",
        minimumFractionDigits: fractionDigits,
        maximumFractionDigits: fractionDigits,
      }),
  ).format(ratio);
}

/**
 * A list, joined the way the locale joins lists.
 *
 * "a, b and c" in English, "a, b und c" in German, and the Arabic and Chinese
 * conventions differ again — none of which a hardcoded `", "` gets right.
 */
export function formatList(
  locale: string,
  items: readonly string[],
  type: "conjunction" | "disjunction" = "conjunction",
): string {
  const key = `l:${locale}:${type}`;
  return memo(
    key,
    () => new Intl.ListFormat(safeLocale(locale), { style: "long", type }),
  ).format(items);
}

// ------------------------------------------------------------- bytes ----

/**
 * Binary units, because this is a file transfer and a storage figure.
 *
 * SFTP, the recorder and the vault all count bytes, and every one of them
 * counts them in powers of two. `Intl` has no binary unit, so the scaling is
 * ours and only the *number* goes through `Intl` — which is the part that
 * differs between locales. The unit name does not: KiB and MiB are IEC 80000-13
 * symbols and are not translated, the same reason SSH and RDP are not.
 */
const BYTE_UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"] as const;

export function formatBytes(locale: string, bytes: number): string {
  if (!Number.isFinite(bytes)) return formatNumber(locale, 0) + "\u00A0" + BYTE_UNITS[0];

  const negative = bytes < 0;
  let value = Math.abs(bytes);
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }

  // Whole bytes have no fractional part to show; scaled values get one
  // decimal, which is the precision a transfer readout can actually keep up
  // with. More digits change every frame and read as noise.
  const digits = unit === 0 ? 0 : value >= 100 ? 0 : 1;
  const number = formatNumber(locale, negative ? -value : value, digits);
  // U+00A0, so a narrow column never wraps "412" onto one line and "MiB" onto
  // the next. Written as an escape: a non-breaking space is indistinguishable
  // from a plain one in a diff, and an invisible character is exactly what this
  // repository's source-is-text check exists to keep out.
  return `${number}\u00A0${BYTE_UNITS[unit] ?? BYTE_UNITS[0]}`;
}

/** Bytes per second, for a transfer in flight. */
export function formatRate(locale: string, bytesPerSecond: number): string {
  return `${formatBytes(locale, bytesPerSecond)}/s`;
}

// --------------------------------------------------------- durations ----

/**
 * A clock-style duration: `04:31`, or `1:04:31` once it passes an hour.
 *
 * The digits go through `Intl` so a locale with its own numbering system gets
 * them — Arabic-Indic digits under `ar-EG`, for one — while the colon stays,
 * because a duration is a clock reading and reads the same way everywhere.
 * `Intl.DurationFormat` would be the right tool and is not yet in the
 * WebKitGTK and WebView2 versions Tauri 2 targets.
 */
export function formatClock(locale: string, totalSeconds: number): string {
  const clamped = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(clamped / 3600);
  const minutes = Math.floor((clamped % 3600) / 60);
  const seconds = clamped % 60;

  const pad = (n: number) =>
    memo(
      `pad:${locale}`,
      () => new Intl.NumberFormat(safeLocale(locale), { minimumIntegerDigits: 2, useGrouping: false }),
    ).format(n);

  return hours > 0
    ? `${formatNumber(locale, hours)}:${pad(minutes)}:${pad(seconds)}`
    : `${pad(minutes)}:${pad(seconds)}`;
}

/** Test seam. Nothing else should need to reach into the formatter cache. */
export function resetFormatCacheForTests() {
  cache.clear();
}
