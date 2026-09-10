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
 */

/** SI steps. `B` has no decimal place; a fractional byte does not exist. */
const BYTE_UNITS = ["B", "kB", "MB", "GB", "TB", "PB"] as const;

/**
 * A byte count as the interface shows it.
 *
 * Negative and non-finite inputs return `0 B` rather than throwing: these are
 * counters read from a live session, and a display formatter is the wrong
 * place to discover that one went wrong.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  let value = bytes;
  let unit = 0;
  while (value >= 1000 && unit < BYTE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const label = BYTE_UNITS[unit] ?? "B";
  if (unit === 0) return `${String(Math.round(value))} ${label}`;
  // One decimal below 100, none above: "9.4 MB" and "412 MB" are both three
  // significant characters, which keeps the status bar from reflowing.
  return `${value < 100 ? value.toFixed(1) : String(Math.round(value))} ${label}`;
}

/**
 * An elapsed duration, coarse enough to read at a glance.
 *
 * The design's own examples are `1d 6h`, `3h 12m`, `41m`, `2m` — two units at
 * most, and the smaller unit dropped once the larger one is big enough that
 * nobody is counting it.
 */
export function formatUptime(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "0s";
  const totalSeconds = Math.floor(ms / 1000);
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  if (days > 0) return `${String(days)}d ${String(hours)}h`;
  if (hours > 0) return `${String(hours)}h ${String(minutes)}m`;
  if (minutes > 0) return `${String(minutes)}m ${String(seconds)}s`;
  return `${String(seconds)}s`;
}

/** `hh:mm:ss`, for a recording clock or a stage timer that must not jump. */
export function formatClock(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor((Number.isFinite(ms) ? ms : 0) / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const mm = String(minutes).padStart(2, "0");
  const ss = String(seconds).padStart(2, "0");
  return hours > 0 ? `${String(hours)}:${mm}:${ss}` : `${mm}:${ss}`;
}

/**
 * A short elapsed time for a pipeline stage: `28 ms`, `310 ms`, `4.2 s`.
 *
 * Milliseconds below a second, because the difference between 28 ms and 310 ms
 * of DNS is the whole point of showing it.
 */
export function formatElapsed(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  if (ms < 1000) return `${String(Math.round(ms))} ms`;
  const seconds = ms / 1000;
  return seconds < 100 ? `${seconds.toFixed(1)} s` : `${String(Math.round(seconds))} s`;
}

/** A terminal's size, as the status bar writes it. */
export function formatSize(cols: number, rows: number): string {
  return `${String(cols)}×${String(rows)}`;
}
