/**
 * Isolating remote-origin text inside a translated sentence.
 *
 * A hostname, a username, a file path, a MOTD line and a directory listing all
 * arrive from a machine this application does not control, and any of them can
 * be interpolated into a translated string. Two separate problems follow, and
 * only one of them is about security.
 *
 * **Rendering.** Remote content is untrusted text and renders as text, always
 * (CLAUDE.md §6). That is already guaranteed: React escapes text children, ICU
 * MessageFormat substitutes arguments as data rather than re-parsing them, and
 * `dangerouslySetInnerHTML` is an ESLint error with no override. Nothing in
 * this file is load-bearing for that; do not read it as if it were.
 *
 * **Direction.** This is what this file is for. The Unicode bidirectional
 * algorithm resolves direction from the characters themselves, so a hostname
 * that happens to contain an Arabic or Hebrew character can reorder the words
 * of an English sentence around it — and inside an Arabic sentence, an ASCII
 * hostname pulls neighbouring punctuation with it, so `db-01:22` can render as
 * `22:db-01`. That is not cosmetic. A user reading a connection banner has to
 * be able to trust that the host they are looking at is the host they typed.
 *
 * The fix is the one docs/features/i18n.md specifies: wrap the value in a
 * first-strong isolate. The characters are written as escapes rather than
 * pasted, because they are invisible and this repository has twice shipped a
 * file that tooling stopped reading because of a character nobody could see.
 *
 * **Geometry.** At the end of the file, the one thing isolation cannot fix: a
 * coordinate. A pointer event reports a physical position, and a box placed at
 * it has to be placed logically. See {@link inlineStartOffset}.
 */

import type { Direction } from "./locales";

/** U+2068 FIRST STRONG ISOLATE — direction taken from the first strong char. */
const FSI = "\u2068";
/** U+2069 POP DIRECTIONAL ISOLATE. */
const PDI = "\u2069";
/** U+200E LEFT-TO-RIGHT MARK. */
const LRM = "\u200E";

/**
 * Wrap a value so the surrounding sentence keeps its own direction.
 *
 * Use it on anything whose direction is not ours to decide: hostnames, IP
 * addresses, ports, usernames, file paths, vault labels, tags, remote error
 * text. Do not use it on interface copy — a translated string is already in
 * the document's direction and isolating it would only add two code points.
 *
 * Empty and whitespace-only values are returned untouched: isolating nothing
 * produces a pair of invisible characters that a `length` check then counts.
 */
export function isolate(value: string): string {
  if (value.trim() === "") return value;
  return `${FSI}${value}${PDI}`;
}

/**
 * As {@link isolate}, but forces left-to-right rather than inferring it.
 *
 * For text that is LTR by specification regardless of its content — an IPv6
 * literal, a Windows path, a base64 fingerprint, a port number. First-strong
 * inference gets these wrong exactly when it matters, because a single leading
 * RTL character is enough to flip a value that is not a natural-language
 * phrase at all.
 */
export function isolateLtr(value: string): string {
  if (value.trim() === "") return value;
  return `${FSI}${LRM}${value}${PDI}`;
}

/**
 * Join values that a translated string presents as an ordered chain — a jump
 * host path, a breadcrumb — with a separator that does not itself flip.
 *
 * The arrow is supplied by the caller from the catalogue, so a locale can use
 * a different glyph; each element is isolated so one Arabic hostname in an
 * English chain does not reverse the chain.
 */
export function isolateChain(values: readonly string[], separator: string): string {
  return values.map(isolate).join(separator);
}

/**
 * The direction the layout is actually running in, read from the DOM.
 *
 * `applyDocumentLanguage()` writes `dir` onto `<html>` and nothing lower in the
 * tree sets it (docs/features/i18n.md), so that attribute is what every CSS
 * logical property in the application resolves against. Code that has to agree
 * with the layout therefore reads the same thing the layout reads, rather than
 * re-deriving it from the language code: the two are equal in the steady state
 * and disagree for exactly as long as a language change takes to apply, which
 * is the moment a disagreement would be visible.
 *
 * Anything that is not the literal string `rtl` is `ltr` — including a missing
 * attribute and a `dir="auto"` — because `ltr` is what the browser falls back
 * to and guessing differently from the browser is the whole class of bug this
 * function exists to avoid.
 */
export function documentDirection(): Direction {
  if (typeof document === "undefined") return "ltr";
  return document.documentElement.getAttribute("dir") === "rtl" ? "rtl" : "ltr";
}

/**
 * Turn a viewport x coordinate into an `inset-inline-start` distance.
 *
 * A pointer event reports `clientX` from the left edge of the viewport in every
 * layout — it is a measurement of the screen, not of the text, and no direction
 * changes it. Positioning the box it opens with `left` is nonetheless wrong:
 * `left` pins the box's left edge and lets it grow rightwards, so under RTL a
 * context menu unfolds away from the direction the reader is scanning, back
 * across the page they have already read, and off toward the edge they started
 * from.
 *
 * `inset-inline-start` pins the box's *reading-start* edge instead, and the box
 * grows toward the reading end — rightwards under LTR, leftwards under RTL. In
 * an RTL containing block that property measures from the right, so the
 * physical x has to be mirrored into it; that mirroring is all this function
 * does.
 *
 * `viewportWidth` is a parameter rather than a `window.innerWidth` read inside,
 * so that a caller which has already clamped the point against the viewport
 * clamps and positions against one and the same number.
 */
export function inlineStartOffset(
  x: number,
  viewportWidth: number,
  direction: Direction,
): number {
  return direction === "rtl" ? viewportWidth - x : x;
}
