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
 */

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
