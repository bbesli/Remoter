/**
 * What happens when a key has no translation.
 *
 * Three requirements pull in different directions, so they are settled here
 * once rather than argued at each call site:
 *
 *  1. Never crash. A missing string is a copy bug, and a copy bug must not be
 *     able to take a window down while a session is open on it.
 *  2. Never show a user a raw key. `settings.updates.consent` on screen is
 *     worse than the wrong sentence: it is unreadable, it looks like a crash,
 *     and it tells the reader nothing about what the control does.
 *  3. Be loud in development. A fallback that looks fine is a fallback nobody
 *     fixes, which is how a catalogue rots.
 *
 * The order matters. i18next resolves the requested language first, then
 * English, and only reaches this file when English is missing the key too — so
 * (2) applies to a string that does not exist anywhere, and the best available
 * answer is the key's own last segment, humanised.
 */

/**
 * `settings.updates.lastCheckedNever` -> `Last checked never`.
 *
 * Keys are semantic and camelCase by convention, which means the last segment
 * is usually a readable phrase already. This is a last resort, not a feature:
 * it exists so the interface degrades to something a user can act on rather
 * than to punctuation.
 */
export function humaniseKey(key: string): string {
  const segments = key.split(/[.:]/);
  const last = segments[segments.length - 1] ?? key;
  const spaced = last
    .replace(/[_-]+/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/\s+/g, " ")
    .trim();
  if (spaced === "") return key;
  return spaced.charAt(0).toUpperCase() + spaced.slice(1).toLowerCase();
}

/**
 * The marker a development build wraps a missing string in.
 *
 * Mathematical white square brackets rather than `[]` or `{}`: neither appears
 * in interface copy, so a marker is unmistakable on screen and greppable in a
 * screenshot's alt text, and neither collides with ICU MessageFormat's braces.
 * Written as escapes because a raw non-ASCII character in a source file is a
 * hazard this repository has already been bitten by twice.
 */
const MARK_OPEN = "\u27E6";
const MARK_CLOSE = "\u27E7";

/** True in `vite dev` and under vitest; false in a shipped build. */
export function isDevelopment(): boolean {
  return import.meta.env.DEV === true;
}

/**
 * The string rendered in place of a key that exists in no catalogue.
 *
 * Marked in development so it cannot be mistaken for real copy, plain in a
 * release build so that a string missed before a release is merely wrong
 * rather than visibly broken.
 */
export function missingKeyText(key: string): string {
  const text = humaniseKey(key);
  return isDevelopment() ? `${MARK_OPEN}${text}${MARK_CLOSE}` : text;
}

/**
 * Development-time reporting.
 *
 * `console.error` and not a thrown error: a screen that renders with one wrong
 * label is debuggable, and a screen that refuses to render is not. The message
 * carries the namespace so the fix has an address.
 */
export function reportMissingKey(languages: readonly string[], namespace: string, key: string) {
  if (!isDevelopment()) return;
  console.error(
    `[i18n] missing key "${key}" in namespace "${namespace}" for ${languages.join(", ")} ` +
      `(and in the English fallback). Add it to locales/en/${namespace}.json.`,
  );
}
