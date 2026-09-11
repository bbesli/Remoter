/**
 * The one place the key-derivation cost becomes a line of text.
 *
 * The core used to compose this sentence — `"Argon2id, 256 MiB, 3 passes, 4
 * lanes"` — and send it across the IPC boundary as a `String`. Six screens
 * printed it verbatim, all of them otherwise translated, and two code comments
 * defended it as "the core's own notation, never translated, for the reason
 * SSH and RDP are not". That defence was false: "passes" and "lanes" are
 * English words. A Turkish reader saw them in the middle of a Turkish screen,
 * no catalogue could reach them, and the frontend fixtures asserted a `t=3`
 * form the core was never able to produce — so the suite was green over a
 * string no user ever saw.
 *
 * What the core sends now is four values (`KdfParams`), and this composes the
 * line out of them. Everything in it is genuinely outside language, which is
 * what makes it safe to build without a catalogue entry of its own:
 *
 *   - `Argon2id` is the function's name, from the core. Proper names are not
 *     translated (docs/features/i18n.md, "What is never translated");
 *   - `256 MiB` is a number the reader's `Intl` formatted plus a standardised
 *     unit symbol — the same pair `formatBytes` produces everywhere else;
 *   - `m`, `t` and `p` are Argon2's own parameter names, from RFC 9106 §3.1.
 *     They are notation, like the `×` between a terminal's columns and rows,
 *     and they read the same in every language. The words this replaces did
 *     not.
 *
 * **The separator between them is the catalogue's**, `common:punctuation
 * .listSeparator`, which is already the one place a translator can change how
 * this application joins a short list — Chinese reads `、` there and
 * Arabic `،`. `Intl.ListFormat` is the wrong tool for this despite
 * looking like the right one: its `conjunction` type adds an "and", and its
 * `unit` type is built for measurements ("3 ft 7 in") rather than
 * enumerations, which is why it joins Chinese with nothing at all and German
 * with "und".
 */

import { formatBytes, formatNumber, i18n } from "@/i18n";
import type { KdfParams } from "@/lib/ipc";

/** A kibibyte, so `formatBytes` — which counts in bytes — scales from `m`. */
const KIB = 1024;

/**
 * The cost line for a slot, or `null` when the slot has no cost to describe.
 *
 * `null` in, `null` out: a recovery, FIDO2 or keychain slot derives with HKDF
 * and has no Argon2 parameters, and the caller decides whether to leave the
 * line out or say something else in its place.
 *
 * The separator is read from the shared i18next instance rather than through
 * `useT()`, because the callers span three namespaces and two of them are not
 * components at all. It is read at call time, inside a render that `useT` has
 * already re-run, so a language change still reaches it — the trap that
 * pattern has is capturing `t` at module scope, which is why this does not.
 */
export function kdfSummary(locale: string, kdf: KdfParams | null): string | null {
  if (kdf === null) return null;
  const separator = i18n().getFixedT(null, "common")("punctuation.listSeparator");
  return [
    kdf.algorithm,
    formatBytes(locale, kdf.memoryKib * KIB),
    `t=${formatNumber(locale, kdf.passes)}`,
    `p=${formatNumber(locale, kdf.lanes)}`,
  ].join(separator);
}
