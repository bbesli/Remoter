/**
 * Matching text that has been through a Unicode bidi isolate.
 *
 * Hostnames, usernames, folder names, vault labels and tags are wrapped in
 * U+2068/U+2069 before they reach a translated sentence, so an Arabic or
 * Hebrew value cannot reorder the English around it (see `src/i18n/bidi.ts`).
 * The characters are invisible, which is the point — and it means
 * `getByText("from Datacentre EU-West")` stops matching for a reason nobody
 * can see in the failure output.
 *
 * Use this normaliser in any query whose expected text contains a value that
 * came from the vault or from a remote host:
 *
 * ```ts
 * screen.getByText("from Datacentre EU-West", { normalizer: withoutBidi })
 * ```
 *
 * Do not reach for it by default. A query that does not involve interpolated
 * data does not need it, and using it everywhere would hide a missing isolate
 * as effectively as it hides a present one.
 */

import { getDefaultNormalizer } from "@testing-library/dom";

/** U+200E, U+200F and the U+2066-U+2069 isolate block. */
const BIDI_MARKS = /[\u200E\u200F\u2066-\u2069]/g;

export function withoutBidi(text: string): string {
  return getDefaultNormalizer()(text).replace(BIDI_MARKS, "");
}
