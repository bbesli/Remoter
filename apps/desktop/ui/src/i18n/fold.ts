/**
 * Case folding, for readers whose alphabet is not English's.
 *
 * `String.prototype.toLowerCase()` is not a case fold. It is the Unicode
 * *default* lowercasing, and the default is wrong in at least three of the ten
 * languages this application ships:
 *
 *   - **Turkish** has two letters where English has one. `"I"` lowercases to
 *     `"i"` by default and to `"ı"` in Turkish; `"i"` uppercases to
 *     `"I"` by default and to `"İ"` in Turkish. A Turkish reader typing
 *     `ANLIYORUM` means `anlıyorum`, and default folding turns it into
 *     `anliyorum` — a different word, made of letters Turkish keeps apart;
 *   - **German** writes `ß` where the upper case is `SS`. Somebody
 *     searching `strasse` should find `Straße`, and lowercasing alone
 *     never brings the two together;
 *   - **Greek** writes sigma two ways, `σ` inside a word and `ς` at
 *     the end of one. Lowercasing `Σ` picks whichever the position calls
 *     for, so the same word folds two ways depending on what follows it.
 *
 * docs/features/i18n.md, "Locale-specific hazards", is normative for the first
 * of those and names the shape of the fix. This module is that fix, in one
 * place, because the alternative — every screen writing its own three-line
 * `fold()` — is how four screens ended up with four different wrong answers.
 *
 * # Two folds, and why the difference matters
 *
 * {@link foldForSearch} folds **in the reader's language**: it is for matching
 * what a person typed against text a person reads — a connection's name, a
 * translated menu label, a tag they invented.
 *
 * {@link foldInvariant} folds in a **fixed** language: it is for the ASCII
 * identifiers that are not language at all — a key cap (`Ctrl`), a query
 * prefix (`tag:`), the literal tag this application treats as a flag. Folding
 * those in the reader's language is its own bug: under Turkish rules
 * `"FAVOURITE"` folds to `"favourıte"` and stops matching the constant it
 * is being compared against.
 *
 * # Why the pipeline is what it is
 *
 * Upper, then lower, then strip. Uppercasing first is what turns `ß`
 * into `SS`, which the round trip back down leaves as `ss` — the same thing
 * Unicode's full case folding does, with no table of our own. The round trip
 * is stable in Turkish (`ı` -> `I` -> `ı`, `i` -> `İ` -> `i`),
 * which is the property that makes it safe to use for every language rather
 * than special-casing one.
 *
 * Combining marks are stripped afterwards, not before: lowercasing `İ`
 * under non-Turkish rules *produces* a combining dot above, and stripping
 * first would leave it behind on screen and in the comparison.
 *
 * Stripping marks is also what makes search diacritic-insensitive, which is
 * the behaviour the tree has always had — `grun` finds `Grün`, and Arabic
 * harakat do not have to be typed to find a host whose name carries them. It
 * is a deliberate widening of what matches, and it is applied to the needle
 * and the haystack alike, so it can never make a search find *less*.
 */

/**
 * The language ASCII identifiers are folded in.
 *
 * A fixed tag, and deliberately not the reader's: the strings folded this way
 * are not written in any language, so the reader's rules can only damage them.
 */
const INVARIANT_LOCALE = "en-US";

/** U+03C2 GREEK SMALL LETTER FINAL SIGMA. */
const FINAL_SIGMA = /ς/g;
/** U+03C3 GREEK SMALL LETTER SIGMA — what a fold maps the final form to. */
const SIGMA = "σ";

/** Every combining mark, in any script. Stripped after the case round trip. */
const COMBINING_MARKS = /\p{M}/gu;

/**
 * Tags this runtime has already accepted, and what to use in their place when
 * it has not.
 *
 * `Intl` and the `toLocale*Case` methods throw a `RangeError` on a tag they
 * cannot parse, and the tag reaching here comes from a settings file — which a
 * newer build may have written with a language this one has never heard of. A
 * confirmation gate and a search box are not where the interface should die,
 * so an unusable tag falls back to the invariant locale: the fold is then no
 * better than it was before it was locale-aware, and no worse.
 */
const RESOLVED = new Map<string, string>();

function usableLocale(locale: string): string {
  const cached = RESOLVED.get(locale);
  if (cached !== undefined) return cached;
  let resolved = INVARIANT_LOCALE;
  try {
    // Cheapest thing that exercises the same parser the callers will hit.
    if (Intl.getCanonicalLocales(locale).length > 0) resolved = locale;
  } catch {
    resolved = INVARIANT_LOCALE;
  }
  RESOLVED.set(locale, resolved);
  return resolved;
}

/**
 * Fold a string for substring matching, in the reader's language.
 *
 * Apply it to the needle and to every haystack, with the same locale. What
 * comes back is for comparing and never for showing: it has lost case, accents
 * and the difference between the two sigmas, and none of that is recoverable.
 */
export function foldForSearch(value: string, locale: string): string {
  const tag = usableLocale(locale);
  return (
    value
      .toLocaleUpperCase(tag)
      .toLocaleLowerCase(tag)
      // NFD so that a precomposed letter and a letter-plus-mark reach the strip
      // below in the same shape; NFC at the end so the result is a normal
      // string again and `includes` compares like with like.
      .normalize("NFD")
      .replace(COMBINING_MARKS, "")
      .replace(FINAL_SIGMA, SIGMA)
      .normalize("NFC")
  );
}

/**
 * Fold an ASCII identifier: a key cap, a query prefix, a tag used as a flag.
 *
 * Same pipeline, fixed language. Use it wherever both sides of the comparison
 * are written by this codebase rather than by a translator or a user.
 */
export function foldInvariant(value: string): string {
  return foldForSearch(value, INVARIANT_LOCALE);
}

/**
 * A collator per language, built once.
 *
 * `sensitivity: "accent"` is the setting that means "case is not a
 * difference, everything else is". It is what lets `KALDIRDIĞIMI` equal
 * `kaldırdığımı` under Turkish rules while keeping
 * `ç` apart from `c` — which is exactly the bargain a typed confirmation
 * wants: forgive the shift key, forgive nothing else.
 *
 * `usage: "search"` asks for the collation tailored to matching rather than to
 * sorting; the two differ in several languages and matching is what this is.
 */
const OPTIONS: Intl.CollatorOptions = { sensitivity: "accent", usage: "search" };
const COLLATORS = new Map<string, Intl.Collator>();

function collatorFor(locale: string): Intl.Collator {
  const tag = usableLocale(locale);
  const cached = COLLATORS.get(tag);
  if (cached !== undefined) return cached;
  const collator = new Intl.Collator(tag, OPTIONS);
  COLLATORS.set(tag, collator);
  return collator;
}

/**
 * A collator for *ordering*, per language, built once.
 *
 * Separate from the matching collator above because the two jobs want
 * different tailorings, and `Intl` says so: `usage: "sort"` is the collation a
 * language sorts a list with, `usage: "search"` the one it matches with. They
 * differ in several languages.
 *
 * `sensitivity: "variant"` keeps every distinction — case, accent, width —
 * because this is deciding the order of a list a person reads, where "a" and
 * "A" landing in an arbitrary order relative to each other looks like a bug.
 */
const SORT_OPTIONS: Intl.CollatorOptions = { usage: "sort", sensitivity: "variant" };
const SORTERS = new Map<string, Intl.Collator>();

/**
 * Order two strings the way the reader's language orders them.
 *
 * Use this anywhere a list of names, labels, paths or tags is sorted for
 * display. It is the counterpart of {@link foldForSearch}: the same rule that
 * says a Turkish reader's `I` is not an `i` also says that Turkish sorts
 * `ı` before `i`, and that Swedish puts `ä` after `z` while German
 * puts it beside `a`.
 *
 * **`String.prototype.localeCompare(other)` with no locale is the bug this
 * replaces.** It does not read the language the interface is in; it reads the
 * one the *operating system* is set to. The connection tree was therefore
 * ordered by the host machine, which means the same vault, in the same chosen
 * language, came out in a different order on a colleague's laptop — and in
 * Turkish, `"İstanbul".localeCompare("Izmir")` is negative by default and
 * positive under `tr`. Nothing in the interface made that visible, and
 * `docs/features/i18n.md` had no rule about collation until this was found.
 *
 * There is no invariant counterpart, deliberately. Ordering is a presentation
 * choice and always belongs to the reader; the identifiers that must be folded
 * invariantly ({@link foldInvariant}) are *compared*, never sorted for show.
 */
export function compareInLocale(a: string, b: string, locale: string): number {
  const tag = usableLocale(locale);
  let collator = SORTERS.get(tag);
  if (collator === undefined) {
    collator = new Intl.Collator(tag, SORT_OPTIONS);
    SORTERS.set(tag, collator);
  }
  return collator.compare(a, b);
}

/**
 * Whether two strings are the same word, ignoring case, in one language.
 *
 * This is the comparison docs/features/i18n.md prescribes, with the language
 * supplied rather than left to the runtime's default — because the caller
 * knows which language the text was *shown* in, and the runtime only knows
 * which language the operating system is set to. Those are the same for most
 * people and different for exactly the people this matters to.
 *
 * Whole strings only. There is no locale-aware `includes`, which is why
 * substring matching goes through {@link foldForSearch} instead.
 */
export function equalsIgnoringCase(a: string, b: string, locale: string): boolean {
  return collatorFor(locale).compare(a, b) === 0;
}
