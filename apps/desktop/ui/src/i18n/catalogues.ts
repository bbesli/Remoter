/**
 * Where the JSON catalogues come from, and which languages are selectable.
 *
 * Catalogues live at `<repo>/locales/<code>/<namespace>.json` — outside this
 * package, because translators reach them through Weblate and a translation
 * workflow should not have to know that the interface is a Vite app. Vite's
 * `import.meta.glob` resolves them at build time, so the paths below are
 * checked by the bundler rather than at runtime, and a renamed directory is a
 * build failure instead of a blank screen.
 *
 * English is bundled eagerly; every other language is a dynamic import. That
 * is the whole loading strategy, and it follows from one rule: English must be
 * present before the first paint, because it is the fallback for every missing
 * key in every other language. If it were fetched, a slow disk would mean a
 * window of raw keys — exactly what §2 of the localisation brief forbids.
 */

import { NAMESPACES, SOURCE_LOCALE, SUPPORTED_LOCALES, type Namespace } from "./locales";

/** A parsed catalogue: nested plain objects with ICU MessageFormat leaves. */
export type Catalogue = Record<string, unknown>;

// The five `..` climb out of src/i18n to the repository root. `vite.config.ts`
// widens `server.fs.allow` to match, or the dev server refuses to serve them.
const EAGER_SOURCE = import.meta.glob("../../../../../locales/en/*.json", {
  eager: true,
  import: "default",
});

// English is excluded rather than filtered out afterwards: a file that is both
// eagerly and dynamically imported cannot be code-split, and Rollup says so on
// every build. The negative pattern keeps the two sets disjoint.
const LAZY_SOURCE = import.meta.glob(
  ["../../../../../locales/*/*.json", "!../../../../../locales/en/*.json"],
  { import: "default" },
);

/** `../../../../../locales/de/settings.json` -> `["de", "settings"]`. */
function splitPath(path: string): { locale: string; namespace: string } | null {
  const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  const locale = match?.[1];
  const namespace = match?.[2];
  if (locale === undefined || namespace === undefined) return null;
  return { locale, namespace };
}

function isNamespace(value: string): value is Namespace {
  return (NAMESPACES as readonly string[]).includes(value);
}

/**
 * A JSON module is `unknown` to the type system; a catalogue is an object.
 * Anything else in the directory is ignored rather than crashing the app,
 * because a half-written file reaching `main` should degrade to English.
 */
function asCatalogue(value: unknown): Catalogue | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Catalogue)
    : null;
}

/** Every namespace English actually ships, in registry order. */
export const ENGLISH_CATALOGUES: Readonly<Partial<Record<Namespace, Catalogue>>> = (() => {
  const out: Partial<Record<Namespace, Catalogue>> = {};
  for (const [path, mod] of Object.entries(EAGER_SOURCE)) {
    const parts = splitPath(path);
    if (parts === null || !isNamespace(parts.namespace)) continue;
    const catalogue = asCatalogue(mod);
    if (catalogue !== null) out[parts.namespace] = catalogue;
  }
  return out;
})();

/** The namespaces that exist in English. The yardstick for every other locale. */
export const SHIPPED_NAMESPACES: readonly Namespace[] = NAMESPACES.filter(
  (ns) => ENGLISH_CATALOGUES[ns] !== undefined,
);

/** locale -> namespace -> loader, for everything that is not English. */
const LAZY_INDEX: ReadonlyMap<string, ReadonlyMap<Namespace, () => Promise<unknown>>> = (() => {
  const out = new Map<string, Map<Namespace, () => Promise<unknown>>>();
  for (const [path, load] of Object.entries(LAZY_SOURCE)) {
    const parts = splitPath(path);
    if (parts === null || !isNamespace(parts.namespace)) continue;
    let forLocale = out.get(parts.locale);
    if (forLocale === undefined) {
      forLocale = new Map();
      out.set(parts.locale, forLocale);
    }
    forLocale.set(parts.namespace, load);
  }
  return out;
})();

/**
 * Whether a language can be offered as a choice.
 *
 * The test is presence of every namespace English ships, which is the closest
 * thing to "complete" that can be answered without loading every catalogue of
 * every language at startup. It is a floor, not a proof: a file that exists but
 * is half-translated passes it, and the missing keys then fall back to English
 * key by key. What it does guarantee is that choosing the language changes
 * something, which is the failure this replaces — nine rows that were choices
 * in appearance only.
 *
 * English is always available; it is the source, not a translation of it.
 */
export function isLocaleAvailable(code: string): boolean {
  if (code === SOURCE_LOCALE) return true;
  const forLocale = LAZY_INDEX.get(code);
  if (forLocale === undefined) return false;
  return SHIPPED_NAMESPACES.every((ns) => forLocale.has(ns));
}

/** The subset of {@link SUPPORTED_LOCALES} that has catalogues behind it. */
export function availableLocales(): readonly string[] {
  return SUPPORTED_LOCALES.map((l) => l.code).filter(isLocaleAvailable);
}

/**
 * Read one catalogue. Resolves to `null` — never rejects — when the file is
 * absent, so a language missing one namespace still shows the nine it has.
 */
export async function loadCatalogue(
  locale: string,
  namespace: Namespace,
): Promise<Catalogue | null> {
  if (locale === SOURCE_LOCALE) return ENGLISH_CATALOGUES[namespace] ?? null;
  const load = LAZY_INDEX.get(locale)?.get(namespace);
  if (load === undefined) return null;
  try {
    return asCatalogue(await load());
  } catch {
    // A malformed JSON file is a translator's mistake, not a reason to leave
    // the user on a blank screen. English fills the gap.
    return null;
  }
}
