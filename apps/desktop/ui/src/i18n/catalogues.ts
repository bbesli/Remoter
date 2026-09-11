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
 * Every message key English ships, per namespace. The yardstick completeness
 * is measured against.
 *
 * `_comment_*` entries are left out: they are notes to the translator, shown
 * in Weblate and never rendered, so a language that has translated every
 * message but dropped a comment is complete as far as a reader is concerned.
 * (The build guard in `plurals.test.ts` does hold them to the comments too —
 * a comment that only exists in English is a comment the next translator
 * cannot see — but that is a repository rule, not a reason to take a language
 * off the Language screen.)
 */
const ENGLISH_KEYS: ReadonlyMap<Namespace, ReadonlySet<string>> = (() => {
  const out = new Map<Namespace, ReadonlySet<string>>();
  for (const ns of SHIPPED_NAMESPACES) {
    out.set(ns, messageKeys(ENGLISH_CATALOGUES[ns] ?? {}));
  }
  return out;
})();

/** Every dotted key with a string behind it, comments excluded. */
function messageKeys(catalogue: Catalogue): ReadonlySet<string> {
  const keys = new Set<string>();
  const walk = (node: unknown, path: string[]): void => {
    if (typeof node === "string") {
      keys.add(path.join("."));
      return;
    }
    if (typeof node !== "object" || node === null || Array.isArray(node)) return;
    for (const [key, value] of Object.entries(node)) {
      if (key.startsWith("_comment")) continue;
      walk(value, [...path, key]);
    }
  };
  walk(catalogue, []);
  return keys;
}

/**
 * One answer per language, computed once.
 *
 * The promise is cached rather than the boolean, so the ninety catalogue files
 * are read at most once each however many callers ask and however close
 * together. Catalogue files cannot change while the application is running, so
 * there is nothing to invalidate.
 */
const COMPLETE = new Map<string, Promise<boolean>>();

/**
 * Whether a language is complete enough to be offered as a choice.
 *
 * **Completeness is key coverage, not file presence.** The previous version of
 * this function checked that every namespace *file* existed, and its own
 * comment admitted what that let through: "a file that exists but is
 * half-translated passes it". It did, and it was not theoretical — deleting a
 * single key from `locales/tr/settings.json` left Turkish offered as a
 * finished language while a string fell back to English inside it. The build
 * guard in `plurals.test.ts` caught that; the running product did not, and the
 * running product is where the reader is.
 *
 * So this loads the language's catalogues and compares their keys against
 * English's. It is asynchronous because there is no honest synchronous answer:
 * the catalogues are dynamic imports, and reading all ninety of them before
 * the first paint to keep a synchronous signature would trade a real cost for
 * a cosmetic one. A caller that needs the answer to draw something waits for
 * it; `setLanguage` — which is about to load those catalogues anyway — pays
 * nothing extra.
 *
 * The cheap test still runs first and short-circuits: a language missing whole
 * namespaces is refused without reading anything.
 *
 * English is always complete; it is the source, not a translation of it.
 */
export function localeIsComplete(code: string): Promise<boolean> {
  const cached = COMPLETE.get(code);
  if (cached !== undefined) return cached;
  const measuring = measureLocale(code);
  COMPLETE.set(code, measuring);
  return measuring;
}

async function measureLocale(code: string): Promise<boolean> {
  if (code === SOURCE_LOCALE) return true;
  const forLocale = LAZY_INDEX.get(code);
  if (forLocale === undefined) return false;
  // Whole namespaces first: no point reading nine files to discover the tenth
  // was never written.
  if (!SHIPPED_NAMESPACES.every((ns) => forLocale.has(ns))) return false;

  const loaded = await Promise.all(SHIPPED_NAMESPACES.map((ns) => loadCatalogue(code, ns)));
  return SHIPPED_NAMESPACES.every((ns, index) => {
    const catalogue = loaded[index];
    // `null` is a file that would not parse. It falls back to English at
    // runtime, which is exactly the half-English screen this gate exists to
    // keep off the Language list.
    if (catalogue === undefined || catalogue === null) return false;
    const theirs = messageKeys(catalogue);
    for (const key of ENGLISH_KEYS.get(ns) ?? []) {
      if (!theirs.has(key)) return false;
    }
    return true;
  });
}

/** The subset of {@link SUPPORTED_LOCALES} a reader can actually read. */
export async function completeLocales(): Promise<readonly string[]> {
  const codes = SUPPORTED_LOCALES.map((l) => l.code);
  const complete = await Promise.all(codes.map(localeIsComplete));
  return codes.filter((_, index) => complete[index] === true);
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
