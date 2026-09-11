/**
 * Real CLDR plural rules, checked against every catalogue rather than a sample.
 *
 * Russian has four categories and Arabic six. English and German have two, so
 * a naive implementation looks correct for as long as nobody tests it in the
 * languages it is wrong in — which is half the shipping list. The first half of
 * this file exists so the day someone "simplifies" the formatter, the failure
 * is here rather than in a bug report from a translator.
 *
 * The second half exists because of how the catalogues actually broke. The
 * check that used to live here named four keys in one namespace and asserted
 * that each contained `other {` — the one category ICU requires of everybody.
 * It passed while five Arabic messages carried `other` alone (Arabic inflects a
 * counted noun at 1, 2, 3-10 and 11+, so one form served all of them wrongly),
 * while `many` was missing from 57 French and 57 Brazilian-Portuguese messages
 * and 18 Spanish ones, and while the **English source** omitted `one` from four
 * messages — an omission every translator then inherited, which is how it
 * reached nine languages. A sampling test is why that shipped. So these
 * enumerate: every plural in every message in every catalogue of every locale,
 * against the categories `Intl.PluralRules` reports for that locale.
 *
 * Two consequences worth knowing before editing a catalogue:
 *
 * - A category is required even when its wording coincides with `other`.
 *   `{count, plural, one {Attempt #} other {Attempt #}}` looks redundant and is
 *   not: the slot is what a translator whose language *does* inflect there sees
 *   and fills in, and `intl-messageformat` silently falling back to `other` is
 *   exactly the failure mode that let five Arabic messages ship one form.
 * - A category the language does not have is also a failure. `many` in German
 *   is dead text that will never be selected, and it usually means a message
 *   was copied from a locale with different rules.
 *
 * The fixture catalogues in the first half are written inline rather than added
 * to `locales/`, because they are test fixtures: real Russian and Arabic copy
 * comes from translators through Weblate, and inventing it here would put
 * unreviewed grammar in a shipping directory.
 */

import { beforeAll, describe, expect, it } from "vitest";
import { IntlMessageFormat } from "intl-messageformat";

import { isLocaleAvailable } from "./catalogues";
import { initI18n } from "./instance";
import { SOURCE_LOCALE, SUPPORTED_LOCALES, type Namespace } from "./locales";

const i18n = initI18n();

/**
 * The fixtures go in a namespace of their own.
 *
 * They used to go in `common`, and `addResourceBundle`'s deep merge writes into
 * the very object `catalogues.ts` imported from `locales/en/common.json` — so
 * loading this file added a `test.files` key to the shipped English catalogue
 * in memory. Nothing noticed until the completeness check below started reading
 * that catalogue and reported nine languages as missing a key that exists in no
 * file. A name outside the registry cannot collide with anything real — and
 * being outside the registry is exactly why it needs the cast: `Namespace` is
 * the set of namespaces that ship, which this deliberately is not.
 */
const NS = "pluralsFixture" as Namespace;

beforeAll(() => {
  // Russian: one (1, 21, 31…), few (2-4, 22-24…), many (0, 5-20, 11-14…), other.
  i18n.addResourceBundle(
    "ru",
    NS,
    {
      test: {
        files:
          "{count, plural, one {# файл} few {# файла} many {# файлов} other {# файла}}",
      },
    },
    true,
    true,
  );

  // Arabic: zero, one, two, few, many, other — all six are reachable.
  i18n.addResourceBundle(
    "ar",
    NS,
    {
      test: {
        files:
          "{count, plural, zero {لا ملفات} one {ملف واحد} two {ملفان} few {# ملفات} many {# ملفًا} other {# ملف}}",
      },
    },
    true,
    true,
  );

  i18n.addResourceBundle(
    "en",
    NS,
    { test: { files: "{count, plural, =0 {no files} one {# file} other {# files}}" } },
    true,
    true,
  );
});

function translate(lng: string, count: number): string {
  return i18n.getFixedT(lng, NS)("test.files" as never, { count } as never) as unknown as string;
}

describe("Russian, four categories", () => {
  it.each([
    [1, "1 файл"],
    [2, "2 файла"],
    [3, "3 файла"],
    [4, "4 файла"],
    [5, "5 файлов"],
    [11, "11 файлов"],
    [21, "21 файл"],
    [22, "22 файла"],
    [25, "25 файлов"],
    [101, "101 файл"],
    [111, "111 файлов"],
  ])("%i", (count, expected) => {
    expect(translate("ru", count)).toBe(expected);
  });

  it("does not collapse to a one/other switch", () => {
    // The whole point: 2 and 5 differ, and a two-form implementation cannot
    // tell them apart.
    expect(translate("ru", 2)).not.toBe(translate("ru", 5));
  });
});

describe("Arabic, six categories", () => {
  it.each([
    [0, "لا ملفات"],
    [1, "ملف واحد"],
    [2, "ملفان"],
    [3, "3 ملفات"],
    [11, "11 ملفًا"],
    [100, "100 ملف"],
  ])("%i", (count, expected) => {
    expect(translate("ar", count)).toBe(expected);
  });

  it("reaches all six forms for distinct counts", () => {
    const forms = new Set([0, 1, 2, 3, 11, 100].map((n) => translate("ar", n)));
    expect(forms.size).toBe(6);
  });
});

describe("English, and the explicit zero case", () => {
  it("uses =0 in preference to the plural category", () => {
    // CLDR puts 0 in `other` for English. `=0` is an exact match and wins,
    // which is what lets the footer say "no sessions" instead of "0 sessions".
    expect(translate("en", 0)).toBe("no files");
    expect(translate("en", 1)).toBe("1 file");
    expect(translate("en", 7)).toBe("7 files");
  });
});

// ------------------------------------------------- the shipped catalogues --

/**
 * Every catalogue of every language, read as data.
 *
 * `catalogues.ts` deliberately splits English (eager) from the rest (lazy) so
 * that a language costs nothing until it is chosen. That is the right shape for
 * the application and the wrong one for a check that has to look at all of
 * them, so this globs the directory directly. It is the same path pattern, and
 * Vite resolves it at build time, so a renamed directory fails here too.
 */
const CATALOGUE_SOURCE = import.meta.glob("../../../../../locales/*/*.json", {
  eager: true,
  import: "default",
});

/** `../../../../../locales/de/settings.json` -> `["de", "settings"]`. */
function splitPath(path: string): { locale: string; namespace: string } | null {
  const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
  const locale = match?.[1];
  const namespace = match?.[2];
  if (locale === undefined || namespace === undefined) return null;
  return { locale, namespace };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const CATALOGUES: ReadonlyMap<string, ReadonlyMap<string, Record<string, unknown>>> = (() => {
  const out = new Map<string, Map<string, Record<string, unknown>>>();
  for (const [path, module] of Object.entries(CATALOGUE_SOURCE)) {
    const parts = splitPath(path);
    if (parts === null || !isRecord(module)) continue;
    let forLocale = out.get(parts.locale);
    if (forLocale === undefined) {
      forLocale = new Map();
      out.set(parts.locale, forLocale);
    }
    forLocale.set(parts.namespace, module);
  }
  return out;
})();

/**
 * A `_comment_*` entry is a note to the translator, not a message. They are
 * prose about ICU syntax and would be parsed as ICU if they were not skipped.
 */
function isComment(segment: string): boolean {
  return segment.startsWith("_comment");
}

/** Every leaf string in a catalogue, with its dotted key, comments excluded. */
function leaves(node: unknown, prefix: readonly string[] = []): [string, string][] {
  if (typeof node === "string") return [[prefix.join("."), node]];
  if (!isRecord(node)) return [];
  return Object.entries(node).flatMap(([key, value]) =>
    isComment(key) ? [] : leaves(value, [...prefix, key]),
  );
}

/**
 * The `intl-messageformat` AST node types this walk cares about.
 *
 * Taken from `@formatjs/icu-messageformat-parser`, which is a transitive
 * dependency rather than a declared one — importing its `TYPE` enum here would
 * make this file depend on a package `package.json` does not name. The three
 * numbers are part of the serialised AST shape, which is public API of
 * `IntlMessageFormat#getAst`.
 */
const TYPE_SELECT = 5;
const TYPE_PLURAL = 6;
const TYPE_TAG = 8;

interface FoundPlural {
  /** The argument the block switches on: `count`, `seconds`, `hops`. */
  readonly argument: string;
  /** Its selectors, `=0` and friends included, in declaration order. */
  readonly selectors: readonly string[];
}

/**
 * Collect every plural block in a parsed message, including nested ones.
 *
 * The AST is walked rather than the source text regex-matched, because the
 * parser doing the walking is the one that will render the message at runtime.
 * A regex that disagreed with it would fail in whichever direction nobody
 * checked — and messages here do nest: `import:preserved.settings` switches on
 * two arguments, and a tag's children can hold a third.
 */
function collectPlurals(nodes: readonly unknown[], found: FoundPlural[]): void {
  for (const node of nodes) {
    if (!isRecord(node)) continue;

    if (node.type === TYPE_TAG && Array.isArray(node.children)) {
      collectPlurals(node.children, found);
      continue;
    }
    if (node.type !== TYPE_PLURAL && node.type !== TYPE_SELECT) continue;

    const options = node.options;
    if (!isRecord(options)) continue;
    if (node.type === TYPE_PLURAL && typeof node.value === "string") {
      found.push({ argument: node.value, selectors: Object.keys(options) });
    }
    for (const branch of Object.values(options)) {
      if (isRecord(branch) && Array.isArray(branch.value)) collectPlurals(branch.value, found);
    }
  }
}

/** Every plural block in every message of one locale's catalogues. */
function pluralsIn(locale: string): { where: string; plural: FoundPlural }[] {
  const namespaces = CATALOGUES.get(locale);
  if (namespaces === undefined) return [];
  const out: { where: string; plural: FoundPlural }[] = [];
  for (const [namespace, catalogue] of namespaces) {
    for (const [key, message] of leaves(catalogue)) {
      const found: FoundPlural[] = [];
      // Parsing can throw on a malformed message. That is a real failure and
      // is meant to surface as one, so it is deliberately not caught.
      collectPlurals(new IntlMessageFormat(message, locale).getAst(), found);
      for (const plural of found) out.push({ where: `${namespace}:${key}`, plural });
    }
  }
  return out;
}

/** What CLDR says this language inflects on. Never a hardcoded list. */
function requiredCategories(locale: string): readonly string[] {
  return new Intl.PluralRules(locale).resolvedOptions().pluralCategories;
}

const LOCALES = SUPPORTED_LOCALES.map((locale) => locale.code);

describe("every plural in every catalogue", () => {
  it("finds the plural messages it is meant to be checking", () => {
    // Without this, a walk that silently returned nothing — a renamed glob, an
    // AST shape that moved — would report every language as clean. The floor is
    // deliberately well under the real count so it does not need editing every
    // time a message is added or removed.
    for (const locale of LOCALES) {
      expect(pluralsIn(locale).length, locale).toBeGreaterThan(40);
    }
  });

  it.each(LOCALES)("%s declares exactly the categories CLDR gives it", (locale) => {
    const required = requiredCategories(locale);
    const wrong: string[] = [];

    for (const { where, plural } of pluralsIn(locale)) {
      // `=0` and friends are exact-value matches, not categories. They are
      // allowed anywhere and say nothing about the language's grammar — the
      // footer's "no sessions" is one — so they are not compared.
      const declared = plural.selectors.filter((selector) => !selector.startsWith("="));
      const missing = required.filter((category) => !declared.includes(category));
      const unexpected = declared.filter((category) => !required.includes(category));
      if (missing.length > 0 || unexpected.length > 0) {
        const problems = [
          missing.length > 0 ? `missing ${missing.join(", ")}` : "",
          unexpected.length > 0 ? `unexpected ${unexpected.join(", ")}` : "",
        ].filter((part) => part !== "");
        wrong.push(`${where} {${plural.argument}}: ${problems.join("; ")}`);
      }
    }

    expect(wrong, `${locale} needs ${required.join(", ")}`).toEqual([]);
  });
});

// ---------------------------------------------- completeness, by key -------

/**
 * A language the picker offers must be complete in keys, not only in files.
 *
 * `isLocaleAvailable` gates on the presence of namespace *files*, which is the
 * only question it can answer synchronously without loading all ninety
 * catalogues before the first paint — see the note on it in `catalogues.ts`.
 * The consequence is that a namespace which exists but is missing keys still
 * counts as available, and those keys then fall back to English one by one.
 * That is the right runtime behaviour (English beats a blank) and a bad place
 * to leave the only check: seventeen palette keys were added to English alone
 * and rendered English inside a Turkish interface, with nothing failing.
 *
 * So completeness is enforced here, where it costs nothing at runtime and where
 * the answer is a red build rather than a language quietly going half-English.
 */
describe("catalogue completeness", () => {
  const TRANSLATIONS = LOCALES.filter((locale) => locale !== SOURCE_LOCALE);

  function keysOf(locale: string, namespace: string): Set<string> {
    const catalogue = CATALOGUES.get(locale)?.get(namespace);
    if (catalogue === undefined) return new Set();
    return new Set(leaves(catalogue).map(([key]) => key));
  }

  const ENGLISH_NAMESPACES = [...(CATALOGUES.get(SOURCE_LOCALE)?.keys() ?? [])].sort();

  it("reads the English catalogues it compares against", () => {
    expect(ENGLISH_NAMESPACES.length).toBeGreaterThan(5);
  });

  it.each(TRANSLATIONS)("%s has every key English ships", (locale) => {
    // Only languages the picker actually offers are held to this. One that is
    // still missing whole namespaces is a translation in progress and is
    // already refused by `isLocaleAvailable`; failing it twice says nothing new.
    if (!isLocaleAvailable(locale)) return;

    const missing: string[] = [];
    for (const namespace of ENGLISH_NAMESPACES) {
      const theirs = keysOf(locale, namespace);
      for (const key of keysOf(SOURCE_LOCALE, namespace)) {
        if (!theirs.has(key)) missing.push(`${namespace}:${key}`);
      }
    }
    expect(missing, `${locale} is offered as a complete language`).toEqual([]);
  });

  it.each(TRANSLATIONS)("%s has no key English has dropped", (locale) => {
    // The other direction is a rename left behind: the message is unreachable,
    // it is still shown to translators, and it is the reason a catalogue drifts
    // into holding two spellings of the same string.
    const stale: string[] = [];
    for (const namespace of ENGLISH_NAMESPACES) {
      const ours = keysOf(SOURCE_LOCALE, namespace);
      for (const key of keysOf(locale, namespace)) {
        if (!ours.has(key)) stale.push(`${namespace}:${key}`);
      }
    }
    expect(stale, `${locale} holds keys no English message backs`).toEqual([]);
  });
});
