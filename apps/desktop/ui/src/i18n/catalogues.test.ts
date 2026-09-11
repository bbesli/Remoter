/**
 * The English catalogues, checked as data.
 *
 * These run over whatever is in `locales/en/` at the time, so they keep
 * applying as the other features are extracted. Each one exists because the
 * failure it catches is invisible until a specific language is selected — and
 * the language that shows it is usually one nobody on the team reads.
 */

import { describe, expect, it } from "vitest";
import { IntlMessageFormat } from "intl-messageformat";

import {
  ENGLISH_CATALOGUES,
  SHIPPED_NAMESPACES,
  availableLocales,
  isLocaleAvailable,
} from "./catalogues";
import { NAMESPACES, SOURCE_LOCALE, SUPPORTED_LOCALES } from "./locales";

/** Every leaf string in a catalogue, with its dotted key. */
function leaves(node: unknown, prefix: string[] = []): [string, string][] {
  if (typeof node === "string") return [[prefix.join("."), node]];
  if (typeof node !== "object" || node === null || Array.isArray(node)) return [];
  return Object.entries(node).flatMap(([key, value]) => leaves(value, [...prefix, key]));
}

const ALL: [string, string, string][] = SHIPPED_NAMESPACES.flatMap((ns) =>
  leaves(ENGLISH_CATALOGUES[ns]).map(([key, message]): [string, string, string] => [
    ns,
    key,
    message,
  ]),
);

/** A `_comment_*` entry is a note to the translator, not a message. */
function isComment(key: string): boolean {
  return key.split(".").some((segment) => segment.startsWith("_comment"));
}

const MESSAGES = ALL.filter(([, key]) => !isComment(key));

describe("the catalogue directory", () => {
  it("ships at least the namespaces this milestone extracted", () => {
    expect(SHIPPED_NAMESPACES).toContain("common");
    expect(SHIPPED_NAMESPACES).toContain("shell");
    expect(SHIPPED_NAMESPACES).toContain("settings");
  });

  it("contains no namespace the registry does not declare", () => {
    for (const ns of SHIPPED_NAMESPACES) {
      expect(NAMESPACES).toContain(ns);
    }
  });

  it("is not empty", () => {
    expect(MESSAGES.length).toBeGreaterThan(100);
  });
});

describe("every message", () => {
  it("parses as ICU MessageFormat", () => {
    // A message that will not parse renders the fallback in `missing.ts`
    // rather than what the author wrote. Catching it here means catching it in
    // English, where it is a typo, rather than in a language nobody on the
    // team reads, where it is a bug report.
    const broken: string[] = [];
    for (const [ns, key, message] of MESSAGES) {
      try {
        new IntlMessageFormat(message, SOURCE_LOCALE, undefined, { ignoreTag: true });
      } catch (error) {
        broken.push(`${ns}:${key} — ${String(error)}`);
      }
    }
    expect(broken).toEqual([]);
  });

  it("declares an `other` branch on every plural", () => {
    // ICU requires it, and it is the fallback for every category a language
    // has that the message does not name. A plural without it throws for the
    // counts that reach the missing category — which may be no count at all in
    // English, and half of them in Russian.
    const missing = MESSAGES.filter(
      ([, , message]) => message.includes(", plural,") && !message.includes("other {"),
    ).map(([ns, key]) => `${ns}:${key}`);
    expect(missing).toEqual([]);
  });

  it("has no leading or trailing whitespace", () => {
    // Padding inside a message is layout smuggled into copy: a translator
    // cannot see it, and it survives into every language.
    const padded = MESSAGES.filter(([, , message]) => message !== message.trim() && message !== " ")
      .map(([ns, key]) => `${ns}:${key}`)
      // `common.punctuation.*` are separators and are padded on purpose.
      .filter((id) => !id.startsWith("common:punctuation."));
    expect(padded).toEqual([]);
  });

  it("carries no bidi control characters", () => {
    // Isolation is applied to interpolated values at the call site, where the
    // code says why. A catalogue with invisible characters baked in is a
    // catalogue a translator cannot round-trip.
    const marked = MESSAGES.filter(([, , message]) =>
      /[\u200E\u200F\u2066-\u2069]/.test(message),
    ).map(([ns, key]) => `${ns}:${key}`);
    expect(marked).toEqual([]);
  });
});

describe("translator comments", () => {
  it("names a key that exists in the same object", () => {
    // A `_comment_foo` whose `foo` was renamed is guidance pointing at
    // nothing, and Weblate will show it against the wrong string.
    const orphans: string[] = [];
    for (const ns of SHIPPED_NAMESPACES) {
      const walk = (node: unknown, path: string[]) => {
        if (typeof node !== "object" || node === null || Array.isArray(node)) return;
        const entries = Object.entries(node);
        const names = new Set(entries.map(([key]) => key));
        for (const [key, value] of entries) {
          if (key.startsWith("_comment_")) {
            const target = key.slice("_comment_".length);
            // `_comment_` and `_comment_file` annotate the object itself.
            if (target !== "" && target !== "file" && !names.has(target)) {
              orphans.push(`${ns}:${[...path, key].join(".")}`);
            }
          } else {
            walk(value, [...path, key]);
          }
        }
      };
      walk(ENGLISH_CATALOGUES[ns], []);
    }
    expect(orphans).toEqual([]);
  });
});

/**
 * What each locale directory actually holds, read from the directory itself.
 *
 * The expectation has to come from somewhere other than a list written in this
 * file. A list is a snapshot of which languages were finished on the day it was
 * typed: the previous version of these tests asserted that every locale but
 * English was unavailable, which was true when it was written and became a
 * failing test — on correct code — the day the translations landed. A test that
 * has to be edited every time a catalogue ships is a test that gets deleted by
 * whoever is in a hurry.
 *
 * So this globs `locales/` a second time, independently of `catalogues.ts`, and
 * the assertions below are about the *rule*: available means "every namespace
 * English ships is present", for whichever languages that happens to be today.
 * `import.meta.glob` without `eager` returns loaders, so this costs a list of
 * paths and reads no files.
 */
const ON_DISK: ReadonlyMap<string, ReadonlySet<string>> = (() => {
  const out = new Map<string, Set<string>>();
  for (const path of Object.keys(import.meta.glob("../../../../../locales/*/*.json"))) {
    const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
    const locale = match?.[1];
    const namespace = match?.[2];
    if (locale === undefined || namespace === undefined) continue;
    const seen = out.get(locale) ?? new Set<string>();
    seen.add(namespace);
    out.set(locale, seen);
  }
  return out;
})();

/** Does this locale's directory hold every namespace English ships? */
function isCompleteOnDisk(code: string): boolean {
  const seen = ON_DISK.get(code);
  return seen !== undefined && SHIPPED_NAMESPACES.every((ns) => seen.has(ns));
}

describe("locale availability", () => {
  it("is measured from the directory, not declared", () => {
    // The bug this replaces: a hardcoded `available: false` on nine languages,
    // which would have kept saying "Not yet available" after the catalogues
    // landed. The assertion is the rule rather than the answer — a catalogue
    // arriving or a namespace being added to English moves both sides of this
    // comparison together, and nobody has to come back and edit it.
    for (const locale of SUPPORTED_LOCALES) {
      expect(isLocaleAvailable(locale.code), locale.code).toBe(isCompleteOnDisk(locale.code));
    }
  });

  it("offers English whatever else is translated", () => {
    // Not a measurement: English is the source and the fallback for every
    // other language, so it is selectable even if `locales/en/` were empty.
    expect(isLocaleAvailable(SOURCE_LOCALE)).toBe(true);
    expect(availableLocales()).toContain(SOURCE_LOCALE);
  });

  it("offers every language whose catalogues are all present", () => {
    const complete = SUPPORTED_LOCALES.map((l) => l.code).filter(isCompleteOnDisk);
    // Guards against the whole check passing vacuously if the glob above ever
    // stops matching: there is always at least English.
    expect(complete.length).toBeGreaterThan(0);
    for (const code of complete) {
      expect(availableLocales(), code).toContain(code);
    }
  });

  it("refuses a language that is short of even one namespace", () => {
    // The state every language is in while it is being translated. Half a
    // catalogue is not a choice: picking it would leave most of the interface
    // in English, which is the failure the Language screen used to have.
    for (const code of ON_DISK.keys()) {
      if (code === SOURCE_LOCALE || isCompleteOnDisk(code)) continue;
      expect(isLocaleAvailable(code), code).toBe(false);
      expect(availableLocales(), code).not.toContain(code);
    }
  });

  it("refuses a locale with no directory at all", () => {
    expect(isLocaleAvailable("xx-YY")).toBe(false);
    expect(availableLocales()).not.toContain("xx-YY");
  });

  it("never offers a language the registry does not list", () => {
    const registered = SUPPORTED_LOCALES.map((l) => l.code);
    for (const code of availableLocales()) {
      expect(registered, code).toContain(code);
    }
  });
});
