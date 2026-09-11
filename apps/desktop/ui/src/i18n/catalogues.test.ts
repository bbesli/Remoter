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

import { ENGLISH_CATALOGUES, SHIPPED_NAMESPACES, isLocaleAvailable } from "./catalogues";
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

describe("locale availability", () => {
  it("is measured from the directory, not declared", () => {
    // The bug this replaces: a hardcoded `available: false` on nine languages,
    // which would have kept saying "Not yet available" after the catalogues
    // landed. Any locale with a complete directory is available; English
    // always is.
    expect(isLocaleAvailable(SOURCE_LOCALE)).toBe(true);
    for (const locale of SUPPORTED_LOCALES) {
      if (locale.code === SOURCE_LOCALE) continue;
      // Presence of every namespace English ships is the whole test.
      expect(isLocaleAvailable(locale.code)).toBe(false);
    }
  });

  it("refuses a locale that is not in the registry at all", () => {
    expect(isLocaleAvailable("xx-YY")).toBe(false);
  });
});
