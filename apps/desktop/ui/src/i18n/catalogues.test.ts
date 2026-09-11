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

import type { Catalogue } from "./catalogues";
import {
  ENGLISH_CATALOGUES,
  SHIPPED_NAMESPACES,
  completeLocales,
  localeIsComplete,
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
 * the assertions below are about the *rule*: complete means "every message
 * English ships is translated", for whichever languages that happens to be
 * today.
 *
 * It reads the files, because that is now what the rule is about. Presence of
 * a namespace file was the old test and the defect: a half-translated
 * catalogue passed it, and the language was offered as finished while strings
 * inside it fell back to English one by one.
 */
const ON_DISK: ReadonlyMap<string, ReadonlyMap<string, Catalogue>> = (() => {
  const out = new Map<string, Map<string, Catalogue>>();
  const files = import.meta.glob<Catalogue>("../../../../../locales/*/*.json", {
    eager: true,
    import: "default",
  });
  for (const [path, catalogue] of Object.entries(files)) {
    const match = /\/locales\/([^/]+)\/([^/]+)\.json$/.exec(path);
    const locale = match?.[1];
    const namespace = match?.[2];
    if (locale === undefined || namespace === undefined) continue;
    const seen = out.get(locale) ?? new Map<string, Catalogue>();
    seen.set(namespace, catalogue);
    out.set(locale, seen);
  }
  return out;
})();

/** Every message key in a catalogue, translator comments excluded. */
function messageKeysOf(catalogue: Catalogue | undefined): ReadonlySet<string> {
  if (catalogue === undefined) return new Set();
  return new Set(leaves(catalogue).map(([key]) => key).filter((key) => !isComment(key)));
}

/** Does this locale translate every message English ships? */
function isCompleteOnDisk(code: string): boolean {
  if (code === SOURCE_LOCALE) return true;
  const theirs = ON_DISK.get(code);
  if (theirs === undefined) return false;
  return SHIPPED_NAMESPACES.every((ns) => {
    const translated = messageKeysOf(theirs.get(ns));
    for (const key of messageKeysOf(ENGLISH_CATALOGUES[ns])) {
      if (!translated.has(key)) return false;
    }
    return true;
  });
}

describe("locale availability", () => {
  it("is measured from the catalogues, not declared", async () => {
    // The bug this replaces twice over: a hardcoded `available: false` on nine
    // languages, and then a check that counted files rather than messages. The
    // assertion is the rule rather than the answer — a translation landing, or
    // a key being added to English, moves both sides of this comparison
    // together and nobody has to come back and edit it.
    for (const locale of SUPPORTED_LOCALES) {
      expect(await localeIsComplete(locale.code), locale.code).toBe(
        isCompleteOnDisk(locale.code),
      );
    }
  });

  it("offers English whatever else is translated", async () => {
    // Not a measurement: English is the source and the fallback for every
    // other language, so it is selectable even if `locales/en/` were empty.
    expect(await localeIsComplete(SOURCE_LOCALE)).toBe(true);
    expect(await completeLocales()).toContain(SOURCE_LOCALE);
  });

  it("offers every language that translates every message", async () => {
    const complete = SUPPORTED_LOCALES.map((l) => l.code).filter(isCompleteOnDisk);
    // Guards against the whole check passing vacuously if the glob above ever
    // stops matching: there is always at least English.
    expect(complete.length).toBeGreaterThan(0);
    const offered = await completeLocales();
    for (const code of complete) {
      expect(offered, code).toContain(code);
    }
  });

  it("refuses a language that is short of even one message", async () => {
    // The state every language is in while it is being translated, including
    // the day a key is added to English. Half a catalogue is not a choice:
    // picking it leaves part of the interface in English, which is the failure
    // the Language screen used to have in a different costume.
    const offered = await completeLocales();
    for (const code of ON_DISK.keys()) {
      if (code === SOURCE_LOCALE || isCompleteOnDisk(code)) continue;
      expect(await localeIsComplete(code), code).toBe(false);
      expect(offered, code).not.toContain(code);
    }
  });

  it("refuses a language whose directory is missing a whole namespace", async () => {
    // The old test, kept: it is still a refusal, now reached by the cheap
    // path that short-circuits before any file is read.
    for (const [code, namespaces] of ON_DISK) {
      if (code === SOURCE_LOCALE) continue;
      if (SHIPPED_NAMESPACES.every((ns) => namespaces.has(ns))) continue;
      expect(await localeIsComplete(code), code).toBe(false);
    }
  });

  it("refuses a locale with no directory at all", async () => {
    expect(await localeIsComplete("xx-YY")).toBe(false);
    expect(await completeLocales()).not.toContain("xx-YY");
  });

  it("never offers a language the registry does not list", async () => {
    const registered = SUPPORTED_LOCALES.map((l) => l.code);
    for (const code of await completeLocales()) {
      expect(registered, code).toContain(code);
    }
  });
});
