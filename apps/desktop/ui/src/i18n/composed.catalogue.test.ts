/**
 * The composed-sentence catalogues, checked against the Rust they describe.
 *
 * `failures.catalogue.test.ts` does this for `IpcError.code`, and it was the
 * only join it guarded — which is exactly how the defect this file exists for
 * survived. Two other places in the core were composing English prose and
 * handing it over finished: the vault picker's "this vault cannot be reached"
 * line and its cloud-sync warning, on the first screen of the application, and
 * the command palette's "1 item" / "12 members", hand-pluralised with English
 * rules and written in ASCII digits. No code, no catalogue, nothing to
 * translate. A Turkish reader met them in English before they had unlocked
 * anything.
 *
 * Both now cross as a stable kind plus values, the same shape the failure
 * catalogue uses, and both need the same guard: the identifier lives in Rust
 * and the sentence lives in JSON, and nothing in the type system connects
 * them. A kind renamed in Rust leaves the catalogue keyed on the old word, and
 * the symptom is one English sentence inside an otherwise translated window,
 * in a language nobody on the team reads.
 *
 * So this test reads the Rust.
 */

import { describe, expect, it } from "vitest";
import { IntlMessageFormat } from "intl-messageformat";

import { SOURCE_LOCALE, SUPPORTED_LOCALES } from "./locales";

// Five levels out of src/i18n, through the bundler, so moving the crate is a
// build failure here rather than a test that quietly stops reading anything.
// `?raw` because these are Rust, not modules.
function rust(glob: Record<string, unknown>): string {
  const first = Object.values(glob)[0];
  return typeof first === "string" ? first : "";
}

const RECENTS = rust(
  import.meta.glob("../../../../../crates/remoter-ipc/src/recents.rs", {
    eager: true,
    query: "?raw",
    import: "default",
  }),
);

const COMMANDS = rust(
  import.meta.glob("../../../../../crates/remoter-ipc/src/commands.rs", {
    eager: true,
    query: "?raw",
    import: "default",
  }),
);

const VAULT_CATALOGUES = import.meta.glob("../../../../../locales/*/vault.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

const CONNECTION_CATALOGUES = import.meta.glob("../../../../../locales/*/connections.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

/** locale -> parsed catalogue, from a glob of one namespace. */
function byLocale(globbed: Record<string, unknown>): Map<string, Record<string, unknown>> {
  return new Map(
    Object.entries(globbed).flatMap(([path, value]) => {
      const locale = /\/locales\/([^/]+)\/[^/]+\.json$/.exec(path)?.[1];
      if (locale === undefined || typeof value !== "object" || value === null) return [];
      return [[locale, value as Record<string, unknown>] as const];
    }),
  );
}

const VAULT = byLocale(VAULT_CATALOGUES);
const CONNECTIONS = byLocale(CONNECTION_CATALOGUES);

/** `picker.unreachable.missing` -> the string at that path, or null. */
function messageAt(catalogue: Record<string, unknown>, key: string): string | null {
  let node: unknown = catalogue;
  for (const segment of key.split(".")) {
    if (typeof node !== "object" || node === null) return null;
    node = (node as Record<string, unknown>)[segment];
  }
  return typeof node === "string" ? node : null;
}

// ------------------------------------------------------- reading the Rust ---

/**
 * Every string literal inside the block that follows `marker`.
 *
 * Braces are walked rather than matched with a regular expression, for the
 * same reason `failures.catalogue.test.ts` walks parentheses: the block is
 * Rust, it nests, and a literal may contain a brace of its own. The marker is
 * an `impl` header whose only body is the `as_str` that names the identifiers,
 * so what comes back is exactly the set of kinds.
 */
function literalsAfter(source: string, marker: string): string[] {
  const at = source.indexOf(marker);
  if (at < 0) return [];
  let index = source.indexOf("{", at);
  if (index < 0) return [];
  index += 1;
  let depth = 1;
  const start = index;
  let inString = false;
  while (index < source.length && depth > 0) {
    const ch = source[index];
    if (inString) {
      if (ch === "\\") {
        index += 2;
        continue;
      }
      if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      depth += 1;
    } else if (ch === "}") {
      depth -= 1;
    }
    index += 1;
  }
  const body = source.slice(start, index - 1);
  return (body.match(/"(?:[^"\\]|\\[\s\S])*"/g) ?? []).map((literal) =>
    literal.slice(1, -1),
  );
}

const UNREACHABLE_KINDS = literalsAfter(RECENTS, "impl UnreachableKind {");
const SUBTITLE_KINDS = literalsAfter(COMMANDS, "impl SubtitleKind {");

/** Every language that ships a catalogue directory, English included. */
const LOCALES = SUPPORTED_LOCALES.map((locale) => locale.code);

describe("the kinds the core can send", () => {
  it("were actually read out of the Rust", () => {
    // A parser that silently matched nothing would make every assertion below
    // vacuous, and this file's whole job is to not be vacuous.
    expect(UNREACHABLE_KINDS).toContain("missing");
    expect(UNREACHABLE_KINDS).toContain("not-a-file");
    expect(SUBTITLE_KINDS).toEqual(["items", "members"]);
  });

  it("are stable identifiers, never words in a language", () => {
    // The same rule error codes follow: dotted or dashed lower-case ASCII,
    // never displayed, never translated. Anything else is not a key this
    // catalogue can hold.
    for (const kind of [...UNREACHABLE_KINDS, ...SUBTITLE_KINDS]) {
      expect(kind, kind).toMatch(/^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    }
  });
});

/** One join: a set of kinds, the catalogue they are keyed in, and the prefix. */
interface Join {
  readonly what: string;
  readonly kinds: readonly string[];
  readonly catalogues: ReadonlyMap<string, Record<string, unknown>>;
  readonly prefix: string;
  /** ICU argument names the sentence must still contain after translation. */
  readonly required: readonly string[];
}

const JOINS: readonly Join[] = [
  {
    what: "why a remembered vault cannot be opened",
    kinds: UNREACHABLE_KINDS,
    catalogues: VAULT,
    prefix: "picker.unreachable.",
    // `detail` is only in one of the three, so it is not required of all.
    required: ["path"],
  },
  {
    what: "a search hit's counted subtitle",
    kinds: SUBTITLE_KINDS,
    catalogues: CONNECTIONS,
    prefix: "palette.subtitle.",
    required: ["count"],
  },
];

describe.each(JOINS)("$what", (join) => {
  it("has an entry for every kind, in every shipped language", () => {
    // A kind with no entry is a reader staring at English — and on the picker,
    // staring at it before they have unlocked anything.
    expect(join.kinds.length).toBeGreaterThan(0);
    const missing: string[] = [];
    for (const locale of LOCALES) {
      const catalogue = join.catalogues.get(locale);
      if (catalogue === undefined) {
        missing.push(`${locale}: no catalogue at all`);
        continue;
      }
      for (const kind of join.kinds) {
        if (messageAt(catalogue, `${join.prefix}${kind}`) === null) {
          missing.push(`${locale}: no entry for ${join.prefix}${kind}`);
        }
      }
    }
    expect(missing).toEqual([]);
  });

  it("names the values the interface passes it", () => {
    // A translation that drops `{path}` is a sentence about a vault that never
    // says which vault, and a `{count}` dropped from a plural is a sentence
    // with no number in it. Both read as finished work.
    const wrong: string[] = [];
    for (const locale of LOCALES) {
      const catalogue = join.catalogues.get(locale);
      if (catalogue === undefined) continue;
      for (const kind of join.kinds) {
        const message = messageAt(catalogue, `${join.prefix}${kind}`);
        if (message === null) continue;
        for (const argument of join.required) {
          if (!message.includes(`{${argument}`)) {
            wrong.push(`${locale}:${join.prefix}${kind} never uses {${argument}}`);
          }
        }
      }
    }
    expect(wrong).toEqual([]);
  });

  it("parses and formats as ICU MessageFormat", () => {
    const broken: string[] = [];
    for (const locale of LOCALES) {
      const catalogue = join.catalogues.get(locale);
      if (catalogue === undefined) continue;
      for (const kind of join.kinds) {
        const message = messageAt(catalogue, `${join.prefix}${kind}`);
        if (message === null) continue;
        try {
          new IntlMessageFormat(message, locale, undefined, { ignoreTag: true }).format({
            path: "/home/ada/work.rvault",
            detail: "Permission denied (os error 13)",
            provider: "Dropbox",
            count: 2,
          });
        } catch (error) {
          broken.push(`${locale}:${join.prefix}${kind} — ${String(error)}`);
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it("says something, and says nothing invisible", () => {
    // An empty entry is worse than English, and a catalogue with bidi controls
    // baked in cannot be round-tripped by a translator. Isolation belongs at
    // the call site, where the code says why.
    const problems: string[] = [];
    for (const locale of LOCALES) {
      const catalogue = join.catalogues.get(locale);
      if (catalogue === undefined) continue;
      for (const kind of join.kinds) {
        const message = messageAt(catalogue, `${join.prefix}${kind}`);
        if (message === null) continue;
        if (message.trim() === "") problems.push(`${locale}:${join.prefix}${kind} is empty`);
        if (/[\u200E\u200F\u2066-\u2069]/.test(message)) {
          problems.push(`${locale}:${join.prefix}${kind} carries a bidi control`);
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it("describes no kind the core cannot send", () => {
    // A label left behind after Rust dropped a kind is unreachable copy that
    // a translator is still being asked to maintain.
    const english = join.catalogues.get(SOURCE_LOCALE) ?? {};
    let node: unknown = english;
    for (const segment of join.prefix.split(".").filter(Boolean)) {
      if (typeof node !== "object" || node === null) {
        node = {};
        break;
      }
      node = (node as Record<string, unknown>)[segment];
    }
    const present =
      typeof node === "object" && node !== null
        ? Object.keys(node).filter((key) => !key.startsWith("_comment"))
        : [];
    expect([...present].sort()).toEqual([...join.kinds].sort());
  });
});

// --------------------------------------------------- the sync-folder line ---

/**
 * The cloud-sync warning has one value and no kind — there is one sentence,
 * and the provider is a brand name. It still has to exist in every language,
 * and it still has to keep the value.
 */
describe("the cloud-sync warning", () => {
  it("exists in every shipped language and names the provider", () => {
    const problems: string[] = [];
    for (const locale of LOCALES) {
      const catalogue = VAULT.get(locale);
      const message = catalogue === undefined ? null : messageAt(catalogue, "detail.syncWarning");
      if (message === null || message.trim() === "") {
        problems.push(`${locale}: no detail.syncWarning`);
        continue;
      }
      if (!message.includes("{provider}")) {
        problems.push(`${locale}: detail.syncWarning never names the provider`);
      }
    }
    expect(problems).toEqual([]);
  });

  it("is what the core stopped composing", () => {
    // The Rust keeps the English as a fallback, and that is the arrangement
    // being asserted: the sentence is still in `recents.rs`, and it is
    // documented there as not being the copy. If this stops matching, someone
    // has either deleted the fallback or started rendering it again.
    expect(RECENTS).toContain("fn sync_warning_text(");
    expect(RECENTS).toContain("pub(crate) fn sync_provider(");
  });
});
