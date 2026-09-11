/**
 * The error catalogue, checked against the Rust it describes.
 *
 * `locales/<lang>/errors.json` is keyed by `IpcError.code`, and the codes live in
 * `crates/remoter-ipc/src/error.rs`. Nothing in the type system connects the
 * two: a code added, renamed or given another action in Rust leaves the
 * catalogue silently short, and the symptom is a single sentence appearing in
 * English inside an otherwise translated window — in a language nobody on the
 * team reads, on a screen nobody hits on purpose.
 *
 * So this test reads the Rust. It is the only thing standing between "every
 * failure is translated" and "every failure was translated in September".
 */

import { describe, expect, it } from "vitest";
import { IntlMessageFormat } from "intl-messageformat";

import { SOURCE_LOCALE } from "./locales";

// Five levels out of src/i18n, the same climb the catalogue loader makes, and
// through the same mechanism: the bundler resolves the path, so moving the
// crate is a build failure here rather than a test that quietly stops reading
// anything. `?raw` because this one is Rust, not a module.
const RUST_SOURCE = import.meta.glob("../../../../../crates/remoter-ipc/src/error.rs", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const CATALOGUES = import.meta.glob("../../../../../locales/*/errors.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

/** locale -> parsed catalogue. */
const BY_LOCALE = new Map<string, Record<string, unknown>>(
  Object.entries(CATALOGUES).flatMap(([path, value]) => {
    const locale = /\/locales\/([^/]+)\/errors\.json$/.exec(path)?.[1];
    if (locale === undefined || typeof value !== "object" || value === null) return [];
    return [[locale, value as Record<string, unknown>]];
  }),
);

interface Entry {
  message: string;
  actions: string[];
}

/** `vault.locked` -> the entry at `{ vault: { locked: … } }`, or null. */
function entryFor(catalogue: Record<string, unknown>, code: string): Entry | null {
  let node: unknown = catalogue;
  for (const segment of code.split(".")) {
    if (typeof node !== "object" || node === null) return null;
    node = (node as Record<string, unknown>)[segment];
  }
  if (typeof node !== "object" || node === null) return null;
  const { message, actions } = node as { message?: unknown; actions?: unknown };
  if (typeof message !== "string") return null;
  return {
    message,
    actions: Array.isArray(actions) ? actions.filter((a): a is string => typeof a === "string") : [],
  };
}

// ------------------------------------------------------- reading the Rust ---

const RUST = Object.values(RUST_SOURCE)[0] ?? "";

/**
 * The string literals inside one `.with_actions(…)` call.
 *
 * Counted by walking the parentheses rather than by a regular expression: the
 * list is sometimes `([…])` on one line and sometimes `(\n  […],\n)` over six,
 * and a literal itself may run across lines with Rust's `\` continuation.
 */
function actionCount(chunk: string): number {
  const open = chunk.indexOf(".with_actions(");
  if (open < 0) return 0;
  let depth = 1;
  let index = open + ".with_actions(".length;
  const start = index;
  let inString = false;
  while (index < chunk.length && depth > 0) {
    const ch = chunk[index];
    if (inString) {
      if (ch === "\\") {
        index += 2;
        continue;
      }
      if (ch === '"') inString = false;
    } else if (ch === '"') {
      inString = true;
    } else if (ch === "(" || ch === "[" || ch === "{") {
      depth += 1;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      depth -= 1;
    }
    index += 1;
  }
  const body = chunk.slice(start, index - 1);
  return (body.match(/"(?:[^"\\]|\\[\s\S])*"/g) ?? []).length;
}

/** Every code `error.rs` can emit, with how many actions it offers. */
function taxonomy(): Map<string, number> {
  const out = new Map<string, number>();
  const chunks = RUST.split("Self::new(").slice(1);
  for (const chunk of chunks) {
    const code = /^\s*"([a-z0-9.-]+)"/.exec(chunk)?.[1];
    if (code === undefined) continue;
    const count = actionCount(chunk);
    // Two codes are raised from two arms (a hardware key refused at unlock and
    // refused as a slot; an item missing from the vault and from the tree).
    // Both arms offer the same number of actions, and the assertion below is
    // what keeps that true.
    const seen = out.get(code);
    expect(seen === undefined || seen === count, `${code} offers a different number of actions in two arms`).toBe(
      true,
    );
    out.set(code, count);
  }
  return out;
}

const TAXONOMY = taxonomy();

describe("the Rust failure taxonomy", () => {
  it("was actually read", () => {
    // A parser that silently matched nothing would make every assertion below
    // vacuous, and this file's whole job is to not be vacuous.
    expect(TAXONOMY.size).toBeGreaterThan(90);
    expect(TAXONOMY.get("vault.unlock-failed")).toBe(3);
    expect(TAXONOMY.get("validation.name-empty")).toBe(1);
  });
});

describe("the English error catalogue", () => {
  const english = BY_LOCALE.get(SOURCE_LOCALE);

  it("exists", () => {
    expect(english).toBeDefined();
  });

  it("has an entry for every code the core can send", () => {
    // A code with no entry is a reader staring at English.
    const missing = [...TAXONOMY.keys()].filter((code) => entryFor(english ?? {}, code) === null);
    expect(missing).toEqual([]);
  });

  it("labels exactly the actions the core offers, no more", () => {
    // Actions are positional. A catalogue with more labels than the core sends
    // means one of them is unreachable — usually because Rust dropped an action
    // and nobody dropped the label.
    const wrong: string[] = [];
    for (const [code, count] of TAXONOMY) {
      const entry = entryFor(english ?? {}, code);
      if (entry !== null && entry.actions.length !== count) {
        wrong.push(`${code}: core offers ${count}, catalogue labels ${entry.actions.length}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it("describes no code the core cannot send", () => {
    // Except `unknown`, which the interface raises itself when a rejection
    // arrives with no shape at all. See `asFailure` in src/lib/ipc.ts.
    const strays: string[] = [];
    const walk = (node: Record<string, unknown>, path: string[]) => {
      for (const [key, value] of Object.entries(node)) {
        if (key.startsWith("_comment")) continue;
        if (typeof value !== "object" || value === null) continue;
        const here = [...path, key];
        if ("message" in value) {
          const code = here.join(".");
          if (code !== "unknown" && !TAXONOMY.has(code)) strays.push(code);
        } else {
          walk(value as Record<string, unknown>, here);
        }
      }
    };
    walk(english ?? {}, []);
    expect(strays).toEqual([]);
  });
});

describe("every translated error catalogue", () => {
  const translated = [...BY_LOCALE.entries()].filter(([locale]) => locale !== SOURCE_LOCALE);

  it("is one of the shipped languages", () => {
    expect(translated.length).toBeGreaterThan(0);
  });

  it("covers every code, with the same number of action labels", () => {
    // A translation that is short by one label shows that one action in
    // English; a translation short by a code shows the whole failure in
    // English. Both are invisible from an English machine.
    const problems: string[] = [];
    for (const [locale, catalogue] of translated) {
      for (const [code, count] of TAXONOMY) {
        const entry = entryFor(catalogue, code);
        if (entry === null) {
          problems.push(`${locale}: no entry for ${code}`);
          continue;
        }
        if (entry.actions.length !== count) {
          problems.push(`${locale}: ${code} labels ${entry.actions.length} of ${count} actions`);
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it("says something in every entry", () => {
    const empty: string[] = [];
    for (const [locale, catalogue] of translated) {
      for (const code of TAXONOMY.keys()) {
        const entry = entryFor(catalogue, code);
        if (entry === null) continue;
        if (entry.message.trim() === "") empty.push(`${locale}:${code}.message`);
        entry.actions.forEach((action, index) => {
          if (action.trim() === "") empty.push(`${locale}:${code}.actions.${index}`);
        });
      }
    }
    expect(empty).toEqual([]);
  });
});

describe("every error message, in every language", () => {
  it("parses and formats as ICU MessageFormat", () => {
    // These are not parsed anywhere else: `catalogues.test.ts` walks objects
    // and stops at arrays, and every action label is an array element.
    const broken: string[] = [];
    for (const [locale, catalogue] of BY_LOCALE) {
      for (const code of [...TAXONOMY.keys(), "unknown"]) {
        const entry = entryFor(catalogue, code);
        if (entry === null) continue;
        for (const [index, text] of [entry.message, ...entry.actions].entries()) {
          try {
            new IntlMessageFormat(text, locale, undefined, { ignoreTag: true }).format({});
          } catch (error) {
            broken.push(`${locale}:${code}[${index}] — ${String(error)}`);
          }
        }
      }
    }
    expect(broken).toEqual([]);
  });

  it("carries no bidi control characters", () => {
    // Isolation is applied at the call site, where the code says why. A
    // catalogue with invisible characters baked in cannot be round-tripped by a
    // translator, and Arabic is exactly where someone is tempted to add them.
    const marked: string[] = [];
    for (const [locale, catalogue] of BY_LOCALE) {
      for (const code of TAXONOMY.keys()) {
        const entry = entryFor(catalogue, code);
        if (entry === null) continue;
        for (const text of [entry.message, ...entry.actions]) {
          if (/[\u200E\u200F\u2066-\u2069]/.test(text)) marked.push(`${locale}:${code}`);
        }
      }
    }
    expect(marked).toEqual([]);
  });
});
