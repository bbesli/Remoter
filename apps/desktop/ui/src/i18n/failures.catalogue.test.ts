/**
 * The error catalogue, checked against the Rust it describes.
 *
 * `locales/<lang>/errors.json` is keyed by `IpcError.code`, and nothing in the
 * type system connects the two: a code added, renamed or given another action
 * in Rust leaves the catalogue silently short, and the symptom is a single
 * sentence appearing in English inside an otherwise translated window — in a
 * language nobody on the team reads, on a screen nobody hits on purpose.
 *
 * So this test reads the Rust. It is the only thing standing between "every
 * failure is translated" and "every failure was translated in September".
 *
 * **It reads the whole crate, and that is the point.** The previous version
 * globbed `error.rs` alone. `IpcError::new` is `pub` and is called from ten
 * other files in the same crate — session.rs, sftp.rs, tunnel.rs, commands.rs,
 * state.rs, bridge.rs, vault_admin.rs, import.rs, recents.rs, audit.rs — so
 * ninety-one of the hundred and ninety codes were structurally invisible to
 * it, including the entire connection-failure taxonomy. The guard reported
 * all-clear over a catalogue that was half empty, which is worse than no guard
 * at all: it is a green tick on the screen a user meets when their password is
 * rejected or a host key has changed.
 *
 * Three shapes of code have to be found, because the crate builds them three
 * ways:
 *
 * 1. `IpcError::new("code", …)` with a literal, anywhere in the crate, its
 *    actions read from the `.with_actions([…])` in the same builder chain;
 * 2. the session taxonomy, where session.rs composes `session.<suffix>` from a
 *    `ProtocolError` and takes the actions from `ProtocolError::next_actions`
 *    in `remoter-proto`, turned into English by `action_text`;
 * 3. `SessionFailureDto { code: String::from("…"), … }`, whose action list is
 *    assembled at the moment of failure and can be any of `action_text`.
 */

import { describe, expect, it } from "vitest";
import { IntlMessageFormat } from "intl-messageformat";

import { SHARED_ACTIONS } from "./failures";
import { SOURCE_LOCALE } from "./locales";

// Five levels out of src/i18n, the same climb the catalogue loader makes, and
// through the same mechanism: the bundler resolves the path, so moving a crate
// is a build failure here rather than a test that quietly stops reading
// anything. `?raw` because these are Rust, not modules.
const IPC_SOURCE = import.meta.glob("../../../../../crates/remoter-ipc/src/*.rs", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const PROTO_SOURCE = import.meta.glob("../../../../../crates/remoter-proto/src/error.rs", {
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

/**
 * A catalogue entry.
 *
 * `message` is nullable because a few entries deliberately have none: the core
 * composes their sentence at the moment of failure and there is nothing to
 * generalise. Those must say so in a `_comment_`, which is asserted below.
 */
interface Entry {
  message: string | null;
  actions: string[];
  explained: boolean;
}

/** `vault.locked` -> the entry at `{ vault: { locked: … } }`, or null. */
function entryFor(catalogue: Record<string, unknown>, code: string): Entry | null {
  let node: unknown = catalogue;
  for (const segment of code.split(".")) {
    if (typeof node !== "object" || node === null) return null;
    node = (node as Record<string, unknown>)[segment];
  }
  if (typeof node !== "object" || node === null || Array.isArray(node)) return null;
  const record = node as Record<string, unknown>;
  const { message, actions } = record;
  return {
    message: typeof message === "string" ? message : null,
    actions: Array.isArray(actions) ? actions.filter((a): a is string => typeof a === "string") : [],
    explained: Object.keys(record).some((key) => key.startsWith("_comment")),
  };
}

// ------------------------------------------------------- reading the Rust ---

/**
 * The same source with every comment blanked out, lengths preserved.
 *
 * Everything below walks delimiters and counts string literals, and a `//` line
 * containing an unbalanced quote or bracket — this crate has several — would
 * otherwise throw the walk off by an arbitrary amount. Character literals are
 * recognised so that `'"'` in audit.rs cannot open a string; a `'` that is not
 * a complete char literal is a lifetime and is left alone.
 */
function stripComments(rust: string): string {
  const out: string[] = [];
  let index = 0;
  while (index < rust.length) {
    const rest = rust.slice(index);
    if (rest.startsWith("//")) {
      const end = rust.indexOf("\n", index);
      const stop = end < 0 ? rust.length : end;
      out.push(" ".repeat(stop - index));
      index = stop;
      continue;
    }
    if (rest.startsWith("/*")) {
      const end = rust.indexOf("*/", index + 2);
      const stop = end < 0 ? rust.length : end + 2;
      out.push(rust.slice(index, stop).replace(/[^\n]/g, " "));
      index = stop;
      continue;
    }
    if (rust[index] === '"') {
      const literal = /^"(?:[^"\\]|\\[\s\S])*"/.exec(rest);
      const text = literal?.[0] ?? rest;
      out.push(text);
      index += text.length;
      continue;
    }
    const char = /^'(?:\\[\s\S]|[^'\\])'/.exec(rest);
    if (char !== null) {
      out.push(" ".repeat(char[0].length));
      index += char[0].length;
      continue;
    }
    out.push(rust[index] ?? "");
    index += 1;
  }
  return out.join("");
}

/** From just inside an opening delimiter to just past its match. */
function pastMatch(rust: string, from: number): number {
  let depth = 1;
  let index = from;
  let inString = false;
  while (index < rust.length && depth > 0) {
    const char = rust[index];
    if (inString) {
      if (char === "\\") {
        index += 2;
        continue;
      }
      if (char === '"') inString = false;
    } else if (char === '"') {
      inString = true;
    } else if (char === "(" || char === "[" || char === "{") {
      depth += 1;
    } else if (char === ")" || char === "]" || char === "}") {
      depth -= 1;
    }
    index += 1;
  }
  return index;
}

/** The string literals in a span, with Rust's escapes resolved. */
function literals(span: string): string[] {
  return (span.match(/"(?:[^"\\]|\\[\s\S])*"/g) ?? []).map((raw) =>
    raw
      .slice(1, -1)
      // A `\` at end of line continues the literal and eats the indentation.
      .replace(/\\\n\s*/g, "")
      .replace(/\\n/g, "\n")
      .replace(/\\t/g, "\t")
      .replace(/\\"/g, '"')
      .replace(/\\\\/g, "\\"),
  );
}

/**
 * The source with its `#[cfg(test)] mod … { … }` blocks removed.
 *
 * Fixtures construct failures with codes of their own, and a test module is not
 * a code the application can emit. Only whole modules are cut: `#[cfg(test)]`
 * also sits on individual helpers here, and those contain no codes.
 */
function withoutTestModules(rust: string): string {
  let out = rust;
  for (let at = out.indexOf("#[cfg(test)]"); at >= 0; at = out.indexOf("#[cfg(test)]", at + 1)) {
    const header = /^[\s\S]{0,400}?\bmod\s+\w+\s*\{/.exec(out.slice(at));
    if (header === null || /\bfn\b|\bconst\b|\bstruct\b|\bimpl\b|;/.test(header[0])) continue;
    out = out.slice(0, at) + out.slice(pastMatch(out, at + header[0].length));
    at = -1;
  }
  return out;
}

/** Codes are dotted lower-case ASCII by construction. */
const CODE = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

/**
 * What the catalogue has to cover for one code.
 *
 * `arms` is one entry per place the crate builds this code, holding the English
 * actions that arm offers. Two arms can disagree — the same code is raised from
 * a command and from the protocol taxonomy, with differently worded buttons —
 * and that is exactly when a positional label is wrong for one of them.
 */
interface Failure {
  arms: string[][];
  /** The action list is assembled at the moment of failure, not written here. */
  composed: boolean;
}

const TAXONOMY = new Map<string, Failure>();

function record(code: string, actions: string[] | null, composed = false): void {
  const found = TAXONOMY.get(code) ?? { arms: [], composed: false };
  if (actions !== null) found.arms.push(actions);
  found.composed = found.composed || composed;
  TAXONOMY.set(code, found);
}

/** Every file in the crate that ships. */
const IPC_FILES: [string, string][] = Object.entries(IPC_SOURCE)
  .map(([path, rust]): [string, string] => [
    /\/([^/]+)\.rs$/.exec(path)?.[1] ?? path,
    withoutTestModules(stripComments(rust)),
  ])
  // Compiled only under `cfg(test)` / the integration-tests feature, per lib.rs.
  .filter(([name]) => name !== "live_tests" && name !== "test_support");

const BY_FILE = new Map(IPC_FILES);

// --- 1 · every `IpcError::new("code", …)` in the crate ---------------------

for (const [, rust] of IPC_FILES) {
  for (const match of rust.matchAll(/(?:IpcError|Self)::new\(\s*"((?:[^"\\]|\\.)*)"\s*,/g)) {
    const code = match[1] ?? "";
    // `Self::new` belongs to other types too; a first argument that is not a
    // code is not one of ours.
    if (!CODE.test(code)) continue;
    let index = pastMatch(rust, (match.index ?? 0) + match[0].length);
    let actions: string[] = [];
    for (;;) {
      const chained = /^\s*\.(with_detail|with_actions)\(/.exec(rust.slice(index));
      if (chained === null) break;
      const opened = index + chained[0].length;
      const closed = pastMatch(rust, opened);
      if (chained[1] === "with_actions") actions = literals(rust.slice(opened, closed - 1));
      index = closed;
    }
    record(code, actions);
  }
}

// --- 2 · the session taxonomy ----------------------------------------------

const SESSION_RS = BY_FILE.get("session") ?? "";
const PROTO_RS = stripComments(Object.values(PROTO_SOURCE)[0] ?? "");

/** The body of a named function, from its signature to its closing brace. */
function bodyOf(rust: string, signature: string): string {
  const at = rust.indexOf(signature);
  if (at < 0) return "";
  const opened = rust.indexOf("{", at) + 1;
  return rust.slice(opened, pastMatch(rust, opened) - 1);
}

/** `NextAction::Retry` -> "Try again". The one place the core words an action. */
const ACTION_TEXT = new Map<string, string>(
  [
    ...bodyOf(SESSION_RS, "fn action_text(").matchAll(
      /NextAction::(\w+)\s*=>\s*(?:\{\s*)?((?:"(?:[^"\\]|\\[\s\S])*"\s*)+)/g,
    ),
  ].map((match) => [match[1] ?? "", literals(match[2] ?? "").join("")]),
);

/** `ProtocolError` variant -> the actions it offers, in order. */
const VARIANT_ACTIONS = new Map<string, string[]>();
for (const arm of bodyOf(PROTO_RS, "pub fn next_actions(").matchAll(
  /((?:Self::\w+(?:\s*\{[^{}]*\})?\s*\|\s*)*Self::\w+(?:\s*\{[^{}]*\})?)\s*=>\s*\{?\s*&\[([^\]]*)\]/g,
)) {
  const actions = [...(arm[2] ?? "").matchAll(/A::(\w+)/g)].map(
    (name) => ACTION_TEXT.get(name[1] ?? "") ?? `«${name[1]}»`,
  );
  for (const variant of (arm[1] ?? "").matchAll(/Self::(\w+)/g)) {
    VARIANT_ACTIONS.set(variant[1] ?? "", actions);
  }
}

/** `E::DnsFailure { … } => (code("dns"), …)` — the failure taxonomy proper. */
const SESSION_VARIANTS = new Map<string, string>();
for (const arm of bodyOf(SESSION_RS, "fn message_for(").matchAll(
  /\bE::(\w+)\s*(?:\{[^{}]*\})?\s*=>\s*\(\s*code\("([a-z0-9-]+)"\)/g,
)) {
  SESSION_VARIANTS.set(arm[1] ?? "", `session.${arm[2] ?? ""}`);
  record(`session.${arm[2] ?? ""}`, VARIANT_ACTIONS.get(arm[1] ?? "") ?? null);
}

// --- 3 · the wrappers whose actions are assembled at the failure ------------

for (const [, rust] of IPC_FILES) {
  for (const match of rust.matchAll(/\bcode:\s*String::from\("([a-z0-9.-]+)"\)/g)) {
    const code = match[1] ?? "";
    if (CODE.test(code)) record(code, null, true);
  }
}

/** Every English action sentence the core can send, from anywhere. */
const EVERY_ACTION = new Set<string>([
  ...ACTION_TEXT.values(),
  ...[...TAXONOMY.values()].flatMap((failure) => failure.arms.flat()),
]);

describe("the Rust failure taxonomy", () => {
  it("was actually read", () => {
    // A parser that silently matched nothing would make every assertion below
    // vacuous, and this file's whole job is to not be vacuous.
    expect(TAXONOMY.size).toBeGreaterThan(185);
    expect(ACTION_TEXT.size).toBeGreaterThan(15);
    expect(VARIANT_ACTIONS.size).toBeGreaterThan(35);
    expect(SESSION_VARIANTS.size).toBeGreaterThan(35);
  });

  it("was read from every file that raises a failure, not just error.rs", () => {
    // The defect this file exists to prevent from recurring. Each of these is
    // raised in a different file of the crate; if the glob narrows again, or a
    // file stops being read, one of them disappears.
    for (const code of [
      "vault.unlock-failed", // error.rs
      "session.host-key-changed", // session.rs
      "session.credential-external", // bridge.rs
      "sftp.subsystem-unavailable", // sftp.rs
      "tunnel.bind-exposed", // tunnel.rs
      "update.rate-limited", // commands.rs
      "vault.unlock-throttled", // state.rs
      "slot.label-empty", // vault_admin.rs
      "import.unknown-format", // import.rs
      "recents.encode", // recents.rs
      "audit.export-encode", // audit.rs
      "session.failed", // the close-event wrapper
      "sftp.transfer-failed", // the transfer wrapper
    ]) {
      expect(TAXONOMY.has(code), code).toBe(true);
    }
  });

  it("reads each arm's actions, not just how many", () => {
    expect(TAXONOMY.get("vault.unlock-failed")?.arms).toEqual([
      [
        "Try again",
        "Check the key file, if this vault uses one",
        "Use your recovery key",
      ],
    ]);
    expect(TAXONOMY.get("session.host-key-changed")?.arms).toContainEqual([
      "Verify the fingerprint with the server's administrator before doing anything else",
      "Contact the server's administrator",
    ]);
  });

  it("uses no reserved prefix as a code", () => {
    // `action.*` is the shared lexicon, not a failure. A code that collided
    // with it would read another entry's button labels as its sentence.
    expect([...TAXONOMY.keys()].filter((code) => code.startsWith("action."))).toEqual([]);
  });
});

describe("the shared action lexicon", () => {
  const slugs = [...SHARED_ACTIONS.values()];

  it("matches what the core actually writes", () => {
    // `failures.ts` joins on the English sentence, so a reworded action in Rust
    // silently stops being translated. This is what makes that a red build.
    const unknown = [...SHARED_ACTIONS.keys()].filter((sentence) => !EVERY_ACTION.has(sentence));
    expect(unknown).toEqual([]);
  });

  it("covers every sentence `action_text` can produce", () => {
    const missing = [...ACTION_TEXT.values()].filter((sentence) => !SHARED_ACTIONS.has(sentence));
    expect(missing).toEqual([]);
  });

  it("covers every action a session failure can offer, whichever failure it came from", () => {
    // `session.hop-failed` hands over the *inner* failure's actions when a hop
    // failed on the far end's identity, and `session.failed` carries whatever
    // the failure underneath it offered. Neither can be labelled by position,
    // so the lexicon has to know every sentence any session failure can send —
    // otherwise "verify the fingerprint with the server's administrator" is the
    // button that stays in English, or worse, wears another action's label.
    const uncovered = new Set<string>();
    for (const [code, failure] of TAXONOMY) {
      if (!code.startsWith("session.")) continue;
      for (const sentence of failure.arms.flat()) {
        if (!SHARED_ACTIONS.has(sentence)) uncovered.add(`${code}: ${sentence}`);
      }
    }
    expect([...uncovered]).toEqual([]);
  });

  it("gives every key its own slug", () => {
    expect(new Set(slugs).size).toBe(slugs.length);
  });

  it("is translated in every language", () => {
    const missing: string[] = [];
    for (const [locale, catalogue] of BY_LOCALE) {
      const lexicon = catalogue.action;
      if (typeof lexicon !== "object" || lexicon === null) {
        missing.push(`${locale}: no action lexicon at all`);
        continue;
      }
      const entries = lexicon as Record<string, unknown>;
      for (const slug of slugs) {
        const text = entries[slug];
        if (typeof text !== "string" || text.trim() === "") missing.push(`${locale}: action.${slug}`);
      }
      for (const key of Object.keys(entries)) {
        // A slug nothing joins on is a string translators keep maintaining for
        // an action that no longer exists.
        if (!key.startsWith("_comment") && !slugs.includes(key)) {
          missing.push(`${locale}: action.${key} matches no action the core sends`);
        }
      }
    }
    expect(missing).toEqual([]);
  });
});

describe("the English error catalogue", () => {
  const english = BY_LOCALE.get(SOURCE_LOCALE) ?? {};

  it("exists", () => {
    expect(BY_LOCALE.get(SOURCE_LOCALE)).toBeDefined();
  });

  it("has an entry for every code the core can send", () => {
    // A code with no entry is a reader staring at English.
    const missing = [...TAXONOMY.keys()].filter((code) => entryFor(english, code) === null);
    expect(missing).toEqual([]);
  });

  it("explains any entry that deliberately has no sentence", () => {
    // An entry with no `message` keeps the core's own sentence, which is right
    // when the core composed it at the moment of failure and there is nothing
    // to generalise — and a mistake the rest of the time. The difference has to
    // be written down where the next person will look.
    const silent = [...TAXONOMY.keys()].filter((code) => {
      const entry = entryFor(english, code);
      return entry !== null && entry.message === null && !entry.explained;
    });
    expect(silent).toEqual([]);
  });

  it("labels no action the core does not offer", () => {
    // Actions are positional. A catalogue with more labels than the core sends
    // means one of them is unreachable — usually because Rust dropped an action
    // and nobody dropped the label.
    const wrong: string[] = [];
    for (const [code, failure] of TAXONOMY) {
      const entry = entryFor(english, code);
      if (entry === null) continue;
      const most = Math.max(0, ...failure.arms.map((arm) => arm.length));
      if (failure.composed && entry.actions.length > 0) {
        wrong.push(`${code}: labels ${entry.actions.length} actions, but its list is composed`);
      } else if (entry.actions.length > most) {
        wrong.push(`${code}: core offers ${most}, catalogue labels ${entry.actions.length}`);
      }
    }
    expect(wrong).toEqual([]);
  });

  it("labels a position only where every arm means the same thing there", () => {
    // Some codes are raised twice — once by a command, once by the protocol
    // taxonomy — with different sentences in the same slot. Labelling position
    // 1 "Open the credential's settings" when the other arm sent "Open this
    // connection's settings" puts the wrong name on a button, so those
    // positions must be left to the lexicon instead.
    const conflicting: string[] = [];
    for (const [code, failure] of TAXONOMY) {
      const entry = entryFor(english, code);
      if (entry === null) continue;
      entry.actions.forEach((_, index) => {
        const sentences = new Set(
          failure.arms.map((arm) => arm[index]).filter((one): one is string => one !== undefined),
        );
        if (sentences.size > 1) {
          conflicting.push(`${code}[${index}]: arms disagree — ${[...sentences].join(" / ")}`);
        }
      });
    }
    expect(conflicting).toEqual([]);
  });

  it("leaves no action untranslatable", () => {
    // The completeness rule, stated once: for every action the core can send,
    // either this entry labels that position or the lexicon knows the sentence.
    // Anything else reaches the reader in English.
    const orphans: string[] = [];
    for (const [code, failure] of TAXONOMY) {
      const entry = entryFor(english, code);
      if (entry === null) continue;
      const sentences = failure.composed ? [[...ACTION_TEXT.values()]] : failure.arms;
      for (const arm of sentences) {
        arm.forEach((sentence, index) => {
          if (entry.actions[index] !== undefined) return;
          if (!SHARED_ACTIONS.has(sentence)) orphans.push(`${code}[${index}]: ${sentence}`);
        });
      }
    }
    expect(orphans).toEqual([]);
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
        if (here[0] === "action") continue;
        if ("message" in value || "_comment_" in value) {
          const code = here.join(".");
          if (code !== "unknown" && !TAXONOMY.has(code)) strays.push(code);
        } else {
          walk(value as Record<string, unknown>, here);
        }
      }
    };
    walk(english, []);
    expect(strays).toEqual([]);
  });
});

describe("every translated error catalogue", () => {
  const translated = [...BY_LOCALE.entries()].filter(([locale]) => locale !== SOURCE_LOCALE);
  const english = BY_LOCALE.get(SOURCE_LOCALE) ?? {};

  it("is one of the shipped languages", () => {
    expect(translated.length).toBeGreaterThan(0);
  });

  it("covers every code, with the same labels English has", () => {
    // A translation that is short by one label shows that one action in
    // English; a translation short by a code shows the whole failure in
    // English. Both are invisible from an English machine.
    const problems: string[] = [];
    for (const [locale, catalogue] of translated) {
      for (const code of TAXONOMY.keys()) {
        const source = entryFor(english, code);
        const entry = entryFor(catalogue, code);
        if (entry === null) {
          problems.push(`${locale}: no entry for ${code}`);
          continue;
        }
        if (source === null) continue;
        if ((source.message === null) !== (entry.message === null)) {
          // Either both keep the core's sentence or neither does: a language
          // that generalises one the others leave alone loses what happened.
          problems.push(`${locale}: ${code} disagrees with English about having a message`);
        }
        if (entry.actions.length !== source.actions.length) {
          problems.push(
            `${locale}: ${code} labels ${entry.actions.length} of ${source.actions.length} actions`,
          );
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
        if (entry.message !== null && entry.message.trim() === "") empty.push(`${locale}:${code}`);
        entry.actions.forEach((action, index) => {
          if (action.trim() === "") empty.push(`${locale}:${code}.actions.${index}`);
        });
      }
    }
    expect(empty).toEqual([]);
  });
});

describe("every error message, in every language", () => {
  /** Every string a reader can be shown from this catalogue. */
  function shown(locale: string, catalogue: Record<string, unknown>): [string, string][] {
    const out: [string, string][] = [];
    for (const code of [...TAXONOMY.keys(), "unknown"]) {
      const entry = entryFor(catalogue, code);
      if (entry === null) continue;
      if (entry.message !== null) out.push([`${locale}:${code}.message`, entry.message]);
      entry.actions.forEach((action, index) =>
        out.push([`${locale}:${code}.actions.${index}`, action]),
      );
    }
    const lexicon = catalogue.action;
    if (typeof lexicon === "object" && lexicon !== null) {
      for (const [slug, text] of Object.entries(lexicon as Record<string, unknown>)) {
        if (typeof text === "string" && !slug.startsWith("_comment")) {
          out.push([`${locale}:action.${slug}`, text]);
        }
      }
    }
    return out;
  }

  it("parses and formats as ICU MessageFormat", () => {
    // These are not parsed anywhere else: `catalogues.test.ts` walks objects
    // and stops at arrays, and every action label is an array element.
    const broken: string[] = [];
    for (const [locale, catalogue] of BY_LOCALE) {
      for (const [where, text] of shown(locale, catalogue)) {
        try {
          new IntlMessageFormat(text, locale, undefined, { ignoreTag: true }).format({});
        } catch (error) {
          broken.push(`${where} — ${String(error)}`);
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
      for (const [where, text] of shown(locale, catalogue)) {
        if (/[\u200E\u200F\u2066-\u2069]/.test(text)) marked.push(where);
      }
    }
    expect(marked).toEqual([]);
  });
});
