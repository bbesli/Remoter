/**
 * The other half of the failure guard.
 *
 * `failures.catalogue.test.ts` proves every code the core can emit has a
 * sentence in every language. It cannot prove anyone reads it — and for four
 * screens nobody did. The tree's load failure, its move failure (English
 * message, English diagnostic, and the English action list joined into prose
 * with a separator of its own), its delete failure, the status bar's
 * resolution failure and the shortcut table's save failure all rendered
 * `IpcFailure.message` directly. Every one of them had a complete Turkish
 * entry sitting in `locales/tr/errors.json`, unused.
 *
 * A green catalogue guard beside a screen that ignores the catalogue is worse
 * than no guard: it is a promise, kept by a file nobody renders. So this one
 * reads the screens.
 *
 * # What it looks for, and why by name
 *
 * A failure reaches a component either as a value called something-`Failure`
 * or through a prop declared `: IpcFailure`, and both are visible in the
 * source. Anything else on those objects — `.message`, `.detail`, `.actions` —
 * is the core's English, and a screen that touches it has stepped around the
 * layer. The text that should be rendered comes from `useFailureText`, whose
 * result is not a failure and is not called one.
 *
 * This is a lexical check, not a type-aware one, so it can be fooled by a
 * failure held under a name that says nothing. That is the trade: a rule
 * legible in one screenful, enforced on every `.tsx` in the tree, beats an
 * AST pass nobody maintains. Name the value for what it is and the guard
 * covers it for free — the same bargain `no-literal-jsx-text` makes with copy
 * props.
 */

import { describe, expect, it } from "vitest";

/** Every component in the tree, as text. `?raw` because these are sources. */
const SOURCES = import.meta.glob("../**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

/**
 * `FailureNotice` is the one component allowed to take a failure apart: it is
 * what the other screens render *through*. It reads `useFailureText`'s result
 * rather than the failure itself, so it would pass anyway — the exemption is
 * here to say so rather than to hide anything.
 */
const RENDERER = "/components/FailureNotice.tsx";

/** The three fields of `IpcFailure` that carry the core's English. */
const ENGLISH_FIELDS = "(?:message|detail|actions)";

/** `someFailure.message`, `moveFailure.detail`, and a bare `failure.actions`. */
const BY_NAME = new RegExp(`\\b[\\w$]*[Ff]ailure\\.${ENGLISH_FIELDS}\\b`, "g");

/** `asFailure(error).message` — the same thing without the intermediate name. */
const BY_CALL = new RegExp(`\\basFailure\\([^)]*\\)\\.${ENGLISH_FIELDS}\\b`, "g");

/** Names a file declares as `IpcFailure`, so `error.message` is caught too. */
const DECLARED = /([A-Za-z_$][\w$]*)\s*\??\s*:\s*(?:readonly\s+)?IpcFailure\b/g;

/**
 * Comments and JSDoc, removed before the scan.
 *
 * Every fix in this area explains in prose what the code used to do, and the
 * prose quotes the expression — so a guard that reads comments fails on the
 * comment describing the bug it is enforcing the absence of. The `//` case
 * spares `://` so that a URL in a string keeps its line.
 */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

function offences(raw: string): string[] {
  const source = withoutComments(raw);
  const found = [...(source.match(BY_NAME) ?? []), ...(source.match(BY_CALL) ?? [])];

  for (const [, name] of source.matchAll(DECLARED)) {
    if (name === undefined) continue;
    const reads = new RegExp(`\\b${name}\\.${ENGLISH_FIELDS}\\b`, "g");
    found.push(...(source.match(reads) ?? []));
  }
  return [...new Set(found)];
}

describe("the guard itself", () => {
  it("reads the components", () => {
    // A glob that silently matched nothing would make the assertion below
    // vacuous, which is the failure this whole file exists to prevent.
    expect(Object.keys(SOURCES).length).toBeGreaterThan(30);
  });

  it("recognises a screen that steps around the layer", () => {
    // The exact shapes that shipped, so a future edit to the patterns cannot
    // quietly stop matching them.
    expect(offences("<span>{moveFailure.message}</span>")).toEqual(["moveFailure.message"]);
    expect(offences("{failure.actions.join(SEP)}")).toEqual(["failure.actions"]);
    expect(offences("t('x', { reason: asFailure(error).message })")).toEqual([
      "asFailure(error).message",
    ]);
    expect(offences("interface P { error?: IpcFailure | null }\n<b title={error.message} />")).toEqual(
      ["error.message"],
    );
  });

  it("passes a screen that goes through the layer", () => {
    expect(offences("const text = useFailureText(failure);\n<p>{text.message}</p>")).toEqual([]);
    expect(offences("<FailureNotice failure={moveFailure} title={t('move.failed')} />")).toEqual([]);
  });
});

describe("every screen", () => {
  it("renders a failure through the localisation layer, never the core's English", () => {
    const strays: string[] = [];
    for (const [path, source] of Object.entries(SOURCES)) {
      if (path.endsWith(RENDERER)) continue;
      // A test asserting on the core's English is asserting the fallback, not
      // breaking it.
      if (path.endsWith(".test.tsx")) continue;
      for (const offence of offences(source)) {
        strays.push(`${path}: ${offence}`);
      }
    }
    // `detail` is exempt from *translation*, not from the layer: it reaches the
    // screen through `useFailureText` like everything else, which is what lets
    // a catalogue override one when the core's is unreadable.
    expect(strays).toEqual([]);
  });
});
