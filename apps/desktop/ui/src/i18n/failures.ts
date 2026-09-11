/**
 * The core's failures, in the reader's language.
 *
 * Every command answers with an `IpcError`: a stable `code`, a sentence naming
 * what failed and where, an optional diagnostic, and the next actions in the
 * order to offer them (`crates/remoter-ipc/src/error.rs`). All of that text is
 * written in English, in Rust, and it must stay there — the core is not the
 * presentation layer (CLAUDE.md §6), and a Turkish reader met a fully
 * translated interface in which every failure, every diagnostic and every
 * suggestion was still English. That is the moment a user most needs their own
 * language.
 *
 * **The code is the join.** `locales/<lang>/errors.json` is keyed by it, and
 * this module is the lookup:
 *
 * - a code the catalogue knows renders the catalogue's sentence and labels;
 * - a code it does not know renders what the core sent, untouched. A failure
 *   added in Rust therefore shows up in English rather than as a blank line or
 *   a raw `vault.kdf-params-refused`, and stays useful until someone translates
 *   it;
 * - `detail` is a machine diagnostic — an OS error string, a node id, a Rust
 *   `Display` — and passes through unless the catalogue deliberately overrides
 *   it. It is what a reader copies into a bug report, and a translated one is
 *   useless to whoever reads that report.
 *
 * Two decisions in here are worth the paragraph each:
 *
 * **English is served from the core, not from the catalogue.** The core's
 * sentence is the catalogue's entry with its specifics substituted in — "after
 * 15 minutes", "byte 4,192", the actual path. Those cannot be recovered from
 * the finished string, so the English catalogue entry is necessarily the same
 * sentence with the specifics generalised away. Rendering it to an English
 * reader would take detail away from the one reader who does not need the
 * translation at all. So English gets the core's own text, and the English
 * catalogue is what every other language is translated from.
 *
 * **The core's text never goes through `t()`.** i18next-icu parses whatever it
 * returns as an ICU message, and the core's sentences contain values the user
 * or a remote host chose: a hostname, a tag, a path. One `{` in a file name
 * would turn a perfectly good sentence into a parse error and put the
 * missing-key fallback on screen. So the lookup asks whether the key exists
 * first, and reaches for the core's string only outside `t()`.
 */

import { useTranslation } from "react-i18next";

import { SOURCE_LOCALE } from "./locales";

/**
 * The part of `IpcFailure` this needs, described structurally so the
 * localisation layer does not depend on the IPC layer. `IpcFailure` from
 * `@/lib/ipc` satisfies it.
 */
export interface CoreFailure {
  readonly code: string;
  readonly message: string;
  readonly detail: string | null;
  readonly actions: readonly string[];
}

/** What the interface should actually render. */
export interface FailureText {
  readonly message: string;
  readonly detail: string | null;
  /** In the order the core offered them; the catalogue may only relabel. */
  readonly actions: readonly string[];
}

/**
 * The catalogue, as this lookup needs to see it.
 *
 * An interface rather than the i18next instance so the resolution rules can be
 * tested against a catalogue written in the test, without a language, a
 * network or a React tree.
 */
export interface FailureCatalogue {
  /** The BCP 47 tag in force. */
  readonly language: string;
  /** Whether a key resolves — in this language, or in the English fallback. */
  has(key: string): boolean;
  /** The text for a key `has` has answered true for. */
  read(key: string): string;
}

/**
 * Codes are dotted lower-case ASCII by construction (`error.rs`). Anything
 * else is not a code this catalogue can hold, and passing it to `t()` would
 * let whatever produced it choose the key separator (`.`) or the namespace
 * separator (`:`) and read some other catalogue.
 */
const CODE = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;

/** `en`, and any regional English a settings file might name. */
function isSourceLanguage(language: string): boolean {
  return language === SOURCE_LOCALE || language.startsWith(`${SOURCE_LOCALE}-`);
}

/** What the core sent, unchanged. The answer whenever the catalogue has nothing. */
function asSent(failure: CoreFailure): FailureText {
  return {
    message: failure.message,
    detail: failure.detail,
    actions: [...failure.actions],
  };
}

/**
 * Translate one failure. Pure: every decision comes from the arguments.
 *
 * Actions are matched by position, because that is what the core promises — an
 * ordered list, most useful first. A catalogue entry with fewer labels than the
 * core sent (the core gained an action, the translation has not caught up)
 * relabels the ones it has and leaves the rest in English, which is better than
 * dropping a way out the reader could have taken.
 */
export function resolveFailureText(
  failure: CoreFailure,
  catalogue: FailureCatalogue,
): FailureText {
  if (isSourceLanguage(catalogue.language)) return asSent(failure);
  const code = failure.code;
  if (!CODE.test(code)) return asSent(failure);

  const messageKey = `${code}.message`;
  const detailKey = `${code}.detail`;
  return {
    message: catalogue.has(messageKey) ? catalogue.read(messageKey) : failure.message,
    detail: catalogue.has(detailKey) ? catalogue.read(detailKey) : failure.detail,
    actions: failure.actions.map((action, index) => {
      const key = `${code}.actions.${index}`;
      return catalogue.has(key) ? catalogue.read(key) : action;
    }),
  };
}

/**
 * Translate one failure against the catalogue in force, and re-render when the
 * language changes.
 *
 * Components take this rather than reaching for `errors:` keys themselves:
 * every rule above then applies in one place, and a screen showing a failure
 * cannot accidentally show half of it in English.
 */
export function useFailureText(failure: CoreFailure): FailureText {
  const { t, i18n } = useTranslation("errors");
  // `t` is typed against the English catalogue's literal keys. An error code is
  // runtime data from the core, so the key cannot be one of those literals —
  // hence the cast. What it gives up is checked instead by
  // `failures.catalogue.test.ts`, which walks every code the Rust taxonomy can
  // emit and asserts the catalogue has an entry for it.
  const read = t as unknown as (key: string) => string;
  return resolveFailureText(failure, {
    language: i18n.resolvedLanguage ?? i18n.language,
    has: (key) => i18n.exists(key, { ns: "errors" }),
    read,
  });
}
