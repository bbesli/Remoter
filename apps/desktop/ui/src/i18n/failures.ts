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
 *   useless to whoever reads that report;
 * - an action is relabelled from the entry's own list by position, and failing
 *   that from the shared lexicon, by the English sentence the core sent. The
 *   second is what translates the connection-failure taxonomy, whose actions
 *   are composed rather than written per code — see [`SHARED_ACTIONS`].
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

/**
 * The actions that cannot be labelled where the failure is, and the key each
 * one is translated under in `errors.json`.
 *
 * A `session.*` failure does not carry its own list of sentences. The core
 * turns a `NextAction` into English in one place — `action_text` in
 * `crates/remoter-ipc/src/session.rs` — and every session failure draws from
 * that set, plus the handful of sentences session.rs and bridge.rs write
 * themselves. So the same seventeen sentences appear under forty-odd codes,
 * and **positional labels cannot translate them**:
 *
 * - the order differs per failure. `session.credential-required` offers
 *   "enter a credential" first from one arm and "choose a different
 *   credential" first from another, so position 0 is not one sentence;
 * - some codes have no fixed list at all. A session that fails while running
 *   arrives as `session.failed` (and a transfer as `sftp.transfer-failed`)
 *   carrying whatever actions the underlying failure offered — any of the
 *   seventeen, in any order;
 * - `session.hop-failed` substitutes the *inner* failure's actions when a hop
 *   failed on the far end's identity (`ProtocolError::next_actions`). A
 *   positional label there would title the button that says "verify the
 *   fingerprint with the server's administrator" as "edit the gateway chain",
 *   which is the one mislabelling in this file that could get someone
 *   compromised.
 *
 * The same problem turns up in miniature wherever one code is raised from
 * several places with a different button each time —
 * `node.field-not-applicable` asks for a credential, for a folder, or for the
 * connection instead, depending which field was patched — and those sentences
 * are here for the same reason.
 *
 * So an action is looked up by **what the core actually sent**, against this
 * table, whenever the failure's own entry has no label at that position. The
 * English sentences below are the join and must match the Rust exactly;
 * `failures.catalogue.test.ts` parses it and fails if they drift.
 */
export const SHARED_ACTIONS: ReadonlyMap<string, string> = new Map<string, string>([
  // `action_text`, in the order the Rust declares it.
  ["Open this connection's settings", "open-connection-settings"],
  ["Edit the gateway chain", "edit-gateway-chain"],
  ["Check the address, or the DNS server that should know it", "check-address"],
  ["Check that the service is listening on that port", "check-service"],
  ["Check the firewall, or the gateway in front of it", "check-firewall"],
  ["Check the network connection", "check-network"],
  ["Try again", "retry"],
  ["Reconnect", "reconnect"],
  ["Choose a different credential", "choose-different-credential"],
  ["Enter a credential for this attempt", "enter-credential"],
  ["Choose a different authentication method", "choose-auth-method"],
  ["Review the host key", "review-host-key"],
  [
    "Verify the fingerprint with the server's administrator before doing anything else",
    "verify-fingerprint-out-of-band",
  ],
  ["Pin the certificate to this connection", "pin-certificate"],
  ["Close another session, or raise the limit", "close-another-session-or-raise-limit"],
  ["Contact the server's administrator", "contact-server-administrator"],
  ["Report this — it is a defect in Remoter", "report-defect"],
  // The sentences session.rs and bridge.rs write at the call site.
  ["Choose a credential", "choose-credential"],
  ["Open the credential's settings", "open-credential-settings"],
  ["Choose a credential for the gateway", "choose-gateway-credential"],
  ["Open its settings", "open-its-settings"],
  ["Verify the fingerprint out of band", "verify-fingerprint"],
  ["Contact the administrator", "contact-administrator"],
  ["Close another session", "close-another-session"],
  ["Open settings", "open-settings"],
  ["Refresh the list", "refresh-list"],
  ["Try connecting again", "try-connecting-again"],
  ["Close the tab", "close-tab"],
  ["Use an SSH or SFTP connection", "use-ssh-or-sftp"],
  ["Report this", "report-this"],
  ["Unlock the vault", "unlock-vault"],
  ["Change the policy in vault settings", "change-lock-policy"],
  // Codes raised from several places with a different button each time. Same
  // problem, smaller: `node.field-not-applicable` is raised seven times in
  // commands.rs and asks for something different every time, so a label at
  // position 0 would be the wrong sentence six times out of seven.
  ["Select a connection or a credential", "select-connection-or-credential"],
  ["Create a credential and point this connection at it", "create-credential-for-connection"],
  ["Select a connection or a folder", "select-connection-or-folder"],
  ["Edit the connection instead", "edit-connection-instead"],
  ["Edit a connection or a folder instead", "edit-connection-or-folder-instead"],
  ["Unlock with a password or your recovery key", "unlock-with-password-or-recovery-key"],
  ["Use a password or recovery slot", "use-password-or-recovery-slot"],
]);

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
 * Actions are matched by position first, because that is what the core
 * promises for a failure that writes its own list — ordered, most useful
 * first. Where the entry has no label at that position, the sentence the core
 * sent is looked up in the shared lexicon (see [`SHARED_ACTIONS`]), which is
 * how every `session.*` action is translated and the only way the ones whose
 * order or membership varies per failure can be. Anything neither knows is
 * left in English, which is better than dropping a way out the reader could
 * have taken.
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
      const positional = `${code}.actions.${index}`;
      if (catalogue.has(positional)) return catalogue.read(positional);
      // Keyed by the English sentence itself, so an action that moved, or that
      // came from a failure wrapped inside this one, is still translated.
      const shared = SHARED_ACTIONS.get(action);
      if (shared !== undefined && catalogue.has(`action.${shared}`)) {
        return catalogue.read(`action.${shared}`);
      }
      return action;
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
