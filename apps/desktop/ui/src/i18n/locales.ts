/**
 * The locale and namespace registry.
 *
 * This is the contract the rest of the interface is written against: a screen
 * names the namespace it needs, and everything else — which files exist, which
 * language is selectable, which way the layout runs — is derived from here or
 * from the catalogue directory itself. Nothing about a language is hardcoded
 * at a call site.
 *
 * The ten locales and their directions come from docs/features/i18n.md.
 * `available` is deliberately NOT a field: a language becomes selectable when
 * its catalogues land, and asking a constant to stay in step with a directory
 * is how a list of nine "Not yet available" rows outlives the translations it
 * was describing. See `catalogues.ts`.
 */

/**
 * One namespace per feature directory, plus two that cut across all of them.
 *
 * A screen loads what it needs and nothing else, so opening Settings does not
 * pull the import wizard's copy over the IPC-free but still real cost of
 * parsing it. The split mirrors `src/features/` one-for-one; `common` and
 * `errors` are the exceptions, and they are exceptions because their strings
 * genuinely belong to no single screen — shared verbs in one, the core's
 * failure taxonomy keyed by `IpcError.code` in the other.
 *
 * **There is deliberately no `security` namespace.** The original list had
 * one, on the grounds that a warning about permanent data loss which a
 * translator has softened is a real source of harm and should be reviewed by a
 * second pair of eyes. The harm is real; a namespace was the wrong mechanism.
 * It would have moved a handful of sentences away from the screens they belong
 * to — the recovery-key warning out of `vault`, the slot-removal warning out of
 * `vaultsettings` — leaving each screen's copy half in one file and half in
 * another, and it sat here for a milestone as a row naming a file nobody had
 * written. What actually carries the review requirement is the string itself:
 * a `_comment_` above it saying SECURITY-CRITICAL and what must not be
 * softened, which Weblate shows the translator at the moment of translating and
 * which cannot drift away from the string it guards.
 */
export const NAMESPACES = [
  "common",
  "shell",
  "settings",
  "connections",
  "sessions",
  // The SFTP file manager. Its own namespace rather than a corner of
  // `sessions`, for the reason the table in docs/features/i18n.md gives: one
  // namespace per directory under `src/features/`, and a dual-pane browser
  // with a transfer queue is a screen rather than a tab's worth of copy.
  "files",
  "vault",
  "vaultsettings",
  "audit",
  "import",
  "errors",
] as const;

export type Namespace = (typeof NAMESPACES)[number];

/** The namespace a `useT()` call gets when it names none. */
export const DEFAULT_NAMESPACE = "common" satisfies Namespace;

/** The source language. Always bundled, always complete, always the fallback. */
export const SOURCE_LOCALE = "en";

export type Direction = "ltr" | "rtl";

export interface LocaleDescriptor {
  /** The BCP 47 tag. Also the catalogue directory name and the settings value. */
  readonly code: string;
  /**
   * The language's own name in its own script. Never translated and never
   * transliterated: a reader looking for their language recognises it written
   * the way they write it, not the way English writes it.
   */
  readonly endonym: string;
  readonly dir: Direction;
}

/** The ten from docs/features/i18n.md, in that document's order. */
export const SUPPORTED_LOCALES: readonly LocaleDescriptor[] = [
  { code: "en", endonym: "English", dir: "ltr" },
  { code: "zh-Hans", endonym: "简体中文", dir: "ltr" },
  { code: "es", endonym: "Español", dir: "ltr" },
  { code: "hi", endonym: "हिन्दी", dir: "ltr" },
  { code: "ar", endonym: "العربية", dir: "rtl" },
  { code: "pt-BR", endonym: "Português (Brasil)", dir: "ltr" },
  { code: "ru", endonym: "Русский", dir: "ltr" },
  { code: "fr", endonym: "Français", dir: "ltr" },
  { code: "de", endonym: "Deutsch", dir: "ltr" },
  { code: "tr", endonym: "Türkçe", dir: "ltr" },
];

const BY_CODE = new Map(SUPPORTED_LOCALES.map((locale) => [locale.code, locale]));

export function localeDescriptor(code: string): LocaleDescriptor | null {
  return BY_CODE.get(code) ?? null;
}

export function isSupportedLocale(code: string): boolean {
  return BY_CODE.has(code);
}

/**
 * Which way the layout runs.
 *
 * Unknown codes get `ltr` rather than a throw: a settings file written by a
 * newer build must not stop this one from starting, and the language it names
 * is refused elsewhere with a sentence the user can act on.
 */
export function localeDirection(code: string): Direction {
  return BY_CODE.get(code)?.dir ?? "ltr";
}
