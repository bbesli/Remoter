/**
 * The accessor every component uses.
 *
 * One import, one call, one rule: if a user can read it, it comes from here.
 *
 * ```tsx
 * const t = useT("settings");
 * <h2>{t("language.title")}</h2>
 * <p>{t("language.progress", { count: available })}</p>
 * ```
 *
 * The namespace is named at the call site rather than inferred, because that
 * is what makes per-feature loading work: the hook tells i18next which
 * catalogue this screen needs, and only that catalogue is fetched when the
 * language is not English.
 *
 * Interpolated values go in the options object and are substituted as data —
 * never concatenated into the key, never spliced into the message. A hostname,
 * a MOTD line or a file name from a remote host is safe to pass here; see the
 * header of `instance.ts` for why, and `interpolation.test.ts` for the proof.
 */

import type { CustomTypeOptions, TFunction } from "i18next";
import { useTranslation } from "react-i18next";

import { initI18n } from "./instance";
import { DEFAULT_NAMESPACE, localeDirection, type Direction } from "./locales";

/**
 * The namespaces a component may ask for: the ones that actually have an
 * English catalogue, taken from the type augmentation in `i18next.d.ts`.
 *
 * Narrower than {@link Namespace} on purpose. `useT("sessions")` should not
 * compile until `locales/en/sessions.json` exists, because a screen written
 * against a catalogue nobody has written yet renders humanised keys and looks
 * finished. Adding the catalogue and its line in `i18next.d.ts` is what makes
 * the namespace available here — in that order.
 */
export type LoadedNamespace = keyof CustomTypeOptions["resources"];

// The instance has to exist before the first component renders. Importing this
// module is what guarantees it, in the application and in a test alike, which
// is why the call is here rather than in `main.tsx` where a test would miss it.
initI18n();

/**
 * Translate within one namespace.
 *
 * The returned function re-renders its component when the language changes, so
 * switching language needs no restart and no remount.
 */
export function useT<N extends LoadedNamespace = typeof DEFAULT_NAMESPACE>(
  namespace?: N,
): TFunction<N> {
  // Generic in the namespace so the returned `t` is typed to that catalogue's
  // keys alone. Without it every `t` would carry the union of all namespaces,
  // and a helper that takes a `TFunction<"shell">` — `provenance()` in the
  // inspector, for one — would not accept it.
  // The cast is `FallbackNs<N>` -> `N`: react-i18next widens a single
  // namespace to include the default one, which is the same catalogue set at
  // run time and only differs in the type.
  const { t } = useTranslation<N>((namespace ?? DEFAULT_NAMESPACE) as N);
  return t as unknown as TFunction<N>;
}

export interface LocaleInfo {
  /** The BCP 47 tag now in force. Pass it to the `format*` functions. */
  readonly code: string;
  readonly dir: Direction;
  readonly isRtl: boolean;
}

/**
 * The language in force, for the things `t()` does not cover: `Intl`
 * formatting, and the handful of places that need to know the direction in
 * JavaScript rather than in CSS.
 */
export function useLocale(): LocaleInfo {
  const { i18n } = useTranslation();
  const code = i18n.resolvedLanguage ?? i18n.language;
  const dir = localeDirection(code);
  return { code, dir, isRtl: dir === "rtl" };
}
