/**
 * The localisation layer's public surface.
 *
 * A component imports from `@/i18n` and nothing else. The modules behind it —
 * the i18next instance, the catalogue loader, the missing-key policy — are
 * implementation, and a screen reaching past this file is a review rejection
 * for the same reason a component calling `invoke()` is: the wrapper is what
 * keeps the layer replaceable.
 */

export { I18nProvider } from "./I18nProvider";
export { useT, useLocale, type LocaleInfo, type LoadedNamespace } from "./useT";
export { applyDocumentLanguage, setLanguage, i18n, initI18n } from "./instance";
export {
  DEFAULT_NAMESPACE,
  NAMESPACES,
  SOURCE_LOCALE,
  SUPPORTED_LOCALES,
  isSupportedLocale,
  localeDescriptor,
  localeDirection,
  type Direction,
  type LocaleDescriptor,
  type Namespace,
} from "./locales";
export { completeLocales, localeIsComplete, SHIPPED_NAMESPACES } from "./catalogues";
export {
  resolveFailureText,
  useFailureText,
  type CoreFailure,
  type FailureCatalogue,
  type FailureText,
} from "./failures";
export {
  strengthBand,
  strengthConsequence,
  useStrengthText,
  type StrengthBand,
  type StrengthConsequence,
  type StrengthSpan,
  type StrengthText,
} from "./strength";
export { documentDirection, inlineStartOffset, isolate, isolateChain, isolateLtr } from "./bidi";
export { compareInLocale, equalsIgnoringCase, foldForSearch, foldInvariant } from "./fold";
export {
  formatBytes,
  formatClock,
  formatDate,
  formatDateTime,
  formatList,
  formatNumber,
  formatPercent,
  formatRate,
  formatRelativeTime,
  formatTime,
  type DateStyle,
} from "./format";
