/**
 * The i18next instance, configured once.
 *
 * The stack is the one docs/features/i18n.md specifies: i18next for lookup and
 * fallback, `i18next-icu` (over `intl-messageformat`) for ICU MessageFormat, and
 * `react-i18next` for the React binding. The alternative — a hand-rolled `t()`
 * with an `n === 1` check — is ruled out by the shipping list: Arabic has six
 * plural categories and Russian four, and no amount of care makes a one/other
 * switch produce grammatical Russian.
 *
 * Two configuration choices carry more weight than they look like they do.
 *
 * **`escapeVariables: false`.** i18next-icu can HTML-escape interpolated values.
 * It must not here. React already escapes every text child, so escaping first
 * would render a hostname `db&01` as `db&amp;01` — the untrusted value would be
 * *displayed wrong* in the name of safety it already had. The guarantee that
 * matters is structural and holds without it: `intl-messageformat` parses the
 * *message* into an AST and substitutes arguments as data into the result. An
 * argument is never re-parsed, so a hostname containing `{`, `}`, `#` or
 * `<script>` cannot become message syntax, an ICU argument, or markup. There is
 * a test for each of those in `interpolation.test.ts`, because this is the one
 * property of the whole layer that a refactor could quietly remove.
 *
 * **`load: "currentOnly"`.** i18next otherwise also tries the base language of
 * a tag — `zh` for `zh-Hans`, `pt` for `pt-BR` — and neither has a catalogue
 * directory. Every failed load is a spurious warning and, with a real backend,
 * a spurious request.
 */

import i18next, { type BackendModule, type ReadCallback, type i18n as I18n } from "i18next";
import ICU from "i18next-icu";
import { initReactI18next } from "react-i18next";
import { IntlMessageFormat } from "intl-messageformat";

import {
  ENGLISH_CATALOGUES,
  SHIPPED_NAMESPACES,
  loadCatalogue,
  localeIsComplete,
  type Catalogue,
} from "./catalogues";
import {
  DEFAULT_NAMESPACE,
  SOURCE_LOCALE,
  SUPPORTED_LOCALES,
  localeDirection,
  type Namespace,
} from "./locales";
import { isDevelopment, missingKeyText, reportMissingKey } from "./missing";

/**
 * The namespaces loaded before the first paint.
 *
 * Everything else arrives when a screen asks for it, which is the point of
 * splitting the catalogues per feature: opening Settings should not also parse
 * the import wizard's copy. English is bundled in full regardless — it is the
 * fallback, so it has to be there before anything can be missing.
 */
const STARTUP_NAMESPACES: readonly Namespace[] = [DEFAULT_NAMESPACE, "shell"].filter((ns) =>
  SHIPPED_NAMESPACES.includes(ns as Namespace),
) as Namespace[];

/** Reads catalogues out of the `locales/` directory. See `catalogues.ts`. */
const catalogueBackend: BackendModule = {
  type: "backend",
  init: () => {
    // Nothing to set up: the loaders are resolved by the bundler.
  },
  read(language: string, namespace: string, callback: ReadCallback) {
    if (language === SOURCE_LOCALE) {
      // Already in the store, bundled. Answering synchronously here keeps
      // `init()` synchronous, which is what lets a test render a component
      // without awaiting anything.
      callback(null, ENGLISH_CATALOGUES[namespace as Namespace] ?? {});
      return;
    }
    void loadCatalogue(language, namespace as Namespace).then((catalogue) => {
      // `null` is "this language does not ship this namespace", not an error:
      // reporting it as one makes i18next retry a file that will never exist.
      // The English fallback covers the gap, key by key.
      callback(null, catalogue ?? {});
    });
  },
};

/** Dotted-path lookup into a parsed catalogue. */
function resolvePath(catalogue: Catalogue, path: readonly string[]): unknown {
  let current: unknown = catalogue;
  for (const segment of path) {
    if (typeof current !== "object" || current === null) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

/** The English source message for a key, whatever namespace it lives in. */
function englishSource(key: string): string | null {
  const [head, ...rest] = key.split(":");
  const explicitNs = rest.length > 0 ? (head as Namespace) : null;
  const path = (rest.length > 0 ? rest.join(":") : key).split(".");
  const search = explicitNs === null ? SHIPPED_NAMESPACES : [explicitNs];
  for (const ns of search) {
    const catalogue = ENGLISH_CATALOGUES[ns];
    if (catalogue === undefined) continue;
    const found = resolvePath(catalogue, path);
    if (typeof found === "string") return found;
  }
  return null;
}

/**
 * What to render when a message will not parse.
 *
 * This is a translator's mistake — an unbalanced brace, a plural category the
 * language does not have — arriving through Weblate rather than through review.
 * i18next-icu's default is to return the raw message, which puts
 * `{count, plural, one {...}}` on screen. That is worse than a missing string:
 * it looks like a crash and says nothing.
 *
 * So: try the English source of the same key, and if that will not parse
 * either, fall back to the humanised key. Loud in development either way.
 */
function parseErrorHandler(error: Error, key: string, res: string, options: object): string {
  if (isDevelopment()) {
    console.error(`[i18n] "${key}" is not a valid ICU message: ${error.message}\n  ${res}`);
  }
  const source = englishSource(key);
  if (source !== null && source !== res) {
    try {
      return String(new IntlMessageFormat(source, SOURCE_LOCALE, undefined, {
        ignoreTag: true,
      }).format(options as Record<string, unknown>));
    } catch {
      // The English source is broken too, which is a review failure rather
      // than a translation one. Nothing left to try.
    }
  }
  return missingKeyText(key);
}

let created: I18n | null = null;

/**
 * Build and initialise the instance. Idempotent — a second call returns the
 * first instance, so importing this module from a test file and from `main.tsx`
 * does not produce two stores.
 */
export function initI18n(): I18n {
  if (created !== null) return created;

  const instance = i18next.createInstance();
  void instance
    .use(catalogueBackend)
    .use(new ICU({ memoize: true, escapeVariables: false, parseErrorHandler }))
    .use(initReactI18next)
    .init({
      lng: SOURCE_LOCALE,
      fallbackLng: SOURCE_LOCALE,
      supportedLngs: SUPPORTED_LOCALES.map((locale) => locale.code),
      load: "currentOnly",
      ns: STARTUP_NAMESPACES,
      defaultNS: DEFAULT_NAMESPACE,
      // English is compiled in; every other language comes from the backend.
      resources: { [SOURCE_LOCALE]: ENGLISH_CATALOGUES },
      partialBundledLanguages: true,
      // Synchronous init, so a component can be rendered on the line after
      // this one — in `main.tsx` and in every test.
      initImmediate: false,
      // ICU does the substitution; i18next's own interpolator never runs, and
      // React escapes what reaches the DOM. See the file header.
      interpolation: { escapeValue: false },
      returnNull: false,
      returnEmptyString: false,
      saveMissing: isDevelopment(),
      missingKeyHandler: (lngs, ns, key) => {
        reportMissingKey(lngs, ns, key);
      },
      parseMissingKeyHandler: (key: string) => missingKeyText(key),
      // Suspense would put a blank window between a language change and the
      // catalogue landing. There is nothing to wait for: English is already in
      // the store, so `t()` renders English for that frame instead of nothing.
      react: { useSuspense: false },
      debug: false,
    });

  created = instance;
  return instance;
}

/** The instance. Created on first use. */
export function i18n(): I18n {
  return initI18n();
}

/**
 * Switch language at runtime.
 *
 * Refuses an incomplete language rather than switching to one and showing
 * English through the gaps: a setting that appears to take effect and only
 * half does is the failure this whole layer exists to remove. The caller
 * decides what to say about a refusal; it returns the language actually in
 * force.
 *
 * "Incomplete" is measured by key coverage, which means reading that
 * language's catalogues — no extra cost here, because the next line loads
 * exactly those files, and the answer is cached for the rest of the session.
 */
export async function setLanguage(code: string): Promise<string> {
  const instance = i18n();
  if (!(await localeIsComplete(code))) return instance.language;
  await instance.changeLanguage(code);
  return instance.language;
}

/**
 * Put the language and its direction on the document.
 *
 * `dir` on `<html>` is the whole of RTL as far as JavaScript is concerned:
 * every layout rule in the application is written in logical properties, so
 * the sidebar, the tab strip's edges, the inspector and every icon that means
 * a direction mirror from this one attribute. `lang` is separate and just as
 * necessary — it selects the font stack, the hyphenation dictionary and the
 * voice a screen reader uses.
 */
export function applyDocumentLanguage(code: string, root: HTMLElement = document.documentElement) {
  root.setAttribute("lang", code);
  root.setAttribute("dir", localeDirection(code));
}
