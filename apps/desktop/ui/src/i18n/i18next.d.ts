/**
 * Type-safe translation keys.
 *
 * Binding the English catalogues to i18next's `CustomTypeOptions` turns a typo
 * in a key into a compile error rather than a marker on screen. It is the
 * cheapest guard in the whole layer, and it is why the missing-key fallback in
 * `missing.ts` should almost never fire in a build that typechecks.
 *
 * **When you add a namespace**, add its catalogue here as well. Until you do,
 * `useT("sessions")` will not compile — which is the intended order of work:
 * the catalogue exists first, the code that reads it second.
 */

import "i18next";

import type audit from "../../../../../locales/en/audit.json";
import type common from "../../../../../locales/en/common.json";
import type connections from "../../../../../locales/en/connections.json";
import type files from "../../../../../locales/en/files.json";
// `import` is a reserved word, so the local binding is `importer`; the
// namespace itself is "import", matching the feature directory.
import type importer from "../../../../../locales/en/import.json";
import type sessions from "../../../../../locales/en/sessions.json";
import type settings from "../../../../../locales/en/settings.json";
import type shell from "../../../../../locales/en/shell.json";
import type vault from "../../../../../locales/en/vault.json";
import type vaultsettings from "../../../../../locales/en/vaultsettings.json";

declare module "i18next" {
  interface CustomTypeOptions {
    defaultNS: "common";
    resources: {
      common: typeof common;
      shell: typeof shell;
      connections: typeof connections;
      settings: typeof settings;
      sessions: typeof sessions;
      files: typeof files;
      import: typeof importer;
      vault: typeof vault;
      vaultsettings: typeof vaultsettings;
      audit: typeof audit;
      // Not `typeof errors`. That catalogue holds an entry for every failure
      // code the core can send — a hundred and ninety of them, each with a
      // sentence and a list of action labels — and asking i18next to build the
      // union of its keys tips the compiler into "type instantiation is
      // excessively deep", taking every other namespace's key checking down
      // with it. Nothing is lost by loosening it: its keys are error codes,
      // runtime data from Rust rather than literals written in this codebase,
      // so `useFailureText` looks them up through a `string` cast either way.
      // What checks them instead is `failures.catalogue.test.ts`, which reads
      // the Rust and fails if any code lacks an entry, in any language.
      errors: Record<string, unknown>;
    };
    returnNull: false;
  }
}
