import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

import remoterI18n from "./eslint-rules/i18n.js";
import { NOT_USER_FACING, NOT_YET_EXTRACTED } from "./eslint-rules/i18n-baseline.js";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: { "react-hooks": reactHooks, "remoter-i18n": remoterI18n },
    rules: {
      ...reactHooks.configs.recommended.rules,

      // Every user-visible string goes through t() — CLAUDE.md §6. Errors, not
      // warnings: the interface reached a state where every string was
      // hardcoded because nothing ever failed over one, and extracting them
      // without leaving a guard behind would only restart that clock. The
      // escape hatch is an ordinary disable comment with a reason; the things
      // that are legitimately never translated (protocol names, hostnames,
      // paths, version strings) are listed in docs/features/i18n.md.
      "remoter-i18n/no-literal-jsx-text": "error",
      "remoter-i18n/no-text-constant": "error",

      // Remote content — hostnames, banners, MOTD, directory listings — is
      // untrusted. It renders as text, always. See CLAUDE.md §6.
      //
      // Enforced by selector rather than by react/no-danger, which would need
      // the react plugin registered; the selector needs no plugin and cannot be
      // silently disabled by a config change.
      "no-restricted-syntax": [
        "error",
        {
          selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
          message:
            "Remote content is untrusted and must render as text. There is no override for this rule.",
        },
        {
          selector:
            "CallExpression[callee.name='invoke']",
          message:
            "Call the typed wrappers in @/lib/ipc instead. That file is the only place invoke() may appear.",
        },
      ],

      // The react-hooks plugin's compiler-era rules. They flag real patterns —
      // a setState in an effect body does cause a cascading render — but every
      // current instance is a deliberate "reset this form when its subject
      // changes", for which the idiomatic fix is a `key` prop rather than a
      // rewrite. Advisory until that pass is done, so that `npm run lint`
      // reports them without blocking a build over them.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/preserve-manual-memoization": "warn",

      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // The wrapper file is where invoke() lives, by design.
    files: ["src/lib/ipc.ts"],
    rules: { "no-restricted-syntax": "off" },
  },
  // The ratchet. These directories predate the catalogues, so their copy is
  // reported as a warning rather than an error and `npm run lint` still
  // exits clean. Every other file — including every new one — errors.
  // Remove a line from the baseline as you extract that feature.
  //
  // Spread rather than written inline, because the list is meant to reach
  // empty: flat config refuses a `files: []` block outright, so the last agent
  // to finish the ratchet would otherwise break `npm run lint` for everyone at
  // the moment the ratchet succeeded.
  ...(NOT_YET_EXTRACTED.length === 0
    ? []
    : [
        {
          files: NOT_YET_EXTRACTED,
          rules: {
            "remoter-i18n/no-literal-jsx-text": "warn",
            "remoter-i18n/no-text-constant": "warn",
          },
        },
      ]),
  {
    // A test asserts on the English a user sees. Its fixtures are copy by
    // definition and there is no defect behind any of them.
    files: NOT_USER_FACING,
    rules: {
      "remoter-i18n/no-literal-jsx-text": "off",
      "remoter-i18n/no-text-constant": "off",
    },
  },
);
