import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";

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
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,

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
);
