import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";

// Tauri drives this dev server; the port is fixed so tauri.conf.json can find it.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 5273,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] },
    // The translation catalogues live at <repo>/locales, outside this package,
    // because translators reach them through Weblate rather than through the
    // frontend build. Vite's default allow-list stops at the nearest lockfile —
    // this directory — so without this the dev server serves a 403 for every
    // catalogue and the interface silently falls back to the bundled English.
    fs: { allow: [fileURLToPath(new URL("../../..", import.meta.url))] },
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    target: "es2022",
    // Off by default, because Tauri embeds everything in `dist` into the
    // binary: source maps were adding 4.5 MB to a 3.9 MB bundle, more than
    // doubling the shipped frontend to carry something no user can use. They
    // also break the one honest way to check whether code reached the build —
    // a map holds the whole original source, so grepping `dist` for a string
    // hits the map whether or not the code was tree-shaken out of the bundle.
    //
    // REMOTER_SOURCEMAPS=1 brings them back for diagnosing a stack trace.
    sourcemap: process.env["REMOTER_SOURCEMAPS"] === "1",
  },
  // A DOM environment, so interface behaviour can be tested rather than only
  // described. Its absence is why the focus traps, the discard prompt and the
  // permanent-skeleton fixes all shipped with "here is what to click" instead
  // of a test.
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: true,
    server: {
      deps: {
        // `intl-messageformat` predates the `exports` field: it declares `main`
        // (CommonJS) and `module` (ESM) and nothing else. A browser build picks
        // `module` and gets a real default export; Vitest's Node resolution
        // picks `main`, and `i18next-icu`'s `import IntlMessageFormat from …`
        // then binds to the CJS namespace object rather than to the class — so
        // every message fails to parse with "is not a constructor", and the
        // parse-error fallback quietly serves plausible-looking English while
        // the tests assert on it. Inlining makes Vitest resolve both the way
        // the browser does.
        inline: ["i18next-icu", "intl-messageformat"],
      },
    },
  },
});
