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
  },
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    target: "es2022",
    sourcemap: true,
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
  },
});
