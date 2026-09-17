/**
 * The interface on invented data, for the README's screenshots.
 *
 * Not part of the application: `vite build` builds `index.html` and nothing
 * else, so this page never reaches a bundle. It exists because a screenshot of
 * a real vault is a screenshot of real host names, addresses and accounts, and
 * the README's pictures should show the interface without showing anyone's
 * estate. Everything the core would answer is answered here from
 * `fixtures.ts`, through Tauri's own IPC mock.
 *
 * `scripts/readme-screenshots.mjs` drives it; `?shot=` picks the screen.
 */

import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";

import { handle } from "./mockCore";

mockWindows("main");
mockIPC((cmd, args) => handle(cmd, args as Record<string, unknown> | undefined));

await import("./mount");
