/**
 * The files whose copy has not been extracted yet.
 *
 * A ratchet, not an exemption list. Inside these globs the two i18n rules
 * report as warnings so that `npm run lint` still exits clean on a tree that
 * was written before the catalogues existed; everywhere else — every new file,
 * and every file already migrated — they are errors.
 *
 * **Delete your feature's line when you extract it.** That is the whole
 * protocol. The list only shrinks; adding to it is how the guard becomes
 * decoration, and a reviewer should treat a new entry the way they would treat
 * a new `@ts-expect-error`.
 *
 * Extracted so far: `features/shell`, `features/settings`, `features/audit`, `features/connections`,
 * `features/vault`, `features/vaultsettings`, `features/import`, and the shared `components/`,
 * `hooks/` and `app/` that every other area inherits its vocabulary from.
 */
export const NOT_YET_EXTRACTED = [];

/**
 * Tests assert on the English a user sees, so their fixtures are English by
 * definition. Running the rules over them would produce a wall of noise with
 * no defect behind any of it.
 */
export const NOT_USER_FACING = ["src/test/**", "**/*.test.ts", "**/*.test.tsx"];
