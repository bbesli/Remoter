/**
 * The two payload types this feature drags between its own panes, and the one
 * encoding both of them use.
 *
 * Their own module so that neither pane has to import the other for a string,
 * which would make the two files circular for no reason.
 *
 * A drag inside this window carries **paths**, which is what the transfer
 * engine takes. A drag in from the desktop carries the file's *contents* and no
 * path at all, which is why an OS drop is refused in words rather than half
 * handled — see `drop.noOsFiles` in the catalogue.
 *
 * # Why the payload is read at all
 *
 * It used not to be. Both panes registered a drop handler that ignored
 * `dataTransfer` entirely and re-ran the bulk action instead: dropping one row
 * on the local pane downloaded *the whole selection*, and dropping a single
 * staged file on the remote pane sent everything staged. A drag that does
 * something other than what was dragged is worse than no drag at all, because
 * the user has no way to tell it apart from one that worked.
 *
 * The webview half of that defect is fixed elsewhere: `dragDropEnabled` is
 * false in `tauri.conf.json` (ADR-0014) so HTML5 drag events reach the page on
 * Windows at all. This module is the other half — what was dragged, said in a
 * form the receiving pane can act on.
 */

/** Remote entries, as their raw server-supplied paths. */
export const REMOTE_DRAG_TYPE = "application/x-remoter-remote-paths";

/** Staged local files, as the paths this machine's picker produced. */
export const LOCAL_DRAG_TYPE = "application/x-remoter-local-paths";

/**
 * Encodes a list of paths for a drag.
 *
 * JSON rather than a separator, because a path may contain any character a
 * separator could be: a newline is legal in a POSIX file name, and a
 * server-chosen name is where one would arrive.
 */
export function encodePaths(paths: readonly string[]): string {
  return JSON.stringify(paths);
}

/**
 * Reads a drag payload back, or `[]` if it is not one.
 *
 * Tolerant on purpose. A payload that arrived from somewhere else, or from a
 * build that wrote it differently, is *not* a reason to act on something the
 * user did not drag — an empty list makes the drop a no-op, which is the safe
 * failure. This is also why the decode refuses anything that is not an array of
 * strings rather than coercing it.
 */
export function decodePaths(payload: string): string[] {
  if (payload === "") return [];
  try {
    // `unknown` rather than a cast: `JSON.parse` returns `any`, and the checks
    // below are the only thing that makes this a `string[]`.
    const parsed: unknown = JSON.parse(payload);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((one): one is string => typeof one === "string" && one !== "");
  } catch {
    return [];
  }
}
