/**
 * The two payload types this feature drags between its own panes.
 *
 * Their own module so that neither pane has to import the other for a string,
 * which would make the two files circular for no reason.
 *
 * A drag inside this window carries a **path**, which is what the transfer
 * engine takes. A drag in from the desktop carries the file's *contents* and no
 * path at all, which is why an OS drop is refused in words rather than half
 * handled — see `drop.noOsFiles` in the catalogue.
 */

/** A remote entry, as its raw server-supplied path. */
export const REMOTE_DRAG_TYPE = "application/x-remoter-remote-paths";

/** A staged local file, as the path this machine's picker produced. */
export const LOCAL_DRAG_TYPE = "application/x-remoter-local-paths";
