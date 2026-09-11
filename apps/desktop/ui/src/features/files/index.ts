/**
 * The file manager's public surface.
 *
 * The shell imports from here; nothing outside this directory reaches into a
 * module of it — the same rule the sessions feature states for the same reason.
 * In particular `usePane` is not exported: a caller that could open a pane
 * without rendering it could open one nothing ever closes, and a pane holds a
 * channel and two tasks on the user's connection.
 *
 * Nothing here imports the sessions feature, and that is load-bearing rather
 * than tidy: the session surface imports `FileSessionHost`, so an import back
 * the other way would make the two features circular. A pane is given a session
 * id and a name; deciding which session that is belongs to whoever mounts it.
 *
 * Two mount points, because there are two ways a user reaches a file pane and
 * the core supports both:
 *
 *   - `FileSessionHost` — a tab whose session *is* a file session. An `sftp`
 *     connection opened from the tree gets one of these instead of a terminal.
 *   - `FilePane` — a pane docked under a session that has a shell as well. The
 *     tab strip's Files toggle opens it, and it runs on the connection that tab
 *     already authenticated: one more channel, not a second sign-in.
 */

export { FileSessionHost } from "./FileSessionHost";
export { FilePane } from "./FilePane";
