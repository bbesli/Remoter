/**
 * The file manager's public surface.
 *
 * The shell imports from here; nothing outside this directory reaches into a
 * module of it — the same rule the sessions feature states for the same reason.
 * In particular `usePane` is not exported: a caller that could open a pane
 * without rendering the screen could open one nothing ever closes, and a pane
 * holds a channel and two tasks on the user's connection.
 *
 * **This screen is not yet mounted anywhere.** `FileManager` takes no props and
 * reads the session list itself, so mounting it is a screen in `stores/app.ts`,
 * a line in `app/App.tsx` and an entry in the title bar — three files that
 * belong to other agents in this milestone, and it is written up in the hand-off
 * rather than edited here.
 */

export { FileManager } from "./FileManager";
