/**
 * Counting what a recursive removal will take, **before** it takes any of it.
 *
 * `sftp_delete` reports what it removed afterwards, which is the right thing
 * for a walk that can be interrupted — but a report is not a confirmation. A
 * user who pointed at the wrong folder needs the number before the walk, not
 * after it, and "Delete `build`?" is the same sentence whether `build` holds
 * four files or four hundred thousand.
 *
 * So this walks the tree with the same `sftp_list` the browser uses and counts.
 * Three properties matter and each is a deliberate choice:
 *
 * **It does not follow links.** `EntryKind::Symlink` is counted and not
 * descended, which is exactly what the engine's own walk does — it stats with
 * `symlink_metadata`, so a link *to* a directory is unlinked rather than
 * emptied. A preview that followed links would promise a removal far larger
 * than the one that happens, and one pointing back up its own tree would never
 * finish.
 *
 * **It is bounded, and says when it stopped.** A build directory with four
 * hundred thousand files must not be counted exactly at the price of a frozen
 * dialog, so the walk stops at {@link PREVIEW_LIMIT} entries and
 * {@link PREVIEW_DEPTH} levels. When it does, `truncated` is set and the dialog
 * says the count is a floor rather than the total — a removal that turns out
 * to be ten times the number on the confirmation is the failure this whole
 * dialog exists to prevent.
 *
 * **It is cancellable, in the only way the frontend can be.** Each listing is
 * its own command and the pane cancels the previous one when the next starts,
 * so an abandoned preview stops making requests as soon as the caller stops
 * awaiting it; `signal` is what tells it to.
 *
 * The bounds here are the interface's, and are deliberately far below the
 * engine's own (250 000 entries, 64 levels). This is a count for a human to
 * read, not an audit.
 */

import type { DirectoryEntry } from "@/lib/ipc";

/** How many entries the preview will look at before it stops counting. */
export const PREVIEW_LIMIT = 2_000;

/** How deep it will go. A tree deeper than this is not one anyone meant to point at. */
export const PREVIEW_DEPTH = 16;

/** How many paths the dialog shows as examples. */
export const SAMPLE_SIZE = 6;

export interface RemovalPreview {
  /** Everything that is not a directory, links included. */
  files: number;
  /** Directories, not counting the one being removed. */
  directories: number;
  /** Links, which are a subset of `files` and are counted again for the notice. */
  links: number;
  /**
   * A few paths, **escaped**, so the user can recognise what they are pointing
   * at. Display only; nothing here addresses anything.
   */
  sample: string[];
  /** True when the walk stopped at its own limit rather than at the end. */
  truncated: boolean;
}

/** Lists one directory. Injected so the walk can be tested without a server. */
export type ListDirectory = (path: string) => Promise<DirectoryEntry[]>;

/**
 * Walks `root` and counts what removing it would take.
 *
 * `root` itself is not counted: the dialog names it in its title, and counting
 * it would make "and 1 folder" appear for an empty directory.
 *
 * A listing that fails mid-walk is counted as a leaf rather than aborting the
 * whole preview. The user cannot read a directory they cannot read, the server
 * will say the same thing to the removal, and a preview that refuses outright
 * because one subdirectory is unreadable would block a removal that would
 * otherwise mostly succeed. What must not happen — and does not — is that the
 * failure is hidden: a preview that hit one gets `truncated`, and the dialog
 * says the count is a floor.
 */
export async function previewRemoval(
  root: DirectoryEntry,
  list: ListDirectory,
  signal?: AbortSignal,
): Promise<RemovalPreview> {
  const preview: RemovalPreview = {
    files: 0,
    directories: 0,
    links: 0,
    sample: [],
    truncated: false,
  };

  // A link to a directory is a link. Nothing below it is ours to remove, so
  // there is nothing to walk.
  if (root.kind !== "directory") {
    preview.files = 1;
    if (root.kind === "symlink") preview.links = 1;
    preview.sample.push(root.displayPath);
    return preview;
  }

  let seen = 0;
  // Breadth-first rather than recursive: the sample then comes from the top of
  // the tree, which is what someone checking they pointed at the right folder
  // recognises, and the queue makes the depth bound a plain number rather than
  // a call stack.
  let frontier: { path: string; depth: number }[] = [{ path: root.path, depth: 0 }];

  while (frontier.length > 0) {
    if (signal?.aborted === true) {
      preview.truncated = true;
      return preview;
    }
    const next: { path: string; depth: number }[] = [];
    for (const { path, depth } of frontier) {
      if (seen >= PREVIEW_LIMIT) {
        preview.truncated = true;
        return preview;
      }
      let entries: DirectoryEntry[];
      try {
        entries = await list(path);
      } catch {
        // Unreadable from here. Counted as visited, and the count becomes a
        // floor; see the note above.
        preview.truncated = true;
        continue;
      }
      for (const entry of entries) {
        seen += 1;
        if (seen > PREVIEW_LIMIT) {
          preview.truncated = true;
          return preview;
        }
        if (preview.sample.length < SAMPLE_SIZE) preview.sample.push(entry.displayPath);
        if (entry.kind === "directory") {
          preview.directories += 1;
          // `risks.separator` means the server sent a name that is not a single
          // path component. The core refuses to build a path from it, so there
          // is nothing to descend into — it is counted and left alone.
          if (depth + 1 < PREVIEW_DEPTH && !entry.risks.separator) {
            next.push({ path: entry.path, depth: depth + 1 });
          } else if (depth + 1 >= PREVIEW_DEPTH) {
            preview.truncated = true;
          }
        } else {
          preview.files += 1;
          if (entry.kind === "symlink") preview.links += 1;
        }
      }
    }
    frontier = next;
  }

  return preview;
}
