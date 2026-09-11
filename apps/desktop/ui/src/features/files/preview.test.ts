/**
 * The count that goes above the Delete button.
 *
 * Three properties, and all three are what make the confirmation worth reading:
 * it does not follow links, it stops rather than hanging, and when it stops it
 * says the number is a floor. A preview that quietly under-reported would be
 * worse than no preview at all — the user would have agreed to a number.
 */

import { describe, expect, it, vi } from "vitest";

import type { DirectoryEntry, EntryKind } from "@/lib/ipc";

import { PREVIEW_DEPTH, PREVIEW_LIMIT, previewRemoval, SAMPLE_SIZE } from "./preview";

function node(path: string, kind: EntryKind): DirectoryEntry {
  const name = path.split("/").filter((p) => p !== "").pop() ?? path;
  return {
    name,
    displayName: name,
    path,
    displayPath: path,
    kind,
    size: null,
    permissions: null,
    mode: null,
    uid: null,
    user: null,
    gid: null,
    group: null,
    modified: null,
    risks: { control: false, bidi: false, invisible: false, separator: false },
  };
}

/** A listing function over a fixed tree. */
function treeOf(tree: Record<string, DirectoryEntry[]>) {
  return (path: string) => Promise.resolve(tree[path] ?? []);
}

describe("previewRemoval", () => {
  it("counts one file without listing anything", () => {
    const list = vi.fn(() => Promise.resolve([]));
    return previewRemoval(node("/srv/a.txt", "file"), list).then((preview) => {
      expect(preview).toMatchObject({ files: 1, directories: 0, truncated: false });
      expect(list).not.toHaveBeenCalled();
    });
  });

  it("counts a tree without counting its own root", () => {
    // Counting the root would make "and 1 folder" appear for an empty
    // directory, which reads as though something were inside it.
    const list = treeOf({
      "/srv/build": [node("/srv/build/a.txt", "file"), node("/srv/build/sub", "directory")],
      "/srv/build/sub": [node("/srv/build/sub/b.txt", "file")],
    });
    return previewRemoval(node("/srv/build", "directory"), list).then((preview) => {
      expect(preview.files).toBe(2);
      expect(preview.directories).toBe(1);
      expect(preview.truncated).toBe(false);
    });
  });

  it("does not follow a link, and says there was one", () => {
    // The engine's own walk stats with `symlink_metadata`, so a link to a
    // directory is unlinked rather than emptied. A preview that descended would
    // promise a removal far larger than the one that happens — and a link
    // pointing back up its own tree would never finish.
    const list = vi.fn((path: string) =>
      Promise.resolve(path === "/srv/build" ? [node("/srv/build/home", "symlink")] : [node("/never", "file")]),
    );
    return previewRemoval(node("/srv/build", "directory"), list).then((preview) => {
      expect(preview.files).toBe(1);
      expect(preview.links).toBe(1);
      expect(preview.directories).toBe(0);
      expect(list).toHaveBeenCalledTimes(1);
    });
  });

  it("stops at its own limit and says the count is a floor", () => {
    const many = Array.from({ length: PREVIEW_LIMIT + 50 }, (_, i) => node(`/srv/build/f${String(i)}`, "file"));
    const list = treeOf({ "/srv/build": many });
    return previewRemoval(node("/srv/build", "directory"), list).then((preview) => {
      expect(preview.truncated).toBe(true);
      expect(preview.files).toBeLessThanOrEqual(PREVIEW_LIMIT);
    });
  });

  it("stops at its own depth", () => {
    // A tree deeper than this is not one anybody meant to point at, and the
    // walk must not follow it to the bottom before the dialog can be read.
    const tree: Record<string, DirectoryEntry[]> = {};
    let path = "/srv/deep";
    for (let depth = 0; depth < PREVIEW_DEPTH + 5; depth += 1) {
      const child = `${path}/d`;
      tree[path] = [node(child, "directory")];
      path = child;
    }
    return previewRemoval(node("/srv/deep", "directory"), treeOf(tree)).then((preview) => {
      expect(preview.truncated).toBe(true);
      expect(preview.directories).toBeLessThanOrEqual(PREVIEW_DEPTH);
    });
  });

  it("keeps going past a subdirectory it cannot read, and marks the count", () => {
    // The user cannot read a directory they cannot read, and the server will
    // say the same thing to the removal. Refusing outright would block a
    // removal that would otherwise mostly succeed — but the count is no longer
    // the whole of it, and the dialog has to say so.
    const list = (path: string) => {
      if (path === "/srv/build") {
        return Promise.resolve([node("/srv/build/locked", "directory"), node("/srv/build/a.txt", "file")]);
      }
      return Promise.reject(new Error("permission denied"));
    };
    return previewRemoval(node("/srv/build", "directory"), list).then((preview) => {
      expect(preview.files).toBe(1);
      expect(preview.directories).toBe(1);
      expect(preview.truncated).toBe(true);
    });
  });

  it("stops when the caller aborts", () => {
    const controller = new AbortController();
    controller.abort();
    return previewRemoval(node("/srv/build", "directory"), treeOf({}), controller.signal).then((preview) => {
      expect(preview.truncated).toBe(true);
    });
  });

  it("samples the top of the tree, and no more than a handful", () => {
    const many = Array.from({ length: SAMPLE_SIZE + 10 }, (_, i) => node(`/srv/build/f${String(i)}`, "file"));
    return previewRemoval(node("/srv/build", "directory"), treeOf({ "/srv/build": many })).then((preview) => {
      expect(preview.sample).toHaveLength(SAMPLE_SIZE);
      expect(preview.sample[0]).toBe("/srv/build/f0");
    });
  });

  it("counts an entry whose name is not a single component without descending into it", () => {
    // The core refuses to build a path from such a name, so there is nothing to
    // list. It is still going to be removed, so it is still counted.
    const hostile = { ...node("/srv/build/x", "directory"), risks: { control: false, bidi: false, invisible: false, separator: true } };
    const list = vi.fn(() => Promise.resolve([hostile]));
    return previewRemoval(node("/srv/build", "directory"), list).then((preview) => {
      expect(preview.directories).toBe(1);
      expect(list).toHaveBeenCalledTimes(1);
    });
  });
});
