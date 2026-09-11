/**
 * Remote paths, and the one rule that matters about them.
 *
 * An SFTP path is `/`-separated whatever the server runs on — a Windows SFTP
 * server still speaks `/home/deploy`, because the separator is the protocol's
 * and not the filesystem's (`docs/architecture/sftp-command-surface.md`,
 * "Naming and shape"). So there is exactly one separator in this file and it is
 * never conditional on a platform.
 *
 * **A path is only ever built from a name this interface can see the user
 * type.** Every path that addresses something on the server comes back from
 * the server — `DirectoryEntry.path`, `sftp_canonicalize` — and is used
 * verbatim. The two exceptions are creating a folder and renaming an entry,
 * where the user types the last component, and both go through
 * {@link validateName} first. Joining a *server-supplied* name onto a directory
 * is the mistake the command surface is most emphatic about: a name containing
 * `../` turns an action in one folder into an action in another, which is why
 * `DirectoryEntry.risks.separator` exists and why a row carrying it offers no
 * actions at all.
 *
 * Display paths are escaped twins and are for reading only. {@link displayTail}
 * is the one function here that takes one, and it exists so that a queue row
 * can show a file name rather than a forty-character path.
 */

const SEPARATOR = "/";

/** The top of the tree, and the path a pane falls back to when it has nothing. */
export const ROOT = "/";

/**
 * Why a typed name cannot be used, as a catalogue key under `name.*`.
 *
 * `null` means it is usable. These are the *interface's* rules, checked before
 * a command is sent; the core checks again and may refuse for reasons only it
 * can see. Checking here is not a substitute for that — it is what turns a
 * round trip into an inline message under the field.
 */
export type NameRefusal = "empty" | "separator" | "dots" | "control";

export function validateName(name: string): NameRefusal | null {
  const trimmed = name.trim();
  if (trimmed === "") return "empty";
  // Both separators are refused. A backslash is a legal character in a POSIX
  // file name, but a name containing one is almost always a Windows path that
  // has been pasted in, and creating `C:\temp\x` as a single file in the
  // current directory is never what was meant.
  if (trimmed.includes(SEPARATOR) || trimmed.includes("\\")) return "separator";
  if (trimmed === "." || trimmed === "..") return "dots";
  // Control characters in a name are what make a listing row lie about itself.
  // The server would accept them; this interface will not create one.
  // eslint-disable-next-line no-control-regex -- the class is the point: C0, DEL and C1.
  if (/[\u0000-\u001F\u007F-\u009F]/.test(trimmed)) return "control";
  return null;
}

/** `/srv/app` + `logs` -> `/srv/app/logs`. The name must already be validated. */
export function joinPath(directory: string, name: string): string {
  const base = directory.endsWith(SEPARATOR) ? directory.slice(0, -1) : directory;
  return `${base}${SEPARATOR}${name}`;
}

/**
 * The directory containing `path`, or `null` at the top.
 *
 * `null` rather than returning `/` for `/`, so the control that goes up can be
 * disabled and explained instead of looking like it did nothing.
 */
export function parentPath(path: string): string | null {
  if (path === ROOT || path === "") return null;
  const trimmed = path.endsWith(SEPARATOR) ? path.slice(0, -1) : path;
  const cut = trimmed.lastIndexOf(SEPARATOR);
  if (cut < 0) return null;
  return cut === 0 ? ROOT : trimmed.slice(0, cut);
}

/** One step of the trail above the current folder. */
export interface Crumb {
  /** The raw path this step addresses. What a click sends to the core. */
  path: string;
  /**
   * The same, escaped — so that navigating to this step keeps a display form
   * for the trail it draws next. Never sent anywhere.
   */
  displayPath: string;
  /**
   * What the step is called, for reading.
   *
   * Derived from the *escaped* path, so a folder whose name carries a
   * right-to-left override cannot reorder the trail it sits in.
   */
  label: string;
}

/**
 * The trail from the root down to `path`, root first.
 *
 * Both forms are walked in step rather than escaping the raw one here: the
 * escaped path is produced by the core, which is the only place that knows the
 * escaping rules, and re-deriving it in the frontend would be a second
 * implementation to keep in step with the first.
 *
 * A display path that does not have the same number of segments as the raw one
 * — which a name containing a separator would produce — falls back to the raw
 * segment count and labels the odd ones from the raw text. That is not a
 * security hole: such an entry carries `risks.separator`, is never navigable,
 * and the caller does not build a trail through one.
 */
export function breadcrumbs(path: string, displayPath: string): Crumb[] {
  const rawParts = path.split(SEPARATOR).filter((part) => part !== "");
  const shownParts = displayPath.split(SEPARATOR).filter((part) => part !== "");
  const crumbs: Crumb[] = [];
  let accumulated = "";
  let shownAccumulated = "";
  for (const [index, part] of rawParts.entries()) {
    const label = shownParts[index] ?? part;
    accumulated = `${accumulated}${SEPARATOR}${part}`;
    shownAccumulated = `${shownAccumulated}${SEPARATOR}${label}`;
    crumbs.push({ path: accumulated, displayPath: shownAccumulated, label });
  }
  return crumbs;
}

/**
 * The last segment of an escaped path, for a row that has no room for all of it.
 *
 * Takes the display form only. Nothing addressed with the result, ever — it is
 * a label, and the raw path travels beside it in the same object.
 */
export function displayTail(displayPath: string): string {
  const parts = displayPath.split(SEPARATOR).filter((part) => part !== "");
  return parts[parts.length - 1] ?? displayPath;
}

/**
 * Whether a path the user typed into the path field is worth sending.
 *
 * Only absoluteness is checked. Everything else — whether it exists, whether it
 * is a directory, whether the account may read it — is the server's to answer,
 * and guessing here would produce a refusal the server disagrees with.
 */
export function isAbsolute(path: string): boolean {
  return path.startsWith(SEPARATOR);
}
