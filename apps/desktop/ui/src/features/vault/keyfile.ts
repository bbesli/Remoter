/**
 * The rules for choosing a key file, shared by the unlock screen and the
 * create wizard.
 *
 * They exist because of one real lock-out. The browser opened in the vault's
 * own folder, the `.rvault` was the obvious file in it, it was chosen as the
 * key file, and the unlock then failed with "That did not unlock the vault." —
 * the one message that is deliberately unable to explain itself. The password
 * was never wrong.
 *
 * Two halves fix it. The dialog filters make the right file obvious without
 * ruling anything out, because the design is explicit that ANY file can be a
 * key file: a .pem, a photograph, a random blob. A hard filter would lock out
 * everyone whose key file is a .pem, so "All files" is not optional.
 *
 * And the vault itself is refused outright. That one is a certainty rather
 * than a warning: a vault file cannot be its own key file, because the key
 * file is read before the vault is opened and the header would have to unwrap
 * a slot keyed by its own bytes.
 */

/**
 * Offered in order. The first names what most people are looking for; the
 * second is what makes every other key file reachable.
 *
 * A function rather than a constant because the dialog plugin's `DialogFilter`
 * takes a mutable `string[]`, and one shared array handed to every call site is
 * a shared mutable it could write through.
 */
export function keyfileFilters(): { name: string; extensions: string[] }[] {
  return [
    { name: "Remoter key file", extensions: ["keyfile"] },
    { name: "All files", extensions: ["*"] },
  ];
}

const TEXT = {
  isTheVault: (name: string) =>
    `${name} is the vault itself, not its key file. Choose a different file.`,
  isAVault: (name: string) =>
    `${name} is a Remoter vault, not a key file. Choose a different file.`,
  isABackup: (name: string) =>
    `${name} is a rolling backup of a vault, not a key file. Choose a different file.`,
} as const;

/** `vault.rvault.bak.1` — the rolling backups written beside a vault. */
const BACKUP_SUFFIX = /\.rvault\.bak\.\d+$/i;
const VAULT_SUFFIX = /\.rvault$/i;

function fileName(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut >= 0 ? path.slice(cut + 1) : path;
}

/**
 * Windows paths differ only in case and in separator; two spellings of one file
 * must compare equal or the "this is the vault you are opening" check misses.
 */
function samePath(a: string, b: string): boolean {
  const normalise = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return normalise(a) === normalise(b);
}

/**
 * Why this path cannot be a key file, or null when it can be one.
 *
 * `vaultPath` may be empty — the wizard has not always settled on one by the
 * time a key file is chosen — in which case only the extension rules apply.
 */
export function keyfileRefusal(path: string, vaultPath: string): string | null {
  if (path === "") return null;
  const name = fileName(path);
  if (vaultPath !== "" && samePath(path, vaultPath)) return TEXT.isTheVault(name);
  if (BACKUP_SUFFIX.test(path)) return TEXT.isABackup(name);
  if (VAULT_SUFFIX.test(path)) return TEXT.isAVault(name);
  return null;
}

/** The folder a path sits in, with its trailing separator kept. */
export function folderOf(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut < 0 ? "" : path.slice(0, cut + 1);
}
