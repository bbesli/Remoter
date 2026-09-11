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
 *
 * **Why these read the catalogue through the instance rather than `useT()`.**
 * Both exported functions are plain functions, not components, and both are
 * called from screens outside this feature — the main window's KDF upgrade bar
 * and the vault-settings key file field — which ask for their own namespace.
 * A hook is not available to them, so the accessor below takes `t` from the
 * shared instance. The catalogue is requested here as well as by the screens
 * in this directory, so a caller that never renders an unlock screen still
 * gets the vault catalogue in the reader's language rather than the English
 * fallback.
 */

import type { TFunction } from "i18next";

import { i18n, isolate } from "@/i18n";

/**
 * `t()` for the vault catalogue, outside a component.
 *
 * Read on every call rather than captured once: the language changes at
 * runtime, and a `t` captured at module scope would answer in whichever
 * language was in force when this file was first imported.
 */
function vaultT(): TFunction<"vault"> {
  return i18n().getFixedT(null, "vault");
}

// The screens in this directory pull the catalogue in through `useT("vault")`.
// Nothing guarantees one of them has rendered before a refusal is needed, so
// ask for it here too. English is compiled in and is the fallback until the
// fetch lands, which makes this a quality improvement rather than a race.
void i18n().loadNamespaces("vault");

/**
 * Offered in order. The first names what most people are looking for; the
 * second is what makes every other key file reachable.
 *
 * A function rather than a constant because the dialog plugin's `DialogFilter`
 * takes a mutable `string[]`, and one shared array handed to every call site is
 * a shared mutable it could write through.
 */
export function keyfileFilters(): { name: string; extensions: string[] }[] {
  const t = vaultT();
  return [
    { name: t("keyfile.filterKeyfile"), extensions: ["keyfile"] },
    { name: t("keyfile.filterAll"), extensions: ["*"] },
  ];
}

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
 *
 * The file name is a user's own, in any script, and it is dropped into the
 * middle of a sentence in the interface's language. It is isolated so that a
 * name beginning with an Arabic or Hebrew character cannot reorder the words
 * around it — see src/i18n/bidi.ts.
 */
export function keyfileRefusal(path: string, vaultPath: string): string | null {
  if (path === "") return null;
  const t = vaultT();
  const name = isolate(fileName(path));
  if (vaultPath !== "" && samePath(path, vaultPath)) return t("keyfile.refusal.isTheVault", { name });
  if (BACKUP_SUFFIX.test(path)) return t("keyfile.refusal.isABackup", { name });
  if (VAULT_SUFFIX.test(path)) return t("keyfile.refusal.isAVault", { name });
  return null;
}

/** The folder a path sits in, with its trailing separator kept. */
export function folderOf(path: string): string {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return cut < 0 ? "" : path.slice(0, cut + 1);
}
