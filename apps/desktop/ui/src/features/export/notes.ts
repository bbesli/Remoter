/**
 * Turning an export's notes into sentences.
 *
 * Each note is the core saying "this is in the file, but not the way the vault
 * holds it" — a connection left out, a route written without a hop's own
 * credential, a name changed so `ssh` can select it. None of them is an error,
 * and all of them are things a person would otherwise find out later, in a
 * terminal, when a route does not go where they expected.
 *
 * The names in a note come from the user's own tree and may be in any script,
 * so each one is isolated before it goes into the sentence.
 *
 * Pure, and taking `t` as a parameter: it is called from a render loop and
 * `useT` is a hook.
 */

import type { TFunction } from "i18next";

import { isolate } from "@/i18n";
import type { ExportNote } from "@/lib/ipc";

export function describeNote(t: TFunction<"connections">, note: ExportNote): string {
  switch (note.kind) {
    case "unsupported-protocol":
      return t("export.note.unsupportedProtocol", {
        item: isolate(note.item),
        // A protocol id as the core spells it — `rdp` — is not a word; its
        // name in writing is the upper-case form.
        protocol: note.protocol.toUpperCase(),
      });
    case "gateway-not-written":
      switch (note.reason) {
        case "deleted-hop":
          return t("export.note.deletedHop", { item: isolate(note.item) });
        case "ambiguous-hop":
          return t("export.note.ambiguousHop", { item: isolate(note.item) });
        case "hop-outside-export":
          return t("export.note.hopOutsideExport", { item: isolate(note.item) });
        case "hop-credential":
          return t("export.note.hopCredential", { item: isolate(note.item) });
        case "hop-not-ssh":
          return t("export.note.hopNotSsh", { item: isolate(note.item) });
      }
      break;
    case "renamed":
      return t("export.note.renamed", {
        item: isolate(note.item),
        written: isolate(note.written),
      });
    case "folder-name-splits":
      return t("export.note.folderNameSplits", { folder: isolate(note.folder) });
    case "value-not-written":
      return t("export.note.valueNotWritten", {
        item: isolate(note.item),
        field: fieldName(t, note.field),
      });
    case "outside-reference":
      return t("export.note.outsideReference", {
        item: isolate(note.item),
        target: isolate(note.target),
      });
  }
  // A note a newer core wrote and this build has no sentence for. Said in
  // general terms rather than dropped: the file still differs from the vault.
  return t("export.note.valueNotWritten", {
    item: isolate(itemOf(note)),
    field: t("export.note.fieldOther"),
  });
}

/** The noun for a field the core names by its own spelling. */
function fieldName(t: TFunction<"connections">, field: string): string {
  switch (field) {
    case "user":
      return t("export.note.fieldUser");
    case "identity-file":
      return t("export.note.fieldIdentityFile");
    case "proxy-jump-user":
      return t("export.note.fieldProxyJumpUser");
    default:
      return t("export.note.fieldOther");
  }
}

function itemOf(note: ExportNote): string {
  const value: unknown = (note as { item?: unknown }).item;
  return typeof value === "string" ? value : "";
}
