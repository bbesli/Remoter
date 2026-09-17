/**
 * Step 6 — where the import lands.
 *
 * The folders are the vault's own, read by the wizard through the same query
 * key anything else reading the tree uses, so a folder created a minute ago in
 * the main window is already in this list. The read is passed in rather than
 * done here because the commit and result steps need the chosen folder's name
 * too, and one query for the three of them is one failure to handle.
 *
 * Importing into a folder of its own is a recommendation, not a rule: the core
 * cannot undo a commit, and a subtree that is easy to find is a subtree that is
 * easy to delete if the result is not what was wanted.
 */

import { BusyStatus, SkeletonRows } from "@/components/Busy";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { compareInLocale, isolate, useT } from "@/i18n";
import type { ConflictPolicy, ImportConflicts, IpcFailure, TreeNode } from "@/lib/ipc";

import s from "./ImportWizard.module.css";

/**
 * What separates the folders of a breadcrumb: "Datacentre EU-West / Web tier".
 *
 * Punctuation rather than copy, and it is not mirrored for a right-to-left
 * layout — each folder name is isolated where it is drawn, so the crumb reads
 * in the document's direction whatever script the names are in.
 */
const PATH_SEPARATOR = " / ";

export interface FolderOption {
  id: string;
  /** "Datacentre EU-West / Web tier", so two folders called "Web" are told apart. */
  path: string;
}

interface DestinationStepProps {
  destinationId: string | null;
  onDestination: (id: string | null) => void;
  /** `null` while the vault's tree is still being read. */
  folders: FolderOption[] | null;
  pending: boolean;
  failure: IpcFailure | null;
  onRetry: () => void;
  /** What the import collides with at the chosen destination; `null` while asked. */
  conflicts: ImportConflicts | null;
  conflictsFailure: IpcFailure | null;
  policy: ConflictPolicy;
  onPolicy: (policy: ConflictPolicy) => void;
}

/** How many colliding items are named on screen; the count says the rest. */
const LISTED_CONFLICTS = 5;

const POLICIES: readonly {
  id: ConflictPolicy;
  labelKey:
    | "destination.conflicts.keepBoth"
    | "destination.conflicts.skip"
    | "destination.conflicts.replace";
  hintKey:
    | "destination.conflicts.keepBothHint"
    | "destination.conflicts.skipHint"
    | "destination.conflicts.replaceHint";
}[] = [
  {
    id: "keep-both",
    labelKey: "destination.conflicts.keepBoth",
    hintKey: "destination.conflicts.keepBothHint",
  },
  { id: "skip", labelKey: "destination.conflicts.skip", hintKey: "destination.conflicts.skipHint" },
  {
    id: "replace",
    labelKey: "destination.conflicts.replace",
    hintKey: "destination.conflicts.replaceHint",
  },
];

export function DestinationStep({
  destinationId,
  onDestination,
  folders,
  pending,
  failure,
  onRetry,
  conflicts,
  conflictsFailure,
  policy,
  onPolicy,
}: DestinationStepProps) {
  const t = useT("import");

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{t("destination.title")}</h2>
        <p className={s.stepLead}>{t("destination.lead")}</p>
      </div>

      {pending && (
        <div className={s.card}>
          <BusyStatus label={t("destination.loading")} />
          <SkeletonRows count={4} />
        </div>
      )}

      {failure !== null && !pending && (
        <FailureNotice
          failure={failure}
          title={t("destination.loadFailed")}
          onRetry={onRetry}
          retryLabel={t("destination.retry")}
        />
      )}

      {folders !== null && (
        <div className={s.destList} role="radiogroup" aria-label={t("destination.chooseLabel")}>
          <button
            type="button"
            role="radio"
            aria-checked={destinationId === null}
            className={s.destOption}
            data-selected={destinationId === null}
            onClick={() => onDestination(null)}
          >
            <span className={s.rowIcon} aria-hidden="true">
              <Icon name="folder" size={13} />
            </span>
            {t("destination.topOption")}
          </button>
          {folders.map((folder) => (
            <button
              key={folder.id}
              type="button"
              role="radio"
              aria-checked={destinationId === folder.id}
              className={s.destOption}
              data-selected={destinationId === folder.id}
              onClick={() => onDestination(folder.id)}
            >
              <span className={`${s.rowIcon} ${s.rowIconFolder}`} aria-hidden="true">
                <Icon name="folder" size={13} />
              </span>
              {/* The breadcrumb is the user's own folder names, in whatever
                  script they wrote them. */}
              {isolate(folder.path)}
            </button>
          ))}
        </div>
      )}

      {folders !== null && folders.length === 0 && (
        <p className={s.stepLead}>{t("destination.noFolders")}</p>
      )}

      {conflictsFailure !== null && (
        <FailureNotice failure={conflictsFailure} title={t("destination.conflicts.failed")} />
      )}

      {conflicts !== null && conflicts.total > 0 && (
        <div className={s.card}>
          <Callout tone="warning" title={t("destination.conflicts.title", { count: conflicts.total })}>
            <ul className={s.conflictList}>
              {conflicts.items.slice(0, LISTED_CONFLICTS).map((item, index) => (
                // Two items can share a name and a folder; the position is the identity.
                <li key={index}>
                  {item.path === ""
                    ? t("destination.conflicts.itemAtTop", { name: isolate(item.name) })
                    : t("destination.conflicts.item", {
                        name: isolate(item.name),
                        path: isolate(item.path),
                      })}
                </li>
              ))}
            </ul>
            {conflicts.total > LISTED_CONFLICTS && (
              <p>{t("destination.conflicts.more", { count: conflicts.total - LISTED_CONFLICTS })}</p>
            )}
          </Callout>
          <div
            className={s.formatList}
            role="radiogroup"
            aria-label={t("destination.conflicts.policyLabel")}
          >
            {POLICIES.map((entry) => (
              <button
                key={entry.id}
                type="button"
                role="radio"
                aria-checked={policy === entry.id}
                className={s.formatOption}
                data-selected={policy === entry.id}
                onClick={() => onPolicy(entry.id)}
              >
                <span>{t(entry.labelKey)}</span>
                <span className={s.formatHint}>{t(entry.hintKey)}</span>
              </button>
            ))}
          </div>
        </div>
      )}

      <p className={s.stepLead}>{t("destination.advice")}</p>
    </div>
  );
}

/**
 * Folders, each with the breadcrumb that identifies it.
 *
 * `group` counts as a folder here: it is a folder with credential-sharing
 * semantics, and it can hold imported nodes exactly as a folder can.
 *
 * `locale` orders the result; the list is read, not computed against.
 */
export function folderPaths(nodes: readonly TreeNode[], locale: string): FolderOption[] {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const options: FolderOption[] = [];

  for (const node of nodes) {
    if (node.kind !== "folder" && node.kind !== "group") continue;
    const parts: string[] = [node.name];
    let cursor = node.parentId;
    // Bounded by the number of nodes: a parent cycle would otherwise spin
    // here, and this list is built on every render of the step.
    for (let hops = 0; cursor !== null && hops < nodes.length; hops += 1) {
      const parent = byId.get(cursor);
      if (parent === undefined) break;
      parts.unshift(parent.name);
      cursor = parent.parentId;
    }
    options.push({ id: node.id, path: parts.join(PATH_SEPARATOR) });
  }

  // Ordered for the reader, so it follows the language the interface is in
  // rather than the one the host operating system is set to. A breadcrumb is
  // made of folder names somebody typed, which is precisely the text whose
  // order differs between languages.
  return options.sort((a, b) => compareInLocale(a.path, b.path, locale));
}
