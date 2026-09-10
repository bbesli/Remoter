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
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import type { IpcFailure, TreeNode } from "@/lib/ipc";

import s from "./ImportWizard.module.css";

const TEXT = {
  title: "Where should this go?",
  lead: "Everything ticked in the preview is created under the folder you choose here, keeping the structure the file had.",
  top: "The top level of the vault",
  loading: "Reading the vault's folders…",
  loadFailed: "The vault's folders could not be read.",
  retry: "Try again",
  noFolders:
    "This vault has no folders yet. The import lands at the top level, keeping its own structure.",
  advice:
    "A folder of its own is the safest choice. Remoter cannot undo a commit, and an import you can see in one place is an import you can delete in one action if it is not what you wanted.",
  chooseLabel: "Destination folder",
} as const;

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
}

export function DestinationStep({
  destinationId,
  onDestination,
  folders,
  pending,
  failure,
  onRetry,
}: DestinationStepProps) {
  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{TEXT.title}</h2>
        <p className={s.stepLead}>{TEXT.lead}</p>
      </div>

      {pending && (
        <div className={s.card}>
          <BusyStatus label={TEXT.loading} />
          <SkeletonRows count={4} />
        </div>
      )}

      {failure !== null && !pending && (
        <FailureNotice
          failure={failure}
          title={TEXT.loadFailed}
          onRetry={onRetry}
          retryLabel={TEXT.retry}
        />
      )}

      {folders !== null && (
        <div className={s.destList} role="radiogroup" aria-label={TEXT.chooseLabel}>
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
            {TEXT.top}
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
              {folder.path}
            </button>
          ))}
        </div>
      )}

      {folders !== null && folders.length === 0 && <p className={s.stepLead}>{TEXT.noFolders}</p>}

      <p className={s.stepLead}>{TEXT.advice}</p>
    </div>
  );
}

/**
 * Folders, each with the breadcrumb that identifies it.
 *
 * `group` counts as a folder here: it is a folder with credential-sharing
 * semantics, and it can hold imported nodes exactly as a folder can.
 */
export function folderPaths(nodes: readonly TreeNode[]): FolderOption[] {
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
    options.push({ id: node.id, path: parts.join(" / ") });
  }

  return options.sort((a, b) => a.path.localeCompare(b.path));
}
