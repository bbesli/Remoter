/**
 * The SFTP file manager, bound to one session: two panes, a queue, and the
 * dialogs between them.
 *
 * # It attaches to a session; it does not make one
 *
 * `SftpBrowser::open` takes the connection a tab is already using and opens one
 * more channel on it (RFC 4254 §6.5), so a file pane on a host with a shell
 * costs a channel rather than a handshake, a host key check and an
 * authentication. That is why this component takes a session id rather than a
 * node id and offers no connect button: there is one place in this application
 * where a host key question is asked and a credential is used, and it is the
 * session pipeline. Opening a second one here would be a second lifetime to get
 * wrong.
 *
 * It used to choose its own session from a dropdown over every open tab, and
 * that was the shape of a screen that was never mounted. A pane belongs to the
 * tab it is looking at — an SFTP tab *is* this component, and an SSH tab docks
 * it under its terminal — so the session is now a prop and the two callers in
 * `features/shell` and `features/sessions` decide which one it is. That also
 * leaves this file with no import of the sessions feature at all, which is what
 * lets the session surface import *this* one without a cycle.
 *
 * A session that ends takes its pane with it — the pane's cancellation token is
 * a child of the session's — so nothing here has to watch for that.
 *
 * # What crosses between the panes
 *
 * A download is `sftp_enqueue` with `direction: "download"`, the remote path
 * the server gave, and a **folder** from the picker. The core derives the local
 * file name from the remote path through `local_name_for`; this screen never
 * joins a server-supplied name onto a local folder, which is the one thing the
 * command surface is most emphatic must not happen.
 *
 * An upload is the same with `"upload"`, a local path the picker gave, and a
 * remote path built from the current folder and the *local* file's own name —
 * the user's string, not the server's.
 */

import { useMemo, useState } from "react";
import { useMutation } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { BusyStatus } from "@/components/Busy";
import { Icon } from "@/components/Icon";
import { isolate, useT } from "@/i18n";
import { asFailure, ipc, type DirectoryEntry, type IpcFailure, type SftpPane, type TransferRequest } from "@/lib/ipc";

import { DeleteDialog } from "./DeleteDialog";
import { LocalPane } from "./LocalPane";
import { NameDialog } from "./NameDialog";
import { RemotePane } from "./RemotePane";
import { TransferQueuePanel } from "./TransferQueuePanel";
import { joinPath, parentPath, validateName } from "./path";
import { usePane } from "./usePane";
import { useDirectory } from "./useDirectory";

import s from "./FilePane.module.css";

export interface FilePaneProps {
  /**
   * The core's id for the session this pane opens its channel on. Null while
   * the tab is still connecting — the pane cannot exist before the connection
   * has authenticated, and this says so rather than drawing an empty browser.
   */
  sessionId: number | null;
  /** The connection's own name, from the vault. */
  name: string;
  /**
   * Puts the pane away again. Passed by the tab strip's dock, where the pane is
   * a panel over a terminal the user still has. A file session's own tab passes
   * nothing: there is no terminal underneath it, and closing it is closing the
   * tab.
   */
  onClose?: (() => void) | undefined;
}

export function FilePane({ sessionId, name, onClose }: FilePaneProps) {
  const t = useT("files");
  const { pane, opening, problem, retry } = usePane(sessionId);

  return (
    <section className={s.screen} aria-label={t("header.title")}>
      <header className={s.header}>
        <h2 className={s.title}>{t("header.title")}</h2>
        {/* The connection's own name, from the vault. Isolated: a name in any
            script must not reorder the heading around it. */}
        <span className={s.on}>{t("header.on", { name: isolate(name) })}</span>
        <div className={s.spacer} />
        {onClose !== undefined && (
          <Button variant="ghost" size="sm" onClick={onClose} title={t("header.close")}>
            <Icon name="x" size={13} />
            <span className={s.closeLabel}>{t("header.close")}</span>
          </Button>
        )}
      </header>

      {sessionId === null && (
        <div className={s.centred}>
          <Callout tone="neutral" title={t("pane.notConnectedTitle")}>
            <p>{t("pane.notConnectedBody")}</p>
          </Callout>
        </div>
      )}

      {opening && (
        <div className={s.centred}>
          <BusyStatus label={t("pane.opening")} />
        </div>
      )}

      {problem !== null && (
        <div className={s.centred}>
          <FailureNotice failure={problem} title={t("pane.openFailed")} onRetry={retry} />
        </div>
      )}

      {/* Keyed by the pane, so a reconnect resets the folder, the selection and
          the staged files together rather than carrying one connection's state
          onto its successor's. */}
      {pane !== null && <PaneWorkspace key={pane.paneId} pane={pane} />}
    </section>
  );
}

/** Which button was pressed with something missing. */
type Blocker = "needFolder" | "needFiles" | "needSelection";

const BLOCKER_KEY = {
  needFolder: "transferTo.needFolder",
  needFiles: "transferTo.needFiles",
  needSelection: "transferTo.needSelection",
} as const satisfies Record<Blocker, string>;

type Dialog =
  | { kind: "newFolder" }
  | { kind: "rename"; entry: DirectoryEntry }
  | { kind: "delete"; entry: DirectoryEntry }
  | null;

function PaneWorkspace({ pane }: { pane: SftpPane }) {
  const t = useT("files");

  const [location, setLocation] = useState({ path: pane.home, displayPath: pane.homeDisplay });
  const [selection, setSelection] = useState<ReadonlySet<string>>(new Set());
  const [folder, setFolder] = useState<string | null>(null);
  const [staged, setStaged] = useState<readonly string[]>([]);
  const [resume, setResume] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [blocker, setBlocker] = useState<Blocker | null>(null);
  const [enqueueProblem, setEnqueueProblem] = useState<IpcFailure | null>(null);

  const view = useDirectory(pane.paneId, location.path);

  const enqueue = useMutation({
    mutationFn: (requests: TransferRequest[]) => ipc.enqueueTransfers(pane.paneId, requests),
    onSuccess: () => {
      setEnqueueProblem(null);
      // The queue panel's own query picks the new entries up; nothing here has
      // to hold them.
    },
    onError: (error: unknown) => {
      setEnqueueProblem(asFailure(error));
    },
  });

  const chosenEntries = useMemo(
    () => view.visible.filter((entry) => selection.has(entry.path)),
    [view.visible, selection],
  );

  const download = () => {
    setBlocker(null);
    setEnqueueProblem(null);
    if (folder === null) {
      setBlocker("needFolder");
      return;
    }
    if (chosenEntries.length === 0) {
      setBlocker("needSelection");
      return;
    }
    enqueue.mutate(
      chosenEntries.map((entry) => ({
        direction: "download",
        // The raw path, exactly as the server sent it.
        remote: entry.path,
        // A folder, never a file name this screen built. `local_name_for` in
        // the core decides the file name from the remote path and refuses
        // anything that still looks like a traversal.
        localDirectory: folder,
        resume,
      })),
    );
  };

  const upload = () => {
    setBlocker(null);
    setEnqueueProblem(null);
    if (staged.length === 0) {
      setBlocker("needFiles");
      return;
    }
    const requests: TransferRequest[] = [];
    for (const local of staged) {
      const name = localBaseName(local);
      // The name came from this machine's own file picker, not from the server,
      // so joining it onto the current folder is safe — and it is still checked,
      // because a batch with one impossible name should refuse as a batch.
      if (validateName(name) !== null) continue;
      requests.push({ direction: "upload", remote: joinPath(location.path, name), local, resume });
    }
    if (requests.length === 0) {
      setBlocker("needFiles");
      return;
    }
    enqueue.mutate(requests);
  };

  const busy = enqueue.isPending;

  return (
    <>
      {blocker !== null && (
        <div className={s.blockers}>
          <Callout tone="warning">{t(BLOCKER_KEY[blocker])}</Callout>
        </div>
      )}

      <div className={s.panes}>
        <RemotePane
          view={view}
          path={location.path}
          displayPath={location.displayPath}
          home={pane.home}
          homeDisplay={pane.homeDisplay}
          selection={selection}
          onSelectionChange={setSelection}
          onNavigate={(next) => {
            setSelection(new Set());
            setLocation(next);
          }}
          onNewFolder={() => {
            setDialog({ kind: "newFolder" });
          }}
          onRename={(entry) => {
            setDialog({ kind: "rename", entry });
          }}
          onDelete={(entry) => {
            setDialog({ kind: "delete", entry });
          }}
          onDownload={download}
          onUploadDropped={upload}
          busy={busy}
        />

        <LocalPane
          folder={folder}
          onFolderChange={setFolder}
          staged={staged}
          onStagedChange={setStaged}
          onUpload={upload}
          onDownloadDropped={download}
          busy={busy}
        />
      </div>

      {/* Beside the buttons that fill it, and mounted for as long as the pane
          is — including while its tab is in the background, which is what lets
          a transfer outlive a tab switch rather than being cancelled by one. */}
      <TransferQueuePanel
        paneId={pane.paneId}
        resume={resume}
        onResumeChange={setResume}
        enqueueProblem={enqueueProblem}
      />

      {dialog?.kind === "newFolder" && (
        <NameDialog
          paneId={pane.paneId}
          directory={location.path}
          directoryDisplay={location.displayPath}
          onClose={() => {
            setDialog(null);
          }}
        />
      )}

      {dialog?.kind === "rename" && (
        <NameDialog
          paneId={pane.paneId}
          // The parent of the entry, not the folder on screen: a rename writes
          // beside the thing it renames.
          directory={parentPath(dialog.entry.path) ?? location.path}
          directoryDisplay={parentPath(dialog.entry.displayPath) ?? location.displayPath}
          entry={dialog.entry}
          onClose={() => {
            setDialog(null);
          }}
        />
      )}

      {dialog?.kind === "delete" && (
        <DeleteDialog
          paneId={pane.paneId}
          entry={dialog.entry}
          onClose={() => {
            setSelection(new Set());
            setDialog(null);
          }}
        />
      )}
    </>
  );
}

/**
 * The last component of a path the *local* picker produced.
 *
 * Both separators, because the platform is Windows about as often as it is not.
 * This is the one place a name is taken from a path and used to build another
 * path, and it is safe for one reason only: the string came from this machine's
 * file picker rather than from the far end.
 */
function localBaseName(path: string): string {
  const parts = path.split(/[\\/]/).filter((part) => part !== "");
  return parts[parts.length - 1] ?? path;
}
