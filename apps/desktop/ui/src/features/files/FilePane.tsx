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
 *
 * A **folder** on either side is one request too. The core walks it and queues
 * one transfer per file underneath, creating the directories on the way; this
 * screen sends the folder and reads the report. That report is why
 * `enqueueTransfers` does not return a bare list of ids: a walk can skip an
 * entry and stop at its own limit, and a screen holding only ids would report a
 * partial result as a success.
 *
 * # Nothing is queued before the question is asked
 *
 * Every transfer goes through `sftp_preflight` first and through the overwrite
 * dialog after it. A transfer truncates its destination and there is no trash
 * on either side, so the sequence is the delete dialog's: find out what is
 * there, say what will be lost, then ask. The one exception is a batch where
 * nothing exists and nothing could not be checked — there is nothing to warn
 * about, so it is queued directly rather than putting a dialog in front of a
 * question with no content.
 */

import { useCallback, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { BusyStatus } from "@/components/Busy";
import { Icon } from "@/components/Icon";
import { isolate, useFailureText, useT } from "@/i18n";
import {
  asFailure,
  ipc,
  type DirectoryEntry,
  type EnqueueReport,
  type EnqueueSkipped,
  type IpcFailure,
  type SftpPane,
  type TransferPreflight,
  type TransferRequest,
} from "@/lib/ipc";
import { invalidatePane } from "@/lib/queryKeys";

import { DeleteDialog } from "./DeleteDialog";
import { LocalPane } from "./LocalPane";
import { NameDialog } from "./NameDialog";
import { OverwriteDialog } from "./OverwriteDialog";
import { PropertiesDialog } from "./PropertiesDialog";
import { RemotePane } from "./RemotePane";
import { TransferQueuePanel } from "./TransferQueuePanel";
import { joinPath, parentPath, validateName } from "./path";
import { useDownloadFolder } from "./useDownloadFolder";
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
  | { kind: "properties"; entry: DirectoryEntry }
  | { kind: "overwrite"; requests: TransferRequest[]; answers: TransferPreflight[] }
  | null;

/** One folder this pane has been in, both forms together. */
interface Location {
  path: string;
  displayPath: string;
}

/** Where the pane has been, and where in that it is. */
interface Trail {
  entries: Location[];
  at: number;
}

/**
 * Goes somewhere new.
 *
 * Everything after the current position is dropped, because a browser's forward
 * button after a fresh navigation points at a page the user chose to leave.
 * Navigating to the folder already on screen is a refresh, not a step, so it
 * does not grow the trail — otherwise pressing Back after two refreshes would
 * appear to do nothing twice.
 */
function visit(trail: Trail, next: Location): Trail {
  if (trail.entries[trail.at]?.path === next.path) return trail;
  const kept = trail.entries.slice(0, trail.at + 1);
  return { entries: [...kept, next], at: kept.length };
}

/** Moves along the trail, clamped at both ends. */
function step(trail: Trail, by: number): Trail {
  const at = Math.min(Math.max(trail.at + by, 0), trail.entries.length - 1);
  return at === trail.at ? trail : { ...trail, at };
}

function PaneWorkspace({ pane }: { pane: SftpPane }) {
  const t = useT("files");
  const queryClient = useQueryClient();

  // The whole trail, and where in it the pane is — **one** piece of state, not
  // two. Back and forward move the index rather than rewriting the trail, which
  // is what makes going back and then forward land where it started; going
  // somewhere new truncates everything after the current position, the way a
  // browser does. Splitting the trail and the index into two `useState`s would
  // let a caller move one without the other, which is a pane pointing at the
  // wrong folder.
  const [trail, setTrail] = useState<Trail>(() => ({
    entries: [{ path: pane.home, displayPath: pane.homeDisplay }],
    at: 0,
  }));
  const location = trail.entries[trail.at] ?? { path: pane.home, displayPath: pane.homeDisplay };

  const [selection, setSelection] = useState<ReadonlySet<string>>(new Set());
  const [staged, setStaged] = useState<readonly string[]>([]);
  const [resume, setResume] = useState(false);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [blocker, setBlocker] = useState<Blocker | null>(null);
  const [enqueueProblem, setEnqueueProblem] = useState<IpcFailure | null>(null);
  const [report, setReport] = useState<EnqueueReport | null>(null);

  const destination = useDownloadFolder();
  const folder = destination.folder;

  const view = useDirectory(pane.paneId, location.path);

  const goTo = useCallback((next: Location) => {
    setSelection(new Set());
    setTrail((current) => visit(current, next));
  }, []);

  /**
   * Queues a batch, after asking about anything it would replace.
   *
   * The preflight is part of the action rather than a step the caller has to
   * remember: every route into a transfer — the button, a drag, a dropped row —
   * goes through here, so there is no path that queues without asking.
   */
  const start = useMutation({
    mutationFn: async (requests: TransferRequest[]) => {
      const answers = await ipc.preflightTransfers(pane.paneId, requests);
      return { requests, answers };
    },
    onSuccess: ({ requests, answers }) => {
      setEnqueueProblem(null);
      const worthAsking = answers.some(
        (answer) => answer.exists || answer.problem !== null || answer.sourceIsFolder,
      );
      if (!worthAsking) {
        enqueue.mutate(requests);
        return;
      }
      setDialog({ kind: "overwrite", requests, answers });
    },
    onError: (error: unknown) => {
      setEnqueueProblem(asFailure(error));
    },
  });

  const enqueue = useMutation({
    mutationFn: (requests: TransferRequest[]) => ipc.enqueueTransfers(pane.paneId, requests),
    onSuccess: async (result) => {
      setEnqueueProblem(null);
      setDialog(null);
      // A folder walk creates directories on the destination side, so the
      // listing on screen may already be out of date before a byte moves — and
      // the queue certainly is. The queue panel's poll cannot catch this on its
      // own: it is switched off while nothing is live, which is exactly the
      // state a pane is in when the first transfer is queued. Without this the
      // transfer the user just started never appeared at all.
      await invalidatePane(queryClient, pane.paneId);
      // Kept only while it has something to say. A complete batch is what the
      // queue itself now shows.
      setReport(result.skipped.length > 0 || result.limitReached ? result : null);
    },
    onError: (error: unknown) => {
      setEnqueueProblem(asFailure(error));
    },
  });

  /** Builds and starts a download of exactly these entries. */
  const download = (entries: readonly DirectoryEntry[]) => {
    setBlocker(null);
    setEnqueueProblem(null);
    setReport(null);
    if (folder === null) {
      setBlocker("needFolder");
      return;
    }
    if (entries.length === 0) {
      setBlocker("needSelection");
      return;
    }
    // The platform's suggestion becomes the stored preference the first time a
    // transfer actually uses it, and not before: "Remoter has never been told
    // where to put things" and "the user settled on their Downloads folder" are
    // different states, and the pane says which one it is in. A folder the user
    // chose is already stored, so this writes nothing on every later download.
    if (destination.isDefault) destination.remember(folder);
    start.mutate(
      entries.map((entry) => ({
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

  /** Builds and starts an upload of exactly these local paths. */
  const upload = (locals: readonly string[]) => {
    setBlocker(null);
    setEnqueueProblem(null);
    setReport(null);
    const requests: TransferRequest[] = [];
    for (const local of locals) {
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
    start.mutate(requests);
  };

  /**
   * Resolves a typed path against the server, then goes there.
   *
   * `sftp_canonicalize` rather than arithmetic here: `..`, `.`, a bare folder
   * name and a symbolic link all mean whatever the *server* says they mean, and
   * the path box used to refuse every one of them by disabling its button
   * without saying why — a control that looked broken and explained nothing.
   *
   * Both forms come back from the command, and both are used: the raw one
   * addresses the folder and the escaped one is what the trail draws. The
   * server chose this string, so there is no reading it unescaped.
   */
  const resolveTyped = useMutation({
    mutationFn: (typed: string) =>
      // Relative to the folder on screen, which is what "logs" means when you
      // type it while looking at /srv.
      ipc.canonicalizePath(pane.paneId, typed.startsWith("/") ? typed : joinPath(location.path, typed)),
    onSuccess: (resolved) => {
      // Both forms, because the server chose this string: a canonicalised path
      // travels through whatever the server's own symbolic links resolve to,
      // and rendering the raw one would put an unescaped remote path on screen.
      goTo(resolved);
    },
  });

  const busy = enqueue.isPending || start.isPending;

  return (
    <>
      {blocker !== null && (
        <div className={s.blockers}>
          <Callout tone="warning">{t(BLOCKER_KEY[blocker])}</Callout>
        </div>
      )}

      {report !== null && <EnqueueReportNotice report={report} />}

      <div className={s.panes}>
        <RemotePane
          view={view}
          path={location.path}
          displayPath={location.displayPath}
          home={pane.home}
          homeDisplay={pane.homeDisplay}
          selection={selection}
          onSelectionChange={setSelection}
          onNavigate={goTo}
          canGoBack={trail.at > 0}
          canGoForward={trail.at < trail.entries.length - 1}
          onBack={() => {
            setSelection(new Set());
            setTrail((current) => step(current, -1));
          }}
          onForward={() => {
            setSelection(new Set());
            setTrail((current) => step(current, 1));
          }}
          onGoToTyped={(typed) => {
            resolveTyped.mutate(typed);
          }}
          resolving={resolveTyped.isPending}
          resolveProblem={resolveTyped.error === null ? null : asFailure(resolveTyped.error)}
          onNewFolder={() => {
            setDialog({ kind: "newFolder" });
          }}
          onRename={(entry) => {
            setDialog({ kind: "rename", entry });
          }}
          onDelete={(entry) => {
            setDialog({ kind: "delete", entry });
          }}
          onProperties={(entry) => {
            setDialog({ kind: "properties", entry });
          }}
          onDownload={download}
          onUploadDropped={upload}
          busy={busy}
        />

        <LocalPane
          folder={folder}
          folderIsDefault={destination.isDefault}
          onFolderChange={destination.remember}
          staged={staged}
          onStagedChange={setStaged}
          onUpload={() => {
            upload(staged);
          }}
          onDownloadDropped={(paths) => {
            // Only rows the pane can still see. A path from a drag that started
            // before a refresh is a path this listing no longer has an entry
            // for, and inventing one would be addressing something unseen.
            const wanted = new Set(paths);
            download(view.visible.filter((entry) => wanted.has(entry.path)));
          }}
          busy={busy}
        />
      </div>

      {/* Beside the buttons that fill it, and mounted for as long as the pane
          is — including while its tab is in the background, which is what lets
          a transfer outlive a tab switch rather than being cancelled by one. */}
      <TransferQueuePanel
        paneId={pane.paneId}
        sessionId={pane.sessionId}
        resume={resume}
        onResumeChange={setResume}
        enqueueProblem={enqueueProblem}
      />

      {dialog?.kind === "overwrite" && (
        <OverwriteDialog
          requests={dialog.requests}
          answers={dialog.answers}
          resume={resume}
          busy={enqueue.isPending}
          onConfirm={({ requests }) => {
            enqueue.mutate(requests);
          }}
          onClose={() => {
            setDialog(null);
          }}
        />
      )}

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

      {dialog?.kind === "properties" && (
        <PropertiesDialog
          paneId={pane.paneId}
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
 * What a folder walk left out.
 *
 * Shown only when there is something to say. A transfer that queued nine
 * hundred and ninety-six of a thousand files has not done what was asked, and a
 * queue showing nine hundred and ninety-six healthy rows is exactly how that
 * goes unnoticed until somebody needs the four.
 */
function EnqueueReportNotice({ report }: { report: EnqueueReport }) {
  const t = useT("files");

  return (
    <div className={s.blockers}>
      <Callout tone="warning" title={t("enqueue.partialTitle")}>
        {report.limitReached && <p>{t("enqueue.limitReached")}</p>}
        {report.skipped.length > 0 && (
          <>
            <p>{t("enqueue.skipped", { count: report.skipped.length })}</p>
            <ul>
              {report.skipped.map((one) => (
                <SkippedLine key={one.path} skipped={one} />
              ))}
            </ul>
          </>
        )}
      </Callout>
    </div>
  );
}

/**
 * One entry a folder walk refused.
 *
 * Its own component because `useFailureText` is a hook and takes one failure:
 * the catalogue's sentence for the code, never the core's English, which would
 * put English in front of every reader who chose another language. The path is
 * the escaped form — on a download every component of it was chosen by the
 * server.
 */
function SkippedLine({ skipped }: { skipped: EnqueueSkipped }) {
  const text = useFailureText({
    code: skipped.code,
    message: skipped.message,
    detail: null,
    actions: [],
  });
  return (
    <li>
      <span className={s.skippedPath}>{isolate(skipped.path)}</span>
      {": "}
      {text.message}
    </li>
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
