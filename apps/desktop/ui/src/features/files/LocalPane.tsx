/**
 * The local half of the browser — and the honest account of what it is not.
 *
 * # Why this pane does not list your files
 *
 * `docs/architecture/sftp-command-surface.md` sets out what the local side
 * would need: `fs_list`, `fs_mkdir`, `fs_rename`, `fs_delete`, "or a platform
 * file picker". The commands do not exist — the document says so itself, under
 * "The local pane is still absent" — and this build ships no filesystem plugin,
 * so there is no way for the frontend to read a directory on this machine at
 * all. What it has is the system picker.
 *
 * So this pane is the picker's pane. It shows the folder chosen to download
 * into and the files chosen to send, and it says on screen that it cannot list
 * anything else. The alternative — five column headings over a permanently
 * empty grid — would read as an empty disk or a broken pane, and the interface
 * would be claiming a capability the build does not have.
 *
 * # A remote name never chooses a local path
 *
 * The rule the command surface is most emphatic about. A download names either
 * a file path the *save* picker produced or a **folder**, and where it names a
 * folder the file name is derived by the core from the remote path through
 * `local_name_for`, which keeps the last component and refuses anything that
 * still looks like a traversal. This pane therefore hands the core a folder and
 * never joins a server-supplied name onto it — that join is exactly how a file
 * manager gets told to overwrite `~/.ssh/authorized_keys`.
 */

import { useState, type DragEvent } from "react";
import { open } from "@tauri-apps/plugin-dialog";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { Icon } from "@/components/Icon";
import { isolateLtr, useT } from "@/i18n";

import { LOCAL_DRAG_TYPE, REMOTE_DRAG_TYPE } from "./dragTypes";

import s from "./LocalPane.module.css";

interface LocalPaneProps {
  /** The chosen download destination, as the platform writes it. */
  folder: string | null;
  onFolderChange: (folder: string) => void;
  /** Local file paths waiting to be sent. */
  staged: readonly string[];
  onStagedChange: (staged: readonly string[]) => void;
  /** Sends everything staged. */
  onUpload: () => void;
  /** A remote row was dropped here: download it into the chosen folder. */
  onDownloadDropped: () => void;
  busy: boolean;
}

export function LocalPane({
  folder,
  onFolderChange,
  staged,
  onStagedChange,
  onUpload,
  onDownloadDropped,
  busy,
}: LocalPaneProps) {
  const t = useT("files");
  const [pickerFailed, setPickerFailed] = useState(false);
  const [dropping, setDropping] = useState(false);
  const [osFilesRefused, setOsFilesRefused] = useState(false);

  const chooseFolder = () => {
    setPickerFailed(false);
    void (async () => {
      try {
        const chosen = await open({ directory: true, multiple: false });
        if (typeof chosen === "string") onFolderChange(chosen);
      } catch {
        setPickerFailed(true);
      }
    })();
  };

  const chooseFiles = () => {
    setPickerFailed(false);
    void (async () => {
      try {
        const chosen = await open({ multiple: true });
        if (chosen === null) return;
        const paths = Array.isArray(chosen) ? chosen : [chosen];
        // De-duplicated against what is already staged: choosing the same file
        // twice should not queue it twice.
        const merged = [...staged];
        for (const path of paths) if (!merged.includes(path)) merged.push(path);
        onStagedChange(merged);
      } catch {
        setPickerFailed(true);
      }
    })();
  };

  const onDrop = (e: DragEvent<HTMLElement>) => {
    setDropping(false);
    // A drop from the desktop carries the file's *contents*, not its path on
    // disk, and the transfer engine sends a path. There is no way to bridge
    // that from here, so it is refused in words rather than silently ignored.
    if (e.dataTransfer.files.length > 0) {
      e.preventDefault();
      setOsFilesRefused(true);
      return;
    }
    if (!e.dataTransfer.types.includes(REMOTE_DRAG_TYPE)) return;
    e.preventDefault();
    setOsFilesRefused(false);
    onDownloadDropped();
  };

  return (
    <section
      className={s.pane}
      aria-label={t("pane.local.title")}
      onDragOver={(e) => {
        if (!e.dataTransfer.types.includes(REMOTE_DRAG_TYPE)) return;
        e.preventDefault();
        setDropping(true);
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropping(false);
      }}
      onDrop={onDrop}
    >
      <header className={s.head}>
        <h3 className={s.title}>{t("pane.local.title")}</h3>
      </header>

      {dropping && (
        // A drop that picked its own folder would be a drop that wrote
        // somewhere the user did not choose, so the hint says what is missing
        // rather than letting the drop fail after the fact.
        <p className={s.dropHint} role="status">
          {folder === null ? t("drop.needFolder") : t("drop.toLocal")}
        </p>
      )}

      <Callout tone="info" title={t("pane.local.noBrowserTitle")}>
        {t("pane.local.noBrowserBody")}
      </Callout>

      {pickerFailed && <Callout tone="warning">{t("pane.local.pickerFailed")}</Callout>}
      {osFilesRefused && <Callout tone="warning">{t("drop.noOsFiles")}</Callout>}

      <div className={s.destination}>
        <span className={s.label}>{t("pane.local.folderLabel")}</span>
        {folder === null ? (
          <span className={s.none}>{t("pane.local.noFolder")}</span>
        ) : (
          // A filesystem path: left-to-right by specification whatever it
          // contains, so it is forced rather than inferred.
          <span className={s.path} title={folder}>
            {isolateLtr(folder)}
          </span>
        )}
        <Button size="sm" onClick={chooseFolder} disabled={busy}>
          {folder === null ? t("pane.local.chooseFolder") : t("pane.local.changeFolder")}
        </Button>
      </div>

      <div className={s.tools}>
        <Button size="sm" onClick={chooseFiles} disabled={busy}>
          {t("pane.local.chooseFiles")}
        </Button>
        <Button size="sm" variant="primary" onClick={onUpload} disabled={busy || staged.length === 0}>
          {t("action.upload")}
        </Button>
        <div className={s.spacer} />
        {staged.length > 0 && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              onStagedChange([]);
            }}
          >
            {t("pane.local.clearStaged")}
          </Button>
        )}
      </div>

      <p className={s.counts}>{t("pane.local.staged", { count: staged.length })}</p>

      <ul className={s.list}>
        {staged.map((path) => (
          <li
            key={path}
            className={s.item}
            draggable
            onDragStart={(e) => {
              e.dataTransfer.setData(LOCAL_DRAG_TYPE, path);
              e.dataTransfer.effectAllowed = "copy";
            }}
          >
            <Icon name="file" size={14} />
            <span className={s.itemName} title={path}>
              {isolateLtr(baseName(path))}
            </span>
            <span className={s.itemPath} title={path}>
              {isolateLtr(path)}
            </span>
            <Button
              size="sm"
              variant="ghost"
              ariaLabel={t("pane.local.remove", { name: path })}
              title={t("pane.local.remove", { name: path })}
              onClick={() => {
                onStagedChange(staged.filter((other) => other !== path));
              }}
            >
              <Icon name="x" size={13} />
            </Button>
          </li>
        ))}
      </ul>
    </section>
  );
}

/**
 * The last component of a local path.
 *
 * Both separators, because this string came from the platform's own picker and
 * the platform is Windows about as often as it is not. Display only — the whole
 * path is what is sent, and it is sent exactly as the picker gave it.
 */
function baseName(path: string): string {
  const parts = path.split(/[\\/]/).filter((part) => part !== "");
  return parts[parts.length - 1] ?? path;
}
