/**
 * What the session area shows when the vault holds nothing.
 *
 * An empty vault is a designed state, not a blank panel: the first thing
 * almost everyone wants is to bring across what they already have, so import
 * leads and carries the accent border. The other two routes are offered
 * because a first-time user has nothing to import and a returning user may
 * have opened the wrong file.
 *
 * Import is the one choice here that navigates rather than acting on this
 * vault, so it reaches the store directly instead of arriving as a callback.
 * The other two need the shell: one opens the connection editor, the other has
 * to lock this vault before the picker is any use.
 */

import { FailureNotice } from "@/components/FailureNotice";
import { Icon, type IconName } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import type { IpcFailure } from "@/lib/ipc";
import { useApp } from "@/stores/app";
import s from "./EmptyVault.module.css";

const TEXT = {
  title: "This vault is empty",
  bodyBefore: "Nothing is stored in ",
  bodyAfter: " yet. Most people start by bringing across what they already have.",
  unnamedVault: "this vault",
  importTitle: "Import from another tool",
  importBody: "mRemoteNG, ~/.ssh/config, CSV",
  createTitle: "Create the first connection",
  createBody: "A host, a protocol and a credential is enough to start.",
  createBusy: "Opening the connection editor…",
  openTitle: "Open a different vault",
  openBody: "Locks this vault and returns to the vault picker.",
  openBusy: "Locking this vault…",
  openFailed: "This vault was not locked, so the picker did not open.",
  retry: "Try again",
} as const;

interface EmptyVaultProps {
  vaultPath: string | null;
  onCreateConnection: () => void;
  onOpenAnother: () => void;
  creating?: boolean | undefined;
  openingAnother?: boolean | undefined;
  /** Set when locking this vault was refused; shown under that choice. */
  openAnotherFailure?: IpcFailure | null | undefined;
}

interface ChoiceProps {
  icon: IconName;
  title: string;
  body: string;
  onClick?: (() => void) | undefined;
  primary?: boolean | undefined;
  busy?: boolean | undefined;
  /**
   * Why this choice cannot be pressed. A control that refuses a click without
   * saying why reads as a broken control, so every disabled state names one.
   */
  disabledReason?: string | undefined;
}

function Choice({ icon, title, body, onClick, primary = false, busy = false, disabledReason }: ChoiceProps) {
  const disabled = busy;

  return (
    <button
      type="button"
      className={[s.choice, primary ? s.choicePrimary : ""].join(" ")}
      onClick={onClick}
      disabled={disabled}
      {...(disabled && disabledReason !== undefined ? { title: disabledReason } : {})}
    >
      <span className={primary ? s.choiceIconPrimary : s.choiceIcon} aria-hidden="true">
        {busy ? <Spinner size={18} label={title} /> : <Icon name={icon} size={18} />}
      </span>
      <span className={s.choiceText}>
        <span className={s.choiceTitle}>{title}</span>
        <span className={s.choiceBody}>{body}</span>
        {disabled && disabledReason !== undefined && (
          <span className={s.choiceReason}>{disabledReason}</span>
        )}
      </span>
      <span className={s.choiceChevron} aria-hidden="true">
        <Icon name="chevron-right" size={15} />
      </span>
    </button>
  );
}

/** The file name is the part the user recognises; the directory is noise here. */
function basename(path: string | null): string {
  if (path === null || path === "") return TEXT.unnamedVault;
  const parts = path.split(/[\\/]/);
  const last = parts[parts.length - 1];
  return last === undefined || last === "" ? path : last;
}

export function EmptyVault({
  vaultPath,
  onCreateConnection,
  onOpenAnother,
  creating = false,
  openingAnother = false,
  openAnotherFailure = null,
}: EmptyVaultProps) {
  const go = useApp((st) => st.go);

  return (
    <div className={s.wrap}>
      <div className={s.card}>
        <div className={s.heading}>
          <h1 className={s.title}>{TEXT.title}</h1>
          <p className={s.body}>
            {TEXT.bodyBefore}
            <span className={s.path}>{basename(vaultPath)}</span>
            {TEXT.bodyAfter}
          </p>
        </div>

        <div className={s.choices}>
          <Choice
            icon="plus"
            title={TEXT.createTitle}
            body={TEXT.createBody}
            onClick={onCreateConnection}
            primary
            busy={creating}
            disabledReason={TEXT.createBusy}
          />
          <Choice
            icon="download"
            title={TEXT.importTitle}
            body={TEXT.importBody}
            onClick={() => go({ name: "import" })}
          />
          <Choice
            icon="folder"
            title={TEXT.openTitle}
            body={TEXT.openBody}
            onClick={onOpenAnother}
            busy={openingAnother}
            disabledReason={TEXT.openBusy}
          />

          {openAnotherFailure !== null && (
            <FailureNotice
              failure={openAnotherFailure}
              title={TEXT.openFailed}
              onRetry={onOpenAnother}
              retryLabel={TEXT.retry}
            />
          )}
        </div>
      </div>
    </div>
  );
}
