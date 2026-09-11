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
import { isolate, useT } from "@/i18n";
import type { IpcFailure } from "@/lib/ipc";
import { useApp } from "@/stores/app";
import s from "./EmptyVault.module.css";


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

/**
 * The file name is the part the user recognises; the directory is noise here.
 *
 * Returns `null` rather than a placeholder so the placeholder can be a
 * translated string: this is a pure function and `t()` is a hook.
 */
function basename(path: string | null): string | null {
  if (path === null || path === "") return null;
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
  const t = useT("shell");
  const tCommon = useT("common");
  const go = useApp((st) => st.go);
  // A file name is user data in an unknown script; isolating it keeps the
  // sentence around it running the document's way.
  const vaultName = basename(vaultPath);

  return (
    <div className={s.wrap}>
      <div className={s.card}>
        <div className={s.heading}>
          <h1 className={s.title}>{t("emptyVault.title")}</h1>
          {/* One message with the name inside it, not three fragments joined
              at render: languages do not agree on where the subject of this
              sentence goes, and a sentence assembled from halves cannot be
              reordered by a translator. The name loses its own styling as a
              result, which is the price of a sentence that survives
              translation. */}
          <p className={s.body}>
            {t("emptyVault.body", {
              vault: isolate(vaultName ?? t("emptyVault.unnamedVault")),
            })}
          </p>
        </div>

        <div className={s.choices}>
          <Choice
            icon="plus"
            title={t("emptyVault.createTitle")}
            body={t("emptyVault.createBody")}
            onClick={onCreateConnection}
            primary
            busy={creating}
            disabledReason={t("emptyVault.createBusy")}
          />
          <Choice
            icon="download"
            title={t("emptyVault.importTitle")}
            body={t("emptyVault.importBody")}
            onClick={() => go({ name: "import" })}
          />
          <Choice
            icon="folder"
            title={t("emptyVault.openTitle")}
            body={t("emptyVault.openBody")}
            onClick={onOpenAnother}
            busy={openingAnother}
            disabledReason={t("emptyVault.openBusy")}
          />

          {openAnotherFailure !== null && (
            <FailureNotice
              failure={openAnotherFailure}
              title={t("emptyVault.openFailed")}
              onRetry={onOpenAnother}
              retryLabel={tCommon("action.retry")}
            />
          )}
        </div>
      </div>
    </div>
  );
}
