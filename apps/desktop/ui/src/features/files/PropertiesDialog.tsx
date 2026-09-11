/**
 * What an entry actually is, and the one thing about it this build can change.
 *
 * # Why it exists
 *
 * Three commands on the SFTP surface were exposed to the interface and called
 * by nothing: `sftp_stat`, `sftp_read_link` and `sftp_set_permissions`. A
 * command surface with unreachable entries is a promise the interface does not
 * keep — the capability is built, tested and paid for, and nobody can get at
 * it. Each of the three answers a question an administrator asks constantly:
 * what is this really, where does this link point, and why will this script not
 * run.
 *
 * # Fresh facts, not the row's
 *
 * The listing on screen is a snapshot, and a dialog that repeated it would tell
 * the user what they already had. `sftp_stat` is read when this opens, so the
 * size and the mode are what the server says now — which is also what makes the
 * permission change verifiable: apply it, and the field re-reads.
 *
 * `sftp_stat` **follows** symbolic links, which is right for "what is this
 * really" and wrong for "what is this row". So a link gets `sftp_read_link`
 * beside it, which does not follow, and the dialog shows both: what the link
 * says, and what is at the other end of it.
 *
 * # The mode is typed, and that is deliberate
 *
 * Nine checkboxes would be prettier and would be a worse control for the people
 * who use this: an administrator knows `755` and `640`, and reaching them
 * through a grid of boxes is slower than typing three digits. The field
 * therefore takes octal, refuses anything that is not, and shows the symbolic
 * form beside it so the two can be checked against each other.
 *
 * Changing a mode is not reversible by anything here — there is no undo on a
 * server — so the button names the act and the field starts at what is there.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { TextInput } from "@/components/TextInput";
import { formatBytes, formatDateTime, isolate, useLocale, useT } from "@/i18n";
import { asFailure, ipc, type DirectoryEntry } from "@/lib/ipc";
import { invalidateListings, qk } from "@/lib/queryKeys";

import { DialogFrame } from "./DialogFrame";

import s from "./PropertiesDialog.module.css";

/** The permission bits, plus set-user-id, set-group-id and sticky. */
const MAX_MODE = 0o7777;

/**
 * Whether a typed string is a mode this build will send.
 *
 * Octal, one to four digits, inside the range the core accepts. Checked here so
 * the refusal is a sentence under the field rather than a round trip — the core
 * checks again, and its answer is the one that decides.
 */
export function parseMode(typed: string): number | null {
  const trimmed = typed.trim();
  if (!/^[0-7]{1,4}$/.test(trimmed)) return null;
  const value = Number.parseInt(trimmed, 8);
  return value <= MAX_MODE ? value : null;
}

interface PropertiesDialogProps {
  paneId: number;
  entry: DirectoryEntry;
  onClose: () => void;
}

export function PropertiesDialog({ paneId, entry, onClose }: PropertiesDialogProps) {
  const t = useT("files");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const queryClient = useQueryClient();

  const [typedMode, setTypedMode] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);

  const stat = useQuery({
    queryKey: qk.sftpStat(paneId, entry.path),
    queryFn: () => ipc.statPath(paneId, entry.path),
    retry: false,
  });

  // Only for a link, and only the link's own answer: `readLink` does not
  // follow, which is the whole difference between it and the stat above.
  const target = useQuery({
    queryKey: qk.sftpLinkTarget(paneId, entry.path),
    queryFn: () => ipc.readLink(paneId, entry.path),
    enabled: entry.kind === "symlink",
    retry: false,
  });

  const facts = stat.data ?? entry;
  // The field starts at what is there and follows a successful change, until
  // the user types over it.
  const modeText = typedMode ?? (facts.permissions === null ? "" : facts.permissions.toString(8));
  const wanted = parseMode(modeText);
  const changed = wanted !== null && wanted !== facts.permissions;

  const apply = useMutation({
    mutationFn: (mode: number) => ipc.setPermissions(paneId, entry.path, mode),
    onSuccess: async () => {
      setApplied(true);
      setTypedMode(null);
      // The mode string is in the listing, so the folder on screen is stale.
      await invalidateListings(queryClient, paneId);
      await stat.refetch();
    },
  });

  return (
    <DialogFrame
      id="files.properties"
      title={t("properties.title", { name: isolate(entry.displayName) })}
      busy={apply.isPending}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={apply.isPending}>
            {tCommon("action.close")}
          </Button>
          <Button
            variant="primary"
            disabled={!changed || apply.isPending}
            onClick={() => {
              if (wanted !== null) apply.mutate(wanted);
            }}
          >
            {t("properties.apply")}
          </Button>
        </>
      }
    >
      {stat.isPending && (
        <p className={s.reading}>
          <Spinner size={14} />
          {t("properties.reading")}
        </p>
      )}

      {stat.error !== null && (
        // The row's own facts are still drawn below; this says they are the
        // listing's rather than the server's answer just now.
        <FailureNotice failure={asFailure(stat.error)} title={t("properties.readFailed")} onRetry={() => {
          void stat.refetch();
        }} />
      )}

      <dl className={s.facts}>
        <dt>{t("columns.name")}</dt>
        {/* The escaped twin, isolated: every string in this list was chosen by
            the far end. */}
        <dd className={s.value}>{isolate(facts.displayName)}</dd>

        <dt>{t("properties.path")}</dt>
        <dd className={s.value}>{isolate(facts.displayPath)}</dd>

        <dt>{t("columns.size")}</dt>
        <dd>
          {facts.size === null ? t("value.unknown") : formatBytes(locale, facts.size)}
        </dd>

        <dt>{t("columns.modified")}</dt>
        <dd>
          {facts.modified === null
            ? t("value.unknown")
            : formatDateTime(locale, facts.modified * 1000, "long")}
        </dd>

        <dt>{t("columns.owner")}</dt>
        <dd className={s.value}>
          {facts.user === null || facts.user === "" ? t("value.unknown") : isolate(facts.user)}
        </dd>

        <dt>{t("properties.group")}</dt>
        <dd className={s.value}>
          {facts.group === null || facts.group === "" ? t("value.unknown") : isolate(facts.group)}
        </dd>

        {entry.kind === "symlink" && (
          <>
            <dt>{t("properties.linkTarget")}</dt>
            <dd className={s.value}>
              {target.data === undefined ? t("value.unknown") : isolate(target.data.displayPath)}
            </dd>
          </>
        )}
      </dl>

      <div className={s.mode}>
        <label className={s.modeLabel} htmlFor="files-properties-mode">
          {t("properties.permissionsLabel")}
        </label>
        <TextInput
          id="files-properties-mode"
          value={modeText}
          onChange={(next) => {
            setApplied(false);
            setTypedMode(next);
          }}
          mono
          ariaLabel={t("properties.permissionsLabel")}
          invalid={modeText !== "" && wanted === null}
        />
        {/* The core's own rendering, ASCII by construction and never
            translated, so the octal and the symbolic form can be checked
            against each other. */}
        <span className={s.symbolic}>{facts.mode ?? t("value.unknown")}</span>
      </div>

      {modeText !== "" && wanted === null && (
        <p className={s.refusal}>{t("properties.invalidMode")}</p>
      )}
      <p className={s.hint}>{t("properties.permissionsHint")}</p>

      {applied && <Callout tone="info">{t("properties.applied")}</Callout>}
      {apply.error !== null && (
        <FailureNotice failure={asFailure(apply.error)} title={t("properties.applyFailed")} />
      )}
    </DialogFrame>
  );
}
