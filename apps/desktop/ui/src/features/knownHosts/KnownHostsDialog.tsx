/**
 * Import OpenSSH's `known_hosts` into the vault's trust store.
 *
 * Someone who has been connecting to their servers with `ssh` for years has
 * already checked those keys once. Asking again for every one of them is how
 * a person learns to accept a host key prompt without reading it, which is the
 * habit the prompt exists to prevent — so the keys can come across instead.
 *
 * Three things this dialog says before anything is written, because each is a
 * way an import could do harm:
 *
 *  - **Every key in the file is trusted as if checked by hand.** A
 *    `known_hosts` somebody else sent can make Remoter trust a machine that
 *    only claims to be the server.
 *  - **A key Remoter already trusts is never replaced.** Where the file and
 *    the vault disagree, the vault's key stays, and the preview lists those
 *    hosts first.
 *  - **Hashed entries name no host.** They can only be matched against the
 *    connections this vault has, so the ones that match nothing are counted
 *    rather than imported.
 *
 * The preview is the core's; nothing is held between it and the import, and
 * the import compares each key with the vault again when it writes.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";

import { BusyButton } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { TextInput } from "@/components/TextInput";
import { auditKeys } from "@/features/audit/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { isolateLtr, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, KnownHostKey, KnownHostsPreview, KnownHostsResult } from "@/lib/ipc";

import s from "./KnownHostsDialog.module.css";

export const KNOWN_HOSTS_MODAL_ID = "trust.known-hosts";

/** How many keys are listed by name; the counts above the list cover the rest. */
const LISTED = 50;

interface KnownHostsDialogProps {
  onClose: () => void;
}

export function KnownHostsDialog({ onClose }: KnownHostsDialogProps) {
  const t = useT("import");
  const tCommon = useT("common");
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const queryClient = useQueryClient();

  // The account's own file is the one worth offering; anything else is typed
  // or browsed to, and the warning below is about exactly that case.
  const location = useQuery({
    queryKey: ["known-hosts", "location"],
    queryFn: () => ipc.knownHostsLocation(),
  });
  const [typed, setTyped] = useState<string | null>(null);
  const path = typed ?? location.data ?? "";

  const [preview, setPreview] = useState<KnownHostsPreview | null>(null);
  const [result, setResult] = useState<KnownHostsResult | null>(null);
  const [failure, setFailure] = useState<IpcFailure | null>(null);
  const [browseFailed, setBrowseFailed] = useState(false);

  useFocusTrap(true, dialogRef);
  useModalRegistration(KNOWN_HOSTS_MODAL_ID, true);

  const read = useMutation({
    mutationFn: (file: string) => ipc.knownHostsPreview(file),
    onSuccess: (read) => {
      setFailure(null);
      setPreview(read);
    },
    onError: (error: unknown) => {
      setPreview(null);
      setFailure(asFailure(error));
    },
  });

  const trust = useMutation({
    mutationFn: (file: string) => ipc.knownHostsImport(file),
    onSuccess: async (written) => {
      setFailure(null);
      setResult(written);
      await queryClient.invalidateQueries({ queryKey: auditKeys.all() });
    },
    onError: (error: unknown) => setFailure(asFailure(error)),
  });

  const busy = read.isPending || trust.isPending;

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // Keys half written cannot be called back, and closing now would leave
      // the user not knowing which ones were.
      if (trust.isPending) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [onClose, trust.isPending]);

  const choosePath = (next: string) => {
    setTyped(next);
    // A preview is of one file; another path is another question.
    setPreview(null);
    setFailure(null);
  };

  const browse = () => {
    void open({ directory: false, multiple: false, title: t("knownHosts.dialogTitle") }).then(
      (picked) => {
        setBrowseFailed(false);
        if (typeof picked === "string") choosePath(picked);
      },
      () => setBrowseFailed(true),
    );
  };

  return (
    <div className={s.backdrop}>
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-label={t("knownHosts.title")}
        tabIndex={-1}
      >
        <h2 className={s.title}>{t("knownHosts.title")}</h2>

        {result !== null ? (
          <>
            <Callout tone="info" title={t("knownHosts.doneTitle", { count: result.trusted })}>
              <p>{t("knownHosts.doneBody")}</p>
              {result.differs > 0 && (
                <p>{t("knownHosts.doneKept", { count: result.differs })}</p>
              )}
            </Callout>
            <div className={s.actions}>
              <Button variant="primary" onClick={onClose}>
                {tCommon("action.close")}
              </Button>
            </div>
          </>
        ) : (
          <>
            <p className={s.lead}>{t("knownHosts.lead")}</p>
            <Callout tone="warning" title={t("knownHosts.trustTitle")}>
              <p>{t("knownHosts.trustBody")}</p>
            </Callout>

            <Field label={t("knownHosts.pathLabel")} htmlFor="known-hosts-path">
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="known-hosts-path"
                    value={path}
                    onChange={choosePath}
                    mono
                    disabled={busy}
                    placeholder={t("knownHosts.pathPlaceholder")}
                  />
                </div>
                <Button variant="secondary" onClick={browse} disabled={busy}>
                  {tCommon("action.browse")}
                </Button>
              </div>
            </Field>
            {browseFailed && <p className={s.note}>{t("source.dialogFailed")}</p>}

            {failure !== null && (
              <FailureNotice
                failure={failure}
                title={preview === null ? t("knownHosts.readFailed") : t("knownHosts.trustFailed")}
              />
            )}

            {preview !== null && <Preview preview={preview} />}

            <div className={s.actions}>
              <Button variant="ghost" onClick={onClose} disabled={trust.isPending}>
                {tCommon("action.cancel")}
              </Button>
              {preview === null ? (
                <BusyButton
                  variant="primary"
                  busy={read.isPending}
                  busyLabel={t("knownHosts.reading")}
                  disabled={path.trim() === ""}
                  onClick={() => read.mutate(path.trim())}
                >
                  {t("knownHosts.read")}
                </BusyButton>
              ) : (
                <BusyButton
                  variant="primary"
                  busy={trust.isPending}
                  busyLabel={t("knownHosts.trusting")}
                  disabled={preview.new === 0}
                  onClick={() => trust.mutate(preview.path)}
                >
                  {t("knownHosts.trust", { count: preview.new })}
                </BusyButton>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function Preview({ preview }: { preview: KnownHostsPreview }) {
  const t = useT("import");
  // Each fact is a whole sentence with its own plural, shown only when it is
  // not zero: a list of "0 revoked keys" lines is a list nobody reads.
  const facts: string[] = [];
  const fact = (count: number, key: FactKey) => {
    if (count > 0) facts.push(t(key, { count }));
  };
  fact(preview.alreadyTrusted, "knownHosts.factTrusted");
  fact(preview.unsupported, "knownHosts.factUnsupported");
  fact(preview.hashedUnmatched, "knownHosts.factHashedUnmatched");
  fact(preview.hashedUnchecked, "knownHosts.factHashedUnchecked");
  fact(preview.patternsUnmatched, "knownHosts.factPatternsUnmatched");
  fact(preview.revoked, "knownHosts.factRevoked");
  fact(preview.certificateAuthorities, "knownHosts.factAuthorities");
  fact(preview.conflicting, "knownHosts.factConflicting");
  fact(preview.malformed, "knownHosts.factMalformed");

  const listed = preview.keys.slice(0, LISTED);
  return (
    <>
      <p className={s.summary}>
        {preview.new === 0
          ? t("knownHosts.nothingNew")
          : t("knownHosts.summary", { count: preview.new })}
      </p>

      {preview.differs > 0 && (
        <Callout tone="warning" title={t("knownHosts.differsTitle", { count: preview.differs })}>
          <p>{t("knownHosts.differsBody")}</p>
        </Callout>
      )}

      {facts.length > 0 && (
        <ul className={s.facts}>
          {facts.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}

      {listed.length > 0 && (
        <ul className={s.keys} aria-label={t("knownHosts.listLabel")}>
          {listed.map((key) => (
            <KeyRow key={`${key.host}:${key.port}:${key.algorithm}`} entry={key} />
          ))}
        </ul>
      )}
      {preview.total > listed.length && (
        <p className={s.note}>{t("knownHosts.more", { count: preview.total - listed.length })}</p>
      )}
    </>
  );
}

type FactKey =
  | "knownHosts.factTrusted"
  | "knownHosts.factUnsupported"
  | "knownHosts.factHashedUnmatched"
  | "knownHosts.factHashedUnchecked"
  | "knownHosts.factPatternsUnmatched"
  | "knownHosts.factRevoked"
  | "knownHosts.factAuthorities"
  | "knownHosts.factConflicting"
  | "knownHosts.factMalformed";

const STATE_KEY = {
  new: "knownHosts.stateNew",
  trusted: "knownHosts.stateTrusted",
  differs: "knownHosts.stateDiffers",
  unsupported: "knownHosts.stateUnsupported",
} as const;

function KeyRow({ entry }: { entry: KnownHostKey }) {
  const t = useT("import");
  // A host and a fingerprint are the file's own text, left to right in any
  // interface language.
  const address = entry.port === 22 ? entry.host : `${entry.host}:${entry.port}`;
  return (
    <li className={s.key}>
      <span className={s.host}>
        {isolateLtr(address)} · {isolateLtr(entry.algorithm)}
      </span>
      <span className={s.state} data-state={entry.state}>
        {t(STATE_KEY[entry.state])}
      </span>
      <span className={s.fingerprint}>{isolateLtr(entry.fingerprint)}</span>
    </li>
  );
}
