/**
 * Export the connection tree — or one folder of it — to a file.
 *
 * The first question is who the file is for, because the answer decides what
 * goes into it:
 *
 *  - **Another Remoter.** A `.rmtr` archive, with the server passwords, keys
 *    and passphrases, sealed under a password the user chooses — the vault's
 *    own encryption, in a file only Remoter opens. The password passes the
 *    same strength gate a vault's master password does, in the core, because
 *    the file is going to leave the machine with every secret in it.
 *  - **Another application.** CSV, an OpenSSH config or JSON, which other
 *    tools read, and into which no secret is ever written. The file is not
 *    encrypted, and the dialog says so before the button.
 *
 * Either way the export is recorded in the audit log, and that is said before
 * the fact. After the write the form gives way to what the core reported: how
 * many connections made it into the file, what came along because the export
 * needed it, and — for the flat formats — what the format could not say the
 * way the vault says it.
 *
 * `aria-modal` is a promise, so this keeps it: focus enters, Tab is trapped,
 * Escape cancels, focus returns, and the window behind stands its shortcuts
 * down through `useModalRegistration`.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { save } from "@tauri-apps/plugin-dialog";

import { BusyButton, BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { auditKeys } from "@/features/audit/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { formatBytes, isolate, isolateLtr, useLocale, useStrengthText, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type {
  IpcFailure,
  PasswordStrength,
  TreeExportFormat,
  TreeExportResult,
} from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { describeNote } from "./notes";
import s from "./TreeExportDialog.module.css";

export const EXPORT_MODAL_ID = "tree.export";

interface TreeExportDialogProps {
  /** The folder or connection the dialog was opened on; null is the whole vault. */
  rootId: string | null;
  onClose: () => void;
}

type Purpose = "remoter" | "other";
type Scope = "node" | "vault";
type FlatFormat = Exclude<TreeExportFormat, "remoter-archive">;

const FLAT_FORMATS: readonly FlatFormat[] = ["csv", "ssh-config", "json"];

/** The extension each format is saved with. An OpenSSH config has none of its own. */
const EXTENSION: Record<TreeExportFormat, string> = {
  "remoter-archive": "rmtr",
  csv: "csv",
  "ssh-config": "config",
  json: "json",
};

export function TreeExportDialog({ rootId, onClose }: TreeExportDialogProps) {
  const t = useT("connections");
  const tCommon = useT("common");
  const { code: locale } = useLocale();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const queryClient = useQueryClient();
  const nodes = useQuery({ queryKey: qk.nodes(), queryFn: () => ipc.listNodes() });
  const root = useMemo(
    () => (rootId === null ? null : (nodes.data?.find((node) => node.id === rootId) ?? null)),
    [nodes.data, rootId],
  );

  const [purpose, setPurpose] = useState<Purpose | null>(null);
  const [flatFormat, setFlatFormat] = useState<FlatFormat>("csv");
  const [scope, setScope] = useState<Scope>(rootId === null ? "vault" : "node");
  const [path, setPath] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [revealed, setRevealed] = useState(false);
  // Each verdict remembers the password it was given for, so a rating that
  // arrives for what the field held a moment ago is never shown for what it
  // holds now.
  const [rated, setRated] = useState<{ password: string; strength: PasswordStrength } | null>(
    null,
  );
  const [ratingFailed, setRatingFailed] = useState<{
    password: string;
    failure: IpcFailure;
  } | null>(null);
  const [generating, setGenerating] = useState(false);
  const [generateFailed, setGenerateFailed] = useState(false);
  const [browseFailed, setBrowseFailed] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [result, setResult] = useState<TreeExportResult | null>(null);
  const [failure, setFailure] = useState<IpcFailure | null>(null);

  const format: TreeExportFormat = purpose === "remoter" ? "remoter-archive" : flatFormat;
  const strength = rated !== null && rated.password === password ? rated.strength : null;
  const strengthFailure =
    ratingFailed !== null && ratingFailed.password === password ? ratingFailed.failure : null;
  const strengthText = useStrengthText(strength?.entropyBits ?? 0);

  useFocusTrap(true, dialogRef);
  useModalRegistration(EXPORT_MODAL_ID, true);

  // The strength comes from the core, which is also where the gate is: the
  // meter is a preview of the refusal, not the refusal itself.
  useEffect(() => {
    if (purpose !== "remoter" || password === "") return;
    let cancelled = false;
    const timer = window.setTimeout(() => {
      ipc.passwordStrength(password).then(
        (verdict) => {
          if (!cancelled) setRated({ password, strength: verdict });
        },
        (error: unknown) => {
          if (!cancelled) setRatingFailed({ password, failure: asFailure(error) });
        },
      );
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [password, purpose]);

  const exportMutation = useMutation({
    mutationFn: () =>
      ipc.exportTree({
        path: path.trim(),
        format,
        rootId: scope === "node" ? rootId : null,
        password: purpose === "remoter" ? password : null,
      }),
    onSuccess: async (written) => {
      setFailure(null);
      setResult(written);
      // The password has done its job; it is not kept for a second export.
      setPassword("");
      setConfirmation("");
      await queryClient.invalidateQueries({ queryKey: auditKeys.all() });
    },
    onError: (error: unknown) => {
      setResult(null);
      setFailure(asFailure(error));
    },
  });

  const busy = exportMutation.isPending;

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape") return;
      // A write in flight cannot be called back, and closing now would leave
      // the user not knowing whether the file exists.
      if (busy) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);

  const withExtension = (current: string, from: TreeExportFormat, to: TreeExportFormat) => {
    // A path whose extension came from the previous format follows the new
    // one; a path the user typed with an extension of their own is theirs.
    const previous = `.${EXTENSION[from]}`;
    return current.endsWith(previous)
      ? `${current.slice(0, -previous.length)}.${EXTENSION[to]}`
      : current;
  };

  const choosePurpose = (next: Purpose | null) => {
    if (next !== null && purpose === null) {
      const to: TreeExportFormat = next === "remoter" ? "remoter-archive" : flatFormat;
      setPath((current) => withExtension(current, format, to));
    }
    setAttempted(false);
    setFailure(null);
    setPurpose(next);
  };

  const chooseFlatFormat = (next: FlatFormat) => {
    setPath((current) => withExtension(current, flatFormat, next));
    setFlatFormat(next);
  };

  const browse = async () => {
    setBrowseFailed(false);
    try {
      const chosen = await save({
        defaultPath: `${fileStem(scope === "node" ? (root?.name ?? null) : null)}.${EXTENSION[format]}`,
        filters: [{ name: formatLabel(t, format), extensions: [EXTENSION[format]] }],
      });
      if (chosen !== null) setPath(chosen);
    } catch {
      // Every path is also typeable, so a dialog that will not open is an
      // inconvenience rather than a dead end.
      setBrowseFailed(true);
    }
  };

  const generate = () => {
    setGenerating(true);
    setGenerateFailed(false);
    ipc
      .generatePassphrase(6)
      .then(
        (phrase) => {
          setPassword(phrase);
          setConfirmation(phrase);
          // Shown, because a passphrase the user has not seen is one they
          // cannot give to whoever imports the archive.
          setRevealed(true);
        },
        () => setGenerateFailed(true),
      )
      .finally(() => setGenerating(false));
  };

  const pathMissing = path.trim() === "";
  const passwordMissing = purpose === "remoter" && password === "";
  const mismatch = purpose === "remoter" && password !== "" && confirmation !== password;
  const tooWeak = purpose === "remoter" && strength !== null && !strength.acceptable;
  const blocked =
    pathMissing ||
    (purpose === "remoter" && (passwordMissing || mismatch || strength === null || tooWeak));

  const submit = () => {
    setAttempted(true);
    if (blocked || busy) return;
    exportMutation.mutate();
  };

  const blockedReason = pathMissing
    ? t("export.pathMissing")
    : passwordMissing
      ? t("export.archive.passwordMissing")
      : mismatch
        ? t("export.archive.mismatch")
        : tooWeak
          ? t("export.archive.tooWeak")
          : undefined;

  return (
    <div className={s.backdrop}>
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-label={t("export.title")}
        tabIndex={-1}
      >
        <h2 className={s.title}>{t("export.title")}</h2>

        <p className={s.audited}>
          <Icon name="alert" size={14} />
          {t("export.audited")}
        </p>

        {result !== null ? (
          <ExportResult result={result} locale={locale} onClose={onClose} />
        ) : purpose === null ? (
          <>
            <div className={s.purposes} role="radiogroup" aria-label={t("export.purposeLabel")}>
              <PurposeCard
                title={t("export.purposeRemoter")}
                body={t("export.purposeRemoterHelp")}
                glyph="lock"
                onSelect={() => choosePurpose("remoter")}
              />
              <PurposeCard
                title={t("export.purposeOther")}
                body={t("export.purposeOtherHelp")}
                glyph="file"
                onSelect={() => choosePurpose("other")}
              />
            </div>
            <div className={s.actions}>
              <Button variant="ghost" onClick={onClose}>
                {tCommon("action.cancel")}
              </Button>
            </div>
          </>
        ) : (
          <>
            {purpose === "remoter" ? (
              <Callout tone="info" title={t("export.archive.included")}>
                {t("export.archive.includedBody")}
              </Callout>
            ) : (
              <Callout tone="warning" title={t("export.noSecrets")}>
                {t("export.plaintextBody")}
              </Callout>
            )}

            {rootId !== null && (
              <Field label={t("export.scopeLabel")}>
                <div className={s.choices} role="radiogroup" aria-label={t("export.scopeLabel")}>
                  <ChoiceButton
                    label={t("export.scopeNode", { name: isolate(root?.name ?? "") })}
                    selected={scope === "node"}
                    disabled={busy}
                    onSelect={() => setScope("node")}
                  />
                  <ChoiceButton
                    label={t("export.scopeVault")}
                    selected={scope === "vault"}
                    disabled={busy}
                    onSelect={() => setScope("vault")}
                  />
                </div>
              </Field>
            )}

            {purpose === "other" && (
              <Field label={t("export.formatLabel")} help={formatHelp(t, flatFormat)}>
                <div className={s.choices} role="radiogroup" aria-label={t("export.formatLabel")}>
                  {FLAT_FORMATS.map((candidate) => (
                    <ChoiceButton
                      key={candidate}
                      label={formatLabel(t, candidate)}
                      selected={flatFormat === candidate}
                      disabled={busy}
                      onSelect={() => chooseFlatFormat(candidate)}
                    />
                  ))}
                </div>
              </Field>
            )}

            {purpose === "remoter" && (
              <>
                <Field
                  label={t("export.archive.passwordLabel")}
                  htmlFor="tree-export-password"
                  help={t("export.archive.passwordHelp")}
                  error={
                    attempted && passwordMissing ? t("export.archive.passwordMissing") : undefined
                  }
                >
                  <div className={s.pathRow}>
                    <div className={s.pathInput}>
                      <TextInput
                        id="tree-export-password"
                        value={password}
                        onChange={setPassword}
                        type={revealed ? "text" : "password"}
                        mono={revealed}
                        disabled={busy}
                        invalid={attempted && (passwordMissing || tooWeak)}
                        ariaLabel={t("export.archive.passwordLabel")}
                      />
                    </div>
                    <Button variant="ghost" size="sm" onClick={() => setRevealed(!revealed)}>
                      {revealed ? t("export.archive.hide") : t("export.archive.show")}
                    </Button>
                  </div>
                </Field>
                <div className={s.strengthRow}>
                  <BusyButton
                    variant="secondary"
                    size="sm"
                    busy={generating}
                    busyLabel={t("export.archive.generating")}
                    onClick={generate}
                    disabled={busy}
                  >
                    {t("export.archive.generate")}
                  </BusyButton>
                  {password !== "" && strength === null && strengthFailure === null && (
                    <BusyStatus label={t("export.archive.rating")} size={12} compact />
                  )}
                  {strength !== null && (
                    <span
                      className={s.strength}
                      data-acceptable={strength.acceptable}
                      role="status"
                    >
                      {strength.acceptable ? strengthText.label : t("export.archive.tooWeak")}
                      {" · "}
                      {strengthText.explanation}
                    </span>
                  )}
                </div>
                {generateFailed && <p className={s.note}>{t("export.archive.generateFailed")}</p>}
                {strengthFailure !== null && (
                  <FailureNotice failure={strengthFailure} title={t("export.archive.ratingFailed")} />
                )}
                <Field
                  label={t("export.archive.confirmLabel")}
                  htmlFor="tree-export-confirm"
                  error={
                    (attempted || confirmation !== "") && mismatch
                      ? t("export.archive.mismatch")
                      : undefined
                  }
                >
                  <TextInput
                    id="tree-export-confirm"
                    value={confirmation}
                    onChange={setConfirmation}
                    type={revealed ? "text" : "password"}
                    mono={revealed}
                    disabled={busy}
                    invalid={(attempted || confirmation !== "") && mismatch}
                    ariaLabel={t("export.archive.confirmLabel")}
                  />
                </Field>
              </>
            )}

            <Field
              label={t("export.pathLabel")}
              htmlFor="tree-export-path"
              error={attempted && pathMissing ? t("export.pathMissing") : undefined}
              help={browseFailed ? t("export.browseFailed") : undefined}
            >
              <div className={s.pathRow}>
                <div className={s.pathInput}>
                  <TextInput
                    id="tree-export-path"
                    value={path}
                    onChange={setPath}
                    mono
                    disabled={busy}
                    invalid={attempted && pathMissing}
                    placeholder={
                      purpose === "remoter"
                        ? t("export.archive.pathPlaceholder")
                        : t("export.pathPlaceholder")
                    }
                    ariaLabel={t("export.pathLabel")}
                  />
                </div>
                <Button variant="secondary" onClick={() => void browse()} disabled={busy}>
                  {t("export.browse")}
                </Button>
              </div>
            </Field>

            {failure !== null && (
              <FailureNotice
                failure={failure}
                title={t("export.failed")}
                onRetry={busy ? undefined : submit}
              />
            )}

            <div className={s.actions}>
              <Button variant="ghost" onClick={() => choosePurpose(null)} disabled={busy}>
                {t("export.back")}
              </Button>
              <div className={s.spacer} />
              <Button variant="ghost" onClick={onClose} disabled={busy}>
                {tCommon("action.cancel")}
              </Button>
              <BusyButton
                variant="primary"
                busy={busy}
                busyLabel={purpose === "remoter" ? t("export.archive.busy") : t("export.busy")}
                onClick={submit}
                title={blockedReason}
              >
                {t("export.submit")}
              </BusyButton>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

type ConnectionsT = ReturnType<typeof useT<"connections">>;

interface ExportResultProps {
  result: TreeExportResult;
  locale: string;
  onClose: () => void;
}

function ExportResult({ result, locale, onClose }: ExportResultProps) {
  const t = useT("connections");
  const tCommon = useT("common");
  const path = isolateLtr(result.path);
  const size = formatBytes(locale, result.bytes);
  const { archive, report } = result;

  return (
    <>
      <Callout tone="info" title={t("export.done")}>
        {archive !== null
          ? t("export.archive.doneDetail", {
              connections: archive.connections,
              secrets: archive.secrets,
              path,
              size,
            })
          : report !== null
            ? t("export.doneDetail", {
                written: report.connections - report.skipped,
                total: report.connections,
                path,
                size,
              })
            : null}
      </Callout>

      {archive !== null && archive.dependencies.length > 0 && (
        <section className={s.notes} aria-labelledby="tree-export-dependencies">
          <h3 className={s.notesTitle} id="tree-export-dependencies">
            {t("export.archive.dependenciesTitle", { count: archive.dependencies.length })}
          </h3>
          <ul className={s.notesList}>
            {archive.dependencies.map((name, index) => (
              // Two dependencies can share a name; the position is the identity.
              <li key={index}>{isolate(name)}</li>
            ))}
          </ul>
        </section>
      )}

      {report !== null && report.notes.length > 0 && (
        <section className={s.notes} aria-labelledby="tree-export-notes">
          <h3 className={s.notesTitle} id="tree-export-notes">
            {t("export.notesTitle", { count: report.notes.length + report.notesDropped })}
          </h3>
          <ul className={s.notesList}>
            {report.notes.map((note, index) => (
              // The core's order is the tree's order, and two notes can be
              // identical; the position is the identity.
              <li key={index}>{describeNote(t, note)}</li>
            ))}
          </ul>
          {report.notesDropped > 0 && (
            <p className={s.notesMore}>{t("export.notesMore", { count: report.notesDropped })}</p>
          )}
        </section>
      )}

      <div className={s.actions}>
        <Button variant="primary" onClick={onClose}>
          {tCommon("action.close")}
        </Button>
      </div>
    </>
  );
}

function formatLabel(t: ConnectionsT, format: TreeExportFormat): string {
  switch (format) {
    case "remoter-archive":
      return t("export.archive.formatLabel");
    case "csv":
      return t("export.csv");
    case "ssh-config":
      return t("export.sshConfig");
    case "json":
      return t("export.json");
  }
}

function formatHelp(t: ConnectionsT, format: FlatFormat): string {
  switch (format) {
    case "csv":
      return t("export.csvHelp");
    case "ssh-config":
      return t("export.sshConfigHelp");
    case "json":
      return t("export.jsonHelp");
  }
}

/**
 * A file name to offer, from the exported folder's name.
 *
 * The characters no file system on the three platforms accepts are replaced,
 * not the whole name: a folder called `Üretim` should be offered as
 * `Üretim.csv`, not as something ASCII.
 */
export function fileStem(name: string | null): string {
  const cleaned = (name ?? "")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f/\\:*?"<>|]+/g, "-")
    .replace(/^[\s.-]+|[\s.-]+$/g, "");
  return cleaned === "" ? "remoter-connections" : cleaned;
}

interface PurposeCardProps {
  title: string;
  body: string;
  glyph: "lock" | "file";
  onSelect: () => void;
}

/** One of the two answers to "who is this file for?". */
function PurposeCard({ title, body, glyph, onSelect }: PurposeCardProps) {
  return (
    <button type="button" role="radio" aria-checked={false} className={s.purpose} onClick={onSelect}>
      <span className={s.purposeGlyph} aria-hidden="true">
        <Icon name={glyph} size={18} />
      </span>
      <span className={s.purposeText}>
        <span className={s.purposeTitle}>{title}</span>
        <span className={s.purposeBody}>{body}</span>
      </span>
    </button>
  );
}

interface ChoiceButtonProps {
  label: string;
  selected: boolean;
  disabled: boolean;
  onSelect: () => void;
}

/** A radio in the shape of a button, as the audit export draws it. */
function ChoiceButton({ label, selected, disabled, onSelect }: ChoiceButtonProps) {
  return (
    <button
      type="button"
      role="radio"
      aria-checked={selected}
      className={selected ? `${s.choice} ${s.choiceOn}` : s.choice}
      disabled={disabled}
      onClick={onSelect}
    >
      {label}
    </button>
  );
}
