/**
 * Step 2 — the document password, and the bad news that arrives with it.
 *
 * Whatever the detection already knows about how the file was protected is
 * said here, before the parse, rather than saved for the report. A file that
 * carries no password of its own is an mRemoteNG file encrypted with the
 * published default, and the moment to learn that is while deciding what to do
 * with its contents — not in a summary after they are in the vault.
 *
 * Detection is not the only thing that can ask for a password. A file whose
 * format the sniffer could not place carries no header for this step to read,
 * and a `confCons.xml` the owner protected then reaches the parse and is
 * refused for the one reason the user can do something about. So the field is
 * put on the screen by either voice — the header saying a password is wanted,
 * or the core saying so after the fact — because a refusal that says "enter the
 * document password" beside no box to enter it in is a dead end.
 *
 * The password lives in this component's state for as long as it takes to hand
 * it to `import_parse`, and nowhere else: not in a store, not in a query cache,
 * not in a log line. It travels inward and never comes back.
 */

import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Button } from "@/components/Button";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { formatBytes, isolateLtr, useLocale, useT } from "@/i18n";
import type { ImportDetection, IpcFailure } from "@/lib/ipc";

import { wantsDocumentPassword } from "./steps";
import s from "./ImportWizard.module.css";

interface SecretsStepProps {
  detection: ImportDetection | null;
  path: string;
  password: string;
  onPassword: (value: string) => void;
  reveal: boolean;
  onReveal: (reveal: boolean) => void;
  /** A parse that failed lands back here, because the password is here. */
  failure: IpcFailure | null;
  onRetry: () => void;
}

export function SecretsStep({
  detection,
  path,
  password,
  onPassword,
  reveal,
  onReveal,
  failure,
  onRetry,
}: SecretsStepProps) {
  const t = useT("import");
  const { code: locale } = useLocale();
  const needsPassword =
    (detection?.passwordRequired ?? false) || wantsDocumentPassword(failure);
  const doc = detection?.document ?? null;
  // mRemoteNG writes a file that asks for no password by encrypting it with a
  // password published in its own source. "No password" and "the default
  // password" are the same state, and the user is entitled to know which.
  const usedDefault = doc !== null && !doc.passwordRequired;

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>
          {needsPassword ? t("secrets.encryptedTitle") : t("secrets.plainTitle")}
        </h2>
        <p className={s.stepLead}>
          {needsPassword ? t("secrets.encryptedLead") : t("secrets.plainLead")}
        </p>
      </div>

      <div className={s.card}>
        <div className={s.fileRow}>
          <span className={s.fileIcon} aria-hidden="true">
            <Icon name="file" size={17} />
          </span>
          <div className={s.fileMeta}>
            {/* A path is left-to-right by specification, whichever way the
                interface around it runs. */}
            <span className={s.fileName}>{isolateLtr(path)}</span>
            <span className={s.fileFacts}>
              {detection === null ? "" : `${formatBytes(locale, detection.sizeBytes)} · `}
              {/* The format's name comes from the core and is a product name:
                  never translated, isolated because it sits in a row of facts. */}
              <strong>
                {detection?.formatLabel == null || detection.formatLabel === ""
                  ? t("secrets.formatChosen")
                  : isolateLtr(detection.formatLabel)}
              </strong>
              {doc === null || doc.confVersion === null
                ? ""
                : ` · ${t("secrets.confVersion", { version: isolateLtr(doc.confVersion) })}`}
            </span>
          </div>
        </div>

        {needsPassword && (
          <Field label={t("secrets.passwordLabel")} help={t("secrets.passwordHelp")}>
            <div className={s.passwordField}>
              <span className={s.passwordInput}>
                <TextInput
                  value={password}
                  onChange={onPassword}
                  type={reveal ? "text" : "password"}
                  autoFocus
                  ariaLabel={t("secrets.passwordLabel")}
                />
              </span>
              <Button variant="ghost" size="sm" onClick={() => onReveal(!reveal)}>
                {reveal ? t("secrets.hide") : t("secrets.show")}
              </Button>
            </div>
          </Field>
        )}

        {failure !== null && (
          <FailureNotice
            failure={failure}
            title={t("secrets.parseFailed")}
            onRetry={onRetry}
            retryLabel={t("secrets.retry")}
          />
        )}
      </div>

      {usedDefault && (
        <Callout tone="danger" title={t("secrets.defaultTitle")}>
          <p>{t("secrets.defaultBody")}</p>
        </Callout>
      )}

      {doc !== null && doc.legacyCipher && (
        <Callout tone="danger" title={t("secrets.legacyTitle")}>
          <p>{t("secrets.legacyBody")}</p>
          {/* Quoted straight out of the document being imported: attribute
              names and their values, so the reader can find them in their own
              file. Never translated (docs/features/i18n.md). */}
          <p className={s.findingCode}>
            {/* eslint-disable-next-line remoter-i18n/no-literal-jsx-text --
                mRemoteNG attribute name, quoted from the file, never translated */}
            {`BlockCipherMode="${doc.cipher.toUpperCase()}"`}
            {doc.kdfIterations === null ? "" : ` · KdfIterations=${doc.kdfIterations}`}
          </p>
        </Callout>
      )}

      {doc !== null && doc.fullFileEncryption && (
        <Callout tone="info" title={t("secrets.fullFileTitle")}>
          <p>{t("secrets.fullFileBody")}</p>
        </Callout>
      )}

      {detection?.format === "ssh-config" && (
        <Callout tone="neutral" title={t("secrets.keysTitle")}>
          <p>{t("secrets.keysBody")}</p>
        </Callout>
      )}
    </div>
  );
}
