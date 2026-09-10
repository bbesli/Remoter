/**
 * Step 2 — the document password, and the bad news that arrives with it.
 *
 * Whatever the detection already knows about how the file was protected is
 * said here, before the parse, rather than saved for the report. A file that
 * carries no password of its own is an mRemoteNG file encrypted with the
 * published default, and the moment to learn that is while deciding what to do
 * with its contents — not in a summary after they are in the vault.
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
import type { ImportDetection, IpcFailure } from "@/lib/ipc";

import { formatBytes } from "./SourceStep";
import s from "./ImportWizard.module.css";

const TEXT = {
  encryptedTitle: "The file is encrypted",
  encryptedLead:
    "Remoter needs the document password to read the credentials inside. The parse happens in the core, in a sandboxed reader; nothing is written to your vault until you commit.",
  plainTitle: "Nothing to supply",
  plainLead:
    "This file needs no password. The next step reads it and shows you the tree it would create.",
  passwordLabel: "Document password",
  passwordHelp: "The password mRemoteNG asks for when it opens this file.",
  show: "Show",
  hide: "Hide",
  parseFailed: "That file could not be read.",
  retry: "Try again",

  defaultTitle: "This file was not really protected",
  defaultBody:
    "It carries no password of its own. mRemoteNG encrypts such files with a password published in its own source, so anyone who has ever held a copy of this file could read every credential in it. The report after the parse will confirm what was found.",

  legacyTitle: "This file uses legacy AES-CBC with an MD5-derived key",
  legacyBody:
    "Remoter can read it. You should know that anyone who has had a copy of this file could have read it too, without much effort. Consider the credentials inside it exposed and change them on the servers after the import.",

  fullFileTitle: "The whole document is encrypted",
  fullFileBody:
    "Not just the passwords — the structure too. Nothing changes about the import; it tells you how the file was configured.",

  keysTitle: "About private keys",
  keysBody:
    "Keys named by this file are imported as references to the files they already live in. Remoter does not read the key material here, so no key passphrase is asked for.",
} as const;

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
  const needsPassword = detection?.passwordRequired ?? false;
  const doc = detection?.document ?? null;
  // mRemoteNG writes a file that asks for no password by encrypting it with a
  // password published in its own source. "No password" and "the default
  // password" are the same state, and the user is entitled to know which.
  const usedDefault = doc !== null && !doc.passwordRequired;

  return (
    <div className={`${s.step} ${s.narrow}`}>
      <div className={s.stepHead}>
        <h2 className={s.stepTitle}>{needsPassword ? TEXT.encryptedTitle : TEXT.plainTitle}</h2>
        <p className={s.stepLead}>{needsPassword ? TEXT.encryptedLead : TEXT.plainLead}</p>
      </div>

      <div className={s.card}>
        <div className={s.fileRow}>
          <span className={s.fileIcon} aria-hidden="true">
            <Icon name="file" size={17} />
          </span>
          <div className={s.fileMeta}>
            <span className={s.fileName}>{path}</span>
            <span className={s.fileFacts}>
              {detection === null ? "" : `${formatBytes(detection.sizeBytes)} · `}
              <strong>{detection?.formatLabel ?? "Format chosen by you"}</strong>
              {doc === null || doc.confVersion === null ? "" : ` · confVersion ${doc.confVersion}`}
            </span>
          </div>
        </div>

        {needsPassword && (
          <Field label={TEXT.passwordLabel} help={TEXT.passwordHelp}>
            <div className={s.passwordField}>
              <span className={s.passwordInput}>
                <TextInput
                  value={password}
                  onChange={onPassword}
                  type={reveal ? "text" : "password"}
                  autoFocus
                  ariaLabel={TEXT.passwordLabel}
                />
              </span>
              <Button variant="ghost" size="sm" onClick={() => onReveal(!reveal)}>
                {reveal ? TEXT.hide : TEXT.show}
              </Button>
            </div>
          </Field>
        )}

        {failure !== null && (
          <FailureNotice
            failure={failure}
            title={TEXT.parseFailed}
            onRetry={onRetry}
            retryLabel={TEXT.retry}
          />
        )}
      </div>

      {usedDefault && (
        <Callout tone="danger" title={TEXT.defaultTitle}>
          <p>{TEXT.defaultBody}</p>
        </Callout>
      )}

      {doc !== null && doc.legacyCipher && (
        <Callout tone="danger" title={TEXT.legacyTitle}>
          <p>{TEXT.legacyBody}</p>
          <p className={s.findingCode}>
            {`BlockCipherMode="${doc.cipher.toUpperCase()}"`}
            {doc.kdfIterations === null ? "" : ` · KdfIterations=${doc.kdfIterations}`}
          </p>
        </Callout>
      )}

      {doc !== null && doc.fullFileEncryption && (
        <Callout tone="info" title={TEXT.fullFileTitle}>
          <p>{TEXT.fullFileBody}</p>
        </Callout>
      )}

      {detection?.format === "ssh-config" && (
        <Callout tone="neutral" title={TEXT.keysTitle}>
          <p>{TEXT.keysBody}</p>
        </Callout>
      )}
    </div>
  );
}
