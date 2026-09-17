/**
 * The questions a server asks mid-handshake, and the two shapes they take.
 *
 * # Why this file exists at all
 *
 * There used to be one panel here with one control on it — Cancel — and that
 * was defensible while nothing the core sent could be answered. It stopped
 * being defensible the moment RDP shipped. **Almost every Windows host presents
 * a self-signed certificate**, so the first connection to one raises
 * `PromptKind::Certificate`, which arrives as a `prompt` message; a panel whose
 * only button gave up meant the protocol worked, the picture worked, and the
 * user could not get past the first dialog. The question was answerable the
 * whole time: `host_key_decide` has taken `Certificate` since it learned to
 * record one.
 *
 * # The two shapes
 *
 * **A certificate question is a trust decision**, and it is drawn as one — the
 * same dialog weight as `HostKeyDialog`'s unknown branch, because it is the
 * same decision about a different kind of key. `crates/remoter-proto/src/
 * hostkey.rs` and `docs/security/transport-security.md` set the rule that
 * governs it: a **first use** is a considered accept, made by comparing a
 * fingerprint against something the far end did not also supply, and a
 * **changed** key is a hard failure that demands the tail of the offered
 * fingerprint typed by hand.
 *
 * Three things follow, and none of them is negotiable:
 *
 * 1. **No accept without the fingerprint on screen.** A trust button beside no
 *    evidence means "trust whatever answered the port". If the core did not
 *    send one, this dialog offers no accept.
 * 2. **No accept for a contradiction.** A certificate that contradicts a pinned
 *    one never arrives here — the RDP adapter raises that as a `HostKey` prompt,
 *    the only shape carrying both fingerprints — and if one ever did, `changed`
 *    is not in {@link FIRST_USE_REASONS} and gets no accept. There is
 *    deliberately no `replace` path in this file; the core refuses `replace` on
 *    a certificate anyway.
 * 3. **No accept for a revoked or unparseable certificate.** Revocation is the
 *    issuer saying this key is compromised, and a fingerprint comparison cannot
 *    answer that. A malformed certificate has nothing to compare.
 *
 * **A typed question is a form.** A password with none stored, the passphrase of
 * an encrypted key, a keyboard-interactive round — a one-time code, an expired
 * password — are answered with what the user types, through
 * `session_prompt_answer`, which the core refuses for a trust decision. Four
 * rules hold for it:
 *
 * 1. **`echo` is the server's, and it is obeyed.** A field the server marked
 *    secret is a password field, with a reveal toggle the user has to press.
 * 2. **The answer is not kept.** It lives in this component's field until it is
 *    sent and is cleared the moment it is; the session store holds the
 *    question, never the answer, and nothing offers to save it.
 * 3. **The server's words are text.** The question and the instruction of a
 *    keyboard-interactive round are peer-supplied, and are rendered as text in
 *    their own block — never as markup, never as a label a server could style.
 * 4. **Cancelling is an answer.** It tells the adapter to give up, and the
 *    attempt ends with a failure the tab can explain and retry.
 */

import { useEffect, useRef, useState, type FormEvent } from "react";

import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { TextInput } from "@/components/TextInput";
import { isolate, isolateLtr, useT } from "@/i18n";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import type { SessionPrompt } from "@/lib/ipc";
import { answerPrompt, decideHostKey } from "./manager";
import type { SessionRecord } from "./store";

import s from "./PromptPanel.module.css";

/**
 * Why the certificate is not trusted, in words.
 *
 * The keys are `remoter_proto::CertificateProblem::as_str` verbatim. A closed
 * set of seven, so this is a translation rather than a passthrough — and a
 * value outside the set is shown as itself rather than guessed at.
 */
type ReasonKey =
  | "surface.certificate.reason.selfSigned"
  | "surface.certificate.reason.untrustedRoot"
  | "surface.certificate.reason.expired"
  | "surface.certificate.reason.nameMismatch"
  | "surface.certificate.reason.revoked"
  | "surface.certificate.reason.malformed"
  | "surface.certificate.reason.changed";

const REASON_KEYS: Readonly<Record<string, ReasonKey>> = {
  "self-signed": "surface.certificate.reason.selfSigned",
  "untrusted root": "surface.certificate.reason.untrustedRoot",
  expired: "surface.certificate.reason.expired",
  "name mismatch": "surface.certificate.reason.nameMismatch",
  revoked: "surface.certificate.reason.revoked",
  malformed: "surface.certificate.reason.malformed",
  changed: "surface.certificate.reason.changed",
};

/**
 * The reasons for which an explicit accept is the right control.
 *
 * Each of these means the same thing: **nothing is pinned for this host and the
 * chain did not validate**. That is a first use, and a first use is decided by
 * comparing the fingerprint out of band — which is exactly what this dialog
 * puts on screen.
 *
 * The three that are absent are absent on purpose. `changed` contradicts a
 * certificate the user already checked and belongs to the host key dialog's
 * replace path, never to this one. `revoked` is the issuer stating that the key
 * is compromised, and no amount of comparing the fingerprint makes that untrue.
 * `malformed` could not be parsed, so there is nothing to compare. For all
 * three the dialog states the reason and offers only the refusal — which is a
 * decision, not a missing control.
 */
const FIRST_USE_REASONS: ReadonlySet<string> = new Set([
  "self-signed",
  "untrusted root",
  "expired",
  "name mismatch",
]);

/**
 * A first-use certificate decision.
 *
 * Escape rejects rather than dismisses, and so does the backdrop. There is no
 * state in which closing this and letting the handshake continue would be
 * right: the core is suspended waiting for exactly one of two answers, and
 * anything that is not an explicit yes is read as a no — `is_affirmative` in
 * the adapter's prompt channel accepts the literal `yes` and nothing else.
 */
function CertificateDialog({ record, prompt }: { record: SessionRecord; prompt: SessionPrompt }) {
  const t = useT("sessions");
  const dialogRef = useRef<HTMLDivElement>(null);
  const busy = record.hostKeyBusy;
  const id = `certificate-${String(prompt.promptId)}`;

  useFocusTrap(true, dialogRef);
  useModalRegistration(id, true);

  const reject = () => {
    void decideHostKey(record.tabId, { decision: "reject", promptId: prompt.promptId });
  };

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      if (record.hostKeyBusy) return;
      void decideHostKey(record.tabId, { decision: "reject", promptId: prompt.promptId });
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [record.tabId, record.hostKeyBusy, prompt.promptId]);

  const fingerprint = prompt.fingerprint;
  const reason = prompt.reason;
  const reasonKey = reason === null ? undefined : REASON_KEYS[reason];

  // The whole gate, in one expression. Both halves are required: evidence to
  // compare, and a reason for which comparing it is the right answer.
  const answerable =
    fingerprint !== null && fingerprint !== "" && reason !== null && FIRST_USE_REASONS.has(reason);

  const titleId = `${id}-title`;
  // `prompt.text` is the address the adapter was connecting to. Machine text,
  // left-to-right, isolated so it cannot reorder the sentence it sits in.
  const host = isolateLtr(prompt.text);

  return (
    <div
      className={s.backdrop}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (!busy) reject();
      }}
    >
      <div
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className={s.header}>
          <p className={s.session}>{record.name}</p>
          <h2 className={s.title} id={titleId}>
            {t("surface.certificate.title", { host })}
          </h2>
          <p className={s.lead}>
            {answerable ? t("surface.certificate.lead") : t("surface.certificate.leadRefused")}
          </p>
        </header>

        <div className={s.body}>
          {reason !== null && (
            <dl className={s.facts}>
              <dt className={s.factLabel}>{t("surface.certificate.reasonLabel")}</dt>
              <dd className={s.factValue}>
                {reasonKey === undefined
                  ? // A problem this build has no sentence for. Shown as the
                    // core's own word, isolated, rather than guessed at — and
                    // it is not in FIRST_USE_REASONS, so there is no accept
                    // beside it either.
                    t("surface.certificate.reason.unnamed", { reason: isolate(reason) })
                  : t(reasonKey)}
              </dd>
            </dl>
          )}

          {fingerprint !== null && fingerprint !== "" && (
            <div>
              <p className={s.factLabel}>{t("surface.certificate.fingerprint")}</p>
              {/* The value the user compares out of band. Peer-supplied text,
                  rendered as text, in its own block. */}
              <p className={s.fingerprint}>{fingerprint}</p>
            </div>
          )}

          <p className={s.compareNote}>
            {answerable ? t("surface.certificate.compare") : t("surface.certificate.noAccept")}
          </p>

          {record.hostKeyError !== null && (
            <FailureNotice
              failure={record.hostKeyError}
              title={t("surface.certificate.decisionRefused")}
            />
          )}
        </div>

        <footer className={s.footer}>
          <p className={s.audited}>{t("hostKey.audited")}</p>
          <div className={s.actions}>
            <Button variant="secondary" onClick={reject} disabled={busy}>
              {t("surface.certificate.reject")}
            </Button>
            {answerable && (
              <Button
                variant="primary"
                onClick={() => {
                  void decideHostKey(record.tabId, {
                    decision: "accept",
                    promptId: prompt.promptId,
                  });
                }}
                disabled={busy}
              >
                {busy ? t("hostKey.deciding") : t("surface.certificate.accept")}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}

/** The three typed questions, and the copy each is drawn with. */
type TypedKind = Exclude<SessionPrompt["kind"], "certificate">;

const TYPED_COPY = {
  password: {
    title: "surface.prompt.passwordTitle",
    lead: "surface.prompt.passwordLead",
    label: "surface.prompt.passwordLabel",
  },
  key_passphrase: {
    title: "surface.prompt.passphraseTitle",
    lead: "surface.prompt.passphraseLead",
    label: "surface.prompt.passphraseLabel",
  },
  keyboard_interactive: {
    title: "surface.prompt.challengeTitle",
    lead: "surface.prompt.challengeLead",
    label: "surface.prompt.answerLabel",
  },
} as const satisfies Record<TypedKind, { title: string; lead: string; label: string }>;

/**
 * A password, passphrase or keyboard-interactive question, answered by typing.
 *
 * Escape cancels, and so does the backdrop: the core is suspended on this
 * question, and walking away from it without saying so would leave the attempt
 * waiting for an answer nobody is going to type.
 */
function TypedPromptDialog({
  record,
  prompt,
  kind,
}: {
  record: SessionRecord;
  prompt: SessionPrompt;
  kind: TypedKind;
}) {
  const t = useT("sessions");
  const dialogRef = useRef<HTMLFormElement>(null);
  const [value, setValue] = useState("");
  const [revealed, setRevealed] = useState(false);
  const busy = record.promptBusy;
  const copy = TYPED_COPY[kind];
  const id = `prompt-${String(prompt.promptId)}`;
  const fieldId = `${id}-field`;
  const titleId = `${id}-title`;

  useFocusTrap(true, dialogRef);
  useModalRegistration(id, true);

  // A keyboard-interactive round may legitimately be answered with nothing;
  // a password or a passphrase may not.
  const required = kind !== "keyboard_interactive";
  const canSend = !busy && (!required || value !== "");

  const cancel = () => {
    setValue("");
    void answerPrompt(record.tabId, prompt.promptId, { response: "cancel" });
  };

  const send = (event: FormEvent) => {
    event.preventDefault();
    if (!canSend) return;
    const typed = value;
    // Out of the field before the command is even awaited: a slow session is
    // no reason for the answer to stay on screen.
    setValue("");
    setRevealed(false);
    void answerPrompt(record.tabId, prompt.promptId, { response: "answer", value: typed });
  };

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      if (record.promptBusy) return;
      setValue("");
      void answerPrompt(record.tabId, prompt.promptId, { response: "cancel" });
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [record.tabId, record.promptBusy, prompt.promptId]);

  // The address the attempt is for: machine text, left to right, isolated.
  const host = isolateLtr(record.target ?? record.name);
  const secret = !prompt.echo;
  const question = kind === "keyboard_interactive" ? prompt.text : "";
  const instruction = kind === "keyboard_interactive" ? (prompt.instruction ?? "") : "";

  return (
    <div
      className={s.backdrop}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (!busy) cancel();
      }}
    >
      <form
        ref={dialogRef}
        className={s.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onSubmit={send}
      >
        <header className={s.header}>
          <p className={s.session}>{record.name}</p>
          <h2 className={s.title} id={titleId}>
            {t(copy.title, { host })}
          </h2>
          <p className={s.lead}>{t(copy.lead)}</p>
        </header>

        <div className={s.body}>
          {(instruction !== "" || question !== "") && (
            <div>
              <p className={s.factLabel}>{t("surface.prompt.serverText")}</p>
              {/* The server's own words. Untrusted, and rendered as text. */}
              <pre className={s.serverText}>
                {[instruction, question].filter((part) => part !== "").join("\n")}
              </pre>
            </div>
          )}

          <div>
            <label className={s.factLabel} htmlFor={fieldId}>
              {t(copy.label)}
            </label>
            <div className={s.answerRow}>
              <div className={s.answerField}>
                <TextInput
                  id={fieldId}
                  value={value}
                  onChange={setValue}
                  type={secret && !revealed ? "password" : "text"}
                  mono={!secret || revealed}
                  autoFocus
                  disabled={busy}
                />
              </div>
              {secret && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setRevealed(!revealed)}
                  disabled={busy}
                >
                  {revealed ? t("surface.prompt.hide") : t("surface.prompt.show")}
                </Button>
              )}
            </div>
          </div>

          {record.promptError !== null && (
            <FailureNotice failure={record.promptError} title={t("surface.prompt.sendFailed")} />
          )}
        </div>

        <footer className={s.footer}>
          <p className={s.audited}>{t("surface.prompt.notSaved")}</p>
          <div className={s.actions}>
            <Button variant="secondary" onClick={cancel} disabled={busy}>
              {t("surface.prompt.cancel")}
            </Button>
            <Button variant="primary" type="submit" disabled={!canSend}>
              {busy ? t("surface.prompt.sending") : t("surface.prompt.submit")}
            </Button>
          </div>
        </footer>
      </form>
    </div>
  );
}

/** Whichever of the two the suspended question needs. */
export function PromptPanel({ record }: { record: SessionRecord }) {
  const prompt = record.prompt;
  if (prompt === null) return null;
  if (prompt.kind === "certificate") {
    return <CertificateDialog record={record} prompt={prompt} />;
  }
  // Keyed by the question: the next round of a keyboard-interactive exchange
  // is a new question, and must not inherit the field of the one before it.
  return (
    <TypedPromptDialog
      key={prompt.promptId}
      record={record}
      prompt={prompt}
      kind={prompt.kind}
    />
  );
}
