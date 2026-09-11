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
 * **Everything else is still unanswerable**, and still says so. A password, a
 * key passphrase and a keyboard-interactive challenge have no command behind
 * them in this build, so they get the notice and the one honest control.
 */

import { useEffect, useRef } from "react";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { isolate, isolateLtr, useT } from "@/i18n";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import type { SessionPrompt } from "@/lib/ipc";
import { cancelConnect, decideHostKey } from "./manager";
import type { SessionRecord } from "./store";

import s from "./PromptPanel.module.css";

/**
 * What the server asked for, as the object of "It asked for …".
 *
 * A record rather than a key built from the wire token, so a kind the core adds
 * without copy for it is a compile error here. The old code printed the token
 * with its underscores swapped for spaces, which produced "key passphrase" in
 * English and nothing usable in any other language.
 */
const PROMPT_KIND_KEYS = {
  password: "surface.prompt.kind.password",
  key_passphrase: "surface.prompt.kind.key_passphrase",
  keyboard_interactive: "surface.prompt.kind.keyboard_interactive",
  certificate: "surface.prompt.kind.certificate",
} as const satisfies Record<SessionPrompt["kind"], string>;

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

/**
 * A question this build cannot answer.
 *
 * The one control is honest: the attempt is suspended on something no command
 * carries an answer for, and giving up is the only thing left to do from here.
 */
function UnanswerablePrompt({ record, prompt }: { record: SessionRecord; prompt: SessionPrompt }) {
  const t = useT("sessions");

  return (
    <div className={s.overlay}>
      <div className={s.notice}>
        <Callout tone="warning" title={t("surface.prompt.title")}>
          <p className={s.noticeBody}>
            {t("surface.prompt.body", { kind: t(PROMPT_KIND_KEYS[prompt.kind]) })}
          </p>
          {prompt.text !== "" && (
            <>
              <p className={s.noticeBody}>{t("surface.prompt.serverText")}</p>
              {/* The server's own text. Untrusted, and rendered as text. */}
              <pre className={s.serverText}>{prompt.text}</pre>
            </>
          )}
          <div className={s.noticeActions}>
            <Button variant="secondary" size="sm" onClick={() => void cancelConnect(record.tabId)}>
              {t("surface.prompt.cancel")}
            </Button>
          </div>
        </Callout>
      </div>
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
  return <UnanswerablePrompt record={record} prompt={prompt} />;
}
