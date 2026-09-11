/**
 * The two host key decisions, and they must not look alike.
 *
 * `docs/security/transport-security.md` treats these as different questions:
 *
 * - **Unknown** — nothing is stored for this host. A decision, not an alarm:
 *   the fingerprint, the randomart, the algorithm, and an explicit accept.
 * - **Changed** — a key that contradicts the one already trusted. A hard
 *   failure. Both fingerprints side by side, when the old one was first
 *   trusted, the plain statement that this is either interception or a rebuilt
 *   server, and no path through that resembles the first-use one: the core
 *   refuses `accept` on a changed key outright, so the only control here is
 *   `replace`, and it needs the tail of the offered fingerprint typed by hand.
 *
 * The friction is the point. A blocking warning that can be dismissed with the
 * same keystroke as every other dialog is a warning nobody reads. Escape
 * therefore *rejects* rather than merely closing — the safe direction, and the
 * same one the backdrop takes.
 *
 * The typed confirmation is checked for length only. The core holds the
 * expected text and never sends it, precisely so this dialog cannot derive the
 * answer it is asking the user to copy off the screen.
 */

import { useEffect, useMemo, useRef, useState } from "react";

import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import type { HostKeyPrompt, IpcFailure } from "@/lib/ipc";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { formatDate, isolate, isolateLtr, useLocale, useT } from "@/i18n";

import s from "./HostKeyDialog.module.css";

interface HostKeyDialogProps {
  prompt: HostKeyPrompt;
  /** The connection's name, so the dialog says which tab is asking. */
  sessionName: string;
  busy: boolean;
  failure: IpcFailure | null;
  onAccept: () => void;
  onReplace: (confirmation: string) => void;
  onReject: () => void;
}

export function HostKeyDialog({
  prompt,
  sessionName,
  busy,
  failure,
  onAccept,
  onReplace,
  onReject,
}: HostKeyDialogProps) {
  const t = useT("sessions");
  const { code: locale } = useLocale();
  const dialogRef = useRef<HTMLDivElement>(null);
  const [confirmation, setConfirmation] = useState("");

  const changed = prompt.status === "changed";
  const id = `host-key-${String(prompt.promptId)}`;

  useFocusTrap(true, dialogRef);
  useModalRegistration(id, true);

  // Escape is a rejection, not a dismissal: there is no state in which closing
  // this dialog and continuing the handshake would be right. The press is
  // swallowed so the shell behind does not also act on it.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      if (!busy) onReject();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [busy, onReject]);

  /**
   * How many characters the core wants. It sends the length, never the text.
   * A changed prompt without one would leave no way through at all, so the
   * dialog falls back to the whole fingerprint rather than to a free pass.
   */
  const needed = useMemo(() => {
    if (!changed) return 0;
    return prompt.confirmationLen ?? prompt.fingerprint.length;
  }, [changed, prompt.confirmationLen, prompt.fingerprint.length]);

  const canReplace = changed && !busy && confirmation.trim().length === needed;

  const titleId = `${id}-title`;
  // Everything the peer sent is isolated before it reaches a sentence: the host
  // and the algorithm name are its text, not ours, and this dialog is precisely
  // the one where a value that renders in the wrong order could be mistaken for
  // a different value. The fingerprint is left-to-right by specification.
  const host = isolateLtr(prompt.host);
  const algorithm = isolate(prompt.algorithm);
  const confirmLabel = t("hostKey.confirmLabel", { count: needed });

  return (
    <div
      className={changed ? [s.backdrop, s.backdropAlarm].join(" ") : s.backdrop}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (!busy) onReject();
      }}
    >
      <div
        ref={dialogRef}
        className={changed ? [s.dialog, s.changed].join(" ") : [s.dialog, s.unknown].join(" ")}
        // `alertdialog` for the changed key: it is an error state that
        // interrupts, and a screen reader should announce it as one.
        role={changed ? "alertdialog" : "dialog"}
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className={s.header}>
          {changed && (
            <span className={s.alarmGlyph} aria-hidden="true">
              <Icon name="alert" size={20} />
            </span>
          )}
          <div className={s.headings}>
            <p className={s.session}>{sessionName}</p>
            <h2 className={s.title} id={titleId}>
              {changed ? t("hostKey.changed.title", { host }) : t("hostKey.unknown.title", { host })}
            </h2>
            <p className={s.lead}>
              {changed ? t("hostKey.changed.lead") : t("hostKey.unknown.lead")}
            </p>
          </div>
        </header>

        <div className={s.body}>
          {changed && prompt.previouslyTrusted !== null ? (
            <div className={s.compare}>
              <section className={[s.key, s.keyTrusted].join(" ")}>
                <p className={s.keyLabel}>{t("hostKey.trustedKey")}</p>
                <p className={s.fingerprint}>{prompt.previouslyTrusted.fingerprint}</p>
                {/* One message rather than a date, a separator and an algorithm
                    concatenated: the order of the two differs by language, and
                    a stored timestamp that will not parse gets its own sentence
                    rather than the word "Invalid Date". */}
                <p className={s.keyMeta}>
                  {Number.isNaN(new Date(prompt.previouslyTrusted.firstTrustedAtMs).getTime())
                    ? t("hostKey.trustedMetaUndated", { algorithm })
                    : t("hostKey.trustedMeta", {
                        date: formatDate(locale, prompt.previouslyTrusted.firstTrustedAtMs),
                        algorithm,
                      })}
                </p>
                <pre className={s.randomart}>{prompt.previouslyTrusted.randomart}</pre>
              </section>
              <section className={[s.key, s.keyOffered].join(" ")}>
                <p className={s.keyLabel}>{t("hostKey.offeredKey")}</p>
                <p className={s.fingerprint}>{prompt.fingerprint}</p>
                <p className={s.keyMeta}>{t("hostKey.offeredMeta", { algorithm })}</p>
                <pre className={s.randomart}>{prompt.randomart}</pre>
              </section>
            </div>
          ) : (
            <div className={s.single}>
              <dl className={s.facts}>
                <dt className={s.factLabel}>{t("hostKey.algorithm")}</dt>
                {/* Peer-supplied text. Rendered as text, never as markup. */}
                <dd className={s.factValue}>{prompt.algorithm}</dd>
                <dt className={s.factLabel}>{t("hostKey.fingerprint")}</dt>
                <dd className={s.fingerprint}>{prompt.fingerprint}</dd>
              </dl>
              <div className={s.randomartBlock}>
                <p className={s.keyLabel}>{t("hostKey.randomart")}</p>
                <pre className={s.randomart}>{prompt.randomart}</pre>
              </div>
            </div>
          )}

          <p className={changed ? s.compareNoteAlarm : s.compareNote}>{t("hostKey.compare")}</p>

          {changed && (
            <div className={s.confirm}>
              <label className={s.confirmLabel} htmlFor={`${id}-confirmation`}>
                {confirmLabel}
              </label>
              <TextInput
                id={`${id}-confirmation`}
                value={confirmation}
                onChange={setConfirmation}
                mono
                disabled={busy}
                ariaLabel={confirmLabel}
              />
              <p className={s.confirmHint}>{t("hostKey.confirmHint")}</p>
            </div>
          )}

          {failure !== null && (
            <div className={s.failure}>
              <FailureNotice failure={failure} title={t("hostKey.decisionRefused")} />
            </div>
          )}
        </div>

        <footer className={s.footer}>
          <p className={s.audited}>{t("hostKey.audited")}</p>
          <div className={s.actions}>
            <Button variant="secondary" onClick={onReject} disabled={busy}>
              {changed ? t("hostKey.changed.reject") : t("hostKey.unknown.reject")}
            </Button>
            {changed ? (
              // Deliberately `danger`: replacing a contradicted key widens
              // exposure, and the weight of the control should match that.
              <Button
                variant="danger"
                onClick={() => onReplace(confirmation.trim())}
                disabled={!canReplace}
              >
                {busy ? t("hostKey.deciding") : t("hostKey.changed.replace")}
              </Button>
            ) : (
              <Button variant="primary" onClick={onAccept} disabled={busy}>
                {busy ? t("hostKey.deciding") : t("hostKey.unknown.accept")}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}
