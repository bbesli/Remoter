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

import s from "./HostKeyDialog.module.css";

const TEXT = {
  unknownTitle: (host: string) => `Trust the host key for ${host}?`,
  unknownLead:
    "Remoter has never seen this machine before, so there is nothing to compare its key against. Check the fingerprint against what the server prints locally, or against what its administrator told you.",
  unknownAccept: "Trust this key and connect",
  unknownReject: "Do not connect",

  changedTitle: (host: string) => `The host key for ${host} has changed`,
  changedLead:
    "Someone may be intercepting this connection. The alternative is that the server was rebuilt and nobody told you. Remoter will not connect until you decide which it is.",
  trusted: "Key you trusted",
  offered: "Key offered now",
  firstTrusted: (when: string) => `Verified ${when}`,
  firstSeenNow: "First seen now",
  compare:
    "Compare the randomart with what the server prints locally. If you cannot check it out of band, do not continue.",
  confirmLabel: (n: number) =>
    `To continue, type the last ${String(n)} characters of the key offered now`,
  confirmHint: "Copy them off the screen above. Remoter does not fill this in for you.",
  changedReject: "Do not connect",
  changedReplace: "Replace the key and connect",
  audited: "Whichever you choose is written to the audit log.",

  algorithm: "Algorithm",
  fingerprint: "SHA-256 fingerprint",
  randomart: "Randomart",
  deciding: "Sending your decision…",
  decisionRefused: "That decision was refused",
  close: "Do not connect",
} as const;

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

function formatDate(ms: number): string {
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return "at an unknown time";
  return date.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
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
              {changed ? TEXT.changedTitle(prompt.host) : TEXT.unknownTitle(prompt.host)}
            </h2>
            <p className={s.lead}>{changed ? TEXT.changedLead : TEXT.unknownLead}</p>
          </div>
        </header>

        <div className={s.body}>
          {changed && prompt.previouslyTrusted !== null ? (
            <div className={s.compare}>
              <section className={[s.key, s.keyTrusted].join(" ")}>
                <p className={s.keyLabel}>{TEXT.trusted}</p>
                <p className={s.fingerprint}>{prompt.previouslyTrusted.fingerprint}</p>
                <p className={s.keyMeta}>
                  {TEXT.firstTrusted(formatDate(prompt.previouslyTrusted.firstTrustedAtMs))} ·{" "}
                  {prompt.algorithm}
                </p>
                <pre className={s.randomart}>{prompt.previouslyTrusted.randomart}</pre>
              </section>
              <section className={[s.key, s.keyOffered].join(" ")}>
                <p className={s.keyLabel}>{TEXT.offered}</p>
                <p className={s.fingerprint}>{prompt.fingerprint}</p>
                <p className={s.keyMeta}>
                  {TEXT.firstSeenNow} · {prompt.algorithm}
                </p>
                <pre className={s.randomart}>{prompt.randomart}</pre>
              </section>
            </div>
          ) : (
            <div className={s.single}>
              <dl className={s.facts}>
                <dt className={s.factLabel}>{TEXT.algorithm}</dt>
                {/* Peer-supplied text. Rendered as text, never as markup. */}
                <dd className={s.factValue}>{prompt.algorithm}</dd>
                <dt className={s.factLabel}>{TEXT.fingerprint}</dt>
                <dd className={s.fingerprint}>{prompt.fingerprint}</dd>
              </dl>
              <div className={s.randomartBlock}>
                <p className={s.keyLabel}>{TEXT.randomart}</p>
                <pre className={s.randomart}>{prompt.randomart}</pre>
              </div>
            </div>
          )}

          <p className={changed ? s.compareNoteAlarm : s.compareNote}>{TEXT.compare}</p>

          {changed && (
            <div className={s.confirm}>
              <label className={s.confirmLabel} htmlFor={`${id}-confirmation`}>
                {TEXT.confirmLabel(needed)}
              </label>
              <TextInput
                id={`${id}-confirmation`}
                value={confirmation}
                onChange={setConfirmation}
                mono
                disabled={busy}
                ariaLabel={TEXT.confirmLabel(needed)}
              />
              <p className={s.confirmHint}>{TEXT.confirmHint}</p>
            </div>
          )}

          {failure !== null && (
            <div className={s.failure}>
              <FailureNotice failure={failure} title={TEXT.decisionRefused} />
            </div>
          )}
        </div>

        <footer className={s.footer}>
          <p className={s.audited}>{TEXT.audited}</p>
          <div className={s.actions}>
            <Button variant="secondary" onClick={onReject} disabled={busy}>
              {changed ? TEXT.changedReject : TEXT.unknownReject}
            </Button>
            {changed ? (
              // Deliberately `danger`: replacing a contradicted key widens
              // exposure, and the weight of the control should match that.
              <Button
                variant="danger"
                onClick={() => onReplace(confirmation.trim())}
                disabled={!canReplace}
              >
                {busy ? TEXT.deciding : TEXT.changedReplace}
              </Button>
            ) : (
              <Button variant="primary" onClick={onAccept} disabled={busy}>
                {busy ? TEXT.deciding : TEXT.unknownAccept}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}
