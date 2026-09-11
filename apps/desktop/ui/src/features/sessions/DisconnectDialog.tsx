/**
 * The question asked before a live session is disconnected.
 *
 * One dialog for every route out — see `closing.ts` for the list and for why a
 * confirmation that only one of them respects is worse than none. It is mounted
 * once, by `app/App.tsx`, and driven from the store rather than from props,
 * because two of the routes (the window's close control, and the shortcut) are
 * not inside the session area's React tree at all.
 *
 * **It is mounted outside the session area on purpose.** A remote desktop uses
 * all four of its own edges, and `features/sessions/layout.test.tsx` fails on
 * anything positioned out of flow inside that area. The exception that test
 * allows is a *blocking question about the session* — the connect panel, the
 * host key dialog, the ended notice — each of which is meant to cover the
 * picture and none of which is present while a session is simply running. This
 * is the same kind of thing and could have sat there; mounting it at the shell
 * instead keeps it out of the sweep entirely and lets it cover the settings
 * screen too, which is where the window's close control is on four of the
 * screens that can reach it.
 *
 * # What it says
 *
 * The host, and what the session knows it would interrupt. "Are you sure?" is
 * not information: the user pressed a control a few pixels from the tab they
 * meant to switch to, and the only thing that tells them whether that was the
 * mistake they think it was is *which machine* is about to go. A transfer still
 * moving in a file pane is named too, because that is the one interruption this
 * build can actually see.
 *
 * # The promise `aria-modal` makes
 *
 * `docs/ui/design-system.md` is explicit that whatever claims the rest of the
 * window is inert has to keep the claim: focus enters, Tab is trapped, Escape
 * cancels, focus returns, and the global shortcuts stand down. The last of
 * those is `useModalRegistration` — the registry exists so Ctrl+K cannot open a
 * second focus trap on top of this one — and the rest is `useFocusTrap`.
 *
 * Escape, the backdrop and Cancel all *decline*. That is the safe direction:
 * the whole point of the dialog is that the destructive answer has to be
 * chosen, and a dialog whose dismissal disconnects would be worse than the
 * control it was added to guard.
 */

import { useEffect, useRef } from "react";

import { Button } from "@/components/Button";
import { Icon } from "@/components/Icon";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { isolate, isolateLtr, useT } from "@/i18n";

import { confirmClose, declineClose, useClosing, type SessionAtRisk } from "./closing";

import s from "./DisconnectDialog.module.css";

const MODAL_ID = "session.disconnect";

/** One line of the window's list: the connection, and where it is. */
function AtRiskRow({ session }: { session: SessionAtRisk }) {
  const t = useT("sessions");
  // The name is the user's own text from the vault and the target is the
  // core's report of a host — both can be in any script, and a right-to-left
  // character in either must not reorder the row around it. The target is
  // additionally left-to-right by specification: a hostname and port are not
  // prose.
  const name = isolate(session.name);
  const target = session.target;

  return (
    <li className={s.row}>
      <span className={s.rowName}>
        {target === null
          ? t("close.rowNoTarget", { name })
          : t("close.rowTarget", { name, target: isolateLtr(target) })}
      </span>
      {session.transfers > 0 && (
        <span className={s.rowTransfers}>
          {t("close.transfers", { count: session.transfers })}
        </span>
      )}
    </li>
  );
}

export function DisconnectDialog() {
  const t = useT("sessions");
  const pending = useClosing((st) => st.pending);
  const busy = useClosing((st) => st.busy);
  const dialogRef = useRef<HTMLDivElement>(null);
  const open = pending !== null;

  useFocusTrap(open, dialogRef);
  useModalRegistration(MODAL_ID, open);

  // Captured, so the screen underneath does not also act on the key — a tab
  // strip that closed a *different* tab on the same Escape would be the defect
  // this dialog was added to prevent, arriving through the dialog itself.
  useEffect(() => {
    if (!open) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      declineClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
    };
  }, [open]);

  if (pending === null) return null;

  const window_ = pending.kind === "window";
  const only = pending.atRisk[0];
  const count = pending.atRisk.length;
  // Every transfer across every session in the question. The window's summary
  // says the total; each row says its own.
  const transfers = pending.atRisk.reduce((sum, session) => sum + session.transfers, 0);

  const titleId = `${MODAL_ID}-title`;
  const title = window_
    ? t("close.window.title", { count })
    : t("close.tab.title", { name: isolate(only?.name ?? "") });

  return (
    <div
      className={s.backdrop}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        declineClose();
      }}
    >
      <div
        ref={dialogRef}
        className={s.dialog}
        // `alertdialog`: it interrupts, and the thing behind the button cannot
        // be undone. A screen reader should announce it rather than wait to be
        // read.
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <header className={s.header}>
          <span className={s.glyph} aria-hidden="true">
            <Icon name="alert" size={18} />
          </span>
          <h2 className={s.title} id={titleId}>
            {title}
          </h2>
        </header>

        <div className={s.body}>
          {window_ ? (
            <>
              <p className={s.line}>{t("close.window.body")}</p>
              <ul className={s.list} aria-label={t("close.window.listLabel")}>
                {pending.atRisk.map((session) => (
                  <AtRiskRow key={session.tabId} session={session} />
                ))}
              </ul>
            </>
          ) : (
            <>
              <p className={s.line}>
                {only?.target === null || only === undefined
                  ? t("close.tab.bodyNoTarget")
                  : t("close.tab.body", { target: isolateLtr(only.target) })}
              </p>
              {only !== undefined && only.transfers > 0 && (
                <p className={s.stake}>{t("close.transfers", { count: only.transfers })}</p>
              )}
            </>
          )}

          {window_ && transfers > 0 && (
            <p className={s.stake}>{t("close.window.transfers", { count: transfers })}</p>
          )}
        </div>

        <div className={s.footer}>
          {/* Cancel first in the source, so it is the first stop for Tab and
              the one focus lands on: the safe answer should be the easy one. */}
          <Button variant="secondary" onClick={declineClose} disabled={busy}>
            {t("close.cancel")}
          </Button>
          <Button
            variant="danger"
            disabled={busy}
            onClick={() => {
              void confirmClose();
            }}
          >
            {busy ? t("close.busy") : window_ ? t("close.confirmWindow") : t("close.confirm")}
          </Button>
        </div>
      </div>
    </div>
  );
}
