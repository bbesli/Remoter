/**
 * The modal shell every dialog on this screen uses.
 *
 * `aria-modal` is a promise that the rest of the window is inert, and nothing
 * in the browser keeps it — see docs/ui/design-system.md. This keeps it: focus
 * enters on open, Tab is trapped, Escape cancels, focus returns to whatever
 * held it, and the press is swallowed so the screen behind does not act on the
 * same Escape. `useModalRegistration` is what tells the global shortcuts to
 * stand down while it is open.
 *
 * Escape cancels *when there is a cancel*. One dialog here has none: a
 * recovery key is shown exactly once, and a stray Escape over it destroys the
 * only copy. `dismissBlockedReason` is that case — the press is still caught,
 * and the dialog answers with the reason instead of vanishing.
 */

import { useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";

import { Icon } from "@/components/Icon";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useT } from "@/i18n";
import { useBlockingModal, useModalRegistration } from "@/hooks/useModalRegistration";

import s from "./Dialog.module.css";

interface DialogProps {
  /** Unique while open; the store keys the modal stack by it. */
  id: string;
  title: string;
  /** The sentence under the title. Every dialog here has consequences to state. */
  lead?: string | undefined;
  /**
   * Called by Escape, the backdrop and the header close button. Null while the
   * dialog must not be dismissed at all, in which case `dismissBlockedReason`
   * says why.
   */
  onDismiss: (() => void) | null;
  dismissBlockedReason?: string | undefined;
  wide?: boolean | undefined;
  footer: ReactNode;
  children: ReactNode;
}

export function Dialog({
  id,
  title,
  lead,
  onDismiss,
  dismissBlockedReason,
  wide = false,
  footer,
  children,
}: DialogProps) {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const dialogRef = useRef<HTMLDivElement>(null);
  const [refused, setRefused] = useState(false);

  useFocusTrap(true, dialogRef);
  useModalRegistration(id, true);

  // A dialog that refuses to be dismissed is still defeated by the window's own
  // close control, which sits above everything and knows nothing about what is
  // on screen. Registering here lets it ask first, and name what would be lost.
  // For the recovery key that is the whole point: it is shown once, and no
  // command can produce it again.
  useBlockingModal(
    id,
    onDismiss === null,
    dismissBlockedReason ?? t("dialog.blockedFallback"),
  );

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      // Swallowed either way. The screen behind this closes on Escape too, and
      // one press must not both cancel the dialog and leave the screen.
      event.stopPropagation();
      if (onDismiss === null) {
        setRefused(true);
        return;
      }
      onDismiss();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onDismiss]);

  const titleId = `${id}-title`;
  const showRefusal = refused && dismissBlockedReason !== undefined && dismissBlockedReason !== "";

  return (
    <div
      className={s.backdrop}
      onMouseDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (onDismiss === null) {
          setRefused(true);
          return;
        }
        onDismiss();
      }}
    >
      <div
        ref={dialogRef}
        className={wide ? [s.dialog, s.wide].join(" ") : s.dialog}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        // Somewhere for focus to land before anything focusable has rendered.
        tabIndex={-1}
      >
        <header className={s.header}>
          <div className={s.headings}>
            <h2 className={s.title} id={titleId}>
              {title}
            </h2>
            {lead !== undefined && lead !== "" && <p className={s.lead}>{lead}</p>}
          </div>
          <button
            type="button"
            className={s.close}
            aria-label={tCommon("action.close")}
            disabled={onDismiss === null}
            {...(onDismiss === null && dismissBlockedReason !== undefined
              ? { title: dismissBlockedReason }
              : {})}
            onClick={() => onDismiss?.()}
          >
            <Icon name="x" size={14} />
          </button>
        </header>

        <div className={s.body}>{children}</div>

        <footer className={s.footer}>
          {showRefusal && (
            <p className={s.refusal} role="status">
              {dismissBlockedReason}
            </p>
          )}
          <div className={s.footerActions}>{footer}</div>
        </footer>
      </div>
    </div>
  );
}
