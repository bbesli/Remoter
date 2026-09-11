/**
 * The frame every dialog in this feature sits in.
 *
 * `role="dialog" aria-modal="true"` is a promise that the rest of the window is
 * inert, and `docs/ui/design-system.md` is explicit that whatever makes the
 * promise has to keep it: focus enters on open, Tab is trapped, Escape cancels,
 * focus returns on close, and the global handlers underneath are suppressed.
 * Three of those are `useFocusTrap`'s, the fourth is the Escape listener below,
 * and the fifth is `useModalRegistration` — which is how the command palette
 * knows not to open Ctrl+K on top of a confirmation, the gap that put two focus
 * traps on screen at once.
 *
 * Escape is ignored while `busy`. A removal or a rename already in flight
 * cannot be called back, and closing over it would leave the user with no idea
 * whether it happened.
 */

import { useEffect, useRef, type ReactNode } from "react";

import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";

import s from "./DialogFrame.module.css";

interface DialogFrameProps {
  /** Registry id, so global shortcuts know a modal surface is open. */
  id: string;
  title: string;
  /** True while a command this dialog started is in flight. */
  busy?: boolean | undefined;
  onClose: () => void;
  children: ReactNode;
  /** The buttons row. Kept out of `children` so every dialog puts it last. */
  footer: ReactNode;
}

export function DialogFrame({ id, title, busy = false, onClose, children, footer }: DialogFrameProps) {
  const dialogRef = useRef<HTMLDivElement | null>(null);

  useFocusTrap(true, dialogRef);
  useModalRegistration(id, true);

  useEffect(() => {
    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key !== "Escape" || busy) return;
      e.preventDefault();
      e.stopPropagation();
      onClose();
    };
    // Capture, so the screen underneath does not also act on the key.
    document.addEventListener("keydown", onKeyDown, true);
    return () => document.removeEventListener("keydown", onKeyDown, true);
  }, [busy, onClose]);

  const titleId = `${id}-title`;

  return (
    <div className={s.backdrop}>
      <div className={s.dialog} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={dialogRef}>
        <h2 className={s.title} id={titleId}>
          {title}
        </h2>
        <div className={s.body}>{children}</div>
        <div className={s.footer}>{footer}</div>
      </div>
    </div>
  );
}
