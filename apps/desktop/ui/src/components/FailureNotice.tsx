/**
 * A failure from the core, rendered where the user was looking.
 *
 * The core's `IpcFailure` already names what failed, where, and what to do
 * next. Replacing that with a house sentence throws away the only part of the
 * message worth reading, so this renders it whole: the message, the underlying
 * diagnostic when there is one, and the suggested actions in the order the
 * core offered them.
 *
 * There is deliberately no toast variant. A failure shown away from the
 * control that produced it is barely better than silence, so every caller
 * places this next to the thing that failed.
 */

import type { ReactNode } from "react";

import { Button } from "./Button";
import { Callout, type CalloutTone } from "./Callout";
import type { IpcFailure } from "@/lib/ipc";

import s from "./FailureNotice.module.css";

interface FailureNoticeProps {
  failure: IpcFailure;
  /**
   * A heading naming the operation, when the surrounding context does not
   * already make it obvious. The core's message becomes the body beneath it.
   */
  title?: string | undefined;
  tone?: CalloutTone | undefined;
  /** Offered as a button, because "Try again" in a list cannot be pressed. */
  onRetry?: (() => void) | undefined;
  retryLabel?: string | undefined;
  /** Further ways out, beside the retry button. */
  children?: ReactNode | undefined;
}

export function FailureNotice({
  failure,
  title,
  tone = "danger",
  onRetry,
  retryLabel = "Try again",
  children,
}: FailureNoticeProps) {
  const heading = title === undefined || title === "" ? failure.message : title;
  const showMessage = heading !== failure.message;
  const hasActions = failure.actions.length > 0;
  const hasButtons = onRetry !== undefined || children !== undefined;

  return (
    <Callout tone={tone} title={heading}>
      {showMessage && <p className={s.message}>{failure.message}</p>}
      {failure.detail !== null && failure.detail !== "" && (
        <p className={s.detail}>{failure.detail}</p>
      )}
      {hasActions && (
        <ul className={s.actions}>
          {failure.actions.map((action) => (
            <li key={action}>{action}</li>
          ))}
        </ul>
      )}
      {hasButtons && (
        <div className={s.buttons}>
          {onRetry !== undefined && (
            <Button variant="secondary" size="sm" onClick={onRetry}>
              {retryLabel}
            </Button>
          )}
          {children}
        </div>
      )}
    </Callout>
  );
}
