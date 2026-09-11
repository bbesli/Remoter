/**
 * A failure from the core, rendered where the user was looking.
 *
 * The core's `IpcFailure` already names what failed, where, and what to do
 * next. Replacing that with a house sentence throws away the only part of the
 * message worth reading, so this renders it whole: the message, the underlying
 * diagnostic when there is one, and the suggested actions in the order the
 * core offered them.
 *
 * What it does not render is the core's *English*. The sentence and the action
 * labels go through `useFailureText`, which looks the failure's stable `code`
 * up in `locales/<lang>/errors.json` and falls back to exactly what the core
 * sent for a code the catalogue does not know yet. See `src/i18n/failures.ts`
 * for why the join is the code and not the text.
 *
 * There is deliberately no toast variant. A failure shown away from the
 * control that produced it is barely better than silence, so every caller
 * places this next to the thing that failed.
 */

import type { ReactNode } from "react";

import { useFailureText, useT } from "@/i18n";

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
  /** Overrides the generic "Try again" where a verb naming the operation reads better. */
  retryLabel?: string | undefined;
  /** Further ways out, beside the retry button. */
  children?: ReactNode | undefined;
}

export function FailureNotice({
  failure,
  title,
  tone = "danger",
  onRetry,
  retryLabel,
  children,
}: FailureNoticeProps) {
  const t = useT("common");
  const text = useFailureText(failure);
  // Defaulted here rather than in the parameter list: the fallback is a
  // translated string and a default parameter is evaluated before the hook.
  const retryText = retryLabel === undefined || retryLabel === "" ? t("action.retry") : retryLabel;
  const heading = title === undefined || title === "" ? text.message : title;
  const showMessage = heading !== text.message;
  const hasActions = text.actions.length > 0;
  const hasButtons = onRetry !== undefined || children !== undefined;

  return (
    <Callout tone={tone} title={heading}>
      {showMessage && <p className={s.message}>{text.message}</p>}
      {text.detail !== null && text.detail !== "" && <p className={s.detail}>{text.detail}</p>}
      {hasActions && (
        <ul className={s.actions}>
          {/* Keyed by position, not by text: two languages may translate two
              different actions to the same words, and the list is ordered. */}
          {text.actions.map((action, index) => (
            <li key={index}>{action}</li>
          ))}
        </ul>
      )}
      {hasButtons && (
        <div className={s.buttons}>
          {onRetry !== undefined && (
            <Button variant="secondary" size="sm" onClick={onRetry}>
              {retryText}
            </Button>
          )}
          {children}
        </div>
      )}
    </Callout>
  );
}
