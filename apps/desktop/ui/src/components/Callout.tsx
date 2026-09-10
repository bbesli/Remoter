/**
 * A block of consequential information that sits in the flow of a form.
 *
 * Not a toast: a callout is for something the user must read before acting,
 * which is exactly what a toast is never allowed to carry.
 */

import type { ReactNode } from "react";

import { Icon, type IconName } from "./Icon";
import s from "./Callout.module.css";

export type CalloutTone = "neutral" | "warning" | "danger" | "info";

interface CalloutProps {
  children: ReactNode;
  tone?: CalloutTone | undefined;
  title?: string | undefined;
}

/** Neutral carries no icon: a glyph there would imply a severity it does not have. */
const TONE_ICON: Record<CalloutTone, IconName | null> = {
  neutral: null,
  warning: "alert",
  danger: "alert",
  info: "shield",
};

export function Callout({ children, tone = "neutral", title }: CalloutProps) {
  const icon = TONE_ICON[tone];

  return (
    <div className={[s.callout, s[tone]].join(" ")} role={tone === "danger" ? "alert" : undefined}>
      {icon !== null && (
        <span className={s.icon} aria-hidden="true">
          <Icon name={icon} size={15} />
        </span>
      )}
      <div className={s.body}>
        {title !== undefined && title !== "" && <p className={s.title}>{title}</p>}
        <div className={s.content}>{children}</div>
      </div>
    </div>
  );
}
