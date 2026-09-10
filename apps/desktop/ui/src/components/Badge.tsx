/**
 * A short status label.
 *
 * Every badge carries text, never colour alone — the accessibility rule in
 * docs/ui/information-architecture.md applies to session state above all.
 */

import type { ReactNode } from "react";

import s from "./Badge.module.css";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info" | "accent";

interface BadgeProps {
  children: ReactNode;
  tone?: BadgeTone | undefined;
  mono?: boolean | undefined;
  title?: string | undefined;
}

export function Badge({ children, tone = "neutral", mono = false, title }: BadgeProps) {
  const classes = [s.badge, s[tone]];
  if (mono) classes.push(s.mono);

  return (
    <span className={classes.join(" ")} {...(title === undefined ? {} : { title })}>
      {children}
    </span>
  );
}
