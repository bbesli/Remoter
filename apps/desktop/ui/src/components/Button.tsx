/**
 * The only button in the application that carries a visual weight.
 *
 * `danger` is not a colour choice — it is reserved for actions that destroy
 * data or widen exposure, so that weight stays proportional to risk.
 */

import type { ReactNode } from "react";

import s from "./Button.module.css";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";
export type ButtonSize = "sm" | "md";

interface ButtonProps {
  children: ReactNode;
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  onClick?: (() => void) | undefined;
  disabled?: boolean | undefined;
  type?: "button" | "submit" | undefined;
  fullWidth?: boolean | undefined;
  title?: string | undefined;
  ariaLabel?: string | undefined;
}

export function Button({
  children,
  variant = "secondary",
  size = "md",
  onClick,
  disabled = false,
  type = "button",
  fullWidth = false,
  title,
  ariaLabel,
}: ButtonProps) {
  const classes = [s.button, s[variant], s[size]];
  if (fullWidth) classes.push(s.fullWidth);

  return (
    <button
      type={type === "submit" ? "submit" : "button"}
      className={classes.filter(Boolean).join(" ")}
      onClick={onClick}
      disabled={disabled}
      {...(title === undefined ? {} : { title })}
      {...(ariaLabel === undefined ? {} : { "aria-label": ariaLabel })}
    >
      {children}
    </button>
  );
}
