/**
 * A single-line text field.
 *
 * `type="password"` is passed straight through to the platform control so the
 * OS keeps the value out of screenshots and accessibility text where it can.
 * The value still lives in React state only long enough to be handed to the
 * core — the frontend never stores a secret.
 */

import type { KeyboardEvent } from "react";

import s from "./TextInput.module.css";

interface TextInputProps {
  value: string;
  onChange: (value: string) => void;
  type?: "text" | "password" | undefined;
  placeholder?: string | undefined;
  mono?: boolean | undefined;
  autoFocus?: boolean | undefined;
  disabled?: boolean | undefined;
  invalid?: boolean | undefined;
  id?: string | undefined;
  ariaLabel?: string | undefined;
  onKeyDown?: ((e: KeyboardEvent<HTMLInputElement>) => void) | undefined;
}

export function TextInput({
  value,
  onChange,
  type = "text",
  placeholder,
  mono = false,
  autoFocus = false,
  disabled = false,
  invalid = false,
  id,
  ariaLabel,
  onKeyDown,
}: TextInputProps) {
  const classes = [s.input];
  if (mono) classes.push(s.mono);
  if (invalid) classes.push(s.invalid);

  return (
    <input
      className={classes.join(" ")}
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      autoFocus={autoFocus}
      aria-invalid={invalid}
      spellCheck={false}
      autoCorrect="off"
      autoCapitalize="off"
      {...(placeholder === undefined ? {} : { placeholder })}
      {...(id === undefined ? {} : { id })}
      {...(ariaLabel === undefined ? {} : { "aria-label": ariaLabel })}
      {...(onKeyDown === undefined ? {} : { onKeyDown })}
    />
  );
}
