/**
 * Label, control, and the one line of help or error text beneath it.
 *
 * Help and error occupy the same slot: an error replaces the help rather than
 * pushing it down, so correcting a field never reflows the form around it.
 */

import type { ReactNode } from "react";

import s from "./Field.module.css";

interface FieldProps {
  children: ReactNode;
  label?: string | undefined;
  help?: string | undefined;
  error?: string | undefined;
  htmlFor?: string | undefined;
}

export function Field({ children, label, help, error, htmlFor }: FieldProps) {
  return (
    <div className={s.field}>
      {label !== undefined && label !== "" && (
        <label className={s.label} {...(htmlFor === undefined ? {} : { htmlFor })}>
          {label}
        </label>
      )}
      {children}
      {error !== undefined && error !== "" ? (
        <p className={s.error} role="alert">
          {error}
        </p>
      ) : help !== undefined && help !== "" ? (
        <p className={s.help}>{help}</p>
      ) : null}
    </div>
  );
}
