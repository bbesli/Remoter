/**
 * An indeterminate progress indicator.
 *
 * A spinner alone never explains a wait — pair it with the stage it is
 * waiting on. It stops animating under `prefers-reduced-motion`.
 */

import s from "./Spinner.module.css";

interface SpinnerProps {
  size?: number | undefined;
  label?: string | undefined;
}

export function Spinner({ size = 16, label }: SpinnerProps) {
  return (
    <span
      className={s.spinner}
      style={{ width: `${size}px`, height: `${size}px` }}
      role="status"
      aria-label={label ?? "Working"}
    >
      <svg viewBox="0 0 24 24" width={size} height={size} aria-hidden="true">
        <circle className={s.track} cx="12" cy="12" r="9" fill="none" strokeWidth="2.4" />
        <circle
          className={s.head}
          cx="12"
          cy="12"
          r="9"
          fill="none"
          strokeWidth="2.4"
          strokeLinecap="round"
        />
      </svg>
    </span>
  );
}
