/**
 * An indeterminate progress indicator.
 *
 * A spinner alone never explains a wait — pair it with the stage it is
 * waiting on. It stops animating under `prefers-reduced-motion`.
 */

import { useT } from "@/i18n";

import s from "./Spinner.module.css";

interface SpinnerProps {
  size?: number | undefined;
  /**
   * What is being waited on, for the screen reader. Pass the stage whenever
   * there is one; the fallback below only stops an unnamed progress indicator
   * reaching a user who cannot see it spin.
   */
  label?: string | undefined;
}

export function Spinner({ size = 16, label }: SpinnerProps) {
  const t = useT("common");

  return (
    <span
      className={s.spinner}
      style={{ width: `${size}px`, height: `${size}px` }}
      role="status"
      aria-label={label ?? t("status.working")}
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
