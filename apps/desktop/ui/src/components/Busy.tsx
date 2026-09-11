/**
 * The one way this application says "working".
 *
 * Three pieces, because a wait needs three different things said about it:
 *
 *  - `BusyButton` — the control that started the work refuses a second click
 *    and shows the work in itself. It keeps the width of the wider of its two
 *    labels, so a row of buttons does not jump when one of them starts working.
 *  - `BusyStatus` — the words. A spinner on its own says only "something";
 *    "Deriving the key…" says the wait is expected. The optional `note` is for
 *    a wait that is long by design — the Argon2id cost is the security
 *    property, so it is explained rather than hidden.
 *  - `Skeleton` / `SkeletonRows` — the shape of what is coming, so a query in
 *    flight is never a blank panel.
 *
 * Motion: the spinner and the skeleton both stop under `prefers-reduced-motion`
 * in their own stylesheets. Nothing here animates by hand.
 */

import type { ReactNode } from "react";

import { Button, type ButtonSize, type ButtonVariant } from "./Button";
import { Spinner } from "./Spinner";
import s from "./Busy.module.css";

/** Spinners scale with the control they sit in; these are the two sizes used. */
const SPINNER_SIZE: Record<ButtonSize, number> = { sm: 13, md: 15 };

interface BusyButtonProps {
  /** The label when idle. */
  children: ReactNode;
  /** What the button is doing, shown beside the spinner. Never a bare "…". */
  busyLabel: string;
  busy: boolean;
  onClick?: (() => void) | undefined;
  /** Blocked for a reason other than being busy. */
  disabled?: boolean | undefined;
  variant?: ButtonVariant | undefined;
  size?: ButtonSize | undefined;
  type?: "button" | "submit" | undefined;
  fullWidth?: boolean | undefined;
  /** Why the button cannot be pressed, when it cannot. */
  title?: string | undefined;
  ariaLabel?: string | undefined;
}

export function BusyButton({
  children,
  busyLabel,
  busy,
  onClick,
  disabled = false,
  variant = "secondary",
  size = "md",
  type = "button",
  fullWidth = false,
  title,
  ariaLabel,
}: BusyButtonProps) {
  const spinner = SPINNER_SIZE[size];

  return (
    <Button
      variant={variant}
      size={size}
      type={type}
      fullWidth={fullWidth}
      // Disabled rather than merely ignored: a second click has to be
      // impossible, not just unhelpful.
      disabled={busy || disabled}
      onClick={onClick}
      title={title ?? (busy ? busyLabel : undefined)}
      ariaLabel={ariaLabel}
    >
      <span className={s.swap}>
        <span className={busy ? `${s.face} ${s.faceHidden}` : s.face} aria-hidden={busy}>
          {children}
        </span>
        <span className={busy ? s.face : `${s.face} ${s.faceHidden}`} aria-hidden={!busy}>
          <Spinner size={spinner} label={busyLabel} />
          {busyLabel}
        </span>
      </span>
    </Button>
  );
}

interface BusyStatusProps {
  /** The stage, in words: "Deriving the key…", "Reading the vault header…". */
  label: string;
  /**
   * Why this particular wait is long. Only for the waits that are long by
   * design — unlock, vault creation, master key rotation.
   */
  note?: string | undefined;
  size?: number | undefined;
  /** Keeps the note on the same line as the label, for a tight bar. */
  compact?: boolean | undefined;
}

export function BusyStatus({ label, note, size = 14, compact = false }: BusyStatusProps) {
  return (
    <span className={s.status} role="status">
      <Spinner size={size} label={label} />
      <span className={compact ? `${s.statusText} ${s.compact}` : s.statusText}>
        <span className={s.statusLabel}>{label}</span>
        {note !== undefined && note !== "" && <span className={s.statusNote}>{note}</span>}
      </span>
    </span>
  );
}

interface SkeletonProps {
  /** A CSS length. Defaults to filling the row. */
  width?: string | undefined;
  height?: string | undefined;
}

/**
 * A block standing in for content that has not arrived. Decorative by
 * definition: the surrounding `BusyStatus` is what a screen reader announces.
 */
export function Skeleton({ width = "100%", height = "var(--space-4)" }: SkeletonProps) {
  return <span className={s.skeleton} style={{ width, height }} aria-hidden="true" />;
}

interface SkeletonRowsProps {
  count: number;
  height?: string | undefined;
  /** Widths cycled through the rows, so the placeholder reads as a list. */
  widths?: readonly string[] | undefined;
}

const DEFAULT_WIDTHS = ["92%", "74%", "84%", "66%"] as const;

export function SkeletonRows({ count, height, widths = DEFAULT_WIDTHS }: SkeletonRowsProps) {
  return (
    <span className={s.rows} aria-hidden="true">
      {Array.from({ length: count }, (_unused, index) => (
        <Skeleton
          key={index}
          width={widths[index % widths.length] ?? "100%"}
          {...(height === undefined ? {} : { height })}
        />
      ))}
    </span>
  );
}
