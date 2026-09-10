/**
 * The Remoter mark.
 *
 * Served from `public/brand/` rather than inlined so that the brand files stay
 * the single source: replacing the SVG replaces every appearance of the logo.
 */

import s from "./Mark.module.css";

interface MarkProps {
  size?: number | undefined;
}

export function Mark({ size = 26 }: MarkProps) {
  return (
    <img
      className={s.mark}
      src="/brand/main-logo.svg"
      width={size}
      height={size}
      alt=""
      draggable={false}
    />
  );
}
