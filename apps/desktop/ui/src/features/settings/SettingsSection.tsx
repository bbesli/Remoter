/**
 * A titled block inside a settings panel.
 *
 * The heading is a real `h2` so the panel has an outline a screen reader can
 * navigate, and the description sits directly beneath it rather than in a
 * tooltip: what a setting does is not secondary information.
 */

import type { ReactNode } from "react";

import s from "./SettingsSection.module.css";

interface SettingsSectionProps {
  title: string;
  description: string;
  children: ReactNode;
  /** Set when a control in the section needs `aria-describedby` on the text. */
  descriptionId?: string | undefined;
}

export function SettingsSection({
  title,
  description,
  children,
  descriptionId,
}: SettingsSectionProps) {
  return (
    <section className={s.section}>
      <div className={s.header}>
        <h2 className={s.title}>{title}</h2>
        <p className={s.description} {...(descriptionId === undefined ? {} : { id: descriptionId })}>
          {description}
        </p>
      </div>
      {children}
    </section>
  );
}
