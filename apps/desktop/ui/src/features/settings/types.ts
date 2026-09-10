/**
 * The shapes the settings sections share with the screen that hosts them.
 *
 * They live here rather than in `AppSettings.tsx` so that a section can import
 * them without importing the screen it is rendered by.
 */

import type { AppSettings as AppSettingsDto, IpcFailure } from "@/lib/ipc";

/** The settings this screen writes. Everything else it shows is read-only. */
export type SettingsField = "theme" | "locale";

export interface SaveFailure {
  field: SettingsField;
  failure: IpcFailure;
}

export interface SectionProps {
  settings: AppSettingsDto;
  onSave: (field: SettingsField, patch: Partial<AppSettingsDto>) => void;
  /** The field currently in flight, so its control can say it is saving. */
  savingField: SettingsField | null;
  /**
   * The last write that failed. A section renders it only when the field is
   * one of its own: a failure shown away from the control that produced it is
   * barely better than silence.
   */
  failure: SaveFailure | null;
  onRetrySave: () => void;
}
