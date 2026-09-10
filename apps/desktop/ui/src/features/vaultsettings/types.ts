/**
 * What the three settings panels share with the screen that hosts them.
 *
 * The same arrangement the application settings screen uses: the screen owns
 * the read and the write, a panel is handed the values and a `save` callback,
 * and a failed write is caught in one place. A panel renders a failure only
 * when the field is one of its own — a failure shown away from the control
 * that produced it is barely better than silence.
 */

import type { IpcFailure, VaultSettings as VaultSettingsDto, VaultSettingsPatch } from "@/lib/ipc";

/** Every field this screen can write. Derived, so the patch stays the truth. */
export type VaultSettingsField = keyof VaultSettingsPatch;

export interface VaultSaveFailure {
  field: VaultSettingsField;
  failure: IpcFailure;
}

export interface VaultSectionProps {
  settings: VaultSettingsDto;
  onSave: (field: VaultSettingsField, patch: VaultSettingsPatch) => void;
  /** The field currently in flight, so its control can say it is saving. */
  savingField: VaultSettingsField | null;
  failure: VaultSaveFailure | null;
  onRetrySave: () => void;
}
