/**
 * What a key slot is called, when it was last used, and every refusal this
 * screen has to make before the core makes it.
 *
 * The refusals live here rather than inline in the components because they are
 * the part that matters and the part a test can hold.
 * `docs/security/key-management.md` is normative for all three:
 *
 *   - a vault must always retain at least one usable slot;
 *   - removing the recovery slot needs an explicit "I understand this removes
 *     my last resort";
 *   - a master key rotation must account for every slot rather than quietly
 *     discarding the ones it could not open.
 *
 * The core refuses each of these on its own — `vault.last-slot` exists — but a
 * user who learns the rule from an error message has already decided to do the
 * thing the rule forbids, and in the last-slot case there is nothing to undo.
 * So the reason is shown on the disabled control, before the attempt.
 */

import type { IconName } from "@/components/Icon";
import type { Slot, SlotKind } from "@/lib/ipc";

const TEXT = {
  kindPassword: "Password",
  kindRecovery: "Recovery key",
  kindFido2: "Security key",
  kindKeychain: "Remember on this device",

  neverUsed: "Never used",
  lastUsed: (day: string) => `Last used ${day}`,
  added: (day: string) => `Added ${day}`,
  withKeyfile: "Needs its key file too",
  noKeyfile: "Password only",

  lastSlot:
    "This is the only way into this vault. Removing it would leave a file nobody can ever open — there is no escrow key and no support override.",
  openedWith:
    "This session was opened with this slot. Removing it does not lock the vault now, but it is the way in you have most recently proved works.",
  lastRecovery:
    "This is the last recovery key on this vault. Without one, a forgotten password is the end of the vault.",

  rotationNoCredential: (label: string, index: number) =>
    `Slot ${index} (${label}) needs its password, or an explicit "discard it".`,
  rotationFido2: (label: string, index: number) =>
    `Slot ${index} (${label}) is a security key, which this version cannot re-wrap. Discard it here and enrol it again afterwards, or cancel.`,
  rotationEmpty:
    "Every slot is marked to discard. A rotation that keeps nothing produces a file nobody can open.",
} as const;

export const SLOT_KIND_LABEL: Record<SlotKind, string> = {
  password: TEXT.kindPassword,
  recovery: TEXT.kindRecovery,
  fido2: TEXT.kindFido2,
  keychain: TEXT.kindKeychain,
};

export const SLOT_KIND_ICON: Record<SlotKind, IconName> = {
  password: "lock",
  recovery: "shield",
  fido2: "usb",
  keychain: "file",
};

/**
 * A slot timestamp as a day.
 *
 * Slot times are Unix seconds. An hour and a minute would suggest a precision
 * that means nothing here — what a reader wants from "created" is whether it
 * was this week or two years ago.
 */
export function formatDay(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.getTime())) return "";
  return new Intl.DateTimeFormat(undefined, {
    day: "numeric",
    month: "short",
    year: "numeric",
  }).format(date);
}

/** "Never used" is the interesting case: it is the slot most likely to be lost. */
export function describeLastUsed(lastUsed: number | null): string {
  return lastUsed === null ? TEXT.neverUsed : TEXT.lastUsed(formatDay(lastUsed));
}

/**
 * The one line under a slot's name: whether a key file is needed, the Argon2id
 * summary when there is one, when it was added and when it last opened the
 * vault.
 */
export function slotDetail(slot: Slot): string {
  const parts: string[] = [];
  if (slot.kind === "password") {
    parts.push(slot.requiresKeyfile ? TEXT.withKeyfile : TEXT.noKeyfile);
  }
  if (slot.kdfSummary !== null && slot.kdfSummary !== "") parts.push(slot.kdfSummary);
  parts.push(TEXT.added(formatDay(slot.createdAt)));
  parts.push(describeLastUsed(slot.lastUsed));
  return parts.join(" · ");
}

/**
 * Why this slot cannot be removed, or null when it can be.
 *
 * The count is of the whole table, not of the "strong" slots: the core's rule
 * is that the table must not empty, and a keychain slot on this machine is as
 * usable as a password for that purpose.
 */
export function removalRefusal(slots: readonly Slot[]): string | null {
  return slots.length <= 1 ? TEXT.lastSlot : null;
}

/**
 * What the user should know before removing this slot, when it is allowed.
 *
 * Two cases, and neither blocks: the slot this session was opened with, and
 * the vault's only remaining recovery key.
 */
export function removalWarning(
  slots: readonly Slot[],
  slot: Slot,
  openedWith: number | null,
): string | null {
  if (slot.kind === "recovery" && slots.filter((s) => s.kind === "recovery").length === 1) {
    return TEXT.lastRecovery;
  }
  if (openedWith !== null && openedWith === slot.index) return TEXT.openedWith;
  return null;
}

/**
 * The sentence key-management.md requires before the recovery slot goes.
 *
 * Typed, not ticked. A checkbox beside a warning is read as furniture; typing
 * the sentence is the only cheap thing that makes a person read it, and this
 * is the deletion with no way back.
 */
export const LAST_RESORT_PHRASE = "I understand this removes my last resort";

export function needsLastResort(kind: SlotKind): boolean {
  return kind === "recovery";
}

/**
 * Whether the typed confirmation counts.
 *
 * Case and run-together spaces are forgiven; the words are not. Someone
 * transcribing a sentence from the line above it should not be defeated by a
 * capital letter, but nor should "yes" get through.
 */
export function lastResortSatisfied(kind: SlotKind, typed: string): boolean {
  if (!needsLastResort(kind)) return true;
  const normalise = (value: string) => value.trim().replace(/\s+/g, " ").toLowerCase();
  return normalise(typed) === normalise(LAST_RESORT_PHRASE);
}

/** One slot's place in a proposed master key rotation, with no secret in it. */
export interface RotationSlotPlan {
  index: number;
  kind: SlotKind;
  label: string;
  /** Whether a password has been typed for this slot. Never the password. */
  hasCredential: boolean;
  /** Whether the plan discards this slot instead of re-wrapping it. */
  drop: boolean;
}

/**
 * Everything wrong with a rotation plan, in the order the form shows it.
 *
 * The core refuses the same three things — `SlotCredentialMissing`,
 * `Fido2Unsupported`, `LastSlot` — but it refuses them after the user has
 * committed to a four-second re-encryption, and one of them cannot be
 * discovered any other way: a slot that is in neither list is a refusal, not a
 * silent deletion, and the form is where that has to be visible.
 */
export function rotationRefusals(plan: readonly RotationSlotPlan[]): string[] {
  const problems: string[] = [];
  const kept = plan.filter((entry) => !entry.drop);

  for (const entry of kept) {
    if (entry.kind === "password" && !entry.hasCredential) {
      problems.push(TEXT.rotationNoCredential(entry.label, entry.index));
    }
    if (entry.kind === "fido2") {
      problems.push(TEXT.rotationFido2(entry.label, entry.index));
    }
  }

  if (plan.length > 0 && kept.length === 0) problems.push(TEXT.rotationEmpty);
  return problems;
}

/**
 * The idle timeouts offered, in minutes.
 *
 * A ladder rather than the design's slider: the slider's leftmost position is
 * "never", which is a security decision, and a control where the strongest and
 * the weakest setting are a pixel apart hides that. Zero means never, which is
 * what the core's `autoLockMinutes` already says.
 */
export const AUTO_LOCK_CHOICES: readonly { minutes: number; label: string }[] = [
  { minutes: 0, label: "Never" },
  { minutes: 1, label: "1 min" },
  { minutes: 5, label: "5 min" },
  { minutes: 15, label: "15 min" },
  { minutes: 30, label: "30 min" },
  { minutes: 60, label: "1 hour" },
  { minutes: 120, label: "2 hours" },
  { minutes: 240, label: "4 hours" },
];

/**
 * The most backups the vault will keep.
 *
 * `remoter-vault` clamps to this silently, so offering more would be offering
 * a number the file will not hold.
 */
export const BACKUP_MAX = 8;
