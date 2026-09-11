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
 *
 * # Why every function here takes `t` and a locale
 *
 * These are pure functions called from render loops, and `useT` is a hook, so
 * the catalogue accessor arrives as an argument rather than being reached for
 * — the same arrangement `settings/ShortcutsSection.tsx` uses. Nothing in this
 * file may hold a resolved string at module scope either: a label resolved at
 * import would keep the language the application started in for the rest of
 * the session, and switching language is supposed to need no restart.
 */

import type { TFunction } from "i18next";

import type { IconName } from "@/components/Icon";
import { kdfSummary } from "@/features/vault/kdf";
import { equalsIgnoringCase, formatDate, isolate } from "@/i18n";
import type { Slot, SlotKind } from "@/lib/ipc";

/** This screen's catalogue accessor, as a value a pure function can take. */
export type VaultT = TFunction<"vaultsettings">;

/**
 * Everything a description of a slot needs: the two catalogues it reads and
 * the language `Intl` formats its dates in.
 */
export interface SlotCopy {
  t: VaultT;
  tCommon: TFunction<"common">;
  /** The BCP 47 tag in force, from `useLocale()`. */
  locale: string;
}

/**
 * The catalogue key naming each kind of slot.
 *
 * Keys rather than labels, for the reason in the file header: this map is
 * module-level, and a translated label here would be frozen at import.
 */
const SLOT_KIND_KEY = {
  password: "slot.kind.password",
  recovery: "slot.kind.recovery",
  fido2: "slot.kind.fido2",
  keychain: "slot.kind.keychain",
} as const satisfies Record<SlotKind, string>;

/** What this kind of slot is called, in the reader's language. */
export function slotKindLabel(kind: SlotKind, t: VaultT): string {
  return t(SLOT_KIND_KEY[kind]);
}

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
 *
 * The locale is the one the user chose in this application, not the one the
 * operating system happens to be set to: this used to build its own
 * `Intl.DateTimeFormat` with `undefined` for the locale, which is how a German
 * interface ends up showing American date order.
 */
export function formatDay(locale: string, unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.getTime())) return "";
  return formatDate(locale, date);
}

/** "Never used" is the interesting case: it is the slot most likely to be lost. */
export function describeLastUsed(lastUsed: number | null, copy: SlotCopy): string {
  return lastUsed === null
    ? copy.t("slot.neverUsed")
    : copy.t("slot.lastUsed", { day: formatDay(copy.locale, lastUsed) });
}

/**
 * The one line under a slot's name: whether a key file is needed, the Argon2id
 * summary when there is one, when it was added and when it last opened the
 * vault.
 *
 * Joined with the separator from `common`, not with a `" · "` written here:
 * the glyph is a locale's choice, and the one place it is declared is the one
 * place a translator can change it.
 */
export function slotDetail(slot: Slot, copy: SlotCopy): string {
  const parts: string[] = [];
  if (slot.kind === "password") {
    parts.push(copy.t(slot.requiresKeyfile ? "slot.withKeyfile" : "slot.noKeyfile"));
  }
  // Notation composed from the numbers the core sends — a function name, a
  // byte figure and Argon2's own `t=` and `p=`. None of it is a word, which is
  // what lets it stand in a translated line untranslated; the English sentence
  // the core used to send here was not that, and printed "3 passes, 4 lanes"
  // into nine other languages. See `@/features/vault/kdf.ts`.
  const kdf = kdfSummary(copy.locale, slot.kdf);
  if (kdf !== null) parts.push(kdf);
  parts.push(copy.t("slot.added", { day: formatDay(copy.locale, slot.createdAt) }));
  parts.push(describeLastUsed(slot.lastUsed, copy));
  return parts.join(copy.tCommon("punctuation.factSeparator"));
}

/**
 * Why this slot cannot be removed, or null when it can be.
 *
 * The count is of the whole table, not of the "strong" slots: the core's rule
 * is that the table must not empty, and a keychain slot on this machine is as
 * usable as a password for that purpose.
 */
export function removalRefusal(slots: readonly Slot[], t: VaultT): string | null {
  return slots.length <= 1 ? t("slots.lastSlotRefusal") : null;
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
  t: VaultT,
): string | null {
  if (slot.kind === "recovery" && slots.filter((s) => s.kind === "recovery").length === 1) {
    return t("slots.lastRecoveryWarning");
  }
  if (openedWith !== null && openedWith === slot.index) return t("slots.openedWithWarning");
  return null;
}

/**
 * The sentence key-management.md requires before the recovery slot goes.
 *
 * Typed, not ticked. A checkbox beside a warning is read as furniture; typing
 * the sentence is the only cheap thing that makes a person read it, and this
 * is the deletion with no way back.
 *
 * Translated, and it has to be: a sentence a reader cannot read is a sentence
 * they transcribe without understanding, which is the one thing this control
 * exists to prevent. The catalogue entry carries that instruction.
 */
export function lastResortPhrase(t: VaultT): string {
  return t("removeSlot.phrase");
}

export function needsLastResort(kind: SlotKind): boolean {
  return kind === "recovery";
}

/**
 * Whether the typed confirmation counts.
 *
 * Case and run-together spaces are forgiven; the words are not. Someone
 * transcribing a sentence from the line above it should not be defeated by a
 * capital letter, but nor should "yes" get through. The phrase is passed in so
 * that what is compared is exactly what was displayed, and the locale with it,
 * so that case is forgiven in the language it was displayed in.
 *
 * **That last clause used to be a lie, and it locked Turkish readers out.**
 * The comparison folded both sides with `toLowerCase()`, which applies English
 * rules whatever the interface says. Turkish has a dotted and a dotless i, and
 * the shift key maps them crosswise: the displayed "Son çaremi kaldırdığımı
 * anlıyorum" typed in capitals comes back as "SON ÇAREMİ KALDIRDIĞIMI
 * ANLIYORUM", which English rules fold to "son çaremi̇ kaldirdiğimi anliyorum"
 * — a combining dot that was never typed, and three dotted i's where the
 * sentence has dotless ones. Refused. The same sentence in English capitals
 * was accepted, so the failure was invisible to everyone who could not read
 * the phrase, and a user who is refused a confirmation they transcribed
 * correctly concludes they mistyped and tries again.
 *
 * `equalsIgnoringCase` compares through a collator for this language, which
 * treats a case difference as no difference and everything else as a
 * difference — so `ç` still does not pass for `c`, and "yes" still does not
 * pass for the sentence. This is the deletion with no way back; the gate may
 * forgive the shift key and nothing else.
 */
export function lastResortSatisfied(
  kind: SlotKind,
  typed: string,
  phrase: string,
  locale: string,
): boolean {
  if (!needsLastResort(kind)) return true;
  // Whitespace first, so a sentence transcribed with a double space between
  // two words still reads as the same sentence to the collator.
  const tidy = (value: string) => value.trim().replace(/\s+/g, " ");
  return equalsIgnoringCase(tidy(typed), tidy(phrase), locale);
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
 *
 * Slot labels are the user's own text and are wrapped in a bidi isolate, so a
 * label written in Hebrew cannot reorder the English sentence around it — or
 * an ASCII label the Arabic one.
 */
export function rotationRefusals(plan: readonly RotationSlotPlan[], t: VaultT): string[] {
  const problems: string[] = [];
  const kept = plan.filter((entry) => !entry.drop);

  for (const entry of kept) {
    if (entry.kind === "password" && !entry.hasCredential) {
      problems.push(
        t("rotateMaster.problemNoCredential", {
          index: entry.index,
          label: isolate(entry.label),
        }),
      );
    }
    if (entry.kind === "fido2") {
      problems.push(
        t("rotateMaster.problemFido2", { index: entry.index, label: isolate(entry.label) }),
      );
    }
  }

  if (plan.length > 0 && kept.length === 0) problems.push(t("rotateMaster.problemEmpty"));
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
export const AUTO_LOCK_MINUTES: readonly number[] = [0, 1, 5, 15, 30, 60, 120, 240];

/**
 * One rung of that ladder, in words.
 *
 * Three messages rather than eight labels, because the number is the variable
 * part: ICU formats it for the locale and pluralises it in whatever categories
 * the language has, which "1 min"/"5 min" written out eight times cannot do.
 */
export function autoLockLabel(minutes: number, t: VaultT): string {
  if (minutes === 0) return t("autoLock.choiceNever");
  if (minutes >= 60 && minutes % 60 === 0) {
    return t("autoLock.choiceHours", { count: minutes / 60 });
  }
  return t("autoLock.choiceMinutes", { count: minutes });
}

/**
 * The most backups the vault will keep.
 *
 * `remoter-vault` clamps to this silently, so offering more would be offering
 * a number the file will not hold.
 */
export const BACKUP_MAX = 8;
