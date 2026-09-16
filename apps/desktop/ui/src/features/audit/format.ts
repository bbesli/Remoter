/**
 * How an audit row reads.
 *
 * The outcome carries a glyph, a word and a colour — three signals, of which
 * colour is the one that can be missing. A colour-only outcome column is
 * unreadable to a colour-blind reviewer, unreadable in a printed export, and
 * unreadable in high contrast where the palette flattens. So the word is always
 * there and the glyph is always there; the tint is the third thing, not the
 * only thing. (docs/ui/design-system.md, principle 5.)
 *
 * Every word in here comes from `locales/en/audit.json` through a `t()` passed
 * in by the caller. The functions take `t` as an argument rather than calling
 * `useT()` themselves because they are not components: a plain function that
 * reaches for a hook cannot be called from an event handler or a test, and a
 * module that caches the words at import time renders the old language after a
 * switch.
 *
 * The three vocabularies below — outcomes, categories, events — are the core's,
 * not this screen's. Each lookup falls back rather than throwing, because a
 * vault written by a newer build can hold a word this one has never heard of,
 * and dropping the row would hide exactly the entry someone is looking for.
 */

import type { TFunction } from "i18next";

import type { AuditCategory, AuditOutcome } from "@/lib/ipc";
import type { IconName } from "@/components/Icon";

/** The `t` this module's helpers need. Bound to the audit catalogue. */
export type AuditT = TFunction<"audit">;

export type OutcomeTone = "success" | "warning" | "danger";

export interface OutcomeLook {
  /** The word. Present whatever the colour does. */
  word: string;
  icon: IconName;
  tone: OutcomeTone;
}

interface OutcomeGlyph {
  icon: IconName;
  tone: OutcomeTone;
}

const OUTCOME_GLYPH: Record<AuditOutcome, OutcomeGlyph> = {
  success: { icon: "check", tone: "success" },
  failure: { icon: "x", tone: "danger" },
  // Refused, not broken: the action was understood and not permitted. The lock
  // says that in a glyph, which "failed" would not.
  denied: { icon: "lock", tone: "warning" },
};

const UNKNOWN_GLYPH: OutcomeGlyph = { icon: "alert", tone: "warning" };

/**
 * Whether the core's word is one this build has a translation for.
 *
 * The parameter is typed as the union because that is what the command
 * declares, but the check is a runtime one: the value crossed an IPC boundary
 * from a vault that a newer build may have written.
 */
function isKnownOutcome(outcome: AuditOutcome): boolean {
  return Object.hasOwn(OUTCOME_GLYPH, outcome);
}

/** The outcome as a word: on a filter chip, and in the Outcome column. */
export function outcomeLabel(t: AuditT, outcome: AuditOutcome): string {
  return isKnownOutcome(outcome) ? t(`outcome.${outcome}`) : t("outcome.unknown");
}

/** The outcome's appearance: the word, and the two signals that carry it. */
export function outcomeLook(t: AuditT, outcome: AuditOutcome): OutcomeLook {
  const glyph = isKnownOutcome(outcome) ? OUTCOME_GLYPH[outcome] : UNKNOWN_GLYPH;
  return { ...glyph, word: outcomeLabel(t, outcome) };
}

/**
 * The five categories the core partitions its events into.
 *
 * Listed here rather than inferred from the union so that an unrecognised
 * category — a chip from a newer build — takes the humanised-spelling path
 * instead of asking for a key that does not exist.
 */
const KNOWN_CATEGORIES: readonly AuditCategory[] = [
  "vault",
  "node",
  "secret",
  "connection",
  "warning",
];

/** A chip label. Falls back to the stored spelling, humanised. */
export function categoryLabel(t: AuditT, category: AuditCategory): string {
  return KNOWN_CATEGORIES.includes(category) ? t(`category.${category}`) : titleCase(category);
}

/** The category shown on a row. `null` is an event this build has no name for. */
export function rowCategoryLabel(t: AuditT, category: AuditCategory | null): string {
  return category === null ? t("category.other") : categoryLabel(t, category);
}

/**
 * Every event name this build recognises.
 *
 * Mirrors `AuditEvent::ALL` in `crates/remoter-vault/src/storage.rs`, whose
 * `as_str()` produces exactly these spellings — the list is the wire format,
 * not a naming choice this screen gets to make. Each one has a key of the same
 * name under `event` in `locales/en/audit.json`.
 *
 * An event outside this list is one a newer build wrote. It keeps its row and
 * is rendered as its stored spelling, humanised.
 */
const KNOWN_EVENTS = [
  "vault_created",
  "vault_unlocked",
  "vault_unlock_failed",
  "vault_locked",
  "vault_saved",
  "vault_migrated",
  "slot_added",
  "slot_removed",
  "recovery_key_issued",
  "password_changed",
  "master_key_rotated",
  "kdf_upgraded",
  "node_created",
  "node_updated",
  "node_deleted",
  "node_moved",
  "secret_stored",
  "secret_removed",
  "secret_used",
  "secret_revealed",
  "secret_exported",
  "trust_pinned",
  "trust_rejected",
  "session_started",
  "session_ended",
  "setting_changed",
] as const;

type KnownEvent = (typeof KNOWN_EVENTS)[number];

function isKnownEvent(event: string): event is KnownEvent {
  return (KNOWN_EVENTS as readonly string[]).includes(event);
}

/**
 * What happened, in the reader's language.
 *
 * An unrecognised event reads as its own spelling with the separators opened
 * out — `some_future.event` as "some future event" — which is a worse label
 * than a translated one and a much better one than a blank cell. The stored
 * spelling stays in the row's tooltip either way, because an event name is
 * what someone greps an export for.
 */
export function eventLabel(t: AuditT, event: string): string {
  return isKnownEvent(event) ? t(`event.${event}`) : humanise(event);
}

/** `host_key.changed` -> `host key changed`. */
function humanise(value: string): string {
  return value.replace(/[._-]+/g, " ").trim();
}

function titleCase(value: string): string {
  const words = humanise(value);
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/**
 * The two timestamp shapes this screen needs, neither of which exists in
 * `@/i18n`'s `format.ts`.
 *
 * The compact stamp drops the year and keeps the seconds: a log is read in
 * order and two entries in the same minute are common, so the second is the
 * digit that carries information and the year is the one that does not. The
 * tooltip is the opposite — full date, and the zone, because "was that 14:05
 * here or 14:05 there?" is a question an incident review actually asks.
 *
 * What is *not* pinned here is the 12/24-hour convention. It used to be forced
 * to 24, which shows an en-US reader a clock they do not read; `Intl` takes it
 * from the locale, and that is the whole reason the locale is a parameter.
 *
 * Formatters are memoised because at tens of thousands of rows, constructing
 * an `Intl.DateTimeFormat` per row is measurable.
 */
const ROW_TIME_OPTIONS: Intl.DateTimeFormatOptions = {
  day: "2-digit",
  month: "short",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};

const FULL_TIME_OPTIONS: Intl.DateTimeFormatOptions = {
  dateStyle: "full",
  timeStyle: "long",
};

const formatters = new Map<string, Intl.DateTimeFormat>();

function dateTimeFormat(
  locale: string,
  shape: string,
  options: Intl.DateTimeFormatOptions,
): Intl.DateTimeFormat {
  const key = `${shape}:${locale}`;
  const hit = formatters.get(key);
  if (hit !== undefined) return hit;
  // A settings file can name a language `Intl` will not accept, and every
  // constructor throws a RangeError on a malformed tag. English beats a blank
  // column.
  let made: Intl.DateTimeFormat;
  try {
    made = new Intl.DateTimeFormat(locale, options);
  } catch {
    made = new Intl.DateTimeFormat("en", options);
  }
  formatters.set(key, made);
  return made;
}

/** The compact stamp in the Time column. */
export function formatRowTime(locale: string, at: number): string {
  return dateTimeFormat(locale, "row", ROW_TIME_OPTIONS).format(new Date(at));
}

/** The unambiguous stamp, with the year and the zone, for the row's tooltip. */
export function formatFullTime(locale: string, at: number): string {
  return dateTimeFormat(locale, "full", FULL_TIME_OPTIONS).format(new Date(at));
}

/**
 * An operating system's own name for itself, from the identifier the core
 * stores (`std::env::consts::OS`).
 *
 * Proper nouns, so not in the catalogue: nobody translates "macOS". An
 * identifier this build does not know is shown as stored rather than dropped —
 * the row was written by a real machine, even one this list has not heard of.
 */
export function osName(os: string): string {
  switch (os) {
    case "linux":
      return "Linux";
    case "windows":
      return "Windows";
    case "macos":
      return "macOS";
    case "freebsd":
      return "FreeBSD";
    default:
      return os;
  }
}
