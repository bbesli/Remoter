/**
 * How strong a password is, said in the reader's language.
 *
 * `password_strength` answers with an entropy estimate, a 0–4 score, a label
 * and a sentence about consequences. The last two arrive as English prose —
 * "Fair", "Guessed instantly at a billion attempts a second." — and the vault
 * wizard used to render them verbatim, so a reader who had set the interface to
 * Turkish was told about their password in English at the exact moment they
 * were deciding whether it was good enough.
 *
 * The bits are enough to say all of it. The thresholds below mirror
 * `score_for` and `consequence` in `crates/remoter-ipc/src/commands.rs`; keep
 * them in step, and treat that file as the source if they ever disagree. The
 * sentence then goes through the catalogue, which buys more than translation:
 * the count is an ICU plural, so Russian gets its four categories and Arabic
 * its six, and the digits follow the locale's numbering system — the same
 * reason the bit count already went through `create.password.bits`.
 *
 * Nothing here ever sees the password. It takes a number.
 */

import { useT } from "./useT";

/** The four words beside the meter. */
export type StrengthBand = "weak" | "fair" | "good" | "strong";

/** Which sentence says what the bit count costs an attacker. */
export type StrengthSpan =
  | "instant"
  | "seconds"
  | "minutes"
  | "hours"
  | "days"
  | "months"
  | "years"
  | "centuries"
  | "universe";

export interface StrengthConsequence {
  readonly span: StrengthSpan;
  /** How many of that unit. 1 or more; meaningless for the three spans that name no number. */
  readonly count: number;
}

// `score_for`: 0 below 28 bits, then 40, 52, 64. The label collapses 0 and 1
// into one word, so only three of the four boundaries are needed here.
const FAIR_BITS = 40;
const GOOD_BITS = 52;
const STRONG_BITS = 64;

const SECOND = 1;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const MONTH = 30 * DAY;
const YEAR = 365.25 * DAY;
const CENTURY_LIMIT = 100 * YEAR;
const UNIVERSE_LIMIT = 1.0e6 * YEAR;

/** Guesses a second the sentence quotes. See `consequence` in commands.rs for why. */
const GUESSES_PER_SECOND = 1e9;

/**
 * Which word describes this many bits.
 *
 * A number that is not a number reads as "weak" rather than "strong": if the
 * estimate is broken, the only safe direction to fail in is the one that does
 * not tell someone a password they are about to commit to is fine.
 */
export function strengthBand(entropyBits: number): StrengthBand {
  if (!Number.isFinite(entropyBits)) return entropyBits === Infinity ? "strong" : "weak";
  if (entropyBits < FAIR_BITS) return "weak";
  if (entropyBits < GOOD_BITS) return "fair";
  if (entropyBits < STRONG_BITS) return "good";
  return "strong";
}

/**
 * How long this many bits costs, at the rate the sentence quotes.
 *
 * Half the keyspace at a billion guesses a second, rounded the way the core
 * rounds it: to the nearest unit, never below one, so "About 0 minutes" cannot
 * appear.
 */
export function strengthConsequence(entropyBits: number): StrengthConsequence {
  // NaN again: nothing is known, so say the worst thing that could be true.
  if (Number.isNaN(entropyBits)) return { span: "instant", count: 0 };

  const seconds = Math.pow(2, entropyBits - 1) / GUESSES_PER_SECOND;
  if (seconds < 1) return { span: "instant", count: 0 };
  if (seconds < MINUTE) return { span: "seconds", count: round(seconds, SECOND) };
  if (seconds < HOUR) return { span: "minutes", count: round(seconds, MINUTE) };
  if (seconds < DAY) return { span: "hours", count: round(seconds, HOUR) };
  if (seconds < MONTH) return { span: "days", count: round(seconds, DAY) };
  if (seconds < YEAR) return { span: "months", count: round(seconds, MONTH) };
  if (seconds < CENTURY_LIMIT) return { span: "years", count: round(seconds, YEAR) };
  if (seconds < UNIVERSE_LIMIT) return { span: "centuries", count: 0 };
  return { span: "universe", count: 0 };
}

function round(seconds: number, unit: number): number {
  return Math.max(1, Math.round(seconds / unit));
}

export interface StrengthText {
  /** One word: the band beside the meter. */
  readonly label: string;
  /** The sentence underneath it — the part that changes behaviour. */
  readonly explanation: string;
}

/**
 * The label and the sentence for an entropy estimate, from the catalogue.
 *
 * Both keys are template literals over the two unions above, so a band or span
 * with no catalogue entry is a compile error rather than a humanised key on
 * screen.
 */
export function useStrengthText(entropyBits: number): StrengthText {
  const t = useT("common");
  const { span, count } = strengthConsequence(entropyBits);
  return {
    label: t(`strength.label.${strengthBand(entropyBits)}`),
    explanation: t(`strength.consequence.${span}`, { count }),
  };
}
