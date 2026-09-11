/**
 * Password strength, said in words rather than bits.
 *
 * The thresholds mirror `score_for` and `consequence` in
 * `crates/remoter-ipc/src/commands.rs`. The expected values below are written
 * out rather than computed from the same formula the implementation uses,
 * because a test that recomputes the thing it is testing agrees with every bug
 * it contains.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { i18n } from "./instance";
import { SOURCE_LOCALE } from "./locales";
import { strengthBand, strengthConsequence, useStrengthText } from "./strength";

const instance = i18n();

/** Every screen's source, read as text. See the last test in this file. */
const COMPONENTS = import.meta.glob("../features/**/*.tsx", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

describe("the band for an estimate", () => {
  it("changes at the bit counts the core scores with", () => {
    expect(strengthBand(0)).toBe("weak");
    expect(strengthBand(27)).toBe("weak");
    expect(strengthBand(39.9)).toBe("weak");
    expect(strengthBand(40)).toBe("fair");
    expect(strengthBand(51.9)).toBe("fair");
    expect(strengthBand(52)).toBe("good");
    expect(strengthBand(63.9)).toBe("good");
    expect(strengthBand(64)).toBe("strong");
    expect(strengthBand(256)).toBe("strong");
  });

  it("calls a broken estimate weak rather than strong", () => {
    // Failing open here would tell someone the password they are about to
    // commit their vault to is fine, on no evidence at all.
    expect(strengthBand(Number.NaN)).toBe("weak");
  });
});

describe("what an estimate costs an attacker", () => {
  it("is half the keyspace at a billion guesses a second", () => {
    expect(strengthConsequence(30)).toEqual({ span: "instant", count: 0 });
    expect(strengthConsequence(31)).toEqual({ span: "seconds", count: 1 });
    expect(strengthConsequence(35)).toEqual({ span: "seconds", count: 17 });
    expect(strengthConsequence(40)).toEqual({ span: "minutes", count: 9 });
    expect(strengthConsequence(45)).toEqual({ span: "hours", count: 5 });
    expect(strengthConsequence(50)).toEqual({ span: "days", count: 7 });
    expect(strengthConsequence(55)).toEqual({ span: "months", count: 7 });
    expect(strengthConsequence(60)).toEqual({ span: "years", count: 18 });
    expect(strengthConsequence(70)).toEqual({ span: "centuries", count: 0 });
    expect(strengthConsequence(80)).toEqual({ span: "universe", count: 0 });
  });

  it("never says 'about 0' of anything", () => {
    // The core clamps at one; a span that rounded to zero would read as a
    // password guessed in no time at all, which is the opposite of what it
    // means.
    for (let bits = 31; bits < 80; bits += 0.5) {
      const { span, count } = strengthConsequence(bits);
      if (span !== "instant" && span !== "centuries" && span !== "universe") {
        expect(count, `${bits} bits`).toBeGreaterThanOrEqual(1);
      }
    }
  });

  it("says the worst thing it can about an estimate that is not a number", () => {
    expect(strengthConsequence(Number.NaN)).toEqual({ span: "instant", count: 0 });
  });
});

// ----------------------------------------------------------- on screen ----

function Meter({ bits }: { bits: number }) {
  const { label, explanation } = useStrengthText(bits);
  return (
    <>
      <p>{label}</p>
      <span>{explanation}</span>
    </>
  );
}

async function switchTo(code: string) {
  await act(async () => {
    await instance.changeLanguage(code);
  });
}

afterEach(async () => {
  await switchTo(SOURCE_LOCALE);
});

describe("the strength text", () => {
  it("comes from the catalogue, not from the core", () => {
    render(<Meter bits={70} />);
    expect(screen.getByText("Strong")).toBeInTheDocument();
    expect(screen.getByText("Centuries of guessing at a billion attempts a second.")).toBeInTheDocument();
  });

  it("inflects the unit with the count", () => {
    // The reason the sentence is a message and not a concatenation: "1 second"
    // and "17 seconds" are one plural rule in English and four in Russian.
    render(<Meter bits={31} />);
    expect(screen.getByText("About 1 second of guessing at a billion attempts a second.")).toBeInTheDocument();
  });

  it("is what components render, rather than the DTO's English", () => {
    // `PasswordStrength.label` and `.explanation` are still on the wire, and
    // rendering either is the whole defect: two English sentences in an
    // otherwise translated wizard, at the moment a reader is deciding whether
    // their password is good enough. A screen reaching for them again is
    // caught here rather than in review.
    const offenders = Object.entries(COMPONENTS)
      .filter(([, source]) => /\bstrength\.(label|explanation)\b/.test(source))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it("follows the language the reader chose", async () => {
    await switchTo("tr");
    render(<Meter bits={70} />);
    // The wording is the translator's; what matters is that the English the
    // core would have sent is not what reached the screen.
    expect(screen.queryByText("Strong")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Centuries of guessing at a billion attempts a second."),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("paragraph").textContent ?? "").not.toBe("");
  });
});
