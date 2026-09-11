/**
 * Case folding, checked in the languages that break it.
 *
 * Every assertion here is written as the question a user asks: "I typed what
 * is written on the machine — why did it find nothing?" English cannot ask it,
 * which is why an English-only test suite let four screens ship a fold that
 * was wrong in three of the ten languages this application offers.
 *
 * The four scripts are the four the design calls out: Turkish for the dotted
 * and dotless i, German for `ß`, Greek for the two sigmas, Arabic for
 * marks that are not case at all.
 */

import { describe, expect, it } from "vitest";

import { compareInLocale, equalsIgnoringCase, foldForSearch, foldInvariant } from "./fold";

/** Does a haystack match a needle, folded the way a search box folds them? */
function finds(haystack: string, needle: string, locale: string): boolean {
  return foldForSearch(haystack, locale).includes(foldForSearch(needle, locale));
}

describe("foldForSearch, in Turkish", () => {
  // Turkish writes four letters where English writes two: I/ı and İ/i.
  // The shift key maps them crosswise, so folding with English rules turns
  // every one of them into the wrong letter.
  it("finds a machine by the name written on it", () => {
    expect(finds("IŞIK-01", "ışık", "tr")).toBe(true);
  });

  it("finds it from the other direction too", () => {
    expect(finds("ışık-01", "IŞIK", "tr")).toBe(true);
  });

  it("matches a dotted capital against the dotted small letter", () => {
    expect(finds("İSTANBUL-GW", "istanbul", "tr")).toBe(true);
  });

  it("leaves no combining dot behind when the locale is not Turkish", () => {
    // `"İ".toLowerCase()` produces i + U+0307 outside Turkish. Left in, it
    // would make the folded name unequal to a typed "istanbul" that nobody
    // could tell apart on screen.
    expect(foldForSearch("İSTANBUL", "en")).toBe("istanbul");
    expect(finds("İSTANBUL-GW", "istanbul", "en")).toBe(true);
  });

  it("is what the old fold was not", () => {
    // The exact expression this replaced, kept as the proof that the bug was
    // real rather than theoretical.
    const old = (v: string) => v.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
    expect(old("IŞIK-01").includes(old("ışık"))).toBe(false);
  });
});

describe("foldForSearch, in German", () => {
  it("finds a sharp s by its two-letter spelling", () => {
    expect(finds("Straße-01", "strasse", "de")).toBe(true);
  });

  it("finds it by itself as well", () => {
    expect(finds("Straße-01", "Straße", "de")).toBe(true);
  });

  it("still ignores an umlaut the reader did not type", () => {
    expect(finds("Grün-VPN", "grun", "de")).toBe(true);
    expect(finds("Grün-VPN", "grün", "de")).toBe(true);
  });
});

describe("foldForSearch, in Greek", () => {
  // Sigma is written ς at the end of a word and σ everywhere else, so
  // the same word lowercases two ways depending on what follows it.
  it("folds both sigmas to one", () => {
    expect(foldForSearch("ΟΔΟΣ", "el")).toBe(
      foldForSearch("οδοσ", "el"),
    );
  });

  it("finds a word written in capitals by its accented lower case", () => {
    expect(finds("ΟΔΟΣ-7", "οδός", "el")).toBe(true);
  });

  it("and the other way round", () => {
    expect(finds("οδός-7", "ΟΔΟΣ", "el")).toBe(true);
  });
});

describe("foldForSearch, in Arabic", () => {
  it("finds a name whose vowel marks the reader did not type", () => {
    // مُحَمَّد — the harakat are combining marks, and nobody types them
    // into a filter box.
    const withMarks = "مُحَمَّد-01";
    const bare = "محمد";
    expect(finds(withMarks, bare, "ar")).toBe(true);
  });

  it("leaves the letters themselves alone", () => {
    const host = "خادم";
    expect(foldForSearch(host, "ar")).toBe(host);
  });

  it("does not match a different word", () => {
    expect(finds("خادم", "محمد", "ar")).toBe(false);
  });
});

describe("foldForSearch", () => {
  it("is idempotent", () => {
    for (const locale of ["tr", "de", "el", "ar", "en"]) {
      const once = foldForSearch("IŞIK Straße ΟΔΟΣ", locale);
      expect(foldForSearch(once, locale)).toBe(once);
    }
  });

  it("survives a language tag this runtime has never heard of", () => {
    // A settings file written by a newer build can name one. A search box is
    // not somewhere the interface may throw.
    expect(() => foldForSearch("IŞIK", "this is not a tag")).not.toThrow();
    expect(foldForSearch("ABC", "this is not a tag")).toBe("abc");
  });
});

describe("foldInvariant", () => {
  it("folds an ASCII flag the same way in every language", () => {
    // The tree reads the tag "favourite" as a flag, not as a word. Folded
    // under Turkish rules it would become "favourıte" and match nothing.
    expect(foldInvariant("FAVOURITE")).toBe("favourite");
    expect(foldForSearch("FAVOURITE", "tr")).not.toBe("favourite");
  });

  it("keeps a key cap findable by the letter printed on it", () => {
    expect(foldInvariant("Ctrl I")).toBe(foldInvariant("ctrl i"));
  });
});

describe("equalsIgnoringCase", () => {
  const PHRASE = "Son çaremi kaldırdığımı anlıyorum";

  it("accepts the Turkish phrase typed in Turkish capitals", () => {
    expect(equalsIgnoringCase(PHRASE.toLocaleUpperCase("tr"), PHRASE, "tr")).toBe(true);
  });

  it("accepts the English phrase typed in English capitals", () => {
    const english = "I understand this removes my last resort";
    expect(equalsIgnoringCase(english.toUpperCase(), english, "en")).toBe(true);
  });

  it("still refuses a different word", () => {
    expect(equalsIgnoringCase("evet", PHRASE, "tr")).toBe(false);
  });

  it("still refuses a letter stripped of its cedilla", () => {
    // Case is forgiven. Nothing else is: this gate guards a deletion with no
    // way back, and "caremi" is not the word that was shown.
    expect(equalsIgnoringCase(PHRASE.replace("ç", "c"), PHRASE, "tr")).toBe(false);
  });

  it("keeps the dotted and dotless i apart", () => {
    // They are two letters in Turkish, not two cases of one.
    expect(equalsIgnoringCase("ı", "i", "tr")).toBe(false);
  });

  it("survives a language tag this runtime has never heard of", () => {
    expect(() => equalsIgnoringCase("a", "A", "this is not a tag")).not.toThrow();
  });
});

/**
 * Ordering, which is the same question as folding and was guarded by nothing.
 *
 * `localeCompare` with no locale reads the *operating system's* language, not
 * the one the interface is in, so a list of names came out in a different
 * order on two machines running the same build in the same language. Nothing
 * in the interface made that visible, and nothing in the documentation
 * forbade it until this was found.
 */
describe("compareInLocale", () => {
  it("sorts Turkish by the Turkish alphabet", () => {
    // The dotless i is a letter of its own in Turkish and sorts before the
    // dotted one, so "ısı" comes first. Elsewhere they are one letter and the
    // decision falls to the second character, which puts "inek" first.
    expect(compareInLocale("ısı", "inek", "tr")).toBeLessThan(0);
    expect(compareInLocale("ısı", "inek", "en")).toBeGreaterThan(0);
  });

  it("sorts Swedish and German umlauts differently, as those languages do", () => {
    // German files "ä" beside "a"; Swedish files it after "z".
    expect(compareInLocale("ä", "z", "de")).toBeLessThan(0);
    expect(compareInLocale("ä", "z", "sv")).toBeGreaterThan(0);
  });

  it("puts identical strings in neither order", () => {
    expect(compareInLocale("web-01", "web-01", "tr")).toBe(0);
  });

  it("survives a language tag this runtime has never heard of", () => {
    expect(() => compareInLocale("a", "b", "this is not a tag")).not.toThrow();
  });
});
