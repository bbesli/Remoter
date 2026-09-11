/**
 * The line the core used to write, composed on this side.
 *
 * Every assertion is a language question, because that is what the defect was:
 * a sentence made of English words crossed the IPC boundary and was printed,
 * unreachable by any catalogue, in the middle of six translated screens.
 */

import { afterEach, describe, expect, it } from "vitest";

import { i18n } from "@/i18n";
import type { KdfParams } from "@/lib/ipc";

import { kdfSummary } from "./kdf";

/** The floor in `KdfParams::FLOOR_*`, as the core sends it. */
const FLOOR: KdfParams = { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 };

afterEach(async () => {
  await i18n().changeLanguage("en");
});

describe("kdfSummary", () => {
  it("names the function, the memory and Argon2's own parameters", () => {
    // U+00A0 between the number and its unit, as `formatBytes` writes it.
    expect(kdfSummary("en", FLOOR)).toBe("Argon2id, 256\u00A0MiB, t=3, p=4");
  });

  it("has nothing to say about a slot that derives with HKDF", () => {
    // A recovery, FIDO2 or keychain slot has no cost, and a caller that gets
    // `null` leaves the line out rather than printing half of one.
    expect(kdfSummary("en", null)).toBeNull();
  });

  it("writes the digits in the reader's numbering system", () => {
    // The English sentence the core used to send could never do this: the
    // numerals were baked into the string before it left Rust.
    const egyptian = kdfSummary("ar-EG", FLOOR) ?? "";
    expect(egyptian).toMatch(/[٠-٩]/u);
    // The function's name is a proper name and stays as it is.
    expect(egyptian).toContain("Argon2id");
  });

  it("joins with the separator the catalogue gives it", async () => {
    // Chinese separates a short list with U+3001, and the catalogue is where
    // that is declared. A hardcoded ", " here would be the same class of bug
    // one level down.
    await i18n().changeLanguage("zh-Hans");
    await i18n().loadNamespaces(["common"]);
    expect(kdfSummary("zh-Hans", FLOOR)).toContain("、");
  });

  it("still reads left to right in every part", () => {
    // No word in it is a word: a name, a unit symbol and two parameter
    // letters. Callers isolate it when it goes into a right-to-left sentence.
    expect(kdfSummary("tr", FLOOR)).toContain("t=3");
  });
});
