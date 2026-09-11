/**
 * The refusals, which are the part of this screen that prevents data loss.
 *
 * Each of these has a counterpart in the core. They are tested here anyway
 * because the core's version arrives as an error after the user has committed,
 * and for the last slot there is nothing to recover afterwards — the screen's
 * job is to refuse first and say why.
 */

import { describe, expect, it } from "vitest";

import { i18n } from "@/i18n";
import { withoutBidi } from "@/test/bidi";
import type { Slot, SlotKind } from "@/lib/ipc";

import {
  lastResortPhrase,
  lastResortSatisfied,
  needsLastResort,
  removalRefusal,
  removalWarning,
  rotationRefusals,
  slotDetail,
  type RotationSlotPlan,
} from "./slots";

/*
 * These helpers take the catalogue accessor rather than reaching for a hook,
 * which is what lets this file test them without rendering anything at all.
 * `i18n()` creates the instance on first call and English is compiled in, so
 * `getFixedT` performs exactly the lookup a component's `t` would.
 */
const t = i18n().getFixedT(null, "vaultsettings");
const tCommon = i18n().getFixedT(null, "common");
const copy = { t, tCommon, locale: "en" };
const LAST_RESORT_PHRASE = lastResortPhrase(t);

/**
 * One catalogue's `removeSlot.phrase`, read from the file the application
 * ships rather than from the instance.
 *
 * Five levels up is `locales/`, the same climb `failures.catalogue.test.ts`
 * makes, and through the same mechanism: the bundler resolves the path, so
 * moving the directory is a build failure here rather than a test that quietly
 * stops reading anything.
 */
const VAULT_CATALOGUES = import.meta.glob("../../../../../../locales/*/vaultsettings.json", {
  eager: true,
  import: "default",
}) as Record<string, { removeSlot?: { phrase?: string } }>;

function shippedPhrase(locale: string): string {
  for (const [path, catalogue] of Object.entries(VAULT_CATALOGUES)) {
    if (!path.endsWith(`/locales/${locale}/vaultsettings.json`)) continue;
    const phrase = catalogue.removeSlot?.phrase;
    if (typeof phrase === "string") return phrase;
  }
  throw new Error(`no removeSlot.phrase in locales/${locale}/vaultsettings.json`);
}

function slot(index: number, kind: SlotKind, over: Partial<Slot> = {}): Slot {
  return {
    index,
    kind,
    label: `${kind} ${index}`,
    createdAt: 1_741_737_600,
    lastUsed: null,
    requiresKeyfile: false,
    kdf: null,
    ...over,
  };
}

describe("removalRefusal", () => {
  it("refuses the only slot, with the reason", () => {
    const refusal = removalRefusal([slot(0, "password")], t);
    expect(refusal).not.toBeNull();
    expect(refusal).toContain("only way into this vault");
  });

  it("allows a removal while another slot remains", () => {
    expect(removalRefusal([slot(0, "password"), slot(1, "recovery")], t)).toBeNull();
  });

  it("counts a keychain slot as a way in", () => {
    // The core's rule is that the slot table must not empty. A keychain slot
    // on this machine opens the vault, so it keeps the table non-empty and the
    // password slot beside it becomes removable.
    expect(removalRefusal([slot(0, "password"), slot(3, "keychain")], t)).toBeNull();
  });
});

describe("removalWarning", () => {
  it("warns when the recovery key being removed is the last one", () => {
    const slots = [slot(0, "password"), slot(1, "recovery")];
    expect(removalWarning(slots, slot(1, "recovery"), null, t)).toContain("last recovery key");
  });

  it("warns when the slot is the one this session was opened with", () => {
    const slots = [slot(0, "password"), slot(1, "recovery"), slot(3, "keychain")];
    expect(removalWarning(slots, slot(3, "keychain"), 3, t)).toContain("opened with this slot");
  });

  it("says nothing about an ordinary removal", () => {
    const slots = [slot(0, "password"), slot(1, "recovery"), slot(2, "password")];
    expect(removalWarning(slots, slot(2, "password"), 0, t)).toBeNull();
  });
});

describe("the last-resort confirmation", () => {
  it("is required only for the recovery slot", () => {
    expect(needsLastResort("recovery")).toBe(true);
    expect(needsLastResort("password")).toBe(false);
    expect(needsLastResort("keychain")).toBe(false);
  });

  it("passes any other slot without a phrase", () => {
    expect(lastResortSatisfied("password", "", LAST_RESORT_PHRASE, "en")).toBe(true);
  });

  it("accepts the sentence whatever the case and spacing", () => {
    expect(lastResortSatisfied("recovery", LAST_RESORT_PHRASE, LAST_RESORT_PHRASE, "en")).toBe(
      true,
    );
    expect(
      lastResortSatisfied(
        "recovery",
        "  i understand this REMOVES my  last resort ",
        LAST_RESORT_PHRASE,
        "en",
      ),
    ).toBe(true);
  });

  it("rejects an acknowledgement that is not the sentence", () => {
    expect(lastResortSatisfied("recovery", "", LAST_RESORT_PHRASE, "en")).toBe(false);
    expect(lastResortSatisfied("recovery", "yes", LAST_RESORT_PHRASE, "en")).toBe(false);
    expect(lastResortSatisfied("recovery", "I understand", LAST_RESORT_PHRASE, "en")).toBe(false);
    expect(
      lastResortSatisfied(
        "recovery",
        "I understand this removes my last resort now",
        LAST_RESORT_PHRASE,
        "en",
      ),
    ).toBe(false);
  });
});

/*
 * The same gate, in the language the repository owner reads.
 *
 * This is the case that was refused in the shipped build: the Turkish
 * sentence, typed in Turkish capitals, folded through English casing rules
 * into a different sentence — a combining dot that was never typed and three
 * dotted i's where Turkish writes dotless ones. The user is told capitals do
 * not matter (`removeSlot.phraseHint`, in every language), so a refusal reads
 * as "you mistyped" and is retried, forever, on an irreversible operation.
 *
 * The phrase is read from the Turkish catalogue rather than written here, so
 * that a translator rewording it cannot make this test pass against a sentence
 * the screen no longer shows.
 */
describe("the last-resort confirmation, in Turkish", () => {
  // Straight off disk rather than through the instance: only English is
  // compiled into a test run, and a phrase that had quietly fallen back to
  // English would make every assertion below vacuous.
  const PHRASE_TR = shippedPhrase("tr");

  it("reads the sentence the Turkish catalogue actually ships", () => {
    expect(PHRASE_TR).not.toBe(LAST_RESORT_PHRASE);
    // The dotless i is the whole hazard. If a translator rewords the sentence
    // out of it, this test stops standing for anything and should be told so.
    expect(PHRASE_TR).toContain("ı");
  });

  it("accepts the sentence typed in Turkish capitals", () => {
    // What a Turkish keyboard produces from the phrase on screen: I -> İ and
    // ı -> I, crosswise to English.
    const typed = PHRASE_TR.toLocaleUpperCase("tr");
    expect(lastResortSatisfied("recovery", typed, PHRASE_TR, "tr")).toBe(true);
  });

  it("accepts it typed exactly as shown", () => {
    expect(lastResortSatisfied("recovery", PHRASE_TR, PHRASE_TR, "tr")).toBe(true);
  });

  it("still refuses a bare acknowledgement", () => {
    expect(lastResortSatisfied("recovery", "evet", PHRASE_TR, "tr")).toBe(false);
    expect(lastResortSatisfied("recovery", "", PHRASE_TR, "tr")).toBe(false);
  });

  it("still refuses the sentence with a letter changed", () => {
    // Case is forgiven; spelling is not. "caremi" is not the word shown.
    expect(lastResortSatisfied("recovery", PHRASE_TR.replace("ç", "c"), PHRASE_TR, "tr")).toBe(
      false,
    );
  });
});

describe("rotationRefusals", () => {
  const plan = (over: Partial<RotationSlotPlan>): RotationSlotPlan => ({
    index: 0,
    kind: "password",
    label: "Master password",
    hasCredential: true,
    drop: false,
    ...over,
  });

  it("passes a plan that accounts for every slot", () => {
    expect(
      rotationRefusals([plan({}), plan({ index: 1, kind: "recovery", hasCredential: false })], t),
    ).toEqual([]);
  });

  it("names a password slot with neither a credential nor a decision to drop it", () => {
    const problems = rotationRefusals(
      [plan({ index: 2, hasCredential: false, label: "Deploy" })],
      t,
    );
    expect(problems).toHaveLength(1);
    expect(withoutBidi(problems[0] ?? "")).toContain("Deploy");
    expect(problems[0]).toContain("discard it");
  });

  it("stops asking once that slot is dropped", () => {
    expect(
      rotationRefusals([plan({}), plan({ index: 2, hasCredential: false, drop: true })], t),
    ).toEqual([]);
  });

  it("refuses to re-wrap a security key, which this version cannot do", () => {
    const problems = rotationRefusals([plan({}), plan({ index: 3, kind: "fido2" })], t);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("security key");
  });

  it("refuses a plan that keeps nothing", () => {
    const problems = rotationRefusals(
      [
        plan({ drop: true }),
        plan({ index: 1, kind: "recovery", hasCredential: false, drop: true }),
      ],
      t,
    );
    expect(problems).toEqual([expect.stringContaining("nobody can open")]);
  });
});

describe("slotDetail", () => {
  it("says a password slot needs its key file, and carries the derivation cost", () => {
    const line = slotDetail(
      slot(0, "password", {
        requiresKeyfile: true,
        // The numbers the core sends; the line is composed from them here.
        kdf: { algorithm: "Argon2id", memoryKib: 262_144, passes: 3, lanes: 4 },
      }),
      copy,
    );
    expect(line).toContain("Needs its key file too");
    // The space before the unit is U+00A0, written as an escape: `formatBytes`
    // puts a non-breaking space there so a narrow column cannot wrap "256"
    // onto one line and "MiB" onto the next.
    expect(line).toContain("Argon2id, 256\u00A0MiB, t=3, p=4");
    expect(line).toContain("Never used");
  });
});
