/**
 * The refusals, which are the part of this screen that prevents data loss.
 *
 * Each of these has a counterpart in the core. They are tested here anyway
 * because the core's version arrives as an error after the user has committed,
 * and for the last slot there is nothing to recover afterwards — the screen's
 * job is to refuse first and say why.
 */

import { describe, expect, it } from "vitest";

import type { Slot, SlotKind } from "@/lib/ipc";

import {
  LAST_RESORT_PHRASE,
  lastResortSatisfied,
  needsLastResort,
  removalRefusal,
  removalWarning,
  rotationRefusals,
  slotDetail,
  type RotationSlotPlan,
} from "./slots";

function slot(index: number, kind: SlotKind, over: Partial<Slot> = {}): Slot {
  return {
    index,
    kind,
    label: `${kind} ${index}`,
    createdAt: 1_741_737_600,
    lastUsed: null,
    requiresKeyfile: false,
    kdfSummary: null,
    ...over,
  };
}

describe("removalRefusal", () => {
  it("refuses the only slot, with the reason", () => {
    const refusal = removalRefusal([slot(0, "password")]);
    expect(refusal).not.toBeNull();
    expect(refusal).toContain("only way into this vault");
  });

  it("allows a removal while another slot remains", () => {
    expect(removalRefusal([slot(0, "password"), slot(1, "recovery")])).toBeNull();
  });

  it("counts a keychain slot as a way in", () => {
    // The core's rule is that the slot table must not empty. A keychain slot
    // on this machine opens the vault, so it keeps the table non-empty and the
    // password slot beside it becomes removable.
    expect(removalRefusal([slot(0, "password"), slot(3, "keychain")])).toBeNull();
  });
});

describe("removalWarning", () => {
  it("warns when the recovery key being removed is the last one", () => {
    const slots = [slot(0, "password"), slot(1, "recovery")];
    expect(removalWarning(slots, slot(1, "recovery"), null)).toContain("last recovery key");
  });

  it("warns when the slot is the one this session was opened with", () => {
    const slots = [slot(0, "password"), slot(1, "recovery"), slot(3, "keychain")];
    expect(removalWarning(slots, slot(3, "keychain"), 3)).toContain("opened with this slot");
  });

  it("says nothing about an ordinary removal", () => {
    const slots = [slot(0, "password"), slot(1, "recovery"), slot(2, "password")];
    expect(removalWarning(slots, slot(2, "password"), 0)).toBeNull();
  });
});

describe("the last-resort confirmation", () => {
  it("is required only for the recovery slot", () => {
    expect(needsLastResort("recovery")).toBe(true);
    expect(needsLastResort("password")).toBe(false);
    expect(needsLastResort("keychain")).toBe(false);
  });

  it("passes any other slot without a phrase", () => {
    expect(lastResortSatisfied("password", "")).toBe(true);
  });

  it("accepts the sentence whatever the case and spacing", () => {
    expect(lastResortSatisfied("recovery", LAST_RESORT_PHRASE)).toBe(true);
    expect(lastResortSatisfied("recovery", "  i understand this REMOVES my  last resort ")).toBe(
      true,
    );
  });

  it("rejects an acknowledgement that is not the sentence", () => {
    expect(lastResortSatisfied("recovery", "")).toBe(false);
    expect(lastResortSatisfied("recovery", "yes")).toBe(false);
    expect(lastResortSatisfied("recovery", "I understand")).toBe(false);
    expect(lastResortSatisfied("recovery", "I understand this removes my last resort now")).toBe(
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
      rotationRefusals([plan({}), plan({ index: 1, kind: "recovery", hasCredential: false })]),
    ).toEqual([]);
  });

  it("names a password slot with neither a credential nor a decision to drop it", () => {
    const problems = rotationRefusals([plan({ index: 2, hasCredential: false, label: "Deploy" })]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("Deploy");
    expect(problems[0]).toContain("discard it");
  });

  it("stops asking once that slot is dropped", () => {
    expect(rotationRefusals([plan({}), plan({ index: 2, hasCredential: false, drop: true })])).toEqual(
      [],
    );
  });

  it("refuses to re-wrap a security key, which this version cannot do", () => {
    const problems = rotationRefusals([plan({}), plan({ index: 3, kind: "fido2" })]);
    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain("security key");
  });

  it("refuses a plan that keeps nothing", () => {
    const problems = rotationRefusals([
      plan({ drop: true }),
      plan({ index: 1, kind: "recovery", hasCredential: false, drop: true }),
    ]);
    expect(problems).toEqual([expect.stringContaining("nobody can open")]);
  });
});

describe("slotDetail", () => {
  it("says a password slot needs its key file, and carries the Argon2id summary", () => {
    const line = slotDetail(
      slot(0, "password", { requiresKeyfile: true, kdfSummary: "Argon2id, 256 MiB, t=3" }),
    );
    expect(line).toContain("Needs its key file too");
    expect(line).toContain("Argon2id, 256 MiB, t=3");
    expect(line).toContain("Never used");
  });
});
