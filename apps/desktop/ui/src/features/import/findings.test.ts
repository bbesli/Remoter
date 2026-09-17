/**
 * The findings a Remoter export produces, read as sentences.
 *
 * The describer is a switch over the core's finding kinds; a kind that reaches
 * it without a branch renders as nothing. These pin the branches Remoter's own
 * formats depend on, through the real English catalogue.
 */

import { beforeAll, describe, expect, it } from "vitest";
import type { TFunction } from "i18next";

import { i18n } from "@/i18n";
import type { ImportFinding } from "@/lib/ipc";

import { describeFinding } from "./findings";

let t: TFunction<"import">;

beforeAll(async () => {
  await i18n().loadNamespaces(["import"]);
  t = i18n().getFixedT("en", "import") as TFunction<"import">;
});

describe("describeFinding", () => {
  it("says how many credentials arrive without their secrets, and what that means", () => {
    const finding: ImportFinding = { severity: "warning", kind: "secrets_not_carried", count: 3 };
    const view = describeFinding(t, finding);
    expect(view.severity).toBe("warning");
    expect(view.title).toBe("3 credentials arrive without their passwords or keys.");
    expect(view.body).toMatch(/asks for its password or key the first time it is used/);
  });

  it("uses the singular for one", () => {
    const view = describeFinding(t, { severity: "warning", kind: "secrets_not_carried", count: 1 });
    expect(view.title).toBe("1 credential arrives without its password or key.");
  });
});
