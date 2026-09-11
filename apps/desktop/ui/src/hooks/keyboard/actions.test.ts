/**
 * The keyboard map's copy actually exists.
 *
 * `actions.ts` holds catalogue keys rather than sentences, and reads them
 * through a cast — i18next types `t` against literal keys and these are fields
 * of a data table. This file is the check that cast gives up: every key in the
 * table resolves to a real English message, so an action added without its
 * catalogue entry fails here rather than putting a humanised key in the
 * settings table.
 */

import { describe, expect, it } from "vitest";

import { ENGLISH_CATALOGUES } from "@/i18n/catalogues";

import { SHORTCUT_ACTIONS } from "./actions";

/** The `shortcut.` object of the English `common` catalogue. */
const SHORTCUTS = (ENGLISH_CATALOGUES.common ?? {})["shortcut"];

/**
 * What `missing.ts` wraps a key that exists in no catalogue in, in development.
 * Written as an escape, like the original: a raw non-ASCII glyph in a source
 * file is a hazard this repository has been bitten by.
 */
const MISSING_MARK = "\u27E6";

describe("the keyboard map's copy", () => {
  it("has a title for every action", () => {
    for (const action of SHORTCUT_ACTIONS) {
      expect(action.title, action.id).not.toBe("");
      expect(action.title, action.id).not.toContain(MISSING_MARK);
    }
  });

  it("resolves every explanation it offers", () => {
    for (const action of SHORTCUT_ACTIONS) {
      for (const text of [action.unrebindableReason, action.reachNote]) {
        if (text === null) continue;
        expect(text, action.id).not.toBe("");
        expect(text, action.id).not.toContain(MISSING_MARK);
      }
    }
  });

  it("says why every fixed binding is fixed", () => {
    // A row that cannot be edited and does not say why is a dead control with
    // no explanation, which is the failure the `unrebindableReason` field was
    // added to remove. Asserted here so that adding an action cannot quietly
    // reintroduce it.
    for (const action of SHORTCUT_ACTIONS) {
      if (action.editable) continue;
      expect(action.unrebindableReason, action.id).not.toBeNull();
    }
  });

  it("leaves no orphan messages behind in the catalogue", () => {
    // The other direction: a translator asked to translate a sentence that
    // nothing renders is being asked to do wasted work, and Weblate has no way
    // to tell them so.
    const used = new Set<string>();
    for (const action of SHORTCUT_ACTIONS) used.add(action.title);
    for (const action of SHORTCUT_ACTIONS) {
      if (action.unrebindableReason !== null) used.add(action.unrebindableReason);
      if (action.reachNote !== null) used.add(action.reachNote);
    }

    const orphans: string[] = [];
    const walk = (node: unknown, path: string): void => {
      if (typeof node === "string") {
        if (!path.startsWith("_comment_") && !path.includes("._comment_") && !used.has(node)) {
          orphans.push(path);
        }
        return;
      }
      if (typeof node !== "object" || node === null) return;
      for (const [key, value] of Object.entries(node)) {
        walk(value, path === "" ? key : `${path}.${key}`);
      }
    };
    walk(SHORTCUTS, "");

    expect(orphans).toEqual([]);
  });
});
