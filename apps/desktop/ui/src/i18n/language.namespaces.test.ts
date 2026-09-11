/**
 * Choosing a language has to bring the whole interface with it.
 *
 * `changeLanguage` loads only the namespaces i18next has active when it is
 * called. At start-up that is `common` and whatever the first screen asked
 * for — so after choosing Turkish, `i18n.language` was "tr" while `settings`,
 * `connections`, `sessions` and the rest were still English, and every screen
 * but one fell back key by key. The language screen reported success and the
 * interface did not move.
 */

import { describe, expect, it } from "vitest";

import { SHIPPED_NAMESPACES } from "./catalogues";
import { i18n, setLanguage } from "./instance";

describe("choosing a language", () => {
  it("loads every shipped namespace, not only the ones already in use", async () => {
    const got = await setLanguage("tr");
    expect(got).toBe("tr");

    const instance = i18n();
    const missing = SHIPPED_NAMESPACES.filter((ns) => !instance.hasResourceBundle("tr", ns));
    expect(missing, "namespaces left in English after switching").toEqual([]);
  });

  it("returns the chosen language's words, not the English fallback", async () => {
    await setLanguage("tr");
    const t = i18n().getFixedT("tr", "settings");
    expect(t("language.title")).toBe("Dil");
  });
});
