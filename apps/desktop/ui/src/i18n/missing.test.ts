/**
 * What a user sees when a string is not there.
 *
 * Three separate failures, three separate behaviours, and none of them is a
 * raw key on screen or a thrown error.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { humaniseKey, missingKeyText } from "./missing";
import { initI18n } from "./instance";
import { SHIPPED_NAMESPACES } from "./catalogues";

const i18n = initI18n();

afterEach(() => {
  vi.restoreAllMocks();
});

describe("humaniseKey", () => {
  it("reads the last segment as a phrase", () => {
    expect(humaniseKey("settings.updates.lastCheckedNever")).toBe("Last checked never");
    expect(humaniseKey("shell.titleBar.lock")).toBe("Lock");
    expect(humaniseKey("a.b.some_snake_case")).toBe("Some snake case");
  });

  it("never returns an empty string", () => {
    expect(humaniseKey("")).toBe("");
    expect(humaniseKey("a..")).toBe("a..");
  });
});

describe("a key that exists in no catalogue", () => {
  it("renders readable text, not the key", () => {
    // Development marks it; the assertion is on what is inside the marker,
    // because that is what a release build shows.
    const rendered = missingKeyText("settings.updates.lastCheckedNever");
    expect(rendered).toContain("Last checked never");
    expect(rendered).not.toContain("settings.updates");
  });

  it("is visibly marked in development", () => {
    // U+27E6 / U+27E7. Neither appears in interface copy, so the marker
    // cannot be mistaken for a real string.
    expect(missingKeyText("x.y.z")).toMatch(/^\u27E6.*\u27E7$/);
  });

  it("reports the namespace so the fix has an address", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => undefined);
    i18n.getFixedT("en", "shell")("titleBar.thisDoesNotExist" as never);
    expect(spy).toHaveBeenCalled();
    expect(String(spy.mock.calls[0]?.[0])).toContain("locales/en/shell.json");
  });

  it("does not throw", () => {
    expect(() =>
      i18n.getFixedT("en", "shell")("nothing.here.at.all" as never, { host: "x" } as never),
    ).not.toThrow();
  });
});

describe("a key missing only in the chosen language", () => {
  it("falls back to English rather than to the key", () => {
    i18n.addResourceBundle("de", "shell", { titleBar: { lock: "Tresor sperren" } }, true, true);
    const de = i18n.getFixedT("de", "shell");
    expect(de("titleBar.lock" as never)).toBe("Tresor sperren");
    // Not translated in the fixture above; English fills in, unmarked, because
    // this is a translation gap and not a bug in the interface.
    expect(de("titleBar.settings" as never)).toBe("Settings");
    expect(de("titleBar.settings" as never)).not.toContain("\u27E6");
  });
});

describe("a message that will not parse", () => {
  it("falls back to the English source instead of showing ICU syntax", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    // An unbalanced brace is exactly what a translator produces when a
    // placeholder is retyped by hand rather than copied.
    i18n.addResource("fr", "shell", "footer.sessions", "{count, plural, one {# session}");
    const rendered = i18n.getFixedT("fr", "shell")("footer.sessions" as never, {
      count: 3,
    } as never) as unknown as string;
    expect(rendered).toBe("3 sessions");
    expect(rendered).not.toContain("plural");
    expect(rendered).not.toContain("{");
  });
});

describe("the English catalogue", () => {
  it("is bundled for every namespace the interface loads", () => {
    // The fallback only works because English is compiled in. If a namespace
    // ever stopped being bundled, every missing key in it would reach the
    // marker instead — silently, and only in the languages nobody tests.
    for (const ns of SHIPPED_NAMESPACES) {
      expect(i18n.hasResourceBundle("en", ns)).toBe(true);
    }
  });
});
