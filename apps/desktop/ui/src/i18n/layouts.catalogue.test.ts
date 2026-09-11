/**
 * The keyboard layout names, checked against the Rust that names them.
 *
 * `crates/remoter-proto-rdp/src/layout.rs` offers each layout as a catalogue
 * key, and the sentences behind those keys live in
 * `locales/<lang>/connections.json`. Nothing in the type system joins the two: a
 * layout added to the Rust list arrives in the editor's dropdown as a raw key
 * — `settings.keyboardLayout.turkishF` sitting in a select next to "German" —
 * and the person who would notice is the one whose keyboard it is.
 *
 * So this reads the Rust, the same way `failures.catalogue.test.ts` does for
 * the error taxonomy. It is the only thing standing between "every offered
 * layout has a name" and "every offered layout had a name in September".
 */

import { describe, expect, it } from "vitest";

// Five levels out of src/i18n, resolved by the bundler, so moving the crate is
// a build failure here rather than a test that quietly stops reading anything.
const LAYOUT_SOURCE = import.meta.glob("../../../../../crates/remoter-proto-rdp/src/layout.rs", {
  eager: true,
  query: "?raw",
  import: "default",
}) as Record<string, string>;

const CATALOGUES = import.meta.glob("../../../../../locales/*/connections.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

/** Every `settings.keyboardLayout.*` key the adapter offers. */
const OFFERED: readonly string[] = (() => {
  const source = Object.values(LAYOUT_SOURCE).join("\n");
  // Only the entries in `KEYBOARD_LAYOUTS`; the tests at the foot of that file
  // name a couple of keys too, and matching those would be matching the
  // guard's own fixtures. Both forms are the same literal, so the set is
  // deduplicated rather than positionally parsed.
  const keys = new Set<string>();
  for (const match of source.matchAll(/"settings\.keyboardLayout\.([A-Za-z0-9]+)"/g)) {
    const name = match[1];
    if (name !== undefined) keys.add(name);
  }
  return [...keys].sort();
})();

function namesIn(locale: string): Record<string, unknown> {
  const entry = Object.entries(CATALOGUES).find(([path]) =>
    path.endsWith(`/locales/${locale}/connections.json`),
  );
  const catalogue = entry?.[1];
  if (typeof catalogue !== "object" || catalogue === null) return {};
  const settings = (catalogue as Record<string, unknown>)["settings"];
  if (typeof settings !== "object" || settings === null) return {};
  const layouts = (settings as Record<string, unknown>)["keyboardLayout"];
  if (typeof layouts !== "object" || layouts === null) return {};
  return layouts as Record<string, unknown>;
}

describe("the keyboard layout catalogue", () => {
  it("found the adapter's list at all", () => {
    // Guards against the glob silently matching nothing, which would make
    // every assertion below pass over an empty set.
    expect(OFFERED.length).toBeGreaterThan(20);
    expect(OFFERED).toContain("turkishQ");
    expect(OFFERED).toContain("turkishF");
  });

  it("has an English name for every layout the adapter offers", () => {
    const english = namesIn("en");
    const missing = OFFERED.filter((key) => typeof english[key] !== "string");
    expect(missing).toEqual([]);
  });

  it("names no layout the adapter does not offer", () => {
    // The other direction: a key left behind by a layout that was removed is
    // a string translators keep paying for and nobody ever reads.
    const english = namesIn("en");
    const orphans = Object.keys(english)
      .filter((key) => !key.startsWith("_comment"))
      .filter((key) => !OFFERED.includes(key));
    expect(orphans).toEqual([]);
  });

  it("keeps Turkish Q and Turkish F as two distinct names", () => {
    // They are one language and two keyboards. A catalogue that gave them the
    // same name would leave the user picking between identical rows.
    const english = namesIn("en");
    expect(english["turkishQ"]).not.toEqual(english["turkishF"]);
  });
});
