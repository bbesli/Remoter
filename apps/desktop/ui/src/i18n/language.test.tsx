/**
 * Switching language at runtime, and what the whole layout does about it.
 *
 * "No restart" is a claim that is easy to make and easy to break — one label
 * resolved at module scope is enough to leave part of the chrome in the old
 * language for the rest of the session, and nothing about that looks wrong on
 * an English machine. So the assertions are on rendered components rather than
 * on the i18next instance.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { applyDocumentLanguage, i18n, setLanguage } from "./instance";
import { isLocaleAvailable, availableLocales } from "./catalogues";
import { SOURCE_LOCALE, localeDirection, SUPPORTED_LOCALES } from "./locales";
import { useT } from "./useT";

const instance = i18n();

/**
 * The languages the gate should let through, and the ones it should turn away,
 * decided here rather than written down.
 *
 * Naming a language — this file used to name `hi` — makes the test a snapshot
 * of which catalogues existed the week it was written, and it fails on correct
 * code the day that language ships. What the gate promises is not "Hindi is
 * refused"; it is "a language you can actually read is selectable and one you
 * cannot is not", and that is what is asserted below.
 */
const TRANSLATED: readonly string[] = availableLocales().filter((code) => code !== SOURCE_LOCALE);

const UNTRANSLATED: readonly string[] = [
  ...SUPPORTED_LOCALES.map((locale) => locale.code).filter((code) => !isLocaleAvailable(code)),
  // Always present, so the refusal is still exercised on the day every shipped
  // language is complete: a tag the registry has never heard of has no
  // catalogue by definition. It is also the realistic case — a settings file
  // written by a newer build, or one edited by hand.
  "xx-YY",
];

/** A German catalogue for the duration of this file, not a shipped one. */
const GERMAN_SHELL = {
  titleBar: { lock: "Tresor sperren", settings: "Einstellungen" },
  footer: {
    sessions: "{count, plural, =0 {keine Sitzungen} one {# Sitzung} other {# Sitzungen}}",
  },
};

function Chrome() {
  const t = useT("shell");
  return (
    <>
      <span>{t("titleBar.lock")}</span>
      <span>{t("footer.sessions", { count: 2 })}</span>
    </>
  );
}

beforeEach(() => {
  instance.addResourceBundle("de", "shell", GERMAN_SHELL, true, true);
});

/**
 * Drives the layer underneath `setLanguage` — the same call it makes once the
 * gate passes.
 *
 * The re-render tests use it so that they read the German bundle added above
 * rather than whatever `locales/de/` happens to hold, which keeps them about
 * re-rendering and plural rules instead of about translation wording. The gate
 * itself is tested on its own, through `setLanguage`, below.
 */
async function switchTo(code: string) {
  await act(async () => {
    await instance.changeLanguage(code);
  });
}

afterEach(async () => {
  await switchTo("en");
  document.documentElement.removeAttribute("dir");
  document.documentElement.removeAttribute("lang");
});

describe("switching language", () => {
  it("re-renders a mounted component without remounting it", async () => {
    render(<Chrome />);
    expect(screen.getByText("Lock the vault")).toBeInTheDocument();

    await switchTo("de");

    // Same tree, different words. Nothing was unmounted and no reload happened.
    expect(await screen.findByText("Tresor sperren")).toBeInTheDocument();
    expect(screen.queryByText("Lock the vault")).not.toBeInTheDocument();
  });

  it("carries the plural rules of the new language with it", async () => {
    render(<Chrome />);
    expect(screen.getByText("2 sessions")).toBeInTheDocument();
    await switchTo("de");
    expect(await screen.findByText("2 Sitzungen")).toBeInTheDocument();
  });

  it("refuses a language with no catalogues rather than pretending", async () => {
    // Switching to a language nothing has been translated into would change
    // nothing on screen, which is the failure the Language screen used to
    // have: a control that looks like it worked and did not. `setLanguage`
    // answers with the language still in force, so the caller can say so.
    for (const code of UNTRANSLATED) {
      const before = instance.language;
      expect(await setLanguage(code), code).toBe(before);
      expect(instance.language, code).toBe(before);
    }
  });

  it("switches to a language whose catalogues are all present", async () => {
    // The other half of the same gate, and the half that was never asserted: a
    // test that only checks refusals also passes when `setLanguage` refuses
    // everything, which is the shape this file was in.
    for (const code of TRANSLATED) {
      // From English each time, so "it moved" is what is being asserted and
      // not "it was already there".
      await switchTo(SOURCE_LOCALE);
      expect(await setLanguage(code), code).toBe(code);
      expect(instance.language, code).toBe(code);
    }

    // English is selectable whether or not anything else is — it is the source
    // language, not a translation of it. Asserted from somewhere else, for the
    // same reason: `setLanguage` returning the language already in force is
    // exactly what a refusal looks like.
    await switchTo("de");
    expect(await setLanguage(SOURCE_LOCALE)).toBe(SOURCE_LOCALE);
    expect(instance.language).toBe(SOURCE_LOCALE);
  });

  it("treats English as available whatever else is", () => {
    expect(availableLocales()).toContain(SOURCE_LOCALE);
  });
});

describe("the document's direction", () => {
  it("is written onto the root element, not onto a component", () => {
    applyDocumentLanguage("ar");
    // Everything else follows from this: the stylesheets are logical
    // throughout, so the sidebar, the tab strip's edges and the inspector all
    // mirror off this one attribute.
    expect(document.documentElement.getAttribute("dir")).toBe("rtl");
    expect(document.documentElement.getAttribute("lang")).toBe("ar");

    applyDocumentLanguage("de");
    expect(document.documentElement.getAttribute("dir")).toBe("ltr");
    expect(document.documentElement.getAttribute("lang")).toBe("de");
  });

  it("knows which of the ten run right to left", () => {
    expect(localeDirection("ar")).toBe("rtl");
    for (const locale of SUPPORTED_LOCALES) {
      if (locale.code !== "ar") expect(locale.dir).toBe("ltr");
    }
  });

  it("falls back to ltr for a tag it does not know", () => {
    // A settings file written by a newer build must not stop this one opening.
    expect(localeDirection("xx-YY")).toBe("ltr");
  });
});
