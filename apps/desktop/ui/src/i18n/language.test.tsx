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
import { localeDirection, SUPPORTED_LOCALES } from "./locales";
import { useT } from "./useT";

const instance = i18n();

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
 * `setLanguage` refuses a language with no catalogue directory, and only
 * English ships one in this build — so the re-render tests drive the layer
 * underneath it. That is the same call `setLanguage` makes once the gate
 * passes; what the gate adds is tested on its own below.
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
    // `hi` ships no catalogue directory in this build. Switching to it would
    // change nothing on screen, which is the failure the Language screen used
    // to have: a control that looks like it worked and did not.
    const before = instance.language;
    const after = await setLanguage("hi");
    expect(after).toBe(before);
    expect(isLocaleAvailable("hi")).toBe(false);
  });

  it("treats English as available whatever else is", () => {
    expect(availableLocales()).toContain("en");
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
