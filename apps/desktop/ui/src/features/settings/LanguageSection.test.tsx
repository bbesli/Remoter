/**
 * Which languages this screen offers, and where the answer comes from.
 *
 * The answer has been wrong twice. First it was a hardcoded `available: false`
 * on nine rows, which would have gone on calling a language unavailable after
 * its catalogue shipped. Then it was the presence of each namespace *file*,
 * which a half-translated catalogue passes: the row said the language was
 * finished while strings inside it fell back to English, one key at a time.
 *
 * So the assertions here are about the rule and never name a language. What is
 * offered today is a property of `locales/` as it stands — a key added to
 * English makes every translation incomplete until it is translated — and a
 * test that has to be edited whenever a catalogue lands is a test that gets
 * deleted by whoever is in a hurry.
 */

import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { completeLocales } from "@/i18n";
import { SUPPORTED_LOCALES } from "@/i18n";
import type { AppSettings } from "@/lib/ipc";

import { LanguageSection } from "./LanguageSection";

const settings: AppSettings = {
  theme: "dark",
  locale: "en",
  autoLockMinutes: 15,
  lockOnScreenLock: true,
  lockOnSuspend: true,
  sidebarWidth: 280,
  inspectorOpen: true,
  updateCheckEnabled: false,
  updateChannel: "stable",
  updateLastCheckedAt: null,
  fileDownloadFolder: null,
  terminalPrefix: "ctrl+alt",
  shortcuts: {},
  terminal: { palette: "auto", overrides: {}, fontFamily: "", fontSize: 13 },
};

function renderSection() {
  render(
    <LanguageSection
      settings={settings}
      onSave={vi.fn()}
      savingField={null}
      failure={null}
      onRetrySave={() => undefined}
    />,
  );
}

/** The radio for one language, found by the endonym it is written in. */
function radioFor(code: string): HTMLInputElement {
  const descriptor = SUPPORTED_LOCALES.find((locale) => locale.code === code);
  const name = descriptor?.endonym ?? code;
  const found = screen
    .getAllByRole("radio")
    .find((input) => (input as HTMLInputElement).value === code);
  if (found === undefined) throw new Error(`no row for ${name}`);
  return found as HTMLInputElement;
}

describe("the Language screen", () => {
  it("offers a language only once its catalogues have been measured", async () => {
    // Measuring means reading the catalogues, which is asynchronous. Until the
    // answer lands the screen offers nothing at all: a row drawn early would
    // be a choice made on a test the interface no longer trusts.
    renderSection();
    expect(screen.queryAllByRole("radio")).toHaveLength(0);

    await waitFor(() => expect(screen.getAllByRole("radio").length).toBeGreaterThan(0));
  });

  it("enables exactly the languages that translate every message", async () => {
    renderSection();
    await waitFor(() => expect(screen.getAllByRole("radio").length).toBeGreaterThan(0));

    const complete = new Set(await completeLocales());
    // Not vacuous whatever the state of the translations: English is always
    // complete, because it is the source rather than a translation of it.
    expect(complete.size).toBeGreaterThan(0);

    for (const locale of SUPPORTED_LOCALES) {
      expect(radioFor(locale.code).disabled, locale.code).toBe(!complete.has(locale.code));
    }
  });

  it("says so on the row of a language that is not complete", async () => {
    renderSection();
    await waitFor(() => expect(screen.getAllByRole("radio").length).toBeGreaterThan(0));

    const complete = new Set(await completeLocales());
    const incomplete = SUPPORTED_LOCALES.filter((locale) => !complete.has(locale.code));
    // Nothing to prove on a tree where every language is finished — and
    // nothing wrong either, which is why this returns rather than fails.
    if (incomplete.length === 0) return;

    // The row's own words, from `settings:language.notReady`.
    expect(screen.getAllByText(/not yet available/i).length).toBe(incomplete.length);
  });
});
