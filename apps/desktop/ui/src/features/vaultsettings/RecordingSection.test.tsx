/**
 * What this section is allowed to claim.
 *
 * This build has no recorder — `docs/roadmap.md` puts session recording at
 * v0.4 — and the screen previously read "Every session is recorded, with a
 * notice before it opens". A user acting on that believes they hold a
 * compliance record that does not exist, so these tests are about the
 * sentences, not the plumbing: the "nothing is recorded" notice is present and
 * sits above the cards, no line claims recording happens today, and the policy
 * is still written to the vault, because storing the intent is the reason the
 * control stays.
 */

import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { VaultSettings as VaultSettingsDto } from "@/lib/ipc";

import { RecordingSection } from "./RecordingSection";

function settings(overrides: Partial<VaultSettingsDto> = {}): VaultSettingsDto {
  return {
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    lockOnMinimise: false,
    sessionOnLock: "freeze_input",
    recording: "never",
    backupCount: 3,
    ...overrides,
  };
}

function renderSection(overrides: Partial<VaultSettingsDto> = {}) {
  const onSave = vi.fn();
  const { container } = render(
    <RecordingSection
      settings={settings(overrides)}
      onSave={onSave}
      savingField={null}
      failure={null}
      onRetrySave={() => undefined}
    />,
  );
  const section = container.querySelector("section");
  if (section === null) throw new Error("the section did not render");
  return { onSave, section };
}

/** Everything on screen as one string, which is what a user reads. */
function copy(section: Element): string {
  return section.textContent ?? "";
}

describe("RecordingSection", () => {
  it("says nothing is recorded in this version", () => {
    const { section } = renderSection();
    expect(copy(section)).toContain("Nothing is recorded in this version");
    expect(copy(section)).toContain("every session in this vault opens unrecorded");
  });

  it("puts that notice above the cards rather than under them", () => {
    const { section } = renderSection();
    const notice = screen.getByText(/Nothing is recorded in this version/);
    const group = within(section).getByRole("radio", { name: /Never/ });

    // DOCUMENT_POSITION_FOLLOWING: the cards come after the notice in reading
    // order, so a reader who stops at the first control has still read it.
    expect(notice.compareDocumentPosition(group) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("makes no present-tense claim that sessions are being recorded", () => {
    const { section } = renderSection({ recording: "always" });
    const text = copy(section);

    expect(text).not.toMatch(/every session is recorded/i);
    expect(text).not.toMatch(/recordings are encrypted/i);
    // A session that "is recorded" is the claim that costs something. The
    // notice's own "Nothing is recorded in this version" is the opposite
    // claim, so the subject has to be part of the pattern.
    expect(text).not.toMatch(/sessions?[^.]{0,30}\b(is|are)\s+recorded\b/i);
  });

  it("does not describe the required policy as something this build can do", () => {
    const { section } = renderSection();
    const text = copy(section);

    expect(text).toContain('A fourth policy, "required"');
    expect(text).toContain("is not offered here");
    // Not "refuses to connect": nothing here refuses anything today.
    expect(text).not.toMatch(/refuses to connect/i);
  });

  it("still writes the policy, because the stored intent is why the cards stay", async () => {
    const user = userEvent.setup();
    const { onSave, section } = renderSection();

    await user.click(within(section).getByRole("radio", { name: /Always/ }));

    expect(onSave).toHaveBeenCalledWith("recording", { recording: "always" });
  });
});
