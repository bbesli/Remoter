/**
 * What this section is allowed to claim, and what it must admit.
 *
 * Two defects, both of them a control that shipped ahead of its behaviour.
 *
 * The idle help text said idle was measured from the desktop's own input idle
 * time. It was not: it was measured from the last call that touched the vault,
 * so typing in a terminal was not activity and the vault locked while it was
 * being used. The measurement is fixed in the core; these tests are about the
 * sentence, because a user who believes their terminal keeps the vault open
 * will behave accordingly.
 *
 * The three switches persisted values nothing observed. A switch this build
 * cannot honour is now disabled and says why, and — this is the part worth a
 * test — it does not write. A disabled control that still saves is the same
 * defect wearing a grey label.
 */

import { render, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { LockTriggerSupport, VaultSettings as VaultSettingsDto } from "@/lib/ipc";

import { AutoLockSection } from "./AutoLockSection";

const ALL_OBSERVED: LockTriggerSupport = {
  screenLock: "observed",
  suspend: "observed",
  minimise: "observed",
};

/** What this build actually reports on Linux today. */
const AS_SHIPPED: LockTriggerSupport = {
  screenLock: "unobserved",
  suspend: "on_resume",
  minimise: "unobserved",
};

function settings(overrides: Partial<VaultSettingsDto> = {}): VaultSettingsDto {
  return {
    autoLockMinutes: 15,
    lockOnScreenLock: true,
    lockOnSuspend: true,
    lockOnMinimise: false,
    lockTriggers: ALL_OBSERVED,
    sessionOnLock: "keep_running",
    recording: "never",
    backupCount: 3,
    ...overrides,
  };
}

function renderWith(value: VaultSettingsDto) {
  const onSave = vi.fn();
  const { container } = render(
    <AutoLockSection
      settings={value}
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

function renderSection(overrides: Partial<VaultSettingsDto> = {}) {
  return renderWith(settings(overrides));
}

/** Everything on screen as one string, which is what a user reads. */
function copy(section: Element): string {
  return section.textContent ?? "";
}

describe("AutoLockSection", () => {
  describe("the idle sentence", () => {
    it("describes what is measured rather than the desktop's input idle time", () => {
      const { section } = renderSection();
      const text = copy(section);

      expect(text).toContain("nothing has touched the vault and no session has carried traffic");
      expect(text).toContain("Keystrokes you send and output a host sends both count");
    });

    it("does not claim to read the desktop's own input idle time", () => {
      const { section } = renderSection();
      const text = copy(section);

      // The old sentence, and the belief it created. The screen may mention
      // input idle time only to deny reading it, so the negative has to be the
      // affirmative claim rather than the words.
      expect(text).not.toMatch(/idle is measured from the desktop's own input idle time/i);
      expect(text).toContain("Remoter does not read the desktop's own input idle time");
    });

    it("still writes the timeout, which is the value the core counts down", async () => {
      const user = userEvent.setup();
      const { onSave, section } = renderSection();

      await user.click(within(section).getByRole("radio", { name: "1 min" }));

      expect(onSave).toHaveBeenCalledWith("autoLockMinutes", { autoLockMinutes: 1 });
    });

    it("says what never means, and only when never is chosen", () => {
      expect(copy(renderSection().section)).not.toMatch(/stays open until you lock it or quit/);
      expect(copy(renderSection({ autoLockMinutes: 0 }).section)).toMatch(
        /stays open until you lock it or quit/,
      );
    });
  });

  describe("a trigger this build can honour", () => {
    it("is an ordinary switch that writes", async () => {
      const user = userEvent.setup();
      const { onSave, section } = renderSection();
      const control = within(section).getByRole("switch", { name: /When the screen locks/ });

      expect(control).toBeEnabled();
      await user.click(control);

      expect(onSave).toHaveBeenCalledWith("lockOnScreenLock", { lockOnScreenLock: false });
    });
  });

  describe("a trigger this build cannot observe", () => {
    it("is disabled and says the switch would not lock anything", () => {
      const { section } = renderSection({ lockTriggers: AS_SHIPPED });

      expect(within(section).getByRole("switch", { name: /When the screen locks/ })).toBeDisabled();
      expect(
        within(section).getByRole("switch", { name: /When the window is minimised/ }),
      ).toBeDisabled();
      expect(copy(section)).toContain("This build cannot see the screen lock on this system");
      expect(copy(section)).toContain("This build cannot see the window being minimised");
    });

    it("does not write when it is clicked", async () => {
      const user = userEvent.setup();
      const { onSave, section } = renderSection({ lockTriggers: AS_SHIPPED });

      await user.click(within(section).getByRole("switch", { name: /When the screen locks/ }));
      await user.click(
        within(section).getByRole("switch", { name: /When the window is minimised/ }),
      );

      expect(onSave).not.toHaveBeenCalled();
    });

    it("says the stored value still applies on a machine that can see the event", () => {
      const { section } = renderSection({ lockTriggers: AS_SHIPPED });
      expect(copy(section)).toContain("still applies on a computer where Remoter can see");
    });

    it("does not show it as on or off, because it is neither", () => {
      const { section } = renderSection({ lockTriggers: AS_SHIPPED, lockOnScreenLock: true });
      const row = within(section)
        .getByRole("switch", { name: /When the screen locks/ })
        .closest("label");
      if (row === null) throw new Error("the switch has no row");
      expect(row.textContent).toContain("N/A");
    });
  });

  describe("a trigger observed only after the fact", () => {
    it("stays usable but says the lock comes on the way back, not on the way down", async () => {
      const user = userEvent.setup();
      const { onSave, section } = renderSection({ lockTriggers: AS_SHIPPED });
      const control = within(section).getByRole("switch", { name: /On suspend or hibernate/ });

      expect(control).toBeEnabled();
      expect(copy(section)).toContain("locks when the machine comes back rather than before");
      // The consequence, said plainly rather than left to be worked out.
      expect(copy(section)).toContain("in the hibernation image if it hibernates");

      await user.click(control);
      expect(onSave).toHaveBeenCalledWith("lockOnSuspend", { lockOnSuspend: false });
    });
  });

  describe("when the core did not say", () => {
    it("renders ordinary switches rather than claiming they are broken", () => {
      // The field left off entirely rather than set to undefined: under
      // `exactOptionalPropertyTypes` those are different values, and absent is
      // the one a fixture that has not been told about lock triggers produces.
      const { lockTriggers: _absent, ...withoutSupport } = settings();
      const { section } = renderWith(withoutSupport);
      expect(within(section).getByRole("switch", { name: /When the screen locks/ })).toBeEnabled();
    });
  });
});
