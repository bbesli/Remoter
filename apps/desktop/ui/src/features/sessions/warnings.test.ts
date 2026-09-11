import { describe, expect, it } from "vitest";

import { canCollapse, describeWarning, loudestTone } from "./warnings";
import type { SessionWarning } from "./store";

function warning(kind: string, detail: string | null = null): SessionWarning {
  return { kind, detail, at: 0 };
}

describe("describeWarning", () => {
  it("names the warnings the adapters actually raise", () => {
    expect(describeWarning(warning("other", "vnc.security.none")).key).toBe(
      "warning.detail.vncSecurityNone",
    );
    expect(
      describeWarning(warning("other", "rdp.network_level_authentication_disabled")).key,
    ).toBe("warning.detail.rdpNlaDisabled");
    expect(
      describeWarning(warning("unencrypted_transport", "vnc.cleartext.routable")).key,
    ).toBe("warning.detail.vncCleartextRoutable");
  });

  it("sounds loudest for the ones that mean something is unprotected", () => {
    expect(describeWarning(warning("other", "vnc.security.none")).tone).toBe("danger");
    expect(describeWarning(warning("unencrypted_transport", "vnc.cleartext.routable")).tone).toBe(
      "danger",
    );
    expect(
      describeWarning(warning("other", "rdp.network_level_authentication_disabled")).tone,
    ).toBe("danger");
  });

  it("does not make a rung bell as loud as an unauthenticated session", () => {
    expect(describeWarning(warning("other", "vnc.bell")).tone).toBe("info");
    expect(describeWarning(warning("other", "rdp.display_control_unavailable")).tone).toBe("info");
  });

  it("carries the algorithm as a value rather than folding it into a key", () => {
    const view = describeWarning(warning("weak_algorithm", "VNC-Auth-DES"));
    expect(view.key).toBe("warning.kind.weakAlgorithm");
    expect(view.algorithm).toBe("VNC-Auth-DES");
  });

  it("quarantines a login banner as remote text", () => {
    // Arbitrary length, arbitrary script, written by a machine this
    // application does not control. It never becomes part of a sentence.
    const view = describeWarning(warning("banner", "Authorised users only\nAll access is logged"));
    expect(view.key).toBe("warning.kind.banner");
    expect(view.remoteText).toContain("Authorised users only");
    expect(view.algorithm).toBeNull();
  });

  it("shows a detail it has no sentence for, as the key it is", () => {
    // An adapter that adds a warning nobody wrote copy for should look
    // unfinished rather than silent.
    const view = describeWarning(warning("other", "rdp.something.new"));
    expect(view.key).toBe("warning.kind.other");
    expect(view.unnamedDetail).toBe("rdp.something.new");
  });

  it("shows a kind it has no sentence for, too", () => {
    const view = describeWarning(warning("a_kind_from_the_future", null));
    expect(view.unnamedDetail).toBe("a_kind_from_the_future");
  });

  it("treats an unnamed unencrypted-transport warning as serious anyway", () => {
    expect(describeWarning(warning("unencrypted_transport", null)).tone).toBe("danger");
  });
});

describe("loudestTone", () => {
  it("takes the worst of the set", () => {
    const views = [
      describeWarning(warning("other", "vnc.bell")),
      describeWarning(warning("other", "vnc.security.none")),
    ];
    expect(loudestTone(views)).toBe("danger");
  });

  it("is neutral for nothing at all", () => {
    expect(loudestTone([])).toBe("neutral");
  });
});

describe("canCollapse", () => {
  it("refuses to fold away a session that is not protecting something", () => {
    // A warning hidden behind a chevron the user clicked once is a warning
    // that was not shown.
    expect(canCollapse([describeWarning(warning("other", "vnc.security.none"))])).toBe(false);
  });

  it("folds the rest", () => {
    expect(
      canCollapse([
        describeWarning(warning("other", "vnc.bell")),
        describeWarning(warning("output_throttled")),
      ]),
    ).toBe(true);
  });
});
