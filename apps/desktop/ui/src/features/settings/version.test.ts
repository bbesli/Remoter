/**
 * The version comparison, held to SemVer 2.0.0 §11.
 *
 * These exist because every way of getting this wrong is silent. A string
 * comparison ships an application that never offers `0.10.0` to somebody on
 * `0.9.0`; dropping §11.3 ships one that pushes a release candidate onto
 * somebody running the finished release. Neither produces an error anywhere.
 */

import { describe, expect, it } from "vitest";

import type { UpdateRelease } from "@/lib/ipc";

import {
  compareVersionStrings,
  formatVersion,
  parseVersion,
  pickUpdate,
} from "./version";

function release(tag: string, prerelease = false): UpdateRelease {
  return {
    tag,
    name: tag,
    notes: "",
    url: `https://github.com/bbesli/Remoter/releases/tag/${tag}`,
    prerelease,
    publishedAt: null,
  };
}

describe("parseVersion", () => {
  it("reads a plain version", () => {
    expect(parseVersion("1.2.3")).toEqual({
      major: 1,
      minor: 2,
      patch: 3,
      prerelease: [],
    });
  });

  it("accepts the leading v the tags are written with", () => {
    expect(parseVersion("v0.2.0")).toEqual({
      major: 0,
      minor: 2,
      patch: 0,
      prerelease: [],
    });
  });

  it("keeps the pre-release identifiers apart", () => {
    expect(parseVersion("1.0.0-rc.1")?.prerelease).toEqual(["rc", "1"]);
    expect(parseVersion("1.0.0-alpha.beta.2")?.prerelease).toEqual(["alpha", "beta", "2"]);
  });

  it("drops build metadata, which SemVer §10 excludes from ordering", () => {
    expect(parseVersion("1.0.0+20260910")).toEqual(parseVersion("1.0.0"));
    // The hyphen inside the metadata must not be mistaken for a pre-release.
    expect(parseVersion("1.0.0+build-7")?.prerelease).toEqual([]);
    expect(parseVersion("1.0.0-rc.1+build-7")?.prerelease).toEqual(["rc", "1"]);
  });

  it("refuses anything that is not a version rather than guessing", () => {
    for (const text of [
      "",
      "1.2",
      "1.2.3.4",
      "1.2.x",
      "latest",
      "v",
      "1.0.0-",
      "1.0.0-rc..1",
      "1.0.0-rc!",
      "-1.0.0",
    ]) {
      expect(parseVersion(text), text).toBeNull();
    }
  });
});

describe("compareVersionStrings", () => {
  it("calls an identical version equal", () => {
    expect(compareVersionStrings("1.2.3", "1.2.3")).toBe(0);
    expect(compareVersionStrings("v1.2.3", "1.2.3")).toBe(0);
    expect(compareVersionStrings("1.2.3+a", "1.2.3+b")).toBe(0);
    expect(compareVersionStrings("1.0.0-rc.1", "1.0.0-rc.1")).toBe(0);
  });

  it("orders the numeric parts as numbers, not as text", () => {
    expect(compareVersionStrings("0.9.0", "0.10.0")).toBe(-1);
    expect(compareVersionStrings("1.0.0", "2.0.0")).toBe(-1);
    expect(compareVersionStrings("1.1.0", "1.0.9")).toBe(1);
    expect(compareVersionStrings("1.0.2", "1.0.10")).toBe(-1);
  });

  it("ranks a pre-release below the release it leads to (§11.3)", () => {
    expect(compareVersionStrings("1.0.0-rc.1", "1.0.0")).toBe(-1);
    expect(compareVersionStrings("1.0.0", "1.0.0-rc.1")).toBe(1);
  });

  it("orders pre-release identifiers by §11.4", () => {
    // The example ladder from the specification itself.
    const ladder = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];

    for (let i = 0; i + 1 < ladder.length; i += 1) {
      const lower = ladder[i];
      const higher = ladder[i + 1];
      if (lower === undefined || higher === undefined) continue;
      expect(compareVersionStrings(lower, higher), `${lower} < ${higher}`).toBe(-1);
      expect(compareVersionStrings(higher, lower), `${higher} > ${lower}`).toBe(1);
    }
  });

  it("ranks a numeric identifier below an alphanumeric one (§11.4.3)", () => {
    expect(compareVersionStrings("1.0.0-1", "1.0.0-alpha")).toBe(-1);
    expect(compareVersionStrings("1.0.0-2", "1.0.0-11")).toBe(-1);
  });

  it("gives no answer when either side is not a version", () => {
    expect(compareVersionStrings("nightly", "1.0.0")).toBeNull();
    expect(compareVersionStrings("1.0.0", "")).toBeNull();
  });
});

describe("formatVersion", () => {
  it("renders a version back without the tag's v", () => {
    const parsed = parseVersion("v1.0.0-rc.2");
    expect(parsed).not.toBeNull();
    if (parsed === null) return;
    expect(formatVersion(parsed)).toBe("1.0.0-rc.2");
  });
});

describe("pickUpdate", () => {
  it("offers the newest release above the running one", () => {
    const verdict = pickUpdate("0.1.0", [
      release("v0.3.0"),
      release("v0.2.0"),
      release("v0.1.0"),
    ]);

    expect(verdict.kind).toBe("update");
    if (verdict.kind !== "update") return;
    expect(verdict.release.tag).toBe("v0.3.0");
    expect(verdict.version).toBe("0.3.0");
  });

  it("does not care what order the list arrives in", () => {
    const verdict = pickUpdate("0.1.0", [
      release("v0.2.0"),
      release("v0.10.0"),
      release("v0.9.0"),
    ]);

    expect(verdict.kind === "update" && verdict.release.tag).toBe("v0.10.0");
  });

  it("says you are current when nothing published is newer", () => {
    const verdict = pickUpdate("1.0.0", [release("v1.0.0"), release("v0.9.0")]);
    expect(verdict).toEqual({ kind: "current", version: "1.0.0" });
  });

  it("tells an empty release list apart from being up to date", () => {
    expect(pickUpdate("1.0.0", [])).toEqual({ kind: "none", version: "1.0.0" });
  });

  it("ignores a pre-release when the running build is not one", () => {
    const verdict = pickUpdate("1.0.0", [release("v1.1.0-rc.1", true), release("v1.0.0")]);
    expect(verdict).toEqual({ kind: "current", version: "1.0.0" });
  });

  it("offers a pre-release to somebody already running one", () => {
    const verdict = pickUpdate("1.1.0-rc.1", [
      release("v1.1.0-rc.2", true),
      release("v1.0.0"),
    ]);

    expect(verdict.kind === "update" && verdict.release.tag).toBe("v1.1.0-rc.2");
  });

  it("still offers the finished release to somebody on a candidate for it", () => {
    const verdict = pickUpdate("1.0.0-rc.1", [release("v1.0.0"), release("v1.0.0-rc.1", true)]);
    expect(verdict.kind === "update" && verdict.release.tag).toBe("v1.0.0");
  });

  it("treats a pre-release tag as one even when the flag says otherwise", () => {
    // A release tagged `-rc.1` but not marked pre-release on GitHub. The
    // cautious reading wins: it is still a candidate, not a release.
    const verdict = pickUpdate("1.0.0", [release("v1.1.0-rc.1", false)]);
    expect(verdict).toEqual({ kind: "current", version: "1.0.0" });
  });

  it("skips a release whose tag is not a version instead of ranking it", () => {
    const verdict = pickUpdate("1.0.0", [release("nightly"), release("v1.1.0")]);
    expect(verdict.kind === "update" && verdict.release.tag).toBe("v1.1.0");
  });

  it("refuses to compare when this build's own version is unreadable", () => {
    expect(pickUpdate("dev", [release("v9.9.9")])).toEqual({
      kind: "unknown",
      version: "dev",
    });
  });
});
