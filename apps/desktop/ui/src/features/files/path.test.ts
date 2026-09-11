/**
 * The path rules, pinned.
 *
 * These are small functions and the temptation is to trust them by reading. The
 * reason not to is that every one of them sits between a name and a command:
 * `validateName` is what stops a slash reaching `sftp_mkdir`, `breadcrumbs` is
 * what keeps the escaped trail in step with the raw one, and a bug in either is
 * invisible on an English machine with ordinary file names.
 */

import { describe, expect, it } from "vitest";

import { breadcrumbs, displayTail, isAbsolute, joinPath, parentPath, validateName } from "./path";

describe("validateName", () => {
  it("accepts an ordinary name", () => {
    expect(validateName("deploy")).toBeNull();
    expect(validateName("2026-03-11.log.gz")).toBeNull();
    // Not English, and not ASCII. A name is not the reader's language and it is
    // not ours either.
    expect(validateName("günlükler")).toBeNull();
    expect(validateName("文件")).toBeNull();
  });

  it("refuses anything that is more than one path component", () => {
    // The whole point: a name with a separator in it turns "create a folder
    // here" into "create a folder somewhere else".
    expect(validateName("a/b")).toBe("separator");
    expect(validateName("../etc")).toBe("separator");
    expect(validateName("/absolute")).toBe("separator");
    // A pasted Windows path, which is what a backslash almost always is.
    expect(validateName("C:\\temp\\x")).toBe("separator");
  });

  it("refuses the two names that mean a directory rather than a file", () => {
    expect(validateName(".")).toBe("dots");
    expect(validateName("..")).toBe("dots");
    // Three is a perfectly ordinary file name.
    expect(validateName("...")).toBeNull();
    // A leading dot is a hidden file, not a refusal.
    expect(validateName(".bashrc")).toBeNull();
  });

  it("refuses control characters", () => {
    // A name a listing row cannot draw honestly is a name this interface will
    // not create, whatever the server would accept.
    expect(validateName("report\u0007")).toBe("control");
    expect(validateName("two\nlines")).toBe("control");
  });

  it("refuses nothing at all", () => {
    expect(validateName("")).toBe("empty");
    expect(validateName("   ")).toBe("empty");
  });
});

describe("joinPath", () => {
  it("puts exactly one separator between the two", () => {
    expect(joinPath("/srv/app", "logs")).toBe("/srv/app/logs");
    expect(joinPath("/srv/app/", "logs")).toBe("/srv/app/logs");
    expect(joinPath("/", "etc")).toBe("/etc");
  });
});

describe("parentPath", () => {
  it("climbs one level", () => {
    expect(parentPath("/srv/app/logs")).toBe("/srv/app");
    expect(parentPath("/srv")).toBe("/");
  });

  it("has nowhere to go from the root", () => {
    // Null rather than "/", so the control that goes up can be disabled and
    // explained rather than looking like it did nothing.
    expect(parentPath("/")).toBeNull();
    expect(parentPath("")).toBeNull();
  });

  it("ignores a trailing separator", () => {
    expect(parentPath("/srv/app/")).toBe("/srv");
  });
});

describe("breadcrumbs", () => {
  it("walks the raw and escaped paths in step", () => {
    const crumbs = breadcrumbs("/srv/app", "/srv/app");
    expect(crumbs.map((c) => c.path)).toEqual(["/srv", "/srv/app"]);
    expect(crumbs.map((c) => c.displayPath)).toEqual(["/srv", "/srv/app"]);
    expect(crumbs.map((c) => c.label)).toEqual(["srv", "app"]);
  });

  it("labels from the escaped form and addresses from the raw one", () => {
    // The folder's real name carries a right-to-left override; the core sent
    // the escaped twin. The trail must draw the escaped one and click through
    // to the raw one, and never the other way round.
    const raw = "/srv/rep\u202Etrop";
    const shown = "/srv/rep\\u{202E}trop";
    const crumbs = breadcrumbs(raw, shown);
    expect(crumbs[1]?.path).toBe(raw);
    expect(crumbs[1]?.label).toBe("rep\\u{202E}trop");
    expect(crumbs[1]?.label).not.toContain("\u202E");
  });

  it("falls back to the raw segment when the two forms disagree in length", () => {
    // Only reachable through an entry carrying `risks.separator`, which is
    // never navigated to — but a mismatch must degrade rather than throw.
    const crumbs = breadcrumbs("/a/b/c", "/a");
    expect(crumbs.map((c) => c.label)).toEqual(["a", "b", "c"]);
  });

  it("has nothing to show at the root", () => {
    expect(breadcrumbs("/", "/")).toEqual([]);
  });
});

describe("displayTail", () => {
  it("takes the last segment", () => {
    expect(displayTail("/srv/app/build.tar.gz")).toBe("build.tar.gz");
    expect(displayTail("/")).toBe("/");
  });
});

describe("isAbsolute", () => {
  it("is the only thing checked about a typed path", () => {
    expect(isAbsolute("/var/log")).toBe(true);
    expect(isAbsolute("var/log")).toBe(false);
    expect(isAbsolute("")).toBe(false);
  });
});
