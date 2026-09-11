/**
 * Semantic version comparison, and the one decision the update check makes.
 *
 * This is pure and separate from the screen for one reason: "is this release
 * newer than the one I am running" is the whole feature, and getting it wrong
 * is invisible. A string comparison would call `0.10.0` older than `0.9.0`; a
 * numeric-only one would offer `1.0.0-rc.1` to somebody on `1.0.0`. Both are
 * silent, both are wrong, and both are only caught by a test — so the rules
 * live here where `version.test.ts` can hold them to SemVer 2.0.0 §11.
 *
 * The core deliberately does not do this. It fetches the release list and says
 * which build is running; what counts as newer is a product decision, and it
 * belongs where it can be read and tested rather than inside a network call.
 */

import type { UpdateRelease } from "@/lib/ipc";

/** A version parsed into the parts SemVer orders it by. */
export interface SemanticVersion {
  major: number;
  minor: number;
  patch: number;
  /**
   * The dot-separated pre-release identifiers, empty for a normal release.
   * `1.0.0-rc.1` is `["rc", "1"]`.
   */
  prerelease: string[];
}

/** Numeric identifiers are compared as numbers; anything else as ASCII. */
const NUMERIC = /^[0-9]+$/;

/** SemVer 2.0.0 §9: a pre-release identifier is alphanumerics and hyphens. */
const IDENTIFIER = /^[0-9A-Za-z-]+$/;

/**
 * Parses a version, or returns `null` when it is not one.
 *
 * A leading `v` is accepted because that is how the tags are written. Build
 * metadata after `+` is dropped, because SemVer §10 says it takes no part in
 * ordering — two builds of one version are the same version.
 *
 * `null` rather than a fallback on purpose: a tag nobody can parse must not be
 * silently treated as `0.0.0`, which would make every release look newer than
 * it.
 */
export function parseVersion(text: string): SemanticVersion | null {
  const trimmed = text.trim();
  const withoutPrefix =
    trimmed.startsWith("v") || trimmed.startsWith("V") ? trimmed.slice(1) : trimmed;

  // Build metadata first: it may itself contain a hyphen, so splitting on `-`
  // before dropping it would mistake `1.0.0+build-7` for a pre-release.
  const withoutBuild = withoutPrefix.split("+", 1)[0] ?? "";

  const hyphen = withoutBuild.indexOf("-");
  const core = hyphen === -1 ? withoutBuild : withoutBuild.slice(0, hyphen);
  const prereleaseText = hyphen === -1 ? "" : withoutBuild.slice(hyphen + 1);

  const parts = core.split(".");
  if (parts.length !== 3) return null;

  const numbers: number[] = [];
  for (const part of parts) {
    if (!NUMERIC.test(part)) return null;
    const value = Number(part);
    if (!Number.isSafeInteger(value)) return null;
    numbers.push(value);
  }

  const [major, minor, patch] = numbers;
  if (major === undefined || minor === undefined || patch === undefined) return null;

  let prerelease: string[] = [];
  if (hyphen !== -1) {
    prerelease = prereleaseText.split(".");
    // An empty identifier — `1.0.0-` or `1.0.0-rc..1` — is not a version.
    if (prerelease.some((identifier) => !IDENTIFIER.test(identifier))) return null;
  }

  return { major, minor, patch, prerelease };
}

/** Orders two identifier lists by SemVer 2.0.0 §11.4. */
function comparePrerelease(a: string[], b: string[]): number {
  // §11.3: a version with a pre-release is *lower* than the same version
  // without one. This is the rule that keeps `1.0.0-rc.1` from being offered
  // to somebody already on `1.0.0`.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  const shared = Math.min(a.length, b.length);
  for (let i = 0; i < shared; i += 1) {
    const left = a[i];
    const right = b[i];
    if (left === undefined || right === undefined) break;
    if (left === right) continue;

    const leftNumeric = NUMERIC.test(left);
    const rightNumeric = NUMERIC.test(right);

    // §11.4.3: numeric identifiers always rank lower than alphanumeric ones.
    if (leftNumeric && !rightNumeric) return -1;
    if (!leftNumeric && rightNumeric) return 1;

    if (leftNumeric && rightNumeric) {
      return Number(left) < Number(right) ? -1 : 1;
    }
    // ASCII order, not the locale's: `localeCompare` would sort by whatever
    // the user's collation says, which is not what SemVer specifies.
    return left < right ? -1 : 1;
  }

  // §11.4.4: everything shared is equal, so the larger set of identifiers wins.
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

/**
 * Orders two parsed versions: `-1`, `0` or `1`.
 *
 * Equal is a real answer and is returned as `0`. The screen needs it: "you are
 * running the newest release" is a different sentence from "there is a newer
 * one", and collapsing them into a boolean loses the one people check for.
 */
export function compareVersions(a: SemanticVersion, b: SemanticVersion): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return comparePrerelease(a.prerelease, b.prerelease);
}

/** Compares two version strings, or returns `null` if either is not one. */
export function compareVersionStrings(a: string, b: string): number | null {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left === null || right === null) return null;
  return compareVersions(left, right);
}

/**
 * What the check concluded.
 *
 * Four outcomes rather than a nullable release, because they need four
 * different sentences. "Nothing has been published" is not "you are up to
 * date", and neither is "this build's own version is unreadable".
 */
export type UpdateVerdict =
  | { kind: "current"; version: string }
  | { kind: "update"; release: UpdateRelease; version: string }
  | { kind: "none"; version: string }
  | { kind: "unknown"; version: string };

/**
 * Picks the release to offer, if any.
 *
 * Pre-releases are ignored unless the running build is itself a pre-release.
 * Somebody on a release candidate has already said they want them; somebody on
 * `0.2.0` has not, and offering them a `1.0.0-rc.1` — which SemVer ranks
 * *below* `1.0.0` — would push them onto a build the project has not finished.
 *
 * Both signals are honoured: GitHub's own pre-release flag, and a pre-release
 * part in the tag. A release marked one way and tagged the other is treated as
 * a pre-release, because the cautious reading is the safe one here.
 */
export function pickUpdate(currentVersion: string, releases: UpdateRelease[]): UpdateVerdict {
  const current = parseVersion(currentVersion);
  if (current === null) return { kind: "unknown", version: currentVersion };
  if (releases.length === 0) return { kind: "none", version: currentVersion };

  const wantsPrereleases = current.prerelease.length > 0;

  let best: { release: UpdateRelease; version: SemanticVersion } | null = null;

  for (const release of releases) {
    const parsed = parseVersion(release.tag);
    if (parsed === null) continue;

    const isPrerelease = release.prerelease || parsed.prerelease.length > 0;
    if (isPrerelease && !wantsPrereleases) continue;

    if (compareVersions(parsed, current) <= 0) continue;
    if (best !== null && compareVersions(parsed, best.version) <= 0) continue;

    best = { release, version: parsed };
  }

  if (best === null) return { kind: "current", version: currentVersion };
  return { kind: "update", release: best.release, version: formatVersion(best.version) };
}

/** Renders a parsed version back, without the tag's `v`. */
export function formatVersion(version: SemanticVersion): string {
  const core = `${version.major}.${version.minor}.${version.patch}`;
  return version.prerelease.length === 0 ? core : `${core}-${version.prerelease.join(".")}`;
}
