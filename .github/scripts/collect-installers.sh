#!/usr/bin/env bash
#
# Assert that every installer this platform owes exists, and gather the ones a
# person can download into one flat directory.
#
# Two jobs, deliberately in one script, because they are the same question asked
# twice. `bundle.targets` in tauri.conf.json lists all seven bundle types and
# tauri-bundler silently drops the ones the host cannot produce -- which is what
# lets one config serve three platforms, and also what lets a platform produce
# nothing at all without saying so. So the list of what each platform owes is
# named from outside, and the same list decides what travels.
#
# Counting *entries* in a bundle directory is not this check. `bundle/deb/`
# holds tauri's staging tree as well as the .deb, so a directory with one
# staging folder and no package in it counts as "1 entry" and passes while the
# artefact it exists to protect is missing. What is asserted here is the
# artefact file, by glob.
#
# Flat, because of what happens downstream. actions/upload-artifact roots an
# artifact at the least common ancestor of its search paths: hand it six globs
# under bundle/ and the files arrive on the other side as deb/x.deb,
# rpm/x.rpm, ... The release job then ran `sha256sum -- *` over a directory
# holding nothing but directories, which exits 1 under `set -e`, so the job
# died before it uploaded anything and the tag produced no release at all.
# Survive that and the prefixes land in SHA256SUMS.txt, where they make the
# documented verification command check the wrong names -- see the measurements
# in prepare-release-files.sh. One search path, one flat directory, bare
# filenames.
#
# Inputs, all required, all as environment variables so the workflow can pass
# them through `env:` without any shell quoting crossing the YAML boundary:
#
#   BUNDLES   the bundle directory, e.g. target/release/bundle
#   EXPECTED  space-separated "<subdirectory>/<glob>" specs, e.g.
#             "deb/*.deb rpm/*.rpm appimage/*.AppImage"
#   STAGE     directory to gather the installers into; recreated empty
set -euo pipefail

: "${BUNDLES:?BUNDLES is not set}"
: "${EXPECTED:?EXPECTED is not set}"
: "${STAGE:?STAGE is not set}"

# GitHub's ::error:: prefix is what puts a line in the run summary and on the
# failing step. Locally it is just a prefix, which is why the sentence after it
# has to stand on its own.
fail() {
  echo "::error::$*" >&2
  exit 1
}

rm -rf -- "$STAGE"
mkdir -p -- "$STAGE"

if [ ! -d "$BUNDLES" ]; then
  fail "no bundle directory at $BUNDLES. The build produced nothing, or it produced it somewhere else -- check the --target flag against the path in the matrix."
fi

# EXPECTED is deliberately unquoted below so it word-splits into specs. Without
# `set -f` the shell would also try to expand "deb/*.deb" as a path relative to
# the working directory, and whether that changed the spec would depend on what
# happened to be lying around next to it.
set -f
# shellcheck disable=SC2206  # word splitting is the point
specs=($EXPECTED)
set +f

[ "${#specs[@]}" -gt 0 ] || fail "EXPECTED is empty; there is nothing to check for"

missing=""
staged=0

for spec in "${specs[@]}"; do
  case "$spec" in
    */*) : ;;
    *) fail "malformed spec '$spec'; each entry must be <subdirectory>/<glob>, e.g. deb/*.deb" ;;
  esac
  dir="${spec%%/*}"
  pattern="${spec#*/}"
  found=""

  # `find` rather than a glob: an unmatched glob in bash expands to itself, and
  # the literal string "bundle/deb/*.deb" would then "exist" as a path.
  #
  # The `-d` test is not decoration either. With `find` run over a missing
  # directory inside a command substitution, find exits non-zero, `pipefail`
  # carries that out of the substitution and `set -e` kills the script *there* --
  # before the message naming which bundle is missing, which is the whole reason
  # this file exists.
  if [ -d "$BUNDLES/$dir" ]; then
    found="$(find "$BUNDLES/$dir" -mindepth 1 -maxdepth 1 -name "$pattern")"
  fi

  if [ -z "$found" ]; then
    echo "$BUNDLES/$spec: MISSING"
    missing="$missing $spec"
    continue
  fi

  count=0
  while IFS= read -r artefact; do
    [ -n "$artefact" ] || continue
    count=$((count + 1))
    if [ -f "$artefact" ]; then
      base="$(basename "$artefact")"
      # A name collision would silently drop one installer out of the release.
      if [ -e "$STAGE/$base" ]; then
        fail "two artefacts are both named $base; one would have overwritten the other"
      fi
      cp -p -- "$artefact" "$STAGE/$base"
      staged=$((staged + 1))
      echo "$BUNDLES/$spec -> $base"
    else
      # macOS's .app is a directory. It is asserted because its absence means
      # the macOS build produced nothing, but it does not travel: a release
      # asset is a single file, and the .dmg already contains it.
      echo "$BUNDLES/$spec -> $(basename "$artefact") (directory, not attached)"
    fi
  done <<EOF
$found
EOF
  echo "$BUNDLES/$spec: $count match(es)"
done

if [ -n "$missing" ]; then
  fail "${RUNNER_OS:-this platform} produced no artefact for:$missing -- the bundler dropped a target silently, which is what this check exists to catch"
fi

[ "$staged" -gt 0 ] || fail "every expected artefact was found but none of them is a file, so nothing would be attached to the release"

echo
echo "Staged $staged installer(s) in $STAGE:"
ls -l -- "$STAGE"
