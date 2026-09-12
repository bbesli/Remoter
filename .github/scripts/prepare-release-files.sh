#!/usr/bin/env bash
#
# Turn whatever actions/download-artifact left behind into the exact set of
# files attached to the release, plus a SHA256SUMS.txt that actually verifies
# them.
#
# The checksum file is the only integrity story an unsigned release has, and the
# names in it are load-bearing. The release notes tell a user to run
#
#     sha256sum -c SHA256SUMS.txt --ignore-missing
#
# in the directory they downloaded into. `--ignore-missing` skips every line
# whose file is not there, so a name carrying a directory prefix the user does
# not have -- `deb/Remoter_0.1.0_amd64.deb` rather than
# `Remoter_0.1.0_amd64.deb` -- is a line that is never checked. Measured, with
# GNU coreutils 9.11: a file where *every* name is prefixed fails loudly
# ("SHA256SUMS.txt: no file was verified", exit 1), which is the documented
# command being broken for every user; a file where only *some* names are
# prefixed exits 0 having verified the rest, and says nothing about the ones it
# skipped. That second shape is the one worth refusing to publish -- a check
# that passes while covering part of what it names is how a person ends up
# confident about an installer for a credential manager that nothing looked at.
#
# So this script does three things in order, and refuses to continue at each:
#
#   1. flattens, because the layout of a downloaded artifact is a property of
#      actions/upload-artifact rather than of anything in this repository, and
#      the release must not depend on getting that right;
#   2. asserts that what it is about to hash is a non-empty set of plain files;
#   3. asserts the names it wrote are bare, and verifies its own output before
#      handing it to anybody.
#
# Input:
#
#   DIST  the directory download-artifact wrote into. Modified in place; what
#         is in it afterwards is what is attached to the release.
set -euo pipefail

: "${DIST:?DIST is not set}"

SUMS="SHA256SUMS.txt"

fail() {
  echo "::error::$*" >&2
  exit 1
}

[ -d "$DIST" ] || fail "no directory at $DIST; download-artifact wrote nothing"

cd "$DIST"

# ---------------------------------------------------------------- flatten ---
#
# actions/upload-artifact roots each artifact at the least common ancestor of
# its search paths. Six globs under bundle/ therefore arrive as deb/x.deb,
# rpm/x.rpm, ... and one staging directory per artifact is enough to put those
# prefixes into SHA256SUMS.txt. The upload side now stages a single flat
# directory so this should find nothing to move -- and it is here anyway,
# because "should" is what the previous version of this file was built on.
moved=0
while IFS= read -r -d '' found; do
  base="$(basename "$found")"
  if [ -e "./$base" ]; then
    fail "flattening would overwrite $base: two artefacts share a name ($found)"
  fi
  mv -- "$found" "./$base"
  echo "flattened $found -> $base"
  moved=$((moved + 1))
done < <(find . -mindepth 2 -type f -print0)

# Only directories that are empty after the move above. A directory with
# something left in it is a surprise, and the assertion below is what says so.
find . -mindepth 1 -type d -empty -delete

# ------------------------------------------------------------- assertions ---
leftover="$(find . -mindepth 1 -maxdepth 1 ! -type f)"
if [ -n "$leftover" ]; then
  echo "$leftover"
  fail "$DIST still contains something that is not a plain file. sha256sum would exit 1 on it and the release job would die here without saying why."
fi

rm -f -- "./$SUMS"

count="$(find . -mindepth 1 -maxdepth 1 -type f | wc -l | tr -d ' ')"
[ "$count" -gt 0 ] || fail "$DIST is empty; there are no installers to release"

# ---------------------------------------------------------------- hashing ---
#
# `*` rather than `find`, because `sha256sum ./x.deb` writes "./x.deb" into the
# file and the leading ./ is a directory prefix like any other. The glob is safe
# to leave unquoted here precisely because the assertions above proved every
# entry is a plain file, and it is expanded before the redirection creates
# SHA256SUMS.txt, so the file cannot hash itself.
sha256sum -- * > "$SUMS"

# The names must be bare. A postcondition on the flattening above rather than
# something that can fire on its own today -- which is the point: it is what
# fails if a later edit weakens or removes that step, instead of the failure
# being a user's checksum command quietly covering less than it names.
while IFS= read -r line; do
  # sha256sum writes "<hash>  <name>" in text mode and "<hash> *<name>" in
  # binary mode. Strip the hash and whichever separator came with it, and keep
  # everything after it: a filename may legitimately contain spaces.
  name="${line#* }"
  name="${name# }"
  name="${name#\*}"
  case "$name" in
    */*) fail "SHA256SUMS.txt names '$name', which carries a directory prefix. A user running 'sha256sum -c SHA256SUMS.txt --ignore-missing' beside the downloaded file would skip that line and be told nothing is wrong." ;;
  esac
done < "$SUMS"

lines="$(wc -l < "$SUMS" | tr -d ' ')"
[ "$lines" -eq "$count" ] || fail "SHA256SUMS.txt has $lines lines for $count files"

# Verify what is about to be published, in the directory it will be unpacked
# into. If this cannot check its own output, the user's copy of the command
# cannot either.
sha256sum -c "$SUMS"

echo
echo "$count file(s) will be attached, with $SUMS over all of them:"
cat "$SUMS"
