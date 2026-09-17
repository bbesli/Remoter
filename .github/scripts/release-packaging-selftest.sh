#!/usr/bin/env bash
#
# Run the release workflow's packaging path on this machine, against a fake
# bundle tree, and check that a tag would actually ship installers.
#
# The release workflow cannot be tested by reading it. It ran for the first
# time and produced nothing: `sha256sum -- *` was handed a directory, exited 1
# under `set -e`, and the job died before it uploaded anything. Nothing in the
# repository could have caught that, because the only way to find out what the
# release job does was to cut a tag.
#
# So the two pieces of shell that decide whether a release exists --
# collect-installers.sh and prepare-release-files.sh -- live in files rather
# than inside release.yml, and this runs them. The matrix values they are driven
# by are read out of release.yml itself, not copied here: a test that carries
# its own copy of the thing under test passes after the real one changes.
#
# Covering the scripts is not covering the release. What broke the first tag was
# the wiring between the steps, and a test that only reads os/bundles/expected
# could not have seen it: release.yml might no longer call either script, the
# directory one step fills might not be the path the next one uploads, and the
# bundle path in the matrix might no longer follow from the --target flag the
# build step passes. Section 0 asserts those joins, and section 7b then drives
# the staging and the upload end to end through the workflow's own values rather
# than through constants written here.
#
# The one thing that cannot run here is actions/upload-artifact. Its rooting
# rule is emulated below, and the emulation's credential is the first check in
# this file: fed the *old* six-glob path list, it has to reproduce the exact
# layout that was observed on a real run (deb/x.deb, rpm/x.rpm, ...). An
# emulator that cannot reproduce the known failure is not evidence about the
# fix. Beyond that, prepare-release-files.sh is deliberately made to work under
# either layout, so the release does not rest on this emulation being right.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

passed=0
failed=0

ok() {
  passed=$((passed + 1))
  printf '  ok    %s\n' "$1"
}

bad() {
  failed=$((failed + 1))
  printf '  FAIL  %s\n' "$1"
}

check() {
  # check <description> <expected> <actual>
  if [ "$2" = "$3" ]; then
    ok "$1"
  else
    bad "$1"
    printf '          expected: %s\n' "$2"
    printf '          actual:   %s\n' "$3"
  fi
}

contains() {
  # contains <description> <needle> <haystack>
  case "$3" in
    *"$2"*) ok "$1" ;;
    *)
      bad "$1"
      printf '          looked for: %s\n' "$2"
      printf '          in: %s\n' "$3"
      ;;
  esac
}

exists() {
  # exists <path> -> "1" or "0", so a missing file is a failed check with a
  # readable expected/actual rather than a `set -e` abort three lines later.
  if [ -f "$1" ]; then echo 1; else echo 0; fi
}

section() { printf '\n%s\n' "$1"; }

# ---------------------------------------------------------------------------
# The matrix, read out of release.yml.
# ---------------------------------------------------------------------------
read_matrix() {
  python3 - "$REPO/.github/workflows/release.yml" <<'PY'
import re, sys, pathlib

# A deliberately small parser rather than PyYAML, which is not guaranteed to be
# importable on a runner. It reads exactly the three keys this test drives, and
# it is written to fail rather than to cope: if release.yml stops having the
# shape below, this test must stop claiming to have checked it.
text = pathlib.Path(sys.argv[1]).read_text()
entries, current = [], None
for line in text.splitlines():
    if re.match(r"^\s*#", line):
        continue
    m = re.match(r"^\s*-\s+os:\s*(\S+)\s*$", line)
    if m:
        current = {"os": m.group(1)}
        entries.append(current)
        continue
    m = re.match(r"^\s+(name|bundles|expected|target):\s*(.+?)\s*$", line)
    if m and current is not None:
        # The first of each key only. Later jobs and steps have `name:` lines
        # of their own, and the last matrix row would otherwise take one.
        current.setdefault(m.group(1), m.group(2))

if len(entries) != 4:
    sys.exit(f"::error::expected 4 matrix entries in release.yml, parsed {len(entries)}")
names = [e.get("name") for e in entries]
if len(set(names)) != len(names):
    sys.exit("::error::two matrix entries in release.yml share a name, so their artifacts would collide")
for e in entries:
    for key in ("name", "bundles", "expected"):
        if key not in e:
            sys.exit(f"::error::matrix entry {e['os']} has no '{key}'")
    # The target last: it is the one column that may be empty, and `read`
    # collapses runs of a whitespace IFS, so an empty column in the middle
    # would shift every one after it.
    print("\t".join([e["os"], e["bundles"], e["expected"], e["name"], e.get("target", "")]))
PY
}

# ---------------------------------------------------------------------------
# The wiring between the steps, read out of release.yml.
#
# Reading os/bundles/expected out of the matrix says what the scripts are given.
# It says nothing about whether release.yml still calls them, or whether the
# directory one step fills is the directory the next one reads -- and that
# second question is the one the first release got wrong. So the values below
# are the joins: which script each step invokes, the staging directory against
# the uploaded path, the downloaded path against the checksum step's input, and
# the build command that decides which of the two shapes the bundle path takes.
# ---------------------------------------------------------------------------
read_wiring() {
  python3 - "$REPO/.github/workflows/release.yml" <<'PY'
import re, sys, pathlib

# The same small deliberately-brittle parser as read_matrix, for the same
# reason: if release.yml stops having this shape, the parse must fail rather
# than report that everything is still wired together.
text = pathlib.Path(sys.argv[1]).read_text()
# Comments first. Several of them talk about upload-artifact, STAGE and the
# --target flag, and a parser that reads prose is a parser that passes when
# only the prose is left.
lines = [l for l in text.splitlines() if not re.match(r"^\s*#", l)]

# Six spaces and a dash is the one indentation a step is written at in this
# file. A step runs to the next step, or to the first non-blank line indented
# less than its own keys.
blocks, current = [], None
for line in lines:
    if re.match(r"^      - ", line):
        if current is not None:
            blocks.append("\n".join(current))
        current = [line]
    elif current is not None:
        if line.strip() and not line.startswith("       "):
            blocks.append("\n".join(current))
            current = None
        else:
            current.append(line)
if current is not None:
    blocks.append("\n".join(current))

def only(needle, what):
    hits = [b for b in blocks if needle in b]
    if len(hits) != 1:
        sys.exit(f"::error::expected exactly one step {what} in release.yml, found {len(hits)}")
    return hits[0]

def value(block, key, what):
    m = re.search(r"^\s+" + re.escape(key) + r":\s*(\S.*?)\s*$", block, re.M)
    if not m:
        sys.exit(f"::error::the {what} step in release.yml has no '{key}:' line")
    return m.group(1)

def script_of(block, what):
    m = re.search(r"run:\s*bash\s+(\S+\.sh)\s*$", block, re.M)
    if not m:
        sys.exit(f"::error::the {what} step in release.yml no longer runs a script as `bash <path>`")
    return m.group(1)

collect = only("collect-installers.sh", "invoking collect-installers.sh")
prepare = only("prepare-release-files.sh", "invoking prepare-release-files.sh")
upload = only("actions/upload-artifact", "uploading the staged installers")
download = only("actions/download-artifact", "downloading them again")
gh_release = only("action-gh-release", "creating the draft release")
build = only("tauri.js build", "building the bundles")

for key, val in {
    "collect_script": script_of(collect, "installer check"),
    "prepare_script": script_of(prepare, "checksum"),
    "collect_shell": value(collect, "shell", "installer check"),
    "collect_bundles": value(collect, "BUNDLES", "installer check"),
    "collect_expected": value(collect, "EXPECTED", "installer check"),
    "stage": value(collect, "STAGE", "installer check"),
    "upload_path": value(upload, "path", "upload"),
    "upload_name": value(upload, "name", "upload"),
    "upload_if_no_files": value(upload, "if-no-files-found", "upload"),
    "dist": value(prepare, "DIST", "checksum"),
    "download_path": value(download, "path", "download"),
    "release_files": value(gh_release, "files", "draft release"),
    "release_unmatched": value(gh_release, "fail_on_unmatched_files", "draft release"),
    "build_run": value(build, "run", "build"),
}.items():
    print(key, val, sep="\t")
PY
}

# ---------------------------------------------------------------------------
# actions/upload-artifact@v4's rooting rule, and the download side.
# ---------------------------------------------------------------------------
artifact_entries() {
  # artifact_entries <root of fake workspace> <path pattern>...
  python3 - "$@" <<'PY'
import os, sys, glob as globmod

# Faithful to actions/upload-artifact v4 + @actions/glob:
#   * each pattern's "search path" is the prefix before the first segment
#     containing a glob character;
#   * more than one search path -> the artifact is rooted at their least
#     common ancestor;
#   * exactly one -> rooted at that search path (or its parent, when the
#     pattern named a single file outright).
# Entry names are the matched files relative to that root, which is what ends
# up inside the artifact and therefore what download-artifact unpacks.
workspace, patterns = sys.argv[1], sys.argv[2:]

def search_path(pattern):
    parts, out = pattern.split("/"), []
    for part in parts:
        if any(c in part for c in "*?[") :
            break
        out.append(part)
    return "/".join(out)

search_paths, results = [], []
for pattern in patterns:
    sp = search_path(pattern)
    if sp not in search_paths:
        search_paths.append(sp)
    for hit in sorted(globmod.glob(os.path.join(workspace, pattern), recursive=True)):
        if os.path.isdir(hit):
            for base, _, files in os.walk(hit):
                results.extend(sorted(os.path.join(base, f) for f in files))
        else:
            results.append(hit)

if len(search_paths) > 1:
    segments = [p.split("/") for p in search_paths]
    common = []
    for i in range(min(len(s) for s in segments)):
        seg = segments[0][i]
        if all(s[i] == seg for s in segments):
            common.append(seg)
        else:
            break
    root = "/".join(common)
else:
    root = search_paths[0]
    absolute = os.path.join(workspace, root)
    if len(results) == 1 and results[0] == absolute:
        root = os.path.dirname(root)

for r in sorted(set(results)):
    print(os.path.relpath(r, os.path.join(workspace, root)))
PY
}

download_merge() {
  # download_merge <destination> <workspace> <root-relative entry>...
  local dest="$1" workspace="$2" root="$3"
  shift 3
  local entry
  for entry in "$@"; do
    mkdir -p "$dest/$(dirname "$entry")"
    cp -p "$workspace/$root/$entry" "$dest/$entry"
  done
}

# ---------------------------------------------------------------------------
# A fake bundle tree, shaped like the one tauri-bundler leaves behind --
# including the staging directories that made the old entry-counting check
# vacuous.
# ---------------------------------------------------------------------------
fake_bundles() {
  # fake_bundles <workspace> <bundles path> <platform> [--no-deb]
  local ws="$1" bundles="$2" platform="$3" skip="${4:-}"
  local dir="$ws/$bundles"
  case "$platform" in
    linux)
      mkdir -p "$dir/deb/remoter_0.1.0_amd64/DEBIAN" "$dir/rpm" \
               "$dir/appimage/remoter.AppDir/usr/bin"
      echo "staging" > "$dir/deb/remoter_0.1.0_amd64/DEBIAN/control"
      echo "appdir" > "$dir/appimage/remoter.AppDir/usr/bin/remoter"
      [ "$skip" = "--no-deb" ] || echo "deb payload" > "$dir/deb/remoter_0.1.0_amd64.deb"
      echo "rpm payload" > "$dir/rpm/remoter-0.1.0-1.x86_64.rpm"
      echo "appimage payload" > "$dir/appimage/remoter_0.1.0_amd64.AppImage"
      ;;
    windows-x64)
      mkdir -p "$dir/msi" "$dir/nsis"
      echo "msi payload" > "$dir/msi/Remoter_0.1.0_x64_en-US.msi"
      echo "nsis payload" > "$dir/nsis/Remoter_0.1.0_x64-setup.exe"
      ;;
    windows-x86)
      mkdir -p "$dir/msi" "$dir/nsis"
      echo "msi x86 payload" > "$dir/msi/Remoter_0.1.0_x86_en-US.msi"
      echo "nsis x86 payload" > "$dir/nsis/Remoter_0.1.0_x86-setup.exe"
      ;;
    macos)
      mkdir -p "$dir/dmg" "$dir/macos/Remoter.app/Contents/MacOS"
      echo "dmg payload" > "$dir/dmg/Remoter_0.1.0_universal.dmg"
      echo "mach-o" > "$dir/macos/Remoter.app/Contents/MacOS/remoter"
      ;;
  esac
}

platform_of() {
  # By the matrix row's name, not its runner label: two rows share
  # windows-latest and build different installers.
  case "$1" in
    linux|windows-x64|windows-x86|macos) echo "$1" ;;
    *) echo "unknown matrix name: $1" >&2; exit 1 ;;
  esac
}

# ===========================================================================
section "The matrix release.yml actually carries"
MATRIX="$(read_matrix)"
echo "$MATRIX" | sed 's/^/  /'
matrix_rows="$(echo "$MATRIX" | wc -l | tr -d ' ')"
check "release.yml describes four builds" "4" "$matrix_rows"

# ===========================================================================
section "0. release.yml still invokes these scripts, and hands each to the next"
WIRING="$(read_wiring)"
echo "$WIRING" | sed 's/^/  /'

field() { printf '%s\n' "$WIRING" | awk -F'\t' -v k="$1" '$1 == k { print $2 }'; }

# The two scripts under test are the ones release.yml names, resolved here and
# used by every section below. A test that hard-codes the paths keeps passing
# after the workflow is pointed somewhere else -- which is the same defect as
# the matrix values being copied rather than read.
COLLECT="$REPO/$(field collect_script)"
PREPARE="$REPO/$(field prepare_script)"
check "the bundle job's installer check names a script that exists" "1" "$(exists "$COLLECT")"
check "the release job's checksum step names a script that exists" "1" "$(exists "$PREPARE")"
# windows-latest defaults `run:` to PowerShell, where these bash scripts would
# be run by whatever `bash` resolved to, if anything.
check "the installer check is pinned to bash, for the Windows runner" "bash" "$(field collect_shell)"

# The check reads bundles/expected out of the matrix. That is only evidence
# about the real job if the real job reads them from there too.
contains "the installer check is handed the matrix's bundle path" \
  "matrix.bundles" "$(field collect_bundles)"
contains "...and the matrix's expected artefacts" \
  "matrix.expected" "$(field collect_expected)"

# The join that broke the first release: one step fills a directory, the next
# uploads a path. Nothing in YAML makes those the same string.
check "what the bundle job stages is the path it uploads" \
  "$(field stage)" "$(field upload_path)"
check "an empty staging directory fails the upload rather than passing" \
  "error" "$(field upload_if_no_files)"
contains "each row uploads under its own name, so two rows on one runner do not collide" \
  "matrix.name" "$(field upload_name)"
check "what download-artifact writes is what the checksum step is pointed at" \
  "$(field download_path)" "$(field dist)"
check "the draft release attaches the directory the checksum step prepared" \
  "$(field dist)/*" "$(field release_files)"
check "a glob matching nothing fails the release rather than publishing an empty one" \
  "true" "$(field release_unmatched)"

# The macOS bundle path is a consequence of the --target flag, so the flag has
# to come from the same matrix row the path does.
contains "the build command passes --target" "--target" "$(field build_run)"
contains "...taken from the matrix row, not a hard-coded triple" \
  "matrix.target" "$(field build_run)"
while IFS="$(printf '\t')" read -r os bundles expected name target; do
  [ -n "$os" ] || continue
  : "$expected" "$name"
  if [ -n "$target" ]; then
    # A triple the runner does not have installed builds nothing, and says so
    # only on the tag.
    case "$target" in
      universal-apple-darwin) wanted="aarch64-apple-darwin" ;;
      *) wanted="$target" ;;
    esac
    contains "$os: the workflow installs the $wanted toolchain" \
      "rustup target add" "$(grep -E "rustup target add .*$wanted" "$REPO/.github/workflows/release.yml" || true)"
    check "$os: --target $target, so the bundle is under that triple" \
      "target/$target/release/bundle" "$bundles"
  else
    check "$os: no --target, so the bundle is under target/release" \
      "target/release/bundle" "$bundles"
  fi
done <<EOF
$MATRIX
EOF

# ===========================================================================
section "1. The emulator reproduces the layout a real run produced"
# The six globs release.yml used to hand to upload-artifact, verbatim.
WS1="$WORK/ws1"
fake_bundles "$WS1" "target/release/bundle" linux
old_entries="$(artifact_entries "$WS1" \
  'target/release/bundle/deb/*.deb' \
  'target/release/bundle/rpm/*.rpm' \
  'target/release/bundle/appimage/*.AppImage' \
  'target/release/bundle/msi/*.msi' \
  'target/release/bundle/nsis/*.exe' \
  'target/release/bundle/dmg/*.dmg' | tr '\n' ' ')"
check "six globs root the artifact at bundle/, so entries keep their subdirectory" \
  "appimage/remoter_0.1.0_amd64.AppImage deb/remoter_0.1.0_amd64.deb rpm/remoter-0.1.0-1.x86_64.rpm " \
  "$old_entries"

# ===========================================================================
section "2. The old release-job shell, on that layout, produces no release"
OLD_DIST="$WORK/old-dist"
mkdir -p "$OLD_DIST"
download_merge "$OLD_DIST" "$WS1" "target/release/bundle" \
  deb/remoter_0.1.0_amd64.deb rpm/remoter-0.1.0-1.x86_64.rpm \
  appimage/remoter_0.1.0_amd64.AppImage
# The step as release.yml carried it: `working-directory: dist`, `set -euo
# pipefail`, `sha256sum -- *`. Run in its own bash so its `set -e` belongs to
# it and not to this file.
old_rc=0
(cd "$OLD_DIST" && bash -c 'set -euo pipefail
sha256sum -- * > SHA256SUMS.txt
cat SHA256SUMS.txt') > "$WORK/old-checksum.log" 2>&1 || old_rc=$?
check "the old Checksums step exits non-zero on the layout that arrived" "1" "$old_rc"
contains "...because it was handed a directory" "Is a directory" "$(cat "$WORK/old-checksum.log")"
check "...so no release asset was ever produced" "0" \
  "$(find "$OLD_DIST" -maxdepth 1 -name SHA256SUMS.txt -size +0 | wc -l | tr -d ' ')"

# ===========================================================================
section "3. The old bundle check passed while the .deb was missing"
WS3="$WORK/ws3"
fake_bundles "$WS3" "target/release/bundle" linux --no-deb
# The check release.yml used to run, verbatim in shape: count entries in the
# directory. tauri's staging tree is one entry, so it scores 1 and passes.
old_count="$(find "$WS3/target/release/bundle/deb" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')"
check "a deb/ holding only tauri's staging directory counts as one entry" "1" "$old_count"
debs="$(find "$WS3/target/release/bundle/deb" -mindepth 1 -maxdepth 1 -name '*.deb' | wc -l | tr -d ' ')"
check "...while holding no .deb at all" "0" "$debs"

# ===========================================================================
section "4. The new bundle check fails, and names what is absent"
set +e
missing_output="$(BUNDLES="$WS3/target/release/bundle" \
  EXPECTED='deb/*.deb rpm/*.rpm appimage/*.AppImage' \
  STAGE="$WORK/stage-missing" \
  RUNNER_OS=Linux \
  bash "$COLLECT" 2>&1)"
missing_rc=$?
set -e
check "collect-installers.sh exits non-zero on a missing .deb" "1" "$missing_rc"
contains "it names the glob that matched nothing" "deb/*.deb" "$missing_output"
contains "it says which platform owes it" "Linux produced no artefact" "$missing_output"

# ===========================================================================
section "5. A bundle directory that does not exist at all is a separate error"
set +e
nodir_output="$(BUNDLES="$WORK/ws3/target/aarch64-apple-darwin/release/bundle" \
  EXPECTED='dmg/*.dmg' STAGE="$WORK/stage-nodir" \
  bash "$COLLECT" 2>&1)"
nodir_rc=$?
set -e
check "collect-installers.sh exits non-zero when the bundle path is wrong" "1" "$nodir_rc"
contains "it points at the --target flag, which is what makes that path wrong" \
  "--target flag" "$nodir_output"

# ===========================================================================
section "6. Every platform stages its installers flat"
WS6="$WORK/ws6"
entries_all=""
while IFS="$(printf '\t')" read -r os bundles expected name target; do
  [ -n "$os" ] || continue
  platform="$(platform_of "$name")"
  fake_bundles "$WS6" "$bundles" "$platform"
  stage="$WORK/stage-$platform"
  collect_rc=0
  BUNDLES="$WS6/$bundles" EXPECTED="$expected" STAGE="$stage" RUNNER_OS="$platform" \
    bash "$COLLECT" > "$WORK/collect-$platform.log" 2>&1 || collect_rc=$?
  if [ "$collect_rc" -ne 0 ]; then
    bad "$name: collect-installers.sh failed on a complete bundle tree"
    sed 's/^/          /' "$WORK/collect-$platform.log"
    continue
  fi
  flat="$(find "$stage" -mindepth 1 ! -type f | wc -l | tr -d ' ')"
  check "$name: the staging directory holds nothing but plain files" "0" "$flat"
  entries_all="$entries_all $(cd "$stage" && ls -1 | tr '\n' ' ')"
  : "$target"
done <<EOF
$MATRIX
EOF

apps="$(find "$WORK"/stage-* -name '*.app' | wc -l | tr -d ' ')"
check "the macOS .app is asserted but does not travel" "0" "$apps"
contains "...and the log says so rather than staying silent" \
  "directory, not attached" "$(cat "$WORK/collect-macos.log")"

# ===========================================================================
section "7. The artifact of a single staged directory has bare entries"
new_entries="$(artifact_entries "$WORK" 'stage-linux' | tr '\n' ' ')"
check "one search path roots the artifact at it, so the names are bare" \
  "remoter-0.1.0-1.x86_64.rpm remoter_0.1.0_amd64.AppImage remoter_0.1.0_amd64.deb " \
  "$(printf '%s\n' $new_entries | LC_ALL=C sort | tr '\n' ' ')"

# ===========================================================================
section "7b. The same, driven end to end by release.yml's own STAGE and path"
# Section 0 asserts the two strings are equal. This asserts what that equality
# is for: stage into the directory the workflow's STAGE names, inside a
# workspace shaped like a runner's, then look through the workflow's own
# upload path. Change one without the other and the artifact comes back empty
# here rather than on a tag.
WS7="$WORK/ws7"
linux_row="$(printf '%s\n' "$MATRIX" | grep '^ubuntu' || true)"
lin_bundles="$(printf '%s' "$linux_row" | cut -f2)"
lin_expected="$(printf '%s' "$linux_row" | cut -f3)"
fake_bundles "$WS7" "$lin_bundles" linux
wired_rc=0
BUNDLES="$WS7/$lin_bundles" EXPECTED="$lin_expected" STAGE="$WS7/$(field stage)" \
  RUNNER_OS=Linux bash "$COLLECT" > "$WORK/collect-wired.log" 2>&1 || wired_rc=$?
check "collect-installers.sh fills release.yml's STAGE from release.yml's matrix" "0" "$wired_rc"
wired_entries="$(artifact_entries "$WS7" "$(field upload_path)" | tr '\n' ' ')"
check "and the workflow's upload path finds exactly those three, unprefixed" \
  "remoter-0.1.0-1.x86_64.rpm remoter_0.1.0_amd64.AppImage remoter_0.1.0_amd64.deb " \
  "$(printf '%s\n' $wired_entries | LC_ALL=C sort | tr '\n' ' ')"

# ===========================================================================
section "8. End to end: four artifacts merged, checksummed, verified"
DIST="$WORK/dist"
mkdir -p "$DIST"
for platform in linux windows-x64 windows-x86 macos; do
  cp -p "$WORK/stage-$platform"/* "$DIST/"
done
DIST="$DIST" bash "$PREPARE" > "$WORK/prepare.log" 2>&1 || {
  cat "$WORK/prepare.log"
  bad "prepare-release-files.sh failed on the flat layout"
}
sums="$DIST/SHA256SUMS.txt"
check "eight installers are attached" "8" "$(find "$DIST" -maxdepth 1 -type f ! -name SHA256SUMS.txt | wc -l | tr -d ' ')"
check "SHA256SUMS.txt has a line for each of them" "8" "$(wc -l < "$sums" | tr -d ' ')"
check "no name in it carries a directory prefix" "0" "$(grep -c '/' "$sums" || true)"
verify_rc=0
(cd "$DIST" && sha256sum -c SHA256SUMS.txt > "$WORK/verify.log" 2>&1) || verify_rc=$?
check "sha256sum -c verifies all eight where they are published" "0" "$verify_rc"

# ===========================================================================
section "9. ...and it copes if the artifacts ever arrive nested again"
NESTED="$WORK/nested"
mkdir -p "$NESTED/deb" "$NESTED/rpm" "$NESTED/appimage" "$NESTED/msi" "$NESTED/nsis" "$NESTED/dmg"
cp -p "$WORK/stage-linux/"*.deb "$NESTED/deb/"
cp -p "$WORK/stage-linux/"*.rpm "$NESTED/rpm/"
cp -p "$WORK/stage-linux/"*.AppImage "$NESTED/appimage/"
cp -p "$WORK/stage-windows-x64/"*.msi "$WORK/stage-windows-x86/"*.msi "$NESTED/msi/"
cp -p "$WORK/stage-windows-x64/"*.exe "$WORK/stage-windows-x86/"*.exe "$NESTED/nsis/"
cp -p "$WORK/stage-macos/"*.dmg "$NESTED/dmg/"
nested_rc=0
DIST="$NESTED" bash "$PREPARE" > "$WORK/nested.log" 2>&1 || nested_rc=$?
check "prepare-release-files.sh survives the old nested layout" "0" "$nested_rc"
check "it leaves nothing but plain files behind" "0" \
  "$(find "$NESTED" -mindepth 1 ! -type f | wc -l | tr -d ' ')"
check "and its names are bare too" "0" "$(grep -c '/' "$NESTED/SHA256SUMS.txt" || true)"

# ===========================================================================
section "10. The command the release notes tell a user to run"
USERDIR="$WORK/downloads"
mkdir -p "$USERDIR"
cp -p "$sums" "$USERDIR/"
# A user downloads the one file for their platform, not all six.
cp -p "$DIST/Remoter_0.1.0_x64-setup.exe" "$USERDIR/"
user_rc=0
user_out="$(cd "$USERDIR" && sha256sum -c SHA256SUMS.txt --ignore-missing 2>&1)" || user_rc=$?
check "sha256sum -c --ignore-missing exits 0 beside one downloaded installer" "0" "$user_rc"
check "...having actually verified it" "1" "$(printf '%s\n' "$user_out" | grep -c ': OK$' || true)"
contains "...and naming it" "Remoter_0.1.0_x64-setup.exe: OK" "$user_out"

# The control that makes the line above mean something: a check that cannot
# fail is not a check.
printf 'tampered' >> "$USERDIR/Remoter_0.1.0_x64-setup.exe"
tamper_rc=0
tamper_out="$(cd "$USERDIR" && sha256sum -c SHA256SUMS.txt --ignore-missing 2>&1)" || tamper_rc=$?
check "a modified installer fails the same command" "1" "$tamper_rc"
contains "...and is named as the one that failed" "Remoter_0.1.0_x64-setup.exe: FAILED" "$tamper_out"

# ===========================================================================
section "11. Why the bare-name assertion exists (measured, not assumed)"
PREFIXED="$WORK/prefixed"
mkdir -p "$PREFIXED"
cp -p "$DIST/Remoter_0.1.0_x64_en-US.msi" "$DIST/Remoter_0.1.0_universal.dmg" "$PREFIXED/"
# Every name prefixed: the documented command breaks for everybody.
sed 's|  |  msi/|' "$sums" > "$PREFIXED/SHA256SUMS.txt"
all_rc=0
all_out="$(cd "$PREFIXED" && sha256sum -c SHA256SUMS.txt --ignore-missing 2>&1)" || all_rc=$?
check "all names prefixed: the user's command exits non-zero" "1" "$all_rc"
contains "...saying nothing was verified" "no file was verified" "$all_out"
# Only some prefixed: exits 0 having silently skipped the rest. This is the
# shape worth refusing to publish, and what prepare-release-files.sh asserts.
{
  grep 'universal.dmg' "$sums"
  grep 'x64_en-US.msi' "$sums" | sed 's|  |  msi/|'
} > "$PREFIXED/SHA256SUMS.txt"
mixed_rc=0
mixed_out="$(cd "$PREFIXED" && sha256sum -c SHA256SUMS.txt --ignore-missing 2>&1)" || mixed_rc=$?
check "some names prefixed: the user's command exits 0" "0" "$mixed_rc"
check "...having checked one of the two files it lists" "1" \
  "$(printf '%s\n' "$mixed_out" | grep -c ': OK$' || true)"

# ===========================================================================
section "12. prepare-release-files.sh fails loudly rather than publishing nothing"
BADNAMES="$WORK/badnames"
mkdir -p "$BADNAMES"
cp -p "$DIST/Remoter_0.1.0_universal.dmg" "$BADNAMES/"
bad_rc=0
bad_out="$(DIST="$BADNAMES" bash "$PREPARE" 2>&1)" || bad_rc=$?
check "a flat directory is published normally" "0" "$bad_rc"

# Something that survives flattening because it holds no files at all. This is
# the shape the old step died on, and the assertion has to reach it rather than
# letting sha256sum exit 1 with no explanation.
STUCK="$WORK/stuck"
mkdir -p "$STUCK/deb/remoter_0.1.0_amd64/DEBIAN"
cp -p "$DIST/Remoter_0.1.0_universal.dmg" "$STUCK/"
ln -s /nonexistent "$STUCK/dangling"
stuck_rc=0
stuck_out="$(DIST="$STUCK" bash "$PREPARE" 2>&1)" || stuck_rc=$?
check "a dist entry that is not a plain file is refused" "1" "$stuck_rc"
contains "...naming what sha256sum would have died on" "is not a plain file" "$stuck_out"

EMPTY="$WORK/empty"
mkdir -p "$EMPTY"
empty_rc=0
empty_out="$(DIST="$EMPTY" bash "$PREPARE" 2>&1)" || empty_rc=$?
check "an empty dist is a failure, not an empty release" "1" "$empty_rc"
contains "...and says so" "no installers to release" "$empty_out"
: "$bad_out"

# ===========================================================================
printf '\n%s\n' "-----------------------------------------------------------"
printf 'release packaging self-test: %d passed, %d failed\n' "$passed" "$failed"
[ "$failed" -eq 0 ] || exit 1
