#!/usr/bin/env bash
#
# Refuse a source file containing a raw control byte.
#
# This is not tidiness. A literal NUL in a .tsx file makes GNU grep classify the
# whole file as binary and skip it *silently* -- so every security scan over the
# tree stops covering it, and nothing says so. It happened once: a tag separator
# was written as a raw control character instead of a backslash-u escape, and
# one file quietly dropped out of every audit until a reviewer noticed file(1)
# calling it "data".
#
# Escape sequences are fine; it is the raw byte that breaks the tooling.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

bad=0
while IFS= read -r -d "" file; do
  # Tab, LF and CR are legitimate; every other byte below 0x20 is not.
  if LC_ALL=C grep -qP "[\x00-\x08\x0B\x0C\x0E-\x1F]" "$file" 2>/dev/null; then
    printf "control byte in source: %s\n" "${file#./}"
    LC_ALL=C grep -cP "[\x00-\x08\x0B\x0C\x0E-\x1F]" "$file" 2>/dev/null |
      sed "s/^/    occurrences: /"
    bad=1
  fi
done < <(find . \
  \( -name .git -o -name target -o -name node_modules -o -name dist -o -name fuzz \) -prune -o \
  -type f \( -name "*.rs" -o -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.css" \
             -o -name "*.json" -o -name "*.toml" -o -name "*.md" -o -name "*.sql" -o -name "*.yml" \) \
  -print0)

if [[ "$bad" == "1" ]]; then
  echo
  echo "Write the character as an escape sequence instead, so the file stays text"
  echo "and grep keeps scanning it."
  exit 1
fi

echo "No control bytes in source. grep can read every file."
