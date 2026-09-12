#!/usr/bin/env bash
#
# Hold the documentation to the two promises it makes about itself.
#
# The specifications in docs/ are cross-referenced heavily, and twice now a
# careful hand-pass has fixed a broken reference and left another one standing
# two files away. A hand-pass is the wrong instrument: it is exhaustive only on
# the day it runs. Both invariants below were established by hand, and both rot
# within a month of nobody looking.
#
#   1. Every relative Markdown link resolves -- including its #fragment, which
#      has to match a real heading, because a link that lands on the right file
#      and the wrong section is the kind of wrong a reader blames themselves for.
#   2. Every feature and architecture document opens with a note saying which
#      part of it ships, and the counts README.md and docs/README.md quote for
#      that are the counts on disk. A number in prose is a number nobody
#      recomputes.
#
# It also asserts that the two index tables -- docs/README.md's map and the ADR
# register -- list every document that exists. That is not decoration: the ADR
# register was found missing ADR-0014 and the map missing verified-apis.md, both
# by this script, within minutes of it first running.
#
# Standalone: ./scripts/check-docs.sh from anywhere, no arguments, no network.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

# A checker that cannot run must say so rather than exit 0. The whole point of
# this file is that a green tick means something.
if ! command -v python3 >/dev/null 2>&1; then
  echo "check-docs: python3 is required and was not found; the documentation checks did not run" >&2
  exit 1
fi

python3 - "$REPO" <<'PYTHON'
# Annotations are never evaluated, so `str | None` and `list[str]` below read
# the modern way while the file still runs on the older python3 a distribution
# or a CI image might hand it.
from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(sys.argv[1])
SKIP_DIRS = {"node_modules", "target", ".git", "dist", "build"}

problems: list[str] = []


def report(message: str) -> None:
    problems.append(message)


def rel(path: pathlib.Path) -> str:
    # A link can point outside the checkout -- "../../elsewhere.md" in an index
    # table, say. That is a problem to report, not a traceback to debug, so the
    # absolute path is printed rather than raising.
    try:
        return str(path.relative_to(REPO))
    except ValueError:
        return str(path)


def markdown_files() -> list[pathlib.Path]:
    return sorted(
        p
        for p in REPO.rglob("*.md")
        if not any(part in SKIP_DIRS for part in p.relative_to(REPO).parts)
    )


def strip_code(text: str) -> str:
    """Blank out fenced code blocks, preserving line numbering.

    A fenced block is illustrative: the `# Heading` in a shell example is not a
    heading, and the [text](path) in a Markdown example is not a link that has
    to resolve. Lines are replaced rather than removed so that any line number
    this script prints still matches the file.
    """
    out = []
    fence = None
    for line in text.split("\n"):
        opener = re.match(r"^\s*(`{3,}|~{3,})", line)
        if fence is None:
            if opener:
                fence = opener.group(1)[0]
                out.append("")
                continue
            out.append(line)
            continue
        if opener and opener.group(1)[0] == fence:
            fence = None
        out.append("")
    return "\n".join(out)


def slug(heading: str) -> str:
    """GitHub's heading anchor, which is what every #fragment here is written against.

    Rendered text first (links reduced to their text, emphasis and code markers
    dropped), then lowercase, then everything that is not a letter, digit,
    space, hyphen or underscore is deleted, then spaces become hyphens. Emoji
    and em dashes fall out at the deletion step without taking the spaces
    around them with it, which is why a heading reading "Tests -- not built"
    anchors as "tests---not-built" and not as "tests-not-built".
    """
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"!?\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\([^)]*\)", r"\1", text)
    text = text.replace("`", "")
    text = re.sub(r"[*_~]", "", text)
    text = text.strip().lower()
    text = "".join(c for c in text if c.isalnum() or c in " -_")
    return text.replace(" ", "-")


_anchor_cache: dict[pathlib.Path, set[str]] = {}


def anchors(path: pathlib.Path) -> set[str]:
    if path in _anchor_cache:
        return _anchor_cache[path]
    raw = path.read_text(encoding="utf-8")
    found: set[str] = set()
    seen: dict[str, int] = {}
    for line in strip_code(raw).split("\n"):
        heading = re.match(r"^(#{1,6})\s+(.*?)\s*#*\s*$", line)
        if not heading:
            continue
        base = slug(heading.group(2))
        if not base:
            continue
        count = seen.get(base, 0)
        seen[base] = count + 1
        found.add(base if count == 0 else f"{base}-{count}")
    # An explicit <a name> or <a id> is a legitimate target too, and unlike a
    # heading it survives a rewording of the section it sits in.
    for explicit in re.finditer(r'<a\s+(?:name|id)="([^"]+)"', raw):
        found.add(explicit.group(1))
    _anchor_cache[path] = found
    return found


LINK = re.compile(r"(?<!\!)\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\(<?([^)\s>]+)>?\)")
REFERENCE = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*<?(\S+?)>?\s*$", re.M)
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|//)", re.I)


def links_in(path: pathlib.Path) -> list[tuple[str, str]]:
    """(target, as-written) for every inline and reference-style link in a file."""
    text = strip_code(path.read_text(encoding="utf-8"))
    found = [(m.group(2), m.group(0)) for m in LINK.finditer(text)]
    found += [(m.group(2), m.group(0).strip()) for m in REFERENCE.finditer(text)]
    return found


def check_links() -> int:
    checked = 0
    for path in markdown_files():
        for target, written in links_in(path):
            if EXTERNAL.match(target):
                continue
            checked += 1
            location, _, fragment = target.partition("#")
            if location:
                destination = (path.parent / location).resolve()
                if not destination.exists():
                    report(f"{rel(path)}: {written} -- no such file: {location}")
                    continue
            else:
                destination = path
            if not fragment:
                continue
            if destination.is_dir():
                report(f"{rel(path)}: {written} -- a directory has no #fragment")
            elif destination.suffix != ".md":
                report(f"{rel(path)}: {written} -- #fragment on a non-Markdown file")
            elif fragment not in anchors(destination):
                where = location or "this file"
                report(f"{rel(path)}: {written} -- no heading in {where} anchors as '{fragment}'")
    return checked


def opening_note(path: pathlib.Path) -> str | None:
    """The blockquote a document opens with, before its first '## ' section.

    The convention is a bold lead-in -- "**What ships.**", "**Status: designed,
    not built.**" -- so the test is a blockquote line beginning with '> **'.
    Deliberately looser than matching those two exact phrases: the next
    document to need one may need to say something neither of them says.
    """
    for line in path.read_text(encoding="utf-8").split("\n"):
        if line.startswith("## "):
            return None
        if line.startswith("> **"):
            return line
    return None


NUMBER_WORDS = {
    word: value
    for value, word in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve "
        "thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty "
        "twenty-one twenty-two twenty-three twenty-four twenty-five".split(),
    )
}


def quoted_number(path: pathlib.Path, pattern: str, expected: int, claim: str) -> None:
    """Assert a count written out in prose against the count on disk.

    The regex is the contract. If a rewording breaks it, this fails loudly and
    asks for the sentence or the check to be brought back into line -- a
    silently unmatched claim is exactly the hole this script exists to close.
    """
    text = re.sub(r"\s+", " ", path.read_text(encoding="utf-8"))
    match = re.search(pattern, text, re.I)
    if not match:
        report(
            f"{rel(path)}: could not find the sentence that states {claim}. "
            f"It is checked here by the pattern /{pattern}/ -- reword the sentence to match, "
            "or update the pattern in scripts/check-docs.sh."
        )
        return
    written = match.group(1).lower()
    value = NUMBER_WORDS.get(written)
    if value is None:
        report(f"{rel(path)}: {claim} is written as '{written}', which is not a number word this check knows")
    elif value != expected:
        report(f"{rel(path)}: says {written} for {claim}; there are {expected}")


def check_opening_notes() -> tuple[int, list[pathlib.Path]]:
    docs = REPO / "docs"
    decisions = docs / "architecture" / "decisions"

    must_have = sorted(
        p
        for p in list((docs / "features").rglob("*.md")) + list((docs / "architecture").rglob("*.md"))
        if decisions not in p.parents
    )
    for path in must_have:
        if opening_note(path) is None:
            report(
                f"{rel(path)}: no opening note. Every document under docs/features/ and "
                "docs/architecture/ opens with a blockquote saying which part of it ships "
                "(see any sibling), and README.md says so."
            )

    elsewhere = sorted(
        p
        for p in docs.rglob("*.md")
        if p not in must_have and decisions not in p.parents and opening_note(p) is not None
    )

    quoted_number(
        REPO / "README.md",
        r"opens with a note saying which part of it ships[^.]*?\b(\w+(?:-\w+)?) files",
        len(must_have),
        "how many documents open with a note",
    )
    quoted_number(
        REPO / "README.md",
        r"\b(\w+(?:-\w+)?) documents elsewhere under `docs/` open with",
        len(elsewhere),
        "how many documents elsewhere open with a note",
    )
    quoted_number(
        REPO / "docs" / "README.md",
        r"\b(\w+(?:-\w+)?) documents elsewhere here do the same",
        len(elsewhere),
        "how many documents elsewhere open with a note",
    )
    return len(must_have), elsewhere


def linked_paths(path: pathlib.Path) -> set[pathlib.Path]:
    out = set()
    for target, _ in links_in(path):
        if EXTERNAL.match(target):
            continue
        location = target.partition("#")[0]
        if location:
            out.add((path.parent / location).resolve())
    return out


def check_indexes() -> None:
    """The two tables that claim to list everything.

    An index nobody maintains is worse than no index: it reads as complete.
    """
    docs = REPO / "docs"
    decisions = docs / "architecture" / "decisions"

    map_file = docs / "README.md"
    mapped = linked_paths(map_file)
    for path in sorted(docs.rglob("*.md")):
        if path == map_file or decisions in path.parents:
            continue
        if path not in mapped:
            report(
                f"{rel(map_file)}: the map does not list {rel(path)}. "
                "Every document under docs/ appears in it, or it is not a map."
            )

    register = decisions / "README.md"
    registered = linked_paths(register)
    for path in sorted(decisions.glob("*.md")):
        if path.name in {"README.md", "0000-template.md"}:
            continue
        if path not in registered:
            report(f"{rel(register)}: the ADR register does not list {rel(path)}")
    for path in sorted(registered):
        if not path.exists():
            report(f"{rel(register)}: lists {rel(path)}, which does not exist")


links_checked = check_links()
noted, elsewhere = check_opening_notes()
check_indexes()

if problems:
    print(f"check-docs: {len(problems)} problem(s)\n")
    for problem in problems:
        print(f"  {problem}")
    print()
    sys.exit(1)

print(f"Links: {links_checked} relative links and fragments, all resolve.")
print(f"Opening notes: {noted} in docs/features and docs/architecture, {len(elsewhere)} elsewhere "
      f"({', '.join(rel(p) for p in elsewhere)}).")
print("Indexes: docs/README.md and the ADR register list every document that exists.")
PYTHON
