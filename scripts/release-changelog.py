#!/usr/bin/env python3
"""The changelog, read as the release gate reads it.

`.github/workflows/release.yml` calls this twice: once to refuse a tag the changelog does not
document, and once to take the release notes out of the section it documents. Both live here rather
than in the workflow because shell inside a YAML string is code nobody runs until a release runs it,
and a release is the worst moment to find out that a regex was wrong.

    release-changelog.py check 1.0.0    # exit 0 if the changelog documents exactly this release
    release-changelog.py notes 1.0.0    # the body of that section, for the GitHub release

What `check` refuses, and why each one is worth refusing:

  * a version with no section at all. Releasing an undocumented version is how a release ends up
    with "no notes provided" on the one page users read.
  * a section whose date is not a real ISO date. The committed entry reads `- unreleased`, which is
    honest in the repository and useless in a release, so setting the date is the first step of the
    documented procedure and this is what enforces it.
  * a version that is not the topmost released section. Tagging 1.0.0 while 1.1.0 is already
    written above it means the tag and the notes disagree about what is being released.
  * a version documented twice.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = REPO_ROOT / "CHANGELOG.md"

# `## [1.0.0] - 2026-09-27`, and the same heading with anything else where the date belongs.
HEADING = re.compile(r"^##\s+\[(?P<version>[^\]]+)\]\s*-\s*(?P<date>.+?)\s*$")
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
ISO_DATE = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])$")
UNRELEASED = "unreleased"


class ChangelogError(Exception):
    """Something a release must stop for, phrased for whoever is reading the job log."""


def sections(text: str) -> list[dict]:
    """Every `## [version] - date` heading in order, with the lines beneath it."""
    found: list[dict] = []
    for index, line in enumerate(text.splitlines()):
        match = HEADING.match(line)
        if match:
            found.append(
                {
                    "version": match.group("version").strip(),
                    "date": match.group("date").strip(),
                    "line": index,
                }
            )
    lines = text.splitlines()
    for position, section in enumerate(found):
        start = section["line"] + 1
        end = found[position + 1]["line"] if position + 1 < len(found) else len(lines)
        section["body"] = "\n".join(lines[start:end]).strip("\n")
    return found


def released_sections(text: str) -> list[dict]:
    """The version sections, with the Unreleased placeholder left out.

    Unreleased is a section like any other in the file and is not a release, so it is excluded
    here rather than special-cased at three call sites.
    """
    return [s for s in sections(text) if s["version"].lower() != UNRELEASED]


def find(text: str, version: str) -> dict:
    matching = [s for s in released_sections(text) if s["version"] == version]
    if not matching:
        documented = ", ".join(s["version"] for s in released_sections(text)) or "none"
        raise ChangelogError(
            f"CHANGELOG.md documents no version {version}. It documents: {documented}. "
            f"Add a `## [{version}] - <date>` section before tagging."
        )
    if len(matching) > 1:
        raise ChangelogError(f"CHANGELOG.md documents version {version} more than once.")
    return matching[0]


def check(text: str, version: str) -> dict:
    if not SEMVER.match(version):
        raise ChangelogError(
            f"{version!r} is not a MAJOR.MINOR.PATCH version. A release tag is `v1.2.3`."
        )

    section = find(text, version)
    first = released_sections(text)[0]
    if first["version"] != version:
        raise ChangelogError(
            f"CHANGELOG.md documents {first['version']} above {version}, so the tag and the notes "
            f"disagree about what is being released. Move the {version} section to the top, or "
            f"release {first['version']}."
        )

    if section["date"].lower() == UNRELEASED:
        raise ChangelogError(
            f"CHANGELOG.md still reads `## [{version}] - unreleased`. Set it to the release date "
            f"in ISO form, for example `## [{version}] - 2026-09-27`, and commit that before "
            f"tagging. Nothing here will invent a date for you."
        )
    if not ISO_DATE.match(section["date"]):
        raise ChangelogError(
            f"`## [{version}] - {section['date']}` is not an ISO date. Use YYYY-MM-DD."
        )
    if not section["body"].strip():
        raise ChangelogError(f"The {version} section of CHANGELOG.md is empty.")
    return section


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "notes"))
    parser.add_argument("version")
    parser.add_argument("--changelog", type=Path, default=CHANGELOG)
    args = parser.parse_args(argv)

    if not args.changelog.is_file():
        print(f"{args.changelog} does not exist.", file=sys.stderr)
        return 1
    text = args.changelog.read_text(encoding="utf-8")

    try:
        section = check(text, args.version)
    except ChangelogError as error:
        print(str(error), file=sys.stderr)
        return 1

    if args.command == "notes":
        print(section["body"])
    else:
        print(f"CHANGELOG.md documents {args.version}, dated {section['date']}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
