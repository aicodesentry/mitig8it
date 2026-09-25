"""`.mitig8it.yml`: what a repository asks not to be reviewed.

One key so far, `exclude`, a list of globs. A path it matches is never analysed: it is dropped
before the scanner sees it, so no finding, no comment and no fix can come from it. Intentionally
vulnerable fixtures, vendored trees and generated output are what this is for.

The App reads the same file in services/api-service/src/services/repositoryConfig.js, and the two
have to agree exactly: a repository that excludes a directory must see the same files skipped
whether the App or the Action reviewed the pull request. The glob dialect is therefore written
down once, in contracts/repository-configuration-v1.json, and both implementations are tested
against its cases rather than against each other's behaviour.

The file comes out of the repository under review, so it is untrusted input. It can only ever
remove files from the analysis, never add anything to it or change how anything is scanned, and
a file that does not parse is reported rather than obeyed: excluding nothing and saying so is
safe, while excluding everything because a quote was unbalanced is not.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

CONFIG_FILENAME = ".mitig8it.yml"
# A configuration file is a short list of globs. Anything larger is not one, and reading it into
# a YAML parser is work a pull request should not be able to ask for.
MAX_CONFIG_BYTES = 64_000
MAX_PATTERNS = 200
MAX_PATTERN_CHARS = 500


class ConfigError(Exception):
    """The file exists but is not a configuration. The run continues, excluding nothing."""


def normalize_path(path: str) -> str:
    """The repository-relative form both sides match against: no leading `./` or `/`."""
    text = str(path or "").replace("\\", "/").strip()
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _translate(pattern: str) -> str:
    """One glob as a regular expression, over the dialect the contract file states.

    `**` is only a globstar when it is a whole segment; `a**b` is two ordinary stars, which the
    per-character branch below already handles by never letting `*` cross a separator.
    """
    parts: List[str] = []
    segments = pattern.split("/")
    for index, segment in enumerate(segments):
        first, last = index == 0, index == len(segments) - 1
        if segment == "**":
            if first and last:
                parts.append(".*")
            elif first:
                # `**/x` matches `x` at the root too, so the separator is part of the option.
                parts.append("(?:.*/)?")
            elif last:
                # `a/**` matches `a` itself as well as everything under it.
                parts[-1] = parts[-1].removesuffix("/")
                parts.append("(?:/.*)?")
            else:
                parts.append("(?:.*/)?")
            continue
        for character in segment:
            if character == "*":
                parts.append("[^/]*")
            elif character == "?":
                parts.append("[^/]")
            else:
                parts.append(re.escape(character))
        if not last:
            parts.append("/")
    return "".join(parts)


def compile_pattern(pattern: str) -> Optional[re.Pattern]:
    """The matcher for one pattern, or None when the pattern is empty and matches nothing."""
    cleaned = normalize_path(pattern)
    if not cleaned:
        return None
    body = _translate(cleaned)
    if "*" not in cleaned and "?" not in cleaned:
        # A plain name is a file or a directory, so it also covers everything underneath it.
        body = f"{body}(?:/.*)?"
    return re.compile(f"^{body}$")


class Exclusions:
    """The compiled `exclude` list. Empty when there is no file, or the file named nothing."""

    def __init__(self, patterns: Sequence[str] = ()):
        self.patterns: Tuple[str, ...] = tuple(patterns)
        self._matchers = [matcher for matcher in (compile_pattern(p) for p in self.patterns) if matcher]

    def __bool__(self) -> bool:
        return bool(self._matchers)

    def matches(self, path: str) -> bool:
        candidate = normalize_path(path)
        return any(matcher.match(candidate) for matcher in self._matchers)

    def partition(self, paths: Iterable[str]) -> Tuple[List[str], List[str]]:
        """(kept, excluded), in the order given."""
        kept: List[str] = []
        excluded: List[str] = []
        for path in paths:
            (excluded if self.matches(path) else kept).append(path)
        return kept, excluded


def parse(text: str) -> Exclusions:
    """`.mitig8it.yml` as an Exclusions. Raises ConfigError when the text is not one."""
    import yaml  # noqa: PLC0415 - optional at import time; the action always ships it.

    if len(text.encode("utf-8", errors="ignore")) > MAX_CONFIG_BYTES:
        raise ConfigError(f"{CONFIG_FILENAME} is larger than {MAX_CONFIG_BYTES} bytes")
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as error:
        raise ConfigError(f"{CONFIG_FILENAME} is not valid YAML: {str(error).splitlines()[0]}") from error
    if document is None:
        return Exclusions()
    if not isinstance(document, dict):
        raise ConfigError(f"{CONFIG_FILENAME} must be a mapping, with `exclude` as one of its keys")
    raw = document.get("exclude")
    if raw is None:
        return Exclusions()
    if not isinstance(raw, list):
        raise ConfigError("`exclude` must be a list of globs, one per line")
    if len(raw) > MAX_PATTERNS:
        raise ConfigError(f"`exclude` names more than {MAX_PATTERNS} globs")
    patterns: List[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            raise ConfigError(f"`exclude` contains {type(entry).__name__} where a glob was expected")
        if len(entry) > MAX_PATTERN_CHARS:
            raise ConfigError(f"an `exclude` glob is longer than {MAX_PATTERN_CHARS} characters")
        patterns.append(entry)
    return Exclusions(patterns)


def load(root: Path) -> Tuple[Exclusions, Optional[str]]:
    """Reads `.mitig8it.yml` from a checkout. Returns (exclusions, problem).

    `problem` is a sentence for the log and the check summary when the file could not be used.
    An absent file is not a problem: most repositories have none.
    """
    path = Path(root) / CONFIG_FILENAME
    try:
        if not path.is_file():
            return Exclusions(), None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        return Exclusions(), f"{CONFIG_FILENAME} could not be read ({type(error).__name__}); nothing was excluded"
    try:
        return parse(text), None
    except ConfigError as error:
        return Exclusions(), f"{error}; nothing was excluded"


def exclusion_summary(count: int) -> Optional[str]:
    """The one sentence the check summary carries. None when nothing was excluded."""
    if count <= 0:
        return None
    return f"{count} file{'' if count == 1 else 's'} excluded by {CONFIG_FILENAME}"


def limitation(count: int) -> Optional[Dict[str, Any]]:
    """The same fact in the shape the App's limitation list uses."""
    message = exclusion_summary(count)
    return {"kind": "path_exclusion", "message": message} if message else None
