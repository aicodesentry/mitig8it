"""Newly added dependencies in a changed lockfile, read offline.

A pull request that adds a dependency usually shows it twice: one line in the manifest a reviewer
reads, and a block in the lockfile nobody reads. The block is where the facts are. It says whether
the package runs a script when it is installed, where its bytes come from, and its exact name,
and each of those is a known way a stranger's pull request gets code onto a maintainer's machine
and into their CI.

Three signals, one rule id each, so the posting policy and the precision tables answer per signal:

* `dependency.lockfile.install_script`: npm's `hasInstallScript: true`, or pnpm's
  `requiresBuild: true`. The package runs code at install time, on every developer machine and
  CI runner that installs the tree.
* `dependency.lockfile.non_registry_source`: the package resolves to a git repository, or to a
  plain `http://` URL, or to an `https://` tarball that is not a registry tarball (`/-/` in the
  path is the npm registry convention, which private registries follow too). A git source is
  whatever the branch or commit holds, and nothing a registry checks applies to it.
* `dependency.lockfile.name_near_popular`: the name is one edit away from one of the 200 most
  downloaded packages of the same ecosystem and is not itself on that list. The list is checked in
  (`data/top_packages.json`, with its provenance), so this runs with no network.

**Only newly added dependencies are reported.** A dependency is new when the line that opens its
lockfile entry is an added line in the patch. A version bump rewrites the fields of an entry whose
key is unchanged and is not reported, even when the new version gained an install script; that is
a different question (what changed in a package the project already trusts) and this module does
not answer it.

**Every signal starts quarantined.** None of them has been measured on real pull requests, and
each has an obvious false-positive class: install scripts are how native modules build, git
sources are how forks are pinned, and short popular names have legitimate neighbours. The
findings are produced and counted and never posted until a measurement says otherwise.

**No fix is offered.** Whether a dependency belongs in the project is the maintainer's decision,
and the finding's remediation says so.

What is read, per file:

| File | New entry opens on | Install script | Source |
| --- | --- | --- | --- |
| `package-lock.json` (v2, v3) | `"node_modules/<name>": {` | `"hasInstallScript": true` | `"resolved"` |
| `pnpm-lock.yaml` (v6 to v9) | `  /name@1.0.0:` or `  name@1.0.0:` | `requiresBuild: true` | `resolution: {tarball/repo}` |
| `yarn.lock` (v1 and berry) | an unindented `name@range:` line | not recorded by yarn | `resolved` / `resolution` |
| `poetry.lock` | `name = "..."` under `[[package]]` | not recorded by poetry | `[package.source]` `type` |
| `requirements*.txt` | the requirement line itself | not recorded | a `git+` or URL requirement |

What is not read: `package-lock.json` v1 (`dependencies` keyed by bare name), `npm-shrinkwrap.json`,
`Pipfile.lock`, `uv.lock`, `Cargo.lock`, `go.sum` and every other lockfile; a lockfile whose patch
the host did not send (GitHub omits the patch of a very large diff, and tier 1 skips a patch over
200 kB, which a large `package-lock.json` change often is); and a dependency added only to a
manifest.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from finding_quality import make_fingerprint, parse_patch_entries
from security_rules import POSTING_QUARANTINE
from taxonomy import build_taxonomy_metadata

RULE_ID_INSTALL_SCRIPT = "dependency.lockfile.install_script"
RULE_ID_NON_REGISTRY_SOURCE = "dependency.lockfile.non_registry_source"
RULE_ID_NAME_NEAR_POPULAR = "dependency.lockfile.name_near_popular"

# The posting policy, declared beside the rules for the reason `secret_detection.POSTING` is:
# `main.QUARANTINED_RULE_IDS` is the union of every detector's declaration, and
# `main.partition_by_posting_policy` is the one place a withheld finding is removed.
POSTING = {
    RULE_ID_INSTALL_SCRIPT: POSTING_QUARANTINE,
    RULE_ID_NON_REGISTRY_SOURCE: POSTING_QUARANTINE,
    RULE_ID_NAME_NEAR_POPULAR: POSTING_QUARANTINE,
}

CATEGORY = "dependency/package risk"
# CWE-1357 is "Reliance on Insufficiently Trustworthy Component", which is what each of the three
# signals is a reason to suspect. The internal type is declared explicitly rather than derived
# from the CWE, because CWE-1357 already resolves to `unpinned_action_reference` for workflows.
CWE_ID = "CWE-1357"
OWASP_CATEGORY = "A08:2021"
INTERNAL_TYPE = "supply_chain_risk"
SEVERITY = "medium"

REMEDIATION = (
    "Check this dependency before merging: who publishes it, why it is needed, and what it runs "
    "or fetches when it is installed. No automatic fix is offered for this finding, because "
    "whether a dependency belongs in the project is the maintainer's decision."
)

NPM = "npm"
PYPI = "pypi"

TOP_PACKAGES_PATH = Path(__file__).resolve().parent / "data" / "top_packages.json"

# A name this short has too many one-edit neighbours to mean anything: `ms`, `qs`, `ws`, `os`
# and `rc` are all real, popular and one edit from each other. Below this length the near-miss
# signal does not compare at all.
MIN_NEAR_MISS_LENGTH = 4

# A cap per file and per signal, as the secrets detector has: a lockfile regenerated from
# scratch adds every entry at once, and that is one conversation, not hundreds.
MAX_FINDINGS_PER_FILE = 10


@dataclass
class NewDependency:
    name: str
    ecosystem: str
    line_number: int
    line_text: str
    version: str = ""
    install_script: bool = False
    source: str = ""
    fields: Dict[str, str] = field(default_factory=dict)


# ── Which file is which ────────────────────────────────────────────────────────

def lockfile_kind(path: Any) -> Optional[str]:
    name = str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name == "package-lock.json":
        return "package-lock"
    if name == "pnpm-lock.yaml":
        return "pnpm"
    if name == "yarn.lock":
        return "yarn"
    if name == "poetry.lock":
        return "poetry"
    if name.startswith("requirements") and name.endswith(".txt"):
        return "requirements"
    return None


# ── The checked-in popular names ───────────────────────────────────────────────

def normalize_name(name: str, ecosystem: str) -> str:
    """PyPI treats `-`, `_` and `.` as the same character and ignores case; npm does neither."""
    if ecosystem == PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


@lru_cache(maxsize=1)
def top_packages() -> Dict[str, Tuple[str, ...]]:
    document = json.loads(TOP_PACKAGES_PATH.read_text(encoding="utf-8"))
    return {
        NPM: tuple(document[NPM]),
        PYPI: tuple(normalize_name(name, PYPI) for name in document[PYPI]),
    }


def within_one_edit(left: str, right: str) -> bool:
    """True when one insertion, deletion, substitution or adjacent swap turns one into the other.

    The swap is counted as one edit because `lodahs` for `lodash` is exactly the typo a squatter
    registers. Equal strings are not within one edit: a package is not a near miss of itself.
    """
    if left == right:
        return False
    if abs(len(left) - len(right)) > 1:
        return False
    if len(left) == len(right):
        differences = [index for index, (a, b) in enumerate(zip(left, right)) if a != b]
        if len(differences) == 1:
            return True
        if len(differences) == 2:
            first, second = differences
            return second == first + 1 and left[first] == right[second] and left[second] == right[first]
        return False
    shorter, longer = (left, right) if len(left) < len(right) else (right, left)
    for index in range(len(longer)):
        if longer[:index] + longer[index + 1 :] == shorter:
            return True
    return False


def near_popular_name(name: str, ecosystem: str) -> Optional[str]:
    """The popular name this one is a near miss of, or None."""
    popular = top_packages().get(ecosystem, ())
    candidate = normalize_name(name, ecosystem)
    if candidate in popular:
        return None
    for known in popular:
        if len(known) < MIN_NEAR_MISS_LENGTH:
            continue
        if within_one_edit(candidate, known):
            return known
    return None


# ── Sources ────────────────────────────────────────────────────────────────────

_GIT_SOURCE_RE = re.compile(r"^(?:git\+|git://|git@|github:|gitlab:|bitbucket:|ssh://)", re.I)


def non_registry_source(source: str) -> Optional[str]:
    """Why `source` is not a registry download, or None when it is one (or is absent)."""
    value = (source or "").strip().strip("'\"")
    if not value:
        return None
    if _GIT_SOURCE_RE.match(value) or re.search(r"\.git(?:#|$)", value):
        return "a git repository"
    if value.lower().startswith("http://"):
        return "an unencrypted http URL"
    if value.lower().startswith("https://"):
        path = value.split("://", 1)[1].split("/", 1)[-1] if "/" in value.split("://", 1)[1] else ""
        if "/-/" in "/" + path:
            return None
        return "a tarball URL that is not a registry download"
    return None


# ── Per-format readers ─────────────────────────────────────────────────────────
#
# Each reader walks the patch's new-side lines in order (added and context, which is everything
# the patch shows of the head file) and returns the dependencies whose opening line was added.
# The fields of an entry are read from the lines that follow it inside the same hunk.

def _new_side(patch: str) -> List[Dict[str, Any]]:
    return [entry for entry in parse_patch_entries(patch) if entry.get("kind") in {"add", "context"}]


def _blocks(entries: List[Dict[str, Any]], opens, belongs) -> Iterable[Tuple[Dict[str, Any], List[Dict[str, Any]]]]:
    """(opening entry, following entries of the same block) for every block whose opener was added."""
    for index, entry in enumerate(entries):
        if entry.get("kind") != "add" or not opens(entry["content"]):
            continue
        body: List[Dict[str, Any]] = []
        for follower in entries[index + 1 :]:
            if follower.get("hunk") != entry.get("hunk") or not belongs(entry["content"], follower["content"]):
                break
            body.append(follower)
        yield entry, body


def _indent(text: str) -> int:
    return len(text) - len(text.lstrip(" \t"))


_NPM_KEY_RE = re.compile(r'^\s*"(?:[^"]*/)?node_modules/(?P<name>(?:@[^/"]+/)?[^/"]+)"\s*:\s*\{\s*$')
_JSON_FIELD_RE = re.compile(r'^\s*"(?P<key>[^"]+)"\s*:\s*(?P<value>"[^"]*"|true|false|[0-9.]+)')


def _package_lock(entries: List[Dict[str, Any]]) -> List[NewDependency]:
    found: List[NewDependency] = []
    for opener, body in _blocks(
        entries,
        lambda text: bool(_NPM_KEY_RE.match(text)),
        lambda head, text: _indent(text) > _indent(head),
    ):
        name = _NPM_KEY_RE.match(opener["content"]).group("name")
        dependency = NewDependency(name, NPM, opener["line_number"], opener["content"])
        for line in body:
            match = _JSON_FIELD_RE.match(line["content"])
            if not match or _indent(line["content"]) != _indent(opener["content"]) + 2:
                continue
            key, value = match.group("key"), match.group("value").strip('"')
            dependency.fields[key] = value
            if key == "hasInstallScript" and value == "true":
                dependency.install_script = True
            elif key == "resolved":
                dependency.source = value
            elif key == "version":
                dependency.version = value
        found.append(dependency)
    return found


_PNPM_KEY_RE = re.compile(r"^  (?P<quote>['\"]?)/?(?P<spec>(?:@[^@/\s'\"]+/)?[^@\s'\"]+@[^\s'\"]+?)(?P=quote):\s*$")


def _pnpm_name(spec: str) -> Tuple[str, str]:
    spec = spec.split("(", 1)[0]
    at = spec.rfind("@")
    return spec[:at], spec[at + 1 :]


def _pnpm(entries: List[Dict[str, Any]]) -> List[NewDependency]:
    found: Dict[str, NewDependency] = {}
    for opener, body in _blocks(
        entries,
        lambda text: bool(_PNPM_KEY_RE.match(text)),
        lambda head, text: not text.strip() or _indent(text) > 2,
    ):
        name, version = _pnpm_name(_PNPM_KEY_RE.match(opener["content"]).group("spec"))
        if name in found:
            # pnpm 9 lists a package under `packages:` and again under `snapshots:`.
            continue
        dependency = NewDependency(name, NPM, opener["line_number"], opener["content"], version=version)
        for line in body:
            text = line["content"].strip()
            if text == "requiresBuild: true":
                dependency.install_script = True
            elif text.startswith("resolution:"):
                tarball = re.search(r"tarball:\s*([^,}\s]+)", text)
                repo = re.search(r"repo:\s*([^,}\s]+)", text)
                if repo:
                    dependency.source = "git+" + repo.group(1)
                elif tarball:
                    dependency.source = tarball.group(1)
        found[name] = dependency
    return list(found.values())


_YARN_KEY_RE = re.compile(r'^(?P<keys>"?(?:@[^@\s"]+/)?[^@\s"]+@[^\n]*?):\s*$')


def _yarn_name(keys: str) -> str:
    first = keys.split(",", 1)[0].strip().strip('"')
    at = first.find("@", 1)
    return first[:at] if at > 0 else first


def _yarn(entries: List[Dict[str, Any]]) -> List[NewDependency]:
    found: List[NewDependency] = []
    for opener, body in _blocks(
        entries,
        lambda text: not text.startswith((" ", "#", "\t")) and bool(_YARN_KEY_RE.match(text)),
        lambda head, text: text.startswith((" ", "\t")),
    ):
        keys = _YARN_KEY_RE.match(opener["content"]).group("keys")
        dependency = NewDependency(_yarn_name(keys), NPM, opener["line_number"], opener["content"])
        for line in body:
            text = line["content"].strip()
            match = re.match(r'^(?P<key>resolved|resolution|version)\s*:?\s+"?(?P<value>[^"]*)"?$', text)
            if not match:
                continue
            key, value = match.group("key"), match.group("value")
            if key == "version":
                dependency.version = value
            elif key == "resolved":
                dependency.source = value
            elif key == "resolution":
                # berry: `name@npm:1.2.3` is the registry; `name@https://...` or `name@git...`
                # names the source after the `@`.
                at = value.find("@", 1)
                target = value[at + 1 :] if at > 0 else value
                if not target.startswith(("npm:", "workspace:", "patch:", "portal:", "link:", "file:")):
                    dependency.source = target
        found.append(dependency)
    return found


def _poetry(entries: List[Dict[str, Any]]) -> List[NewDependency]:
    found: List[NewDependency] = []
    current: Optional[NewDependency] = None
    in_package = False
    in_source = False
    for entry in entries:
        text = entry["content"].strip()
        if text.startswith("["):
            in_package = text == "[[package]]"
            in_source = text == "[package.source]"
            if in_package:
                current = None
            continue
        if in_package and text.startswith("name =") and entry.get("kind") == "add":
            name = text.split("=", 1)[1].strip().strip('"')
            current = NewDependency(name, PYPI, entry["line_number"], entry["content"])
            found.append(current)
            continue
        if current is None:
            continue
        if in_package and text.startswith("version ="):
            current.version = text.split("=", 1)[1].strip().strip('"')
        if in_source and text.startswith("type ="):
            kind = text.split("=", 1)[1].strip().strip('"')
            if kind == "git":
                current.source = "git+" + current.fields.get("url", "")
            elif kind == "url":
                current.source = current.fields.get("url", "") or "https://"
            current.fields["type"] = kind
        if in_source and text.startswith("url ="):
            url = text.split("=", 1)[1].strip().strip('"')
            current.fields["url"] = url
            if current.fields.get("type") == "git":
                current.source = "git+" + url
            elif current.fields.get("type") == "url":
                current.source = url
    return found


_REQUIREMENT_NAME_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)")
_EGG_RE = re.compile(r"#egg=(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)")


def _requirements(entries: List[Dict[str, Any]]) -> List[NewDependency]:
    found: List[NewDependency] = []
    for entry in entries:
        if entry.get("kind") != "add":
            continue
        raw = entry["content"]
        text = raw.split(" #", 1)[0].strip()
        if not text or text.startswith("#"):
            continue
        editable = False
        if text.startswith(("-e ", "--editable ")):
            editable = True
            text = text.split(None, 1)[1].strip() if len(text.split(None, 1)) > 1 else ""
        elif text.startswith("-"):
            # `-r other.txt`, `--hash=...`, `-i URL`: options, not requirements.
            continue
        source = ""
        name = ""
        if " @ " in text:
            name, source = (part.strip() for part in text.split(" @ ", 1))
            name = re.split(r"[\[;<>=!~ ]", name, 1)[0]
        elif re.match(r"^(?:git\+|https?://)", text, re.I):
            source = text
            egg = _EGG_RE.search(text)
            name = egg.group("name") if egg else ""
        else:
            match = _REQUIREMENT_NAME_RE.match(text)
            name = match.group("name") if match else ""
        if editable and not source:
            continue
        if not name and not source:
            continue
        found.append(NewDependency(name, PYPI, entry["line_number"], raw, source=source.split(";", 1)[0].strip()))
    return found


READERS = {
    "package-lock": _package_lock,
    "pnpm": _pnpm,
    "yarn": _yarn,
    "poetry": _poetry,
    "requirements": _requirements,
}


def new_dependencies(path: str, patch: str) -> List[NewDependency]:
    kind = lockfile_kind(path)
    if kind is None or not patch:
        return []
    return READERS[kind](_new_side(patch))


# ── Findings ───────────────────────────────────────────────────────────────────

def _signals(dependency: NewDependency) -> List[Tuple[str, str, Dict[str, Any]]]:
    """(rule id, sentence, extra evidence) for every signal this dependency raises."""
    signals: List[Tuple[str, str, Dict[str, Any]]] = []
    label = f"`{dependency.name}`" if dependency.name else "This dependency"
    if dependency.install_script:
        signals.append((
            RULE_ID_INSTALL_SCRIPT,
            f"{label} is newly added and runs a script when it is installed, on every machine "
            "and CI runner that installs this tree.",
            {"signal": "install_script"},
        ))
    why = non_registry_source(dependency.source)
    if why:
        signals.append((
            RULE_ID_NON_REGISTRY_SOURCE,
            f"{label} is newly added and resolves to {why} (`{dependency.source[:120]}`), so "
            "nothing a package registry checks applies to what is installed.",
            {"signal": "non_registry_source", "resolved_source": dependency.source[:200]},
        ))
    if dependency.name:
        near = near_popular_name(dependency.name, dependency.ecosystem)
        if near:
            signals.append((
                RULE_ID_NAME_NEAR_POPULAR,
                f"{label} is newly added and its name is one edit away from `{near}`, one of the "
                f"200 most downloaded {dependency.ecosystem} packages.",
                {"signal": "name_near_popular", "popular_name": near},
            ))
    return signals


def build_finding(dependency: NewDependency, rule_id: str, sentence: str, extra: Dict[str, Any], path: str) -> Dict[str, Any]:
    title = {
        RULE_ID_INSTALL_SCRIPT: "New dependency runs an install script",
        RULE_ID_NON_REGISTRY_SOURCE: "New dependency installed from outside the registry",
        RULE_ID_NAME_NEAR_POPULAR: "New dependency name is a near miss of a popular package",
    }[rule_id]
    snippet = dependency.line_text.strip()
    taxonomy = build_taxonomy_metadata(
        rule_id=rule_id,
        category=CATEGORY,
        cwe_id=CWE_ID,
        owasp_category=OWASP_CATEGORY,
        internal_type=INTERNAL_TYPE,
        title=title,
        description=sentence,
        file_path=path,
        code_snippet=snippet,
    )
    details_extra = {
        "dependency_name": dependency.name,
        "dependency_version": dependency.version,
        "ecosystem": dependency.ecosystem,
        "fix_offered": False,
        **extra,
    }
    return {
        "rule_id": rule_id,
        "internal_type": taxonomy["internal_type"],
        "title": title,
        "description": sentence,
        "category": CATEGORY,
        "cwe_id": taxonomy["primary_cwe_id"],
        "owasp_category": taxonomy["primary_owasp_category"],
        "taxonomy_mappings": taxonomy["taxonomy_mappings"],
        "taxonomy_versions": taxonomy["taxonomy_versions"],
        "severity": SEVERITY,
        "confidence": 0.6,
        "exploitability": "medium",
        "file_path": path,
        "line_start": dependency.line_number,
        "line_end": dependency.line_number,
        "code_snippet": snippet,
        "evidence": sentence,
        "exploit_scenario": "",
        "remediation": REMEDIATION,
        "remediation_patch": "",
        "evidence_details": {"extra": details_extra},
        "fingerprint": make_fingerprint(rule_id, path, dependency.line_number, snippet),
    }


def dependency_diff_findings(path: str, patch: str, content: str = "") -> List[Dict[str, Any]]:
    """Tier 1's lockfile pass over one changed file. The signature `secret_findings` has.

    `content` is accepted for that symmetry and not read: everything this module needs is in the
    patch, and reading the head file would report entries this pull request did not add.
    """
    del content
    findings: List[Dict[str, Any]] = []
    per_rule: Dict[str, int] = {}
    for dependency in new_dependencies(path, patch):
        for rule_id, sentence, extra in _signals(dependency):
            if per_rule.get(rule_id, 0) >= MAX_FINDINGS_PER_FILE:
                continue
            per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
            findings.append(build_finding(dependency, rule_id, sentence, extra, path))
    return findings
