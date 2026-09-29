"""Resolving a GitHub Actions reference to the commit digest it currently points at.

This exists because of where the two halves of the pinning repair live. The patch is the repair
service's: replace `uses: owner/repo@v3` with `uses: owner/repo@<40 hex>`. The lookup cannot be,
because the repair sandbox has no network by design -- that is the property the whole
verification story rests on -- so a template that called the GitHub API there would either fail
or prove the sandbox does not hold.

So the digest is resolved here, while the product is still doing analysis and still has egress,
and carried on the finding as `evidence_details.extra.resolved_action_digest`. A finding that
arrives at the repair service without one is refused rather than pinned to a guess.

Two things are deliberately conservative.

**It is off by default.** `WORKFLOW_ACTION_DIGEST_LOOKUP` has to be set for any request to leave
the process. A scanner that quietly makes outbound calls per finding is a scanner nobody can
reason about, and the Action's contract is that nothing leaves the runner at all, so the default
has to be the one that is safe in both places. The Action must never set it.

The hosted deployment may set it and, until 29 September 2026, this docstring claimed it did.
Nothing set it: no deploy workflow named the variable, so every workflow pinning repair in both
products was refused with `action_digest_unresolved`, and the rule those refusals came from is the
most precise one in the whole set (1.00 over 46 findings,
`docs/validation/workflow-tampering-2026-09.md`). `deploy-analysis-cloudrun.yml` now passes the
variable through from a repository variable of the same name, so the switch is reachable, and it is
still off unless an operator turns it on.

Turning it on without `WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN` means the unauthenticated GitHub API
rate limit, 60 requests an hour shared by every instance behind one egress address. Exceeding it
returns None, which is the same outcome as leaving the lookup off, so the failure is safe and
silent rather than wrong. It is not good enough to build a product promise on, and the note in the
validation document's known debt says what a real fix looks like: the App already holds an
installation token in github-service, and the digest should be resolved there rather than by
anonymous calls from the scanner.

**A failure is silence, never a guess.** An unreachable API, a rate limit, a tag that does not
exist, a repository that is private to us: every one of those returns None and the finding simply
carries no digest. The repair side already refuses that case by name.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Optional, Tuple

# `owner/repo@ref`, or `owner/repo/subdir@ref` for an action published in a subdirectory. A
# leading `./` (a local action) and a `docker://` reference are not GitHub refs and never reach
# here, because the rule that produces these findings excludes both.
ACTION_REFERENCE_RE = re.compile(
    r"^(?P<owner>[A-Za-z0-9][\w.-]*)/(?P<repo>[\w.-]+)(?P<subdir>(?:/[\w.-]+)*)@(?P<ref>[^\s'\"#]+)$"
)
FULL_DIGEST_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

GITHUB_API = "https://api.github.com"
LOOKUP_TIMEOUT_SECONDS = 5
# One process, one cache. An action reference repeats across a repository's workflows -- the
# corpus measurement saw `pypa/gh-action-pypi-publish@master` twice in one file -- and every
# repeat would otherwise be another request.
_CACHE: Dict[Tuple[str, str], Optional[str]] = {}


def lookup_enabled() -> bool:
    """Whether this process may make an outbound request to resolve a reference."""
    return str(os.getenv("WORKFLOW_ACTION_DIGEST_LOOKUP", "")).strip().lower() in {"1", "true", "yes", "on"}


def parse_action_reference(line: str) -> Optional[Dict[str, str]]:
    """`{repository, subdirectory, ref}` for the `uses:` value on a line, or None.

    Purely lexical, and the half of this module that always runs: the reference is worth carrying
    on the finding whether or not the digest could be resolved, because it is what a reviewer
    reads and what a later resolution attempt would need.
    """
    match = re.match(r"^[ \t]*(?:-[ \t]+)?uses[ \t]*:[ \t]*(?P<quote>['\"]?)(?P<value>[^\s'\"#]+)(?P=quote)", str(line or ""))
    if not match:
        return None
    reference = ACTION_REFERENCE_RE.match(match.group("value"))
    if not reference:
        return None
    return {
        "repository": f"{reference.group('owner')}/{reference.group('repo')}",
        "subdirectory": (reference.group("subdir") or "").lstrip("/"),
        "ref": reference.group("ref"),
    }


def _request(url: str) -> Optional[dict]:
    # The only host this module ever reads is the GitHub API over https, and the caller builds
    # the url from a reference the scanner matched. Refusing anything else here means a crafted
    # `uses:` value can never turn this lookup into a request somewhere of its choosing.
    if not url.startswith(f"{GITHUB_API}/"):
        return None
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "mitig8it-analysis",
    })
    token = os.getenv("WORKFLOW_ACTION_DIGEST_LOOKUP_TOKEN") or ""
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        # The guard above pins the scheme and the host, which is what makes this safe.
        with urllib.request.urlopen(request, timeout=LOOKUP_TIMEOUT_SECONDS) as response:  # nosec B310
            if response.status != 200:
                return None
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        # Every failure is the same failure here: no digest. The repair side refuses that by name.
        return None


def resolve_action_digest(repository: str, ref: str) -> Optional[str]:
    """The 40-character commit sha `ref` resolves to in `repository`, or None.

    `GET /repos/{repository}/commits/{ref}` answers for a tag, a branch and a sha alike, which is
    exactly the set of things an action reference can be.
    """
    if not repository or not ref:
        return None
    if FULL_DIGEST_RE.match(ref):
        # Already a digest. Answering with it rather than None keeps the caller from treating a
        # pinned reference as a lookup failure.
        return ref.lower()
    if not lookup_enabled():
        return None
    key = (repository, ref)
    if key in _CACHE:
        return _CACHE[key]
    payload = _request(f"{GITHUB_API}/repos/{repository}/commits/{urllib.parse.quote(ref, safe='')}")
    sha = str((payload or {}).get("sha") or "")
    digest = sha.lower() if FULL_DIGEST_RE.match(sha) else None
    _CACHE[key] = digest
    return digest


def action_reference_evidence(line: str) -> Dict[str, str]:
    """The `evidence_details.extra` entries a finding on an unpinned action carries.

    `workflow_action_reference` and `workflow_action_ref` always, because they are deterministic;
    `resolved_action_digest` only when a lookup actually answered.
    """
    reference = parse_action_reference(line)
    if not reference:
        return {}
    extra: Dict[str, str] = {
        "workflow_action_reference": reference["repository"],
        "workflow_action_ref": reference["ref"],
    }
    if reference["subdirectory"]:
        extra["workflow_action_subdirectory"] = reference["subdirectory"]
    digest = resolve_action_digest(reference["repository"], reference["ref"])
    if digest:
        extra["resolved_action_digest"] = digest
    return extra


def reset_cache() -> None:
    """For tests: the cache is process-wide and a test that changes the flag must not inherit it."""
    _CACHE.clear()
