"""Secrets in the diff.

A committed credential is the most consequential thing a pull request can carry, and the
one tier 1 regex that looked for one (`secret.hardcoded.credential`) is a substring search:
a credential-ish identifier, a colon or an equals sign, and twelve or more characters of
anything. It has no key formats, no structural verification and no entropy, and it is one of
the rules that has fired on documentation prose.

This module is the replacement, and it differs in three ways.

**It reads the added lines only.** An existing secret is not this pull request's fault, and
re-reporting it on every change to the file is noise a maintainer learns to ignore. Only
entries whose `kind` is `add` are scanned.

**It carries two independent signals, and says which one fired.**

* `secret.format.known_key` recognizes a credential by its published format and then
  verifies the structure that format defines: the fixed prefix, the exact length, the
  charset, and, where the format is self-describing, the content. A JWT's header has to
  base64url-decode to a JSON object with an `alg`; a connection string has to parse to a URL
  with a real password in it; a PEM block has to be a private key marker rather than a
  public one. That verification is the difference between a detector and a substring search,
  and it is why this signal may post on its structure rather than on a measured precision:
  the same argument the posting policy already makes for a sink-only pattern.
* `secret.entropy.credential_assignment` recognizes a high-entropy value assigned to an
  identifier whose name says it is a credential. It is the signal that catches the key
  formats nobody has written down, and it is the signal that can be wrong, so it carries a
  measured precision and is bounded on both sides: the name has to be a credential name and
  not one of the near misses (`key_id`, `public_key`, `token_url`), and the value has to
  survive an exclusion list built from the shapes that are legitimately high entropy.

**It knows where fake keys live.** Test fixtures, benchmark corpora, documentation and
lockfiles are where a repository writes credentials down on purpose. The path model is the
one the product already has (`test_code_scope`), not a second one: `is_test_code_path` makes
a finding informational through `classify_finding`, `is_prose_path`/`is_data_path`/
`is_template_path` turn the entropy signal off, and `.mitig8it.yml` keeps our own measurement
corpus out of our own pull requests.

Comments are **not** stripped before matching. Every other tier 1 rule reads the
comment-blanked text because its signal is the shape of executable code, and a commented-out
route is not a route. A commented-out credential is still a committed credential, so this
module reads the author's line as written.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

from finding_quality import (
    is_transcript_artifact_line,
    make_fingerprint,
    parse_patch_entries,
)
from remediation_patches import build_remediation_patch
from security_rules import POSTING_POST, POSTING_QUARANTINE
from taxonomy import build_taxonomy_metadata
from test_code_scope import is_non_code_text_path

# ── The two signals ──────────────────────────────────────────────────────────
# One rule id per signal, so the posting policy, the metrics and the precision tables all
# answer per signal. Which format matched is recorded in `evidence_details.extra.secret_type`
# rather than in the rule id: twenty rule ids would each need their own three adjudicated
# findings before any of them could post, and the structural verification is the same
# argument for all of them.
SIGNAL_FORMAT = "key_format"
SIGNAL_ENTROPY = "entropy"

RULE_ID_FORMAT = "secret.format.known_key"
RULE_ID_ENTROPY = "secret.entropy.credential_assignment"

SIGNAL_BY_RULE_ID = {
    RULE_ID_FORMAT: SIGNAL_FORMAT,
    RULE_ID_ENTROPY: SIGNAL_ENTROPY,
}

# The posting policy, declared here for the same reason `security_rules.py` declares it on the
# rule: `main.QUARANTINED_RULE_IDS` is the union of every tier's declaration, and
# `main.partition_by_posting_policy` is the one place a withheld finding is removed.
POSTING = {
    RULE_ID_FORMAT: POSTING_POST,
    RULE_ID_ENTROPY: POSTING_POST,
}

# A file with a lot of secrets in it is one review conversation, not five, and a `.env` with
# thirty keys is not thirty findings. The cap is per file and per signal.
MAX_FINDINGS_PER_FILE = 5

CATEGORY = "hardcoded secrets"
CWE_ID = "CWE-798"
OWASP_CATEGORY = "A07:2021"

# ── The two remediation messages ─────────────────────────────────────────────
# Both say the credential has to be rotated, because removing a value from the diff does not
# un-leak it: it is in the history, and anyone who could read the repository between the push
# and the removal has it. The second is for the shapes no template can rewrite, and it says
# outright that no fix is offered rather than leaving a reviewer waiting for one.
#
# These strings are the finding's `remediation`, which is the field the api-service publishes
# in the pull request comment and the field the Action renders in its annotation, so the App
# and the Action read the same sentence by construction.
REMEDIATION_MOVE_AND_ROTATE = (
    "Rotate this credential now, then replace the literal with a read from the environment "
    "or a secret manager. Rotating matters as much as removing: the value is in the commit "
    "history, so deleting the line does not un-leak it."
)
REMEDIATION_ROTATE_ONLY = (
    "Rotate this credential now, then remove it from the repository. Rotating matters as "
    "much as removing: the value is in the commit history, so deleting the line does not "
    "un-leak it. No automatic fix is offered for this shape, because the literal is not "
    "bound to a constant a template can rewrite."
)


# ── Entropy ──────────────────────────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    """Bits per character of `value`, over the characters it actually contains."""
    text = str(value or "")
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for character in text:
        counts[character] = counts.get(character, 0) + 1
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


HEX_ONLY_RE = re.compile(r"^[0-9a-fA-F]+$")
BASE62ISH_RE = re.compile(r"^[A-Za-z0-9+/=_\-.]+$")


def _character_classes(value: str) -> int:
    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


# Thresholds. Hex halves the alphabet, so the same key scores about 4 bits per character in
# base62 and about 3.9 at best in hex; one threshold for both would either miss every hex key
# or accept every lowercase word.
ENTROPY_MIN_LENGTH_BASE62 = 20
ENTROPY_MIN_BITS_BASE62 = 4.0
ENTROPY_MIN_LENGTH_HEX = 32
ENTROPY_MIN_BITS_HEX = 3.2
ENTROPY_MAX_LENGTH = 200


_SEGMENT_SPLIT_RE = re.compile(r"[-_.]+")


def random_core(value: str) -> str:
    """The longest segment of `value` that carries no separator.

    A credential's randomness lives in one segment; the rest is structure the vendor put
    there. `sk-live-7f3a91bc44de2210`, a fixture this repository's own `.gitleaksignore`
    records, is twenty-four characters of which sixteen are random, and scoring the whole
    string counted `sk` and `live` as entropy. Scoring the longest segment instead separates
    it from a real key, whose random part is the length the vendor chose.
    """
    segments = _SEGMENT_SPLIT_RE.split(str(value or ""))
    return max(segments, key=len) if segments else ""


def is_high_entropy_secret_value(value: str) -> bool:
    """True when `value` is long and random enough to be a key rather than a word.

    The measurement is made on `random_core(value)`, not on the whole string. Hex and base62
    are scored separately, and a base62 core must mix at least two character classes: a
    twenty-character lowercase-only string is a sentence fragment with the spaces taken out,
    not a credential.
    """
    text = str(value or "")
    if not text or len(text) > ENTROPY_MAX_LENGTH:
        return False
    core = random_core(text)
    if not core:
        return False
    if HEX_ONLY_RE.match(core):
        return len(core) >= ENTROPY_MIN_LENGTH_HEX and shannon_entropy(core) >= ENTROPY_MIN_BITS_HEX
    if not BASE62ISH_RE.match(core):
        # Spaces, quotes or punctuation beyond the base64 alphabet: a sentence or an
        # expression, not an encoded key.
        return False
    if len(core) < ENTROPY_MIN_LENGTH_BASE62:
        return False
    if _character_classes(core) < 2:
        return False
    return shannon_entropy(core) >= ENTROPY_MIN_BITS_BASE62


# ── What a credential identifier is called, and what it is not ───────────────

# The name is read as tokens rather than as a substring, because a substring list gets this
# wrong in both directions. `API_KEY` contains `key`, which has to be disqualifying on its own
# (`key` is a dictionary key far more often than a credential) and must not disqualify
# `api_key`; `password_hash` contains `password` and is not one. Splitting on separators and
# camelCase boundaries, then asking what the *last* token is and what qualifies it, decides
# both cases with one rule.
_TOKEN_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")

# A last token that makes the name an identifier, a location, a shape or a description rather
# than a credential. Checked first, and it wins: `token_url` is a URL.
NAME_DISQUALIFYING_TAILS = frozenset({
    "id", "ids", "uid", "guid", "name", "names", "path", "paths", "file", "files",
    "filename", "dir", "directory", "type", "types", "kind", "class", "size", "length",
    "len", "bytes", "prefix", "suffix", "pattern", "regex", "url", "uri", "urls", "uris",
    "endpoint", "endpoints", "host", "hostname", "port", "domain", "field", "fields",
    "header", "headers", "label", "labels", "policy", "policies", "hash", "hashes",
    "digest", "algorithm", "alg", "expiry", "expires", "expiration", "exp", "ttl", "arn",
    "ref", "refs", "version", "manager", "store", "storage", "count", "list", "keys",
    "env", "var", "vars", "column", "columns", "param", "params", "arg", "args",
    "placeholder", "example", "sample", "template", "format", "encoding", "scheme",
    "required", "optional", "enabled", "disabled", "mode", "provider", "source", "target",
    "input", "output", "error", "errors", "message", "messages", "description", "doc",
    "docs", "hint", "help", "prompt", "title", "form", "regexp", "selector", "locator",
    "key",  # bare `key` as the whole name, or as an unqualified tail
})

# A first token that says the value is not secret.
NAME_DISQUALIFYING_HEADS = frozenset({"public", "pub", "fake", "dummy", "mock", "example", "sample"})

# Tokens that are a credential on their own, wherever they appear as the last token.
CREDENTIAL_TAILS = frozenset({
    "token", "secret", "password", "passwd", "pwd", "passphrase", "credential",
    "credentials", "dsn", "authorization", "apikey", "seckey",
})

# Tokens that turn a bare `key` into a credential key.
KEY_QUALIFIERS = frozenset({
    "api", "secret", "access", "private", "signing", "sign", "encryption", "encrypt",
    "master", "license", "licence", "activation", "app", "application", "client",
    "consumer", "session", "cookie", "webhook", "shared", "refresh", "bearer", "auth",
    "authentication", "service", "admin", "root", "db", "database", "aws", "gcp", "azure",
    "stripe", "slack", "github", "gitlab", "twilio", "sendgrid", "openai", "anthropic",
    "mailgun", "sentry", "datadog", "jwt", "hmac", "crypto", "cipher", "deploy",
})

# Two-token phrases that are a credential however they end.
CREDENTIAL_BIGRAMS = frozenset({("connection", "string"), ("conn", "string")})


def name_tokens(name: str) -> List[str]:
    """`SESSION_SECRET`, `sessionSecret` and `session-secret` all read as the same two tokens."""
    spaced = _CAMEL_BOUNDARY_RE.sub("_", str(name or ""))
    return [token.lower() for token in _TOKEN_SPLIT_RE.split(spaced) if token]


def looks_like_credential_name(name: str) -> bool:
    """True when the identifier says the value is a credential.

    The order is what does the work: a disqualifying head, then a credential phrase, then
    `key` with a qualifier in front of it, then a self-standing credential tail, then a
    disqualifying tail. That separates `api_key` from `key_id` and `session_secret` from
    `secret_name` in one pass, and it leaves bare `key` on the disqualified side.
    """
    tokens = name_tokens(name)
    if not tokens:
        return False
    if tokens[0] in NAME_DISQUALIFYING_HEADS:
        return False
    for left, right in zip(tokens, tokens[1:]):
        if (left, right) in CREDENTIAL_BIGRAMS:
            return True
    tail = tokens[-1]
    if len(tokens) >= 2 and tail == "key" and tokens[-2] in KEY_QUALIFIERS:
        return True
    if tail in NAME_DISQUALIFYING_TAILS:
        return False
    return tail in CREDENTIAL_TAILS


# ── What a high-entropy value is legitimately allowed to be ──────────────────

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SRI_HASH_RE = re.compile(r"^sha(?:256|384|512)-")
DIGEST_NAME_RE = re.compile(
    r"(?:sha\d*|md5|hash|digest|checksum|integrity|etag|fingerprint|commit|revision|"
    r"oid|blob|tree|content[_-]?id)",
    re.IGNORECASE,
)
PATH_LIKE_RE = re.compile(r"^(?:\.{0,2}/|~/|[A-Za-z]:\\)|/[A-Za-z0-9_.\-]+\.[A-Za-z0-9]{1,6}$")
INTERPOLATION_RE = re.compile(r"\$\{|\{\{|%\(|%s\b|\$\(|<[A-Za-z_]|#\{")
ENV_READ_RE = re.compile(
    r"process\.env|os\.environ|os\.getenv|getenv|ENV\[|System\.getenv|"
    r"Environment\.GetEnvironmentVariable|secretmanager|vault",
    re.IGNORECASE,
)
PLACEHOLDER_VALUE_RE = re.compile(
    r"^(?:"
    r"x+|\*+|\.+|-+|_+|0+|"
    r"(?:your|my|the)[_-]?.*|"
    r".*(?:change[_-]?me|placeholder|redacted|removed|omitted|not[_-]?a[_-]?real|"
    r"replace[_-]?me|insert[_-]?here|todo|tbd|none|null|nil|undefined|"
    r"example|sample|dummy|fake|mock|stub|test|testing|demo|default|"
    r"foo|bar|baz|qux|lorem|ipsum|abc123|secret|password|hunter2).*"
    r")$",
    re.IGNORECASE,
)
REPEATED_CHARACTER_RE = re.compile(r"^(.)\1{7,}$")

# A JWT-shaped string, captured in three pieces so the signature can be looked at on its own.
JWT_SHAPED_RE = re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,})\.([A-Za-z0-9_\-]*)\.([A-Za-z0-9_\-]*)")


def _is_unsigned_jwt(value: str) -> bool:
    """A JWT with no signature, which anyone can mint and which therefore grants nothing.

    `_verify_jwt` already refuses these for the format signal, and the entropy signal has to
    refuse them too: otherwise the weaker signal re-reports under its own rule id exactly what
    the stronger one examined and rejected, and tells the author to rotate a token that was
    never a credential.

    The September 2026 measurement is where this came from. Juice-shop's `alg:none` forgery
    fixtures are `authorization: 'Bearer eyJ…fQ.'`, two segments and a trailing dot, and the
    entropy signal reported both of them at 5.4 bits under the identifier `authorization`.
    """
    for header, _payload, signature in JWT_SHAPED_RE.findall(str(value or "")):
        if len(signature) >= 10:
            continue
        if isinstance(_decode_base64url_json(header), dict):
            return True
    return False

# Lockfiles. `.lock` and `.json` are already `is_data_path`, but `go.sum`, `pnpm-lock.yaml`
# and `Pipfile.lock`'s siblings are not, and a lockfile is the single largest source of
# legitimately high-entropy strings in any repository.
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "bun.lockb", "bun.lock", "poetry.lock", "pipfile.lock", "pdm.lock", "uv.lock",
    "gemfile.lock", "cargo.lock", "composer.lock", "go.sum", "mix.lock",
    "packages.lock.json", "flake.lock", "conan.lock", "deno.lock",
}


def is_lockfile_path(path: Any) -> bool:
    name = str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return name in LOCKFILE_NAMES


def _is_base64_asset(value: str) -> bool:
    """A base64 blob rather than a key: a data URI, or long enough to be a file."""
    text = str(value or "")
    if text.lower().startswith("data:"):
        return True
    return len(text) > 120 and text.rstrip("=").isalnum() is False and "/" in text and "+" in text


ENTROPY_EXCLUSION_REASONS = (
    "lockfile_path",
    "non_code_text_path",
    "uuid",
    "subresource_integrity_hash",
    "digest_identifier",
    "path_like",
    "interpolation",
    "environment_read",
    "placeholder_value",
    "repeated_character",
    "base64_asset",
    "value_echoes_name",
    "published_example",
    "unsigned_jwt",
)


def entropy_exclusion_reason(name: str, value: str) -> Optional[str]:
    """Why a high-entropy value assigned to a credential name is not a finding.

    Returns the reason, so a test can name the shape it is protecting and a quarantine
    decision can say which exclusion was missing rather than "the heuristic".
    """
    text = str(value or "")
    if UUID_RE.match(text):
        return "uuid"
    if SRI_HASH_RE.match(text):
        return "subresource_integrity_hash"
    if DIGEST_NAME_RE.search(str(name or "")):
        return "digest_identifier"
    if PATH_LIKE_RE.search(text):
        return "path_like"
    if INTERPOLATION_RE.search(text):
        return "interpolation"
    if ENV_READ_RE.search(text):
        return "environment_read"
    if REPEATED_CHARACTER_RE.match(text):
        return "repeated_character"
    if PLACEHOLDER_VALUE_RE.match(text):
        return "placeholder_value"
    if is_published_example_value(text):
        return "published_example"
    if _is_unsigned_jwt(text):
        return "unsigned_jwt"
    if _is_base64_asset(text):
        return "base64_asset"
    if text.lower() == str(name or "").lower():
        return "value_echoes_name"
    return None


# ── Known key formats, and the structure each one declares ───────────────────

@dataclass(frozen=True)
class KeyFormat:
    secret_type: str
    label: str
    pattern: re.Pattern
    structure: str
    # A shape no template can rewrite to an environment read: the literal is not bound to a
    # constant. These post the rotation-only message and offer no patch.
    rotation_only: bool = False
    # A second pass over the captured value, for the formats that describe their own
    # content. Returning False means the candidate failed its own format.
    verify: Optional[Callable[[str], bool]] = None
    # The identifier on the line has to name the vendor. Used where the value's shape alone
    # is generic: a 40-character base64 string and a 32-character hex string are not
    # self-identifying.
    name_hint: Optional[re.Pattern] = None
    severity: str = "critical"
    confidence: float = 0.95


def _verify_jwt(value: str) -> bool:
    """A JWT with three segments, a decodable JSON header naming a real algorithm, a
    decodable JSON payload, and a non-empty signature.

    This is the verification the format makes possible: `eyJ` followed by two dots is a
    substring search, and a header that base64url-decodes to `{"alg":"HS256","typ":"JWT"}`
    is a token.
    """
    parts = str(value or "").split(".")
    if len(parts) != 3:
        return False
    header_raw, payload_raw, signature = parts
    if len(signature) < 10:
        return False
    header = _decode_base64url_json(header_raw)
    if not isinstance(header, dict):
        return False
    algorithm = header.get("alg")
    if not isinstance(algorithm, str) or not algorithm or algorithm.lower() == "none":
        return False
    return isinstance(_decode_base64url_json(payload_raw), dict)


def _decode_base64url_json(segment: str) -> Any:
    try:
        padded = segment + "=" * (-len(segment) % 4)
        return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


# The vocabulary every tutorial, compose file and `.env.example` uses. `dev`/`devpass123`
# and `pass123456` are in this repository's own documentation and tests.
PLACEHOLDER_PASSWORD_RE = re.compile(
    r"^(?:|x+|\*+|password\d*|passwd\d*|pass\d*|pwd\d*|secret\d*|changeme|change_me|"
    r"example\d*|sample\d*|test\d*|dev\d*|devpass\d*|local\d*|dummy\d*|fake\d*|"
    r"placeholder|redacted|your[_-]?password|mypassword|root|admin|postgres|mysql|mongo|"
    r"redis|guest|hunter2)$",
    re.IGNORECASE,
)

# A connection string whose host is a loopback address, a documentation domain or a bare
# service alias grants access to nothing outside the developer's own machine or compose
# network, and the password in it is a local development password. Four of the five
# connection strings this detector found in our own tree were exactly that.
# The bind-all address is in the set as a host to recognize and dismiss, never as an address
# anything here listens on, which is the only thing bandit's B104 is about.
LOCAL_OR_EXAMPLE_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "host.docker.internal",  # nosec B104
    "example.com", "example.org", "example.net", "test.com", "mydomain.com",
})
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_local_or_example_host(hostname: Optional[str]) -> bool:
    host = str(hostname or "").lower()
    if not host:
        return True
    if host in LOCAL_OR_EXAMPLE_HOSTS or host.endswith(".example.com") or host.endswith(".local"):
        return True
    if IPV4_RE.match(host):
        return host.startswith(("127.", "10.", "192.168.", "0."))
    # A bare alias with no dot: a docker-compose service name (`db`, `postgres`, `host`),
    # not a reachable address.
    return "." not in host


def _verify_connection_string_password(value: str) -> bool:
    """A database URL whose password is a real one, reaching a host outside the machine.

    The verification is a URL parse, not a regex: `urlsplit` is what decides where the
    password ends and what the host is. A URL with no password, an interpolated password,
    one of the vocabulary of placeholders every tutorial uses, or a host that is loopback,
    a documentation domain or a bare compose alias, is not a leak.
    """
    try:
        parts = urlsplit(str(value or ""))
        password = parts.password
        hostname = parts.hostname
    except ValueError:
        return False
    if not password:
        return False
    if INTERPOLATION_RE.search(password) or ENV_READ_RE.search(password):
        return False
    if PLACEHOLDER_PASSWORD_RE.match(password):
        return False
    if len(password) < 6:
        return False
    if _is_local_or_example_host(hostname):
        return False
    return password.lower() != (parts.username or "").lower()


def _verify_pem_private_key(value: str) -> bool:
    """A private key marker, not a public one and not a certificate."""
    text = str(value or "")
    if "PUBLIC KEY" in text or "CERTIFICATE" in text:
        return False
    return bool(re.match(r"^-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5}$", text.strip()))


# Values published as examples. AWS's own documentation uses the first two everywhere, and
# `EXAMPLE` in a key is a convention the vendors themselves adopted; a real 40-character
# random key containing the substring is a coincidence nobody will ever see.
PUBLISHED_EXAMPLE_VALUES = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAI44QH8DHBEXAMPLE",
    "ASIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}
DOCUMENTATION_MARKER_RE = re.compile(
    r"EXAMPLE|example|placeholder|PLACEHOLDER|redacted|REDACTED|xxxxxxxx|XXXXXXXX|"
    r"your[_-]?(?:key|token|secret)|YOUR[_-]?(?:KEY|TOKEN|SECRET)"
)

# Key bodies a vendor publishes in its own quickstart, which end up in thousands of
# repositories and in this repository's own rule comments. Checked as a substring, because
# the same body appears under several prefixes (`sk_live_`, `sk_test_`, `pk_test_`).
PUBLISHED_EXAMPLE_BODIES = (
    # Stripe's documentation key, the one `security_rules.py` quotes in its own comment.
    "4eC39HqLyjWDarjtT1zdp7dc",
    # The signature of the example token on jwt.io's front page, over the `{"sub":"1234567890",
    # "name":"John Doe","iat":1516239022}` payload and the secret `your-256-bit-secret`. It is
    # the single most copied JWT in existence, it passes `_verify_jwt` in full, and the
    # September 2026 measurement found it committed in juice-shop's own specs. A token whose
    # signing key is published on a documentation page is not a credential.
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
)


def _has_sequential_run(text: str, length: int = 8) -> bool:
    """A hand-typed fixture runs through the alphabet or the digits; a key does not.

    Eight, not ten, because the commonest hand-typed fixture body in this repository is
    `1234567890abcdef`: the ascending run there is `12345678 9` and then `0`, which is nine
    characters, and ten missed it. A real key containing eight ascending characters has a
    probability around 1 in 10^13 per position, so the shorter run costs nothing.
    """
    run = 1
    for previous, current in zip(text, text[1:]):
        if ord(current) - ord(previous) == 1:
            run += 1
            if run >= length:
                return True
        else:
            run = 1
    return False


def is_published_example_value(value: str) -> bool:
    """True when the value is a documented example rather than a credential.

    Applied to every key-format match, not only to the entropy signal: a fixed prefix and an
    exact length are satisfied by the example key in the vendor's own quickstart, and that
    example is in thousands of repositories.
    """
    text = str(value or "")
    if text in PUBLISHED_EXAMPLE_VALUES:
        return True
    if any(body in text for body in PUBLISHED_EXAMPLE_BODIES):
        return True
    if DOCUMENTATION_MARKER_RE.search(text):
        return True
    # The sequential run is looked for in the random core, not in the whole value. A real
    # Slack token embeds its team and installation ids, and `xoxb-123456789012-…` carries an
    # eight-character ascending run in a segment the vendor chose rather than in the secret.
    return _has_sequential_run(random_core(text))


def _verify_random_body(minimum_bits: float = 3.0) -> Callable[[str], bool]:
    """The random part of a prefixed token really is random.

    A format prefix plus the right number of characters is satisfied by `ghp_` and
    thirty-six zeroes, which is what a fixture looks like. The entropy floor here is low on
    purpose: it rejects a padded placeholder without making a judgement about the key.
    """

    def verify(value: str) -> bool:
        body = re.sub(r"^[A-Za-z_]+[-_.]", "", str(value or ""))
        if REPEATED_CHARACTER_RE.match(body):
            return False
        return shannon_entropy(body) >= minimum_bits

    return verify


def _verify_openai_key(value: str) -> bool:
    """A legacy `sk-` key needs the marker; a prefixed project key is self-identifying.

    `sk-` plus forty-eight alphanumerics collides with several other vendors' shapes, so the
    legacy form is only accepted when it carries the `T3BlbkFJ` marker every OpenAI key
    embeds. The project, service-account and admin prefixes are distinctive on their own.
    """
    text = str(value or "")
    if re.match(r"^sk-(?:proj|svcacct|admin)-", text):
        return _verify_random_body()(text)
    return "T3BlbkFJ" in text and _verify_random_body()(text)


KEY_FORMATS: List[KeyFormat] = [
    KeyFormat(
        secret_type="aws_access_key_id",
        label="AWS access key id",
        pattern=re.compile(
            r"\b((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b"
        ),
        structure="one of AWS's nine four-character key-type prefixes and exactly 20 base32 characters",
    ),
    KeyFormat(
        secret_type="aws_secret_access_key",
        label="AWS secret access key",
        pattern=re.compile(
            r"""aws[_-]?secret(?:[_-]?access)?[_-]?key\s*(?:=|:|=>)\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
            re.IGNORECASE,
        ),
        structure="exactly 40 base64 characters under an `aws_secret_access_key` identifier",
        verify=_verify_random_body(3.5),
        name_hint=re.compile(r"aws", re.IGNORECASE),
    ),
    KeyFormat(
        secret_type="github_token",
        label="GitHub token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36})\b"),
        structure=(
            "a `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` prefix and exactly 36 base62 characters, "
            "the length GitHub's token format fixes"
        ),
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="github_fine_grained_pat",
        label="GitHub fine-grained personal access token",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b"),
        structure="`github_pat_`, a 22-character identifier, an underscore and exactly 59 base62 characters",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="google_api_key",
        label="Google API key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        structure="the `AIza` prefix and exactly 35 further characters, a fixed total length of 39",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="slack_token",
        label="Slack token",
        pattern=re.compile(
            r"\b(xox[abposr]-(?:[0-9]{10,16}-){1,3}[A-Za-z0-9]{24,34})\b"
        ),
        structure="a `xox?-` prefix, Slack's numeric team and installation segments, and a 24-to-34 character tail",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="slack_webhook",
        label="Slack incoming webhook",
        pattern=re.compile(
            r"(https://hooks\.slack\.com/(?:services|workflows)/T[A-Za-z0-9_]{7,12}/"
            r"B[A-Za-z0-9_]{7,12}/[A-Za-z0-9]{24})"
        ),
        structure="the webhook host, a `T` team id, a `B` channel id and a 24-character secret tail",
        rotation_only=True,
    ),
    KeyFormat(
        secret_type="stripe_live_key",
        label="Stripe live secret key",
        pattern=re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b"),
        structure="the `sk_live_`/`rk_live_` prefix Stripe reserves for live secret keys, and at least 24 base62 characters",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="stripe_test_key",
        label="Stripe test secret key",
        pattern=re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{24,99})\b"),
        structure="the `sk_test_`/`rk_test_` prefix and at least 24 base62 characters",
        verify=_verify_random_body(),
        # A test key cannot move money, so it is not critical. It is still a credential that
        # should not be in a repository, and it is often the same account as the live one.
        severity="medium",
        confidence=0.9,
    ),
    KeyFormat(
        secret_type="twilio_api_key",
        label="Twilio API key",
        pattern=re.compile(r"\b(SK[0-9a-f]{32})\b"),
        structure="the `SK` prefix and exactly 32 lowercase hex characters",
        verify=_verify_random_body(),
        name_hint=re.compile(r"twilio|\bsid\b|api[_-]?key", re.IGNORECASE),
    ),
    KeyFormat(
        secret_type="twilio_auth_token",
        label="Twilio auth token",
        pattern=re.compile(
            r"""twilio[A-Za-z0-9_]{0,20}(?:auth[_-]?token|token|secret)\s*(?:=|:|=>)\s*['"]?([0-9a-fA-F]{32})['"]?""",
            re.IGNORECASE,
        ),
        structure="exactly 32 hex characters under a Twilio auth-token identifier",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="sendgrid_api_key",
        label="SendGrid API key",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"),
        structure="`SG.`, a 22-character key id, a dot and exactly 43 characters of secret",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="openai_api_key",
        label="OpenAI API key",
        pattern=re.compile(
            r"\b(sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{32,200}|sk-[A-Za-z0-9]{48})\b"
        ),
        structure=(
            "either a `sk-proj-`/`sk-svcacct-`/`sk-admin-` prefix, or the legacy 48-character "
            "form carrying the `T3BlbkFJ` marker every OpenAI key embeds"
        ),
        verify=_verify_openai_key,
    ),
    KeyFormat(
        secret_type="anthropic_api_key",
        label="Anthropic API key",
        pattern=re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,120})\b"),
        structure="the `sk-ant-api`/`sk-ant-admin` prefix with its two-digit version and an 80-to-120 character body",
        verify=_verify_random_body(),
    ),
    KeyFormat(
        secret_type="private_key_pem",
        label="Private key PEM block",
        pattern=re.compile(r"(-{5}BEGIN [A-Z0-9 ]*PRIVATE KEY-{5})"),
        structure="a PEM `BEGIN … PRIVATE KEY` armour marker, which a public key and a certificate do not carry",
        verify=_verify_pem_private_key,
        rotation_only=True,
    ),
    KeyFormat(
        secret_type="jwt",
        label="JSON Web Token",
        pattern=re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{10,})"),
        structure=(
            "three base64url segments whose header decodes to a JSON object naming a real "
            "`alg`, whose payload decodes to a JSON object, and whose signature is non-empty"
        ),
        verify=_verify_jwt,
        severity="high",
        confidence=0.9,
    ),
    KeyFormat(
        secret_type="database_connection_string",
        label="Database connection string with a password",
        pattern=re.compile(
            r"((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|"
            r"clickhouse|cockroachdb|jdbc:[a-z0-9]+)://[^\s'\"`<>]+)",
            re.IGNORECASE,
        ),
        structure="a URL that parses to a driver scheme, a host and a password that is neither empty, interpolated nor a placeholder",
        verify=_verify_connection_string_password,
    ),
]

KEY_FORMATS_BY_TYPE = {fmt.secret_type: fmt for fmt in KEY_FORMATS}


# ── The `.env` file case ─────────────────────────────────────────────────────
# A `.env` added to a pull request is a leak of everything in it, and it is a path-level
# finding rather than a line-level one: one review conversation, not one per variable.
#
# `.env.example`, `.env.sample`, `.env.template` and `.env.dist` are the documented
# placeholder files every project carries, so they are not this. `.env.local` and
# `.env.production` are real.
DOTENV_PATH_RE = re.compile(r"(?:^|/)\.env(?:\.[A-Za-z0-9_-]+)*$")
DOTENV_PLACEHOLDER_SUFFIXES = (
    ".example", ".sample", ".template", ".dist", ".tpl", ".defaults", ".schema", ".ci",
)
DOTENV_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<value>.*?)\s*$"
)


def is_dotenv_path(path: Any) -> bool:
    normalized = str(path or "").replace("\\", "/").lower()
    if not DOTENV_PATH_RE.search(normalized):
        return False
    name = normalized.rsplit("/", 1)[-1]
    return not name.endswith(DOTENV_PLACEHOLDER_SUFFIXES)


def is_dotenv_placeholder_path(path: Any) -> bool:
    """A `.env.example` and its siblings: a file whose whole purpose is placeholder values.

    Scanned by nothing. This repository's own `.env.example` files carry
    `DATABASE_URL=postgresql://dev:devpass123@localhost:5432/...`, which the connection
    string format matched before this gate existed.
    """
    normalized = str(path or "").replace("\\", "/").lower()
    if not DOTENV_PATH_RE.search(normalized):
        return False
    return normalized.rsplit("/", 1)[-1].endswith(DOTENV_PLACEHOLDER_SUFFIXES)


def _dotenv_value(raw: str) -> str:
    text = str(raw or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "'\"":
        text = text[1:-1]
    # A trailing comment on an unquoted value.
    return text.split(" #", 1)[0].strip()


def _dotenv_secret_line(name: str, value: str) -> bool:
    """A `.env` line that actually carries a credential.

    The file being a `.env` is not enough: `NODE_ENV=production` and `PORT=3000` are in every
    one of them. A line counts when a known key format matches the value, or when the
    identifier is a credential name and the value is neither a placeholder nor an
    interpolation.
    """
    if not value:
        return False
    if _first_format_match(value, context=f"{name}={value}") is not None:
        return True
    if not looks_like_credential_name(name):
        return False
    if entropy_exclusion_reason(name, value) is not None:
        return False
    return len(value) >= 8


# ── Matching ─────────────────────────────────────────────────────────────────

ASSIGNMENT_RE = re.compile(
    r"""(?P<name>[A-Za-z_$][A-Za-z0-9_$.\-]{1,60})\s*(?::=|=>|[:=])\s*"""
    r"""(?P<quote>['"`])(?P<value>[^'"`\n]{16,200})(?P=quote)"""
)


def _first_format_match(text: str, context: str = "") -> Optional[Dict[str, Any]]:
    """The first key format that matches `text` and passes its own verification."""
    haystack = context or text
    for fmt in KEY_FORMATS:
        for match in fmt.pattern.finditer(text):
            value = match.group(1)
            if is_published_example_value(value):
                continue
            if fmt.verify is not None and not fmt.verify(value):
                continue
            if fmt.name_hint is not None and not fmt.name_hint.search(haystack):
                continue
            return {"format": fmt, "value": value, "match": match}
    return None


def redact(value: str) -> str:
    """The evidence line quotes a shape, never a whole credential.

    `code_snippet` keeps the author's line as written, because that is what every other rule
    does and what the suggestion the App publishes has to match. The evidence sentence is
    this module's own prose, so it says `ghp_1234…` and the length instead of handing the
    credential to a second system.
    """
    text = str(value or "")
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}…{'*' * 6}… ({len(text)} characters)"


@dataclass
class SecretMatch:
    rule_id: str
    signal: str
    secret_type: str
    label: str
    line_number: int
    line_text: str
    matched_text: str
    severity: str
    confidence: float
    rotation_only: bool
    structure: str
    redacted: str
    extra: Dict[str, Any] = field(default_factory=dict)


def _format_matches(
    path: str, entries: List[Dict[str, Any]], claimed_lines: set
) -> List[SecretMatch]:
    """Format findings, recording in `claimed_lines` every line a format matched.

    A line whose key format was already reported under a different line is still that
    signal's line: the entropy pass must not pick the same value up again as its own finding.
    """
    matches: List[SecretMatch] = []
    seen: set = set()
    for entry in entries:
        line = str(entry.get("content") or "")
        found = _first_format_match(line)
        if found is None:
            continue
        claimed_lines.add(int(entry.get("line_number") or 0))
        fmt: KeyFormat = found["format"]
        value = found["value"]
        key = (fmt.secret_type, value)
        if key in seen:
            continue
        seen.add(key)
        matches.append(
            SecretMatch(
                rule_id=RULE_ID_FORMAT,
                signal=SIGNAL_FORMAT,
                secret_type=fmt.secret_type,
                label=fmt.label,
                line_number=int(entry.get("line_number") or 1),
                line_text=line,
                matched_text=value,
                severity=fmt.severity,
                confidence=fmt.confidence,
                rotation_only=fmt.rotation_only or not is_rewritable_credential_shape(path, line),
                structure=fmt.structure,
                redacted=redact(value),
            )
        )
        if len(matches) >= MAX_FINDINGS_PER_FILE:
            break
    return matches


def _entropy_matches(
    path: str,
    entries: List[Dict[str, Any]],
    lines_already_reported: Optional[set] = None,
) -> List[SecretMatch]:
    matches: List[SecretMatch] = []
    seen: set = set()
    already = lines_already_reported or set()
    for entry in entries:
        # A line the format signal has already reported is that signal's finding. Reporting
        # it twice would double-count one credential and would make each signal's measured
        # precision depend on the other's coverage.
        if int(entry.get("line_number") or 0) in already:
            continue
        line = str(entry.get("content") or "")
        for match in ASSIGNMENT_RE.finditer(line):
            name = match.group("name")
            value = match.group("value")
            if not looks_like_credential_name(name):
                continue
            if not is_high_entropy_secret_value(value):
                continue
            reason = entropy_exclusion_reason(name, value)
            if reason is not None:
                continue
            key = (name, value)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                SecretMatch(
                    rule_id=RULE_ID_ENTROPY,
                    signal=SIGNAL_ENTROPY,
                    secret_type="high_entropy_assignment",
                    label="High-entropy value assigned to a credential identifier",
                    line_number=int(entry.get("line_number") or 1),
                    line_text=line,
                    matched_text=match.group(0),
                    severity="high",
                    confidence=0.8,
                    rotation_only=not is_rewritable_credential_shape(path, line),
                    structure=(
                        f"{len(value)} characters at "
                        f"{shannon_entropy(value):.2f} bits per character under the identifier `{name}`"
                    ),
                    redacted=redact(value),
                    extra={
                        "identifier": name,
                        "entropy_bits_per_character": round(shannon_entropy(value), 2),
                        "value_length": len(value),
                    },
                )
            )
            if len(matches) >= MAX_FINDINGS_PER_FILE:
                return matches
    return matches


def _dotenv_match(path: str, entries: List[Dict[str, Any]]) -> Optional[SecretMatch]:
    for entry in entries:
        line = str(entry.get("content") or "")
        assignment = DOTENV_ASSIGNMENT_RE.match(line)
        if not assignment:
            continue
        name = assignment.group("name")
        value = _dotenv_value(assignment.group("value"))
        if not _dotenv_secret_line(name, value):
            continue
        return SecretMatch(
            rule_id=RULE_ID_FORMAT,
            signal=SIGNAL_FORMAT,
            secret_type="dotenv_file",
            label="Environment file with credentials committed",
            line_number=int(entry.get("line_number") or 1),
            line_text=line,
            matched_text=f"{name}=",
            severity="critical",
            confidence=0.95,
            rotation_only=True,
            structure=(
                f"a `.env` file, not a `.env.example`, carrying `{name}` with a value that is "
                "neither a placeholder nor an interpolation"
            ),
            redacted=redact(value),
            extra={"identifier": name},
        )
    return None


# ── What the `hardcoded_credential` repair family can actually rewrite ───────
#
# Mirrored, deliberately, from `services/remediation-service/src/sites.py`: `_JS_CONSTANT_RE`
# and `_JS_PROPERTY_RE` are the only two JavaScript shapes `_js_credential` rewrites, and
# `python_module_assignment` accepts only a **module-level** `NAME = "literal"`. The engine
# derives the family from the CWE (`families.rule_family`), so a CWE-798 finding is handed to
# that family whatever its shape; what this decides is whether the finding promises a fix or
# says plainly that there is none.
#
# If either of those matchers changes, change this in the same commit, the way
# `scripts/replay/prodfilters.py` mirrors the orchestrator's filters.
_JS_CREDENTIAL_SUFFIXES = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")
_JS_CONSTANT_SHAPE_RE = re.compile(
    r"""^\s*(?:export\s+)?(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*"""
    r"""(?::\s*[\w$.<>\[\]| ]+\s*)?=\s*(?P<quote>['"])(?P<literal>(?:(?!(?P=quote)).)*)(?P=quote)\s*;?\s*$"""
)
_JS_PROPERTY_SHAPE_RE = re.compile(
    r"""^\s*(?:[A-Za-z_$][\w$]*|['"][A-Za-z_$][\w$]*['"])\s*:\s*"""
    r"""(?P<quote>['"])(?P<literal>(?:(?!(?P=quote)).)*)(?P=quote)\s*,?\s*$"""
)
_PY_MODULE_ASSIGNMENT_SHAPE_RE = re.compile(
    r"""^(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<quote>['"])(?P<literal>.*)(?P=quote)\s*(?:#.*)?$"""
)


def _literal_is_rewritable(literal: str) -> bool:
    """`sites.js_literal_assignment` refuses an empty literal, an escape and an interpolation.

    An escape or a `${` means the characters in the source are not the characters of the
    value, so replacing the literal is not replacing the secret.
    """
    return bool(literal) and "\\" not in literal and "${" not in literal


def is_rewritable_credential_shape(path: str, line: str) -> bool:
    """True when the `hardcoded_credential` templates can move this literal to the environment.

    A key inside a JSON config, a PEM block, a `.env` line and an indented Python assignment
    are all outside the two JavaScript shapes and the one Python shape the family recognizes.
    A finding on one of those gets the rotation-only message instead of a promise of a patch.
    """
    normalized = str(path or "").lower()
    text = str(line or "").rstrip()
    if normalized.endswith(_JS_CREDENTIAL_SUFFIXES):
        for pattern in (_JS_CONSTANT_SHAPE_RE, _JS_PROPERTY_SHAPE_RE):
            match = pattern.match(text)
            if match and _literal_is_rewritable(match.group("literal")):
                return True
        return False
    if normalized.endswith(".py"):
        # Module level only: `python_module_assignment` reads `tree.body`, so an assignment
        # inside a function or a class is not a site, and indentation is how that shows on
        # the line.
        if text[:1].isspace():
            return False
        match = _PY_MODULE_ASSIGNMENT_SHAPE_RE.match(text)
        return bool(match) and _literal_is_rewritable(match.group("literal"))
    return False


# ── The public entry point ───────────────────────────────────────────────────

def secret_matches(path: str, patch: str, content: str = "") -> List[SecretMatch]:
    """Every secret this module recognizes in the **added** lines of `patch`.

    Separated from the finding construction so a measurement script, a test and the
    benchmark can all read the same verdicts without building a finding object.
    """
    entries = [
        entry
        for entry in parse_patch_entries(patch, path, content)
        if entry.get("kind") == "add" and not is_transcript_artifact_line(str(entry.get("content") or ""))
    ]
    if not entries:
        return []

    if is_dotenv_placeholder_path(path):
        return []

    if is_dotenv_path(path):
        match = _dotenv_match(path, entries)
        return [match] if match else []

    claimed_lines: set = set()
    matches = _format_matches(path, entries, claimed_lines)

    # The entropy signal is off wherever a repository legitimately writes high-entropy
    # strings down: a lockfile, a changelog, a JSON document, a template. The format signal
    # stays on, because a key that passes its own structural verification is a leak wherever
    # it is written, which is the same reason the tier 1 credential rule sets `scans_prose`.
    if not is_lockfile_path(path) and not is_non_code_text_path(path):
        matches.extend(_entropy_matches(path, entries, claimed_lines))

    return matches


def build_finding(match: SecretMatch, path: str) -> Dict[str, Any]:
    """A finding object in the shape `main.generate_finding` produces.

    Built here rather than in `main` because the evidence sentence, the remediation message
    and the fix routing are all properties of the signal that fired.
    """
    title = (
        f"{match.label} committed in this change"
        if match.signal == SIGNAL_FORMAT
        else "High-entropy credential value committed in this change"
    )
    description = (
        f"{match.label} appears on a line this pull request adds. Verified structure: "
        f"{match.structure}."
    )
    remediation = REMEDIATION_ROTATE_ONLY if match.rotation_only else REMEDIATION_MOVE_AND_ROTATE

    taxonomy = build_taxonomy_metadata(
        rule_id=match.rule_id,
        category=CATEGORY,
        cwe_id=CWE_ID,
        owasp_category=OWASP_CATEGORY,
        title=title,
        description=description,
        file_path=path,
        code_snippet=match.line_text,
    )

    finding: Dict[str, Any] = {
        "rule_id": match.rule_id,
        "internal_type": taxonomy["internal_type"],
        "title": title,
        "description": description,
        "category": CATEGORY,
        "cwe_id": taxonomy["primary_cwe_id"],
        "owasp_category": taxonomy["primary_owasp_category"],
        "taxonomy_mappings": taxonomy["taxonomy_mappings"],
        "taxonomy_versions": taxonomy["taxonomy_versions"],
        "severity": match.severity,
        "confidence": round(match.confidence, 2),
        "exploitability": "high",
        "file_path": path,
        "line_start": match.line_number,
        "line_end": match.line_number,
        "code_snippet": match.line_text,
        "evidence": (
            f"{match.label} on an added line: `{match.redacted}`. {match.structure}."
        ),
        "exploit_scenario": "",
        "remediation": remediation,
        "remediation_patch": "",
        "fingerprint": make_fingerprint(
            match.rule_id, path, match.line_number, match.line_text
        ),
    }

    extra: Dict[str, Any] = {
        "signal": match.signal,
        "secret_type": match.secret_type,
        "structure_verified": match.structure,
        "rotation_required": True,
        "secret_preview": match.redacted,
    }
    extra.update(match.extra)

    if not match.rotation_only:
        # The literal is bound to a constant, which is exactly the shape the
        # `hardcoded_credential` repair family rewrites, so the finding is routed into it
        # through the same CWE-798 dispatch every credential finding uses.
        finding["remediation_patch"] = build_remediation_patch(finding) or ""
        if finding["remediation_patch"]:
            finding["evidence_details"] = {
                "reviewability": "changed-lines-only",
                "fix_scope": "line",
                "fix_target_line": match.line_number,
                "fix_target_expr": match.matched_text,
                "missing_control_type": "secret_manager_or_environment_variable",
                "auto_fix_eligible": True,
                "extra": extra,
            }
            return finding

    extra["fix_offered"] = False
    finding["evidence_details"] = {"extra": extra}
    return finding


def secret_findings(path: str, patch: str, content: str = "") -> List[Dict[str, Any]]:
    """Tier 1's secrets pass over one changed file. The signature `dependency_findings` has."""
    return [build_finding(match, path) for match in secret_matches(path, patch, content)]
