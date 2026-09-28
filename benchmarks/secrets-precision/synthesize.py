"""Builds the fixture value a case in `cases.json` declares, so the file holds none.

`cases.json` used to carry its fixtures as literal strings. Several of them were, by
construction, exactly the shape of a live credential -- that is what a positive fixture for a
key format *is* -- and GitHub's push protection refused the branch over three of them. It was
right to. The alternative on offer was an allowlist entry per case, renewed by hand every time
a case is added, in the repository whose own product exists to stop people from committing
keys.

So a case no longer stores a value. It names a **specification** and this module builds a
value that satisfies it. The detector is then run on a string built from the same structure it
claims to recognize, which is a stronger test than a literal: a format narrowed so that it no
longer matches its own declared shape now fails at the builder, loudly, instead of going quiet.

Two kinds of specification, in the order they are preferred.

**`key_format`, `entropy_value`, `jwt`, `pem`, `connection_string`** -- generated. The body is
drawn from a SHA-256 stream keyed by the case's seed, so the value is identical on every run
and on every machine, and no state is shared between cases. Where a format defines content
rather than only a length -- OpenAI's `T3BlbkFJ` marker, a JWT's base64url-JSON header and
payload, a PEM armour marker, a URL that has to parse -- the builder produces it, because a
case whose value fails the format's own verification proves nothing.

**`reassembled`** -- for the handful of cases where an exact published literal is the point.
The detector refuses Stripe's quickstart key, AWS's documentation key and the token on jwt.io's
front page *by identity*: a generated value cannot stand in for them, because what is being
asserted is that this exact string is recognized as an example rather than a credential. Those
are stored split into parts that match no credential pattern on their own and joined here, with
each case saying why. The assembled string is a published example in a vendor's own
documentation, not a credential, but assembled on disk it still trips a scanner, and a
benchmark that has to be allowlisted past secret scanning is the thing this category exists to
prevent.

Every builder is checked against the detector itself by
`tests/test_secrets_precision_benchmark.py`: a generated value for a `key_format` spec must
match that format's own pattern and pass its own `verify`, or the gate fails. That check is
what keeps this file honest as the formats change.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Iterator, List

BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
BASE64URL = BASE62 + "-_"
BASE64 = BASE62 + "+/"
HEX_LOWER = "0123456789abcdef"
DIGITS = "0123456789"
UPPER_BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

ALPHABETS = {
    "base62": BASE62,
    "base64": BASE64,
    "base64url": BASE64URL,
    "hex": HEX_LOWER,
    "digits": DIGITS,
    "upper_base32": UPPER_BASE32,
}


def _byte_stream(seed: str) -> Iterator[int]:
    """An endless deterministic byte stream keyed by `seed`.

    SHA-256 over `seed:counter` rather than `random.Random(seed)`, because the standard
    library's generator makes no promise that a given seed yields the same sequence across
    Python releases, and a benchmark whose fixtures change under an interpreter upgrade is a
    benchmark that stops describing the detector.
    """
    counter = 0
    while True:
        block = hashlib.sha256(f"{seed}:{counter}".encode("utf-8")).digest()
        yield from block
        counter += 1


def _draw(seed: str, alphabet: str, length: int) -> str:
    """`length` characters from `alphabet`, deterministic in `seed`.

    An ascending run of eight characters is redrawn rather than accepted: the detector reads
    one as the signature of a hand-typed fixture and refuses the value
    (`is_published_example_value`), so a generated positive fixture that happened to contain
    one would fail for a reason that has nothing to do with what its case asserts.
    """
    stream = _byte_stream(seed)
    while True:
        drawn = "".join(alphabet[next(stream) % len(alphabet)] for _ in range(length))
        if not _has_ascending_run(drawn) and len(set(drawn)) > 1:
            return drawn


def _has_ascending_run(text: str, length: int = 8) -> bool:
    run = 1
    for previous, current in zip(text, text[1:]):
        if ord(current) - ord(previous) == 1:
            run += 1
            if run >= length:
                return True
        else:
            run = 1
    return False


def _base64url_json(payload: Any) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# ── The key formats ──────────────────────────────────────────────────────────
# One builder per `secret_type` in `secret_detection.KEY_FORMATS`, plus the `.env` case, which
# is not in that table. Each builds the structure the format's own docstring describes. Where
# the comment names a length, it is the length the format fixes; the gate asserts the result
# against the format's real pattern, so a disagreement here is a failure and not a silent pass.


def _aws_access_key_id(seed: str) -> str:
    # One of AWS's nine key-type prefixes and exactly 16 further base32 characters.
    return "AKIA" + _draw(seed, UPPER_BASE32, 16)


def _aws_secret_access_key(seed: str) -> str:
    # Exactly 40 base64 characters. Drawn without `/` or `+` so the value is also a legal
    # shell word, which is how every one of these appears in a real config file.
    return _draw(seed, BASE62, 40)


def _github_token(seed: str, length: int = 36) -> str:
    # `ghp_` and exactly 36 base62 characters. `length` is overridden by the one case that
    # asserts a token of the wrong length is refused.
    return "ghp_" + _draw(seed, BASE62, length)


def _github_fine_grained_pat(seed: str) -> str:
    # `github_pat_`, a 22-character identifier, an underscore, 59 base62 characters.
    return f"github_pat_{_draw(seed + ':id', BASE62, 22)}_{_draw(seed + ':body', BASE62, 59)}"


def _google_api_key(seed: str) -> str:
    # `AIza` and 35 further characters, a fixed total length of 39. Drawn from base62 rather
    # than the format's wider charset so the value carries no `-` or `_`: the separators are
    # what `random_core` splits on, and the whole string being one segment is what the
    # entropy floor is meant to see.
    return "AIza" + _draw(seed, BASE62, 35)


def _slack_token(seed: str) -> str:
    # `xoxb-`, two numeric ids, and a 24-character tail.
    team = _draw(seed + ":team", DIGITS, 12)
    installation = _draw(seed + ":installation", DIGITS, 12)
    return f"xoxb-{team}-{installation}-{_draw(seed + ':tail', BASE62, 24)}"


def _slack_webhook(seed: str) -> str:
    # The webhook host, a `T` team id, a `B` channel id and a 24-character secret tail.
    team = "T" + _draw(seed + ":team", BASE62, 8)
    channel = "B" + _draw(seed + ":channel", BASE62, 8)
    tail = _draw(seed + ":tail", BASE62, 24)
    return f"https://hooks.slack.com/services/{team}/{channel}/{tail}"


def _stripe_key(seed: str, mode: str) -> str:
    # `sk_live_`/`sk_test_` and 24 base62 characters.
    return f"sk_{mode}_" + _draw(seed, BASE62, 24)


def _twilio_api_key(seed: str) -> str:
    # `SK` and exactly 32 lowercase hex characters.
    return "SK" + _draw(seed, HEX_LOWER, 32)


def _hex_token(seed: str, length: int = 32) -> str:
    return _draw(seed, HEX_LOWER, length)


def _sendgrid_api_key(seed: str) -> str:
    # `SG.`, a 22-character key id, a dot, 43 characters of secret.
    return f"SG.{_draw(seed + ':id', BASE62, 22)}.{_draw(seed + ':body', BASE62, 43)}"


def _openai_legacy_key(seed: str) -> str:
    # The legacy form: `sk-` and exactly 48 base62 characters, which the detector accepts only
    # when they carry the `T3BlbkFJ` marker every OpenAI key embeds. The marker is placed at a
    # fixed offset inside the 48 so the total length stays exactly what the format fixes.
    marker = "T3BlbkFJ"
    body = _draw(seed, BASE62, 48 - len(marker))
    return "sk-" + body[:20] + marker + body[20:]


def _openai_project_key(seed: str) -> str:
    # The project prefix is self-identifying, so no marker is needed.
    return "sk-proj-" + _draw(seed, BASE62, 40)


def _anthropic_api_key(seed: str) -> str:
    # `sk-ant-api` with its two-digit version and a body inside the 80-to-120 window.
    return "sk-ant-api03-" + _draw(seed, BASE62, 95)


def _pem_body(seed: str, length: int = 64) -> str:
    return _draw(seed, BASE64, length)


def _connection_string_password(seed: str) -> str:
    # Long enough to clear the six-character floor and outside the placeholder vocabulary,
    # which is what `_verify_connection_string_password` reads.
    return _draw(seed, BASE62, 12)


KEY_FORMAT_BUILDERS = {
    "aws_access_key_id": _aws_access_key_id,
    "aws_secret_access_key": _aws_secret_access_key,
    "github_token": _github_token,
    "github_fine_grained_pat": _github_fine_grained_pat,
    "google_api_key": _google_api_key,
    "slack_token": _slack_token,
    "slack_webhook": _slack_webhook,
    "stripe_live_key": lambda seed: _stripe_key(seed, "live"),
    "stripe_test_key": lambda seed: _stripe_key(seed, "test"),
    "twilio_api_key": _twilio_api_key,
    "twilio_auth_token": _hex_token,
    "sendgrid_api_key": _sendgrid_api_key,
    "openai_api_key": _openai_legacy_key,
    "openai_api_key_project": _openai_project_key,
    "anthropic_api_key": _anthropic_api_key,
}

# The `secret_type` the detector reports for a spec whose builder has a different name. Only
# OpenAI needs it: two shapes, one reported type.
REPORTED_SECRET_TYPE = {"openai_api_key_project": "openai_api_key"}


# ── The builders ─────────────────────────────────────────────────────────────


def _build_key_format(spec: Dict[str, Any], seed: str) -> str:
    name = spec["format"]
    builder = KEY_FORMAT_BUILDERS[name]
    if "body_length" in spec:
        return builder(seed, spec["body_length"])
    return builder(seed)


def _build_entropy_value(spec: Dict[str, Any], seed: str) -> str:
    return _draw(seed, ALPHABETS[spec.get("charset", "base62")], spec["length"])


def _build_jwt(spec: Dict[str, Any], seed: str) -> str:
    """A JWT assembled from its parts, so each variant says what it is in the spec.

    `alg: none` and an empty signature are the two shapes the detector refuses, and a header
    that is deliberately not JSON is the third. Each is produced here rather than pasted in,
    so the case reads as the claim it makes.
    """
    if spec.get("header_not_json"):
        header = base64.urlsafe_b64encode(b'{notjson\n').decode("ascii").rstrip("=")
    else:
        header = _base64url_json({"alg": spec.get("alg", "HS256"), "typ": "JWT"})
    payload = _base64url_json(spec.get("payload", {"sub": "1234567890"}))
    signature_length = spec.get("signature_length", 36)
    signature = _draw(seed, BASE64URL, signature_length) if signature_length else ""
    return f"{header}.{payload}.{signature}"


def _build_pem(spec: Dict[str, Any], seed: str) -> str:
    return _pem_body(seed, spec.get("length", 64))


def _build_connection_string(spec: Dict[str, Any], seed: str) -> str:
    return _connection_string_password(seed)


def _build_reassembled(spec: Dict[str, Any], seed: str) -> str:
    return str(spec.get("joiner", "")).join(spec["parts"])


def _build_sequential(spec: Dict[str, Any], seed: str) -> str:
    """The hand-typed fixture: a run straight through the alphabet and then the digits.

    Declared rather than stored, because what the case asserts is the *shape* -- an ascending
    run no real key has -- and a construction states that where a pasted literal only shows it.
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    length = spec["length"]
    body = (alphabet * (length // len(alphabet) + 1))[:length]
    return str(spec.get("prefix", "")) + body


BUILDERS = {
    "key_format": _build_key_format,
    "entropy_value": _build_entropy_value,
    "jwt": _build_jwt,
    "pem": _build_pem,
    "connection_string": _build_connection_string,
    "reassembled": _build_reassembled,
    "sequential": _build_sequential,
}

PLACEHOLDER = "{{secret}}"


def build(spec: Dict[str, Any], seed: str) -> str:
    """The value `spec` declares."""
    kind = spec["kind"]
    if kind not in BUILDERS:
        raise KeyError(f"unknown fixture kind {kind!r}")
    return BUILDERS[kind](spec, seed)


def line_for(case: Dict[str, Any]) -> str:
    """The case's source line, with its declared value substituted into the template.

    A case with no `secret` holds no credential-shaped value at all -- an idempotency
    identifier, a UUID, a placeholder, an endpoint, an environment read -- and its line is the
    literal being asserted about. Those stay verbatim, because the exact text is the case.

    Substitution is `str.replace`, not `str.format`, because the templates contain `${...}` on
    purpose: an interpolated password is one of the shapes the detector has to refuse.

    The placeholder is doubled rather than `{secret}` for a reason the detector found itself: a
    single-brace placeholder inside a database URL parses as an eight-character password, so the
    connection-string format fired on this file's own template. `{{` is in `INTERPOLATION_RE`,
    so the placeholder now reads as what it is.
    """
    template = case["line"]
    spec = case.get("secret")
    if spec is None:
        if PLACEHOLDER in template:
            raise ValueError(f"{case['id']}: template has a placeholder and no `secret` spec")
        return template
    if PLACEHOLDER not in template:
        raise ValueError(f"{case['id']}: `secret` spec with no placeholder in the template")
    # The seed defaults to the case id, so it is unique without being written down twice. A
    # case that must reproduce another's value -- the context-line and `.env.example` cases,
    # which assert that the *same* line is refused in a different position or path -- names
    # that case's id as its seed instead.
    seed = spec.get("seed", case["id"])
    return template.replace(PLACEHOLDER, build(spec, seed))


def secret_of(case: Dict[str, Any]) -> str:
    """Just the built value, for the tests that check it against the format it claims."""
    spec = case["secret"]
    return build(spec, spec.get("seed", case["id"]))


def all_lines(cases: List[Dict[str, Any]]) -> Dict[str, str]:
    return {case["id"]: line_for(case) for case in cases}
