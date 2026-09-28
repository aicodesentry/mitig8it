"""The secrets precision gate.

`benchmarks/secrets-precision/cases.json` holds one true-positive fixture per key format and
per entropy shape the detector claims, and every line the September 2026 measurement read by
hand and judged wrong, including all nine entries of this repository's own `.gitleaksignore`.

The gate exists because both halves of a precision claim decay silently. A format narrowed to
remove a false positive stops matching its own key and nothing fails: the detector just goes
quiet, which is the state this category started from. An exclusion loosened for coverage
starts matching the fixture it was written to refuse, and the measured precision quietly
stops describing the detector.

This runs in the same suite and the same CI job as `test_tier1_precision_benchmark.py` and
`test_tier2_precision_benchmark.py`, so it is the same gate; it has its own case file because
the detector is Python rather than an OpenGrep rule and its cases are lines rather than files
to scan.

**The case file stores no credential.** A case names the format its fixture has and
`benchmarks/secrets-precision/synthesize.py` builds a value that satisfies it, keyed by a seed
that defaults to the case id. That module's own docstring says why: the literals this file used
to hold were, for the positive cases, exactly the shape of a live key, and GitHub's push
protection refused the branch over three of them rather than take a repository's word for it.
`TestTheFixtureBuildersMatchTheFormats` is what keeps the indirection honest -- a generated
value has to match the real format's real pattern and pass its real verification, so a format
narrowed away from its own declared shape fails there rather than going quiet.
"""

import json
import importlib.util
import re
from pathlib import Path

import pytest

import secret_detection as sd
from main import AnalyzePRRequest, analyze_tier1_payload

REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
BENCHMARK_DIR = REPOSITORY_ROOT / "benchmarks" / "secrets-precision"
# `<commit>:<path>:<gitleaks rule>:<line>`, the format gitleaks writes and reads.
GITLEAKS_ENTRY_RE = re.compile(r"^[0-9a-f]{40}:[^:]+:[^:]+:\d+$")
DOCUMENT = json.loads((BENCHMARK_DIR / "cases.json").read_text(encoding="utf-8"))
CASES = DOCUMENT["cases"]


def _load_synthesizer():
    """The fixture builder, loaded from the benchmark directory beside the cases it builds for.

    It lives there rather than in `src` because it is part of the case file's meaning: a
    reviewer reading a case has the specification and the builder side by side. It is not
    importable by name from here, so it is loaded by path.
    """
    path = BENCHMARK_DIR / "synthesize.py"
    spec = importlib.util.spec_from_file_location("secrets_precision_synthesize", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


synthesize = _load_synthesizer()

FINDING_CASES = [case for case in CASES if case["expect"] == "finding"]
NO_FINDING_CASES = [case for case in CASES if case["expect"] == "no-finding"]
GENERATED_KEY_FORMAT_CASES = [
    case
    for case in CASES
    if case.get("secret", {}).get("kind") == "key_format"
    and "body_length" not in case["secret"]
]


def _line(case):
    return synthesize.line_for(case)


def _patch(case):
    """The case's line as a one-line hunk, added unless the case says it is context."""
    line = _line(case)
    if case.get("as_context_line"):
        return "@@ -1,2 +1,2 @@\n %s\n+const unrelated = 1;\n" % line
    return "@@ -1,1 +1,1 @@\n+%s\n" % line


def _matches(case):
    return sd.secret_matches(case["path"], _patch(case))


def _ids(cases):
    return [case["id"] for case in cases]


class TestTheCaseFileHoldsNoCredential:
    """The property that made this rewrite necessary, asserted rather than trusted.

    The detector is the best scanner this repository has for its own case file, so it is the
    one used: every line of `cases.json` as it sits on disk is run through the format signal,
    and nothing may fire. A case that goes back to pasting a key fails here, before a push
    does, and without an allowlist entry to renew.
    """

    # The one thing in `cases.json` the detector matches, and it is not key material: the PEM
    # armour marker is the whole of `tp.format.private-key-pem`'s line, with no key after it.
    # A marker on its own is what the format matches, so there is nothing to build and nothing
    # to steal. Named here rather than skipped, so that a *second* match fails this test.
    ALLOWED_IN_THE_CASE_FILE = {("private_key_pem", "-----BEGIN RSA PRIVATE KEY-----")}

    @staticmethod
    def _whole_file_matches(name):
        text = (BENCHMARK_DIR / name).read_text(encoding="utf-8")
        lines = text.split("\n")
        patch = "@@ -0,0 +1,%d @@\n" % len(lines) + "\n".join(f"+{line}" for line in lines)
        return sd.secret_matches(f"benchmarks/secrets-precision/{name}", patch)

    def test_no_line_of_the_case_file_carries_a_key(self):
        """The detector is the best scanner this repository has, so it reads its own case file.

        As `.json`, which is the path the file really has: the entropy signal is off for a data
        document, so what this asserts is the format signal, the one that models a published key
        shape and the one push protection agrees with.
        """
        fired = {
            (match.secret_type, match.matched_text.strip())
            for match in self._whole_file_matches("cases.json")
        }
        assert fired <= self.ALLOWED_IN_THE_CASE_FILE, sorted(fired - self.ALLOWED_IN_THE_CASE_FILE)

    def test_the_builder_file_carries_no_key_either(self):
        """The specifications describe key shapes; none of them is a key."""
        fired = [
            (match.secret_type, match.line_number)
            for match in self._whole_file_matches("synthesize.py")
        ]
        assert not fired, fired

    def test_every_positive_fixture_is_built_rather_than_stored(self):
        """A true positive is by definition key-shaped, so it may never be a stored literal."""
        for case in FINDING_CASES:
            if case["secret_type"] == "private_key_pem" and "secret" not in case:
                # The bare armour marker, which is the whole of that case's line and is the
                # detector's own pattern rather than key material.
                assert case["line"].startswith("-----BEGIN"), case["id"]
                continue
            assert "secret" in case, case["id"]
            assert synthesize.PLACEHOLDER in case["line"], case["id"]


class TestTheFixtureBuildersMatchTheFormats:
    """A generated fixture has to satisfy the format it claims, or the case proves nothing.

    This is the link that makes a specification safe to substitute for a literal. A format
    narrowed so that it no longer accepts its own declared structure fails here, naming the
    builder, instead of quietly matching nothing and taking the case's assertion with it.
    """

    @pytest.mark.parametrize(
        "case", GENERATED_KEY_FORMAT_CASES, ids=_ids(GENERATED_KEY_FORMAT_CASES)
    )
    def test_the_built_value_matches_the_real_pattern_and_verifier(self, case):
        """Matched against the built *line*, because two formats are identifier-scoped.

        `aws_secret_access_key` and `twilio_auth_token` are forty base64 and thirty-two hex
        characters, which are not self-identifying shapes; the pattern requires the vendor's own
        identifier beside them, and that identifier is part of the case's template. So the line
        is what the format is given, exactly as tier 1 gives it one.
        """
        spec = case["secret"]
        secret_type = synthesize.REPORTED_SECRET_TYPE.get(spec["format"], spec["format"])
        fmt = sd.KEY_FORMATS_BY_TYPE[secret_type]

        match = fmt.pattern.search(_line(case))
        assert match, f"{case['id']}: the {secret_type} pattern does not match its own fixture"
        captured = match.group(1)
        assert synthesize.secret_of(case) in _line(case), case["id"]
        assert not sd.is_published_example_value(captured), case["id"]
        if fmt.verify is not None:
            assert fmt.verify(captured), f"{case['id']}: failed {secret_type} verification"

    def test_every_builder_is_reachable_from_a_case(self):
        """A builder nothing exercises is a specification nobody has checked."""
        declared = set(synthesize.KEY_FORMAT_BUILDERS)
        used = {
            case["secret"]["format"]
            for case in CASES
            if case.get("secret", {}).get("kind") == "key_format"
        }
        assert declared - used == set(), sorted(declared - used)

    def test_building_is_deterministic(self):
        assert synthesize.all_lines(CASES) == synthesize.all_lines(CASES)

    # A case that asserts the *same* line is refused somewhere else: in a context line rather
    # than an added one, in `.env.example` rather than `.env`, or in a second file carrying the
    # same fixture. Each pair shares a seed, and sharing a seed has to mean sharing a string.
    SHARED_VALUE_PAIRS = [
        ("fp.scope.context-line", "tp.format.stripe-live-key"),
        ("fp.scope.dotenv-example", "tp.format.dotenv-file"),
        (
            "fp.own-repo.gitleaksignore.proof-module-closure-fixture",
            "fp.own-repo.gitleaksignore.dependency-installed-fixture",
        ),
        ("fp.path.prose-entropy", "tp.entropy.session-secret"),
    ]

    def test_cases_that_must_share_a_value_do(self):
        lines = synthesize.all_lines(CASES)
        checked = 0
        for left, right in self.SHARED_VALUE_PAIRS:
            if left not in lines or right not in lines:
                continue
            assert synthesize.secret_of(next(c for c in CASES if c["id"] == left)) == (
                synthesize.secret_of(next(c for c in CASES if c["id"] == right))
            ), f"{left} and {right} share a seed but not a value"
            checked += 1
        assert checked, "no shared-value pair was found to check"

    def test_no_two_cases_share_a_value_by_accident(self):
        """Distinct seeds must give distinct fixtures, or a case is testing another's value."""
        built = {}
        for case in CASES:
            if "secret" not in case:
                continue
            value = synthesize.secret_of(case)
            seed = case["secret"].get("seed", case["id"])
            built.setdefault(value, set()).add(seed)
        collisions = {value: seeds for value, seeds in built.items() if len(seeds) > 1}
        assert not collisions, sorted(collisions.values())


class TestSetIntegrity:
    def test_every_case_is_well_formed(self):
        for case in CASES:
            assert case["expect"] in ("finding", "no-finding"), case["id"]
            assert case["path"] and case["line"] and case["evidence"], case["id"]
            if case["expect"] == "finding":
                assert case["signal"] in DOCUMENT["signals"], case["id"]
                assert case["secret_type"], case["id"]
            else:
                assert case["reason"] in DOCUMENT["no_finding_reasons"], case["id"]

    def test_every_reassembled_case_says_why(self):
        """Storing a literal at all is the exception, so each one carries its own reason."""
        for case in CASES:
            spec = case.get("secret") or {}
            if spec.get("kind") == "reassembled":
                assert spec.get("why"), case["id"]
                assert spec["parts"], case["id"]

    def test_case_ids_are_unique(self):
        ids = _ids(CASES)
        assert len(ids) == len(set(ids))

    def test_every_key_format_has_a_true_positive_fixture(self):
        """A format with no fixture is a format nobody has shown works."""
        covered = {case["secret_type"] for case in FINDING_CASES}
        declared = {fmt.secret_type for fmt in sd.KEY_FORMATS}
        assert declared - covered == set(), sorted(declared - covered)

    def test_the_dotenv_case_is_covered_too(self):
        """`dotenv_file` is not in `KEY_FORMATS`, so the check above cannot reach it."""
        assert "dotenv_file" in {case["secret_type"] for case in FINDING_CASES}

    def test_both_signals_have_true_positive_fixtures(self):
        assert {case["signal"] for case in FINDING_CASES} == set(DOCUMENT["signals"])

    def test_every_recorded_no_finding_reason_is_used(self):
        unused = sorted(set(DOCUMENT["no_finding_reasons"]) - {c["reason"] for c in NO_FINDING_CASES})
        assert not unused, f"reasons documented but never exercised: {unused}"

    def test_every_gitleaksignore_entry_is_represented(self):
        """Our own known false positives are in the set, read out of `.gitleaksignore` itself.

        By path, not by count. The idempotency key appears in five files and the
        `sk-live-abc123def456` fixture in two, and a count would have let a case stand in for a
        file it was never run against; the path is what decides scope, so each entry needs its
        own case. Adding a line to `.gitleaksignore` without adding its case fails here.
        """
        entries = {
            line.strip().split(":")[1]
            for line in (REPOSITORY_ROOT / ".gitleaksignore").read_text().split("\n")
            if GITLEAKS_ENTRY_RE.match(line.strip())
        }
        assert entries, "the known-false-positive set was not found"
        covered = {
            case["path"] for case in NO_FINDING_CASES if "gitleaksignore" in case["id"]
        }
        assert entries - covered == set(), sorted(entries - covered)


class TestTruePositivesStillFire:
    @pytest.mark.parametrize("case", FINDING_CASES, ids=_ids(FINDING_CASES))
    def test_the_case_produces_its_finding(self, case):
        found = {(match.rule_id, match.secret_type) for match in _matches(case)}
        assert (case["signal"], case["secret_type"]) in found, sorted(found)

    @pytest.mark.parametrize("case", FINDING_CASES, ids=_ids(FINDING_CASES))
    def test_the_finding_reaches_a_reviewer(self, case):
        """A true positive that the posting policy withholds is not a true positive yet."""
        result = analyze_tier1_payload(
            AnalyzePRRequest(
                repository_full_name="acme/app",
                pull_request_number=1,
                commit_sha="a" * 40,
                files=[{"path": case["path"], "patch": _patch(case)}],
            )
        )
        assert case["signal"] in {finding["rule_id"] for finding in result["findings"]}


class TestNoFindingCasesStaySilent:
    @pytest.mark.parametrize("case", NO_FINDING_CASES, ids=_ids(NO_FINDING_CASES))
    def test_the_case_produces_no_secrets_finding(self, case):
        """Nothing fires, unless the case names one signal that must stay silent.

        `silent_signal` is for a line where one signal is wrong and the other is not. A
        thirty-five-character random token is not a GitHub token, and the format signal has to
        say so; the entropy signal reporting an unrecognised high-entropy credential on the
        same line is a different claim and a defensible one.
        """
        fired = [(match.rule_id, match.secret_type) for match in _matches(case)]
        silent = case.get("silent_signal")
        if silent:
            assert not [row for row in fired if row[0] == silent], f"{case['id']}: {fired}"
            return
        assert not fired, f"{case['id']} ({case['reason']}): {fired}"


class TestEveryFindingSaysToRotate:
    @pytest.mark.parametrize("case", FINDING_CASES, ids=_ids(FINDING_CASES))
    def test_the_rotation_sentence_is_on_the_finding(self, case):
        """Removing a value from the diff does not un-leak it, and the copy has to say so.

        It is the same sentence in the App and in the Action because it is a field on the
        finding, not a string either publisher owns.
        """
        finding = sd.secret_findings(case["path"], _patch(case))[0]
        assert "Rotate this credential now" in finding["remediation"]
        assert "does not un-leak it" in finding["remediation"]
        assert finding["evidence_details"]["extra"]["rotation_required"] is True

    @pytest.mark.parametrize(
        "case",
        [c for c in FINDING_CASES if c["secret_type"] in ("private_key_pem", "dotenv_file", "slack_webhook")],
        ids=_ids([c for c in FINDING_CASES if c["secret_type"] in ("private_key_pem", "dotenv_file", "slack_webhook")]),
    )
    def test_a_shape_no_template_can_rewrite_offers_no_fix(self, case):
        finding = sd.secret_findings(case["path"], _patch(case))[0]
        assert finding["remediation_patch"] == ""
        assert finding["remediation"] == sd.REMEDIATION_ROTATE_ONLY
        assert finding["evidence_details"]["extra"]["fix_offered"] is False
