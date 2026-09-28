"""The secrets detector: the two signals, the structure each format verifies, and the
shapes that are legitimately high entropy.

The tests are grouped the way the precision argument is: what the format signal accepts and
why, what the entropy signal refuses and which exclusion refuses it, where the path model
turns a signal off, and what the finding promises a reviewer.
"""

import base64
import json

import pytest

import secret_detection as sd
from main import (
    AnalyzePRRequest,
    LEGACY_CREDENTIAL_RULE_ID,
    QUARANTINED_RULE_IDS,
    analyze_tier1_payload,
)


def patch_of(*lines):
    header = "@@ -1,%d +1,%d @@\n" % (len(lines), len(lines))
    return header + "".join(f"+{line}\n" for line in lines)


def types_in(path, *lines, content=""):
    return [match.secret_type for match in sd.secret_matches(path, patch_of(*lines), content)]


# Not jwt.io's example signature. That one is now in `PUBLISHED_EXAMPLE_BODIES`, because the
# September 2026 measurement found it committed in juice-shop's specs and a token whose signing
# key is published on a documentation page is not a credential. A fixture signed with it would
# assert the opposite of what the detector now does.
def jwt(alg="HS256", signature="k8Rm2QpLzV4nB7xW1sT6yU3hJ9dF0gA5cE2vN8iO7bY"):
    def segment(payload):
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    return f"{segment({'alg': alg, 'typ': 'JWT'})}.{segment({'sub': '1234567890'})}.{signature}"


# Random-looking values built here rather than pasted, so nothing in this file is a string a
# secret scanner should flag in our own repository.
RANDOM_22 = "k8Rm2QpLzV4nB7xW1sT6yU"
RANDOM_28 = "k8Rm2QpLzV4nB7xW1sT6yU3hJ9dF"
RANDOM_36 = "k8Rm2QpLzV4nB7xW1sT6yU3hJ9dF0gA5cE2v"
RANDOM_40 = "k8Rm2QpLzV4nB7xW1sT6yU3hJ9dF0gA5cE2vN8iO"
RANDOM_48 = "k8Rm2QpLzV4nT3BlbkFJB7xW1sT6yU3hJ9dF0gA5cE2vN8iO"
RANDOM_59 = "9dF0gA5cE2vN8iO7bY4qZ3mX6pL1kR8mQ2pLzV4nB7xW1sT6yU3hJ9dF0gA"
RANDOM_35 = "yD-k8Rm2QpLzV4nB7xW1sT6yU3hJ9dF0gA5"
RANDOM_43 = "3hJ9dF0gA5cE2vN8iO7bY4qZ3mX6pL1kR8mQ2pLzV4n"
RANDOM_24 = "k8Rm2QpLzV4nB7xW1sT6yU3h"
RANDOM_32_HEX = "a7f3c9e1b4d2680fa5c8e3b7d1409f62"
RANDOM_95 = RANDOM_48 + RANDOM_40 + "k8Rm2Qp"


class TestAddedLinesOnly:
    def test_a_context_line_is_not_a_finding(self):
        """An existing secret is not this pull request's fault."""
        patch = "@@ -1,3 +1,3 @@\n const key = \"sk_live_%s\";\n-const old = 1;\n+const new = 1;\n" % RANDOM_24
        assert sd.secret_matches("src/app.js", patch) == []

    def test_a_removed_line_is_not_a_finding(self):
        patch = "@@ -1,2 +1,1 @@\n-const key = \"sk_live_%s\";\n+const key = process.env.KEY;\n" % RANDOM_24
        assert sd.secret_matches("src/app.js", patch) == []

    def test_an_added_line_is(self):
        assert types_in("src/app.js", f'const key = "sk_live_{RANDOM_24}";') == ["stripe_live_key"]


class TestKeyFormats:
    @pytest.mark.parametrize(
        "secret_type,line",
        [
            ("aws_access_key_id", f'AWS_ID = "AKIA{RANDOM_22[:16].upper()}"'),
            ("aws_secret_access_key", f'aws_secret_access_key = "{RANDOM_40}"'),
            ("github_token", f'GH = "ghp_{RANDOM_36}"'),
            ("github_token", f'GH = "ghs_{RANDOM_36}"'),
            ("github_fine_grained_pat", f'GH = "github_pat_{RANDOM_22}_{RANDOM_59}"'),
            ("google_api_key", f'GOOGLE = "AIza{RANDOM_35}"'),
            ("slack_token", f'SLACK = "xoxb-123456789012-987654321098-{RANDOM_24}"'),
            (
                "slack_webhook",
                'HOOK = "https://hooks.slack.com/services/T0K8RM2QP/B7XW1ST6Y/%s"' % RANDOM_24,
            ),
            ("stripe_live_key", f'STRIPE = "sk_live_{RANDOM_24}"'),
            ("stripe_test_key", f'STRIPE = "sk_test_{RANDOM_24}"'),
            ("twilio_api_key", f'TWILIO_API_KEY = "SK{RANDOM_32_HEX}"'),
            ("twilio_auth_token", f'twilio_auth_token = "{RANDOM_32_HEX}"'),
            ("sendgrid_api_key", f'SENDGRID = "SG.{RANDOM_22}.{RANDOM_43}"'),
            ("openai_api_key", f'OPENAI = "sk-{RANDOM_48}"'),
            ("openai_api_key", f'OPENAI = "sk-proj-{RANDOM_40}"'),
            ("anthropic_api_key", f'ANTHROPIC = "sk-ant-api03-{RANDOM_95}"'),
            ("private_key_pem", "-----BEGIN RSA PRIVATE KEY-----"),
            ("private_key_pem", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("jwt", f'ID_TOKEN = "{jwt()}"'),
            (
                "database_connection_string",
                'DATABASE_URL = "postgresql://appuser:Xk9mQ2pLzV4n@db.internal:5432/prod"',
            ),
        ],
    )
    def test_the_format_is_recognized(self, secret_type, line):
        assert secret_type in types_in("src/settings.py", line)

    def test_every_format_has_a_case_here(self):
        """A format with no test is a format nobody has shown works."""
        covered = {
            "aws_access_key_id", "aws_secret_access_key", "github_token",
            "github_fine_grained_pat", "google_api_key", "slack_token", "slack_webhook",
            "stripe_live_key", "stripe_test_key", "twilio_api_key", "twilio_auth_token",
            "sendgrid_api_key", "openai_api_key", "anthropic_api_key", "private_key_pem",
            "jwt", "database_connection_string",
        }
        assert {fmt.secret_type for fmt in sd.KEY_FORMATS} == covered


class TestStructureIsVerified:
    """The difference between a detector and a substring search."""

    def test_a_github_token_one_character_short_is_not_one(self):
        assert types_in("src/a.py", f'GH = "ghp_{RANDOM_36[:-1]}"') == []

    def test_a_github_token_one_character_long_is_not_one(self):
        assert types_in("src/a.py", f'GH = "ghp_{RANDOM_36}x"') == []

    def test_an_aws_key_id_needs_one_of_the_nine_prefixes(self):
        assert types_in("src/a.py", f'AWS = "AKXA{RANDOM_22[:16].upper()}"') == []

    def test_a_google_key_needs_exactly_thirty_nine_characters(self):
        assert types_in("src/a.py", f'G = "AIza{RANDOM_35[:-1]}"') == []

    def test_a_padded_placeholder_fails_the_entropy_floor(self):
        assert types_in("src/a.py", 'GH = "ghp_000000000000000000000000000000000000"') == []

    def test_a_jwt_needs_a_decodable_json_header(self):
        assert types_in("src/a.js", 'const t = "eyJub3Rqc29uCg.eyJzdWIiOjF9.aaaaaaaaaaaaaa"') == []

    def test_a_jwt_with_alg_none_is_not_a_credential(self):
        assert "jwt" not in types_in("src/a.js", f'const configured = "{jwt(alg="none")}"')

    def test_a_jwt_needs_a_non_empty_signature(self):
        assert types_in("src/a.js", f'const t = "{jwt(signature="")}"') == []

    def test_a_pem_public_key_is_not_a_private_key(self):
        assert types_in("src/a.py", "-----BEGIN PUBLIC KEY-----") == []

    def test_a_pem_certificate_is_not_a_private_key(self):
        assert types_in("src/a.py", "-----BEGIN CERTIFICATE-----") == []

    def test_a_connection_string_with_no_password_is_not_a_leak(self):
        assert types_in("src/a.py", 'URL = "postgresql://appuser@db.internal:5432/prod"') == []

    def test_a_connection_string_with_a_placeholder_password_is_not_a_leak(self):
        assert types_in("src/a.py", 'URL = "postgresql://app:password@localhost:5432/dev"') == []

    def test_a_connection_string_with_an_interpolated_password_is_not_a_leak(self):
        assert types_in("src/a.py", 'URL = "postgresql://app:${DB_PASSWORD}@localhost/dev"') == []

    def test_a_legacy_openai_key_without_the_marker_is_not_one(self):
        without_marker = RANDOM_48.replace("T3BlbkFJ", "k8Rm2Qp0")
        assert len(without_marker) == 48
        assert "openai_api_key" not in types_in("src/a.py", f'K = "sk-{without_marker}"')

    def test_the_aws_secret_key_needs_the_vendor_in_the_identifier(self):
        """Forty base64 characters is not a self-identifying shape."""
        assert types_in("src/a.py", f'SOME_BLOB = "{RANDOM_40}"') == []


class TestPublishedExamples:
    @pytest.mark.parametrize(
        "line",
        [
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
            'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
            'GH = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"',
        ],
    )
    def test_a_documented_example_is_not_a_credential(self, line):
        assert types_in("src/a.py", line) == []

    def test_a_sequential_run_is_a_hand_typed_fixture(self):
        assert sd.is_published_example_value("abcdefghijklmnop")
        assert not sd.is_published_example_value(RANDOM_36)

    def test_the_jwt_io_example_token_is_not_a_credential(self):
        """The most copied JWT in existence, and it passes `_verify_jwt` in full.

        Its signing key is `your-256-bit-secret`, printed beside it on jwt.io's front page, so
        the token grants nothing. The September 2026 measurement found it committed in
        juice-shop's own Angular specs, which is where this case came from; every tutorial that
        shows a decoded JWT has the same string in it.
        """
        example = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        assert sd._verify_jwt(example), "the token is well formed; that is the point"
        assert sd.is_published_example_value(example)
        assert types_in("src/auth.js", f"const token = '{example}';") == []


class TestEntropySignal:
    def test_a_random_value_under_a_credential_name_is_a_finding(self):
        assert types_in("src/cfg.py", f'SESSION_SECRET = "{RANDOM_28}"') == [
            "high_entropy_assignment"
        ]

    def test_camel_case_names_are_read_the_same_way(self):
        assert types_in("src/cfg.js", f'const signingKey = "{RANDOM_28}";') == [
            "high_entropy_assignment"
        ]

    @pytest.mark.parametrize(
        "name",
        ["key", "key_id", "keyName", "keyword", "public_key", "password_hash", "token_url",
         "TOKEN_TYPE", "secret_name", "credentials_path", "AUTHORIZATION_HEADER",
         "api_key_length", "fake_token"],
    )
    def test_a_near_miss_name_is_not_a_credential_name(self, name):
        assert not sd.looks_like_credential_name(name)
        assert types_in("src/cfg.py", f'{name} = "{RANDOM_28}"') == []

    @pytest.mark.parametrize(
        "name",
        ["api_key", "API_KEY", "apiKey", "secret_key", "access_token", "AUTH_TOKEN",
         "session_secret", "clientSecret", "PASSWORD", "passphrase", "connection_string",
         "signing_key", "sas_token", "dsn"],
    )
    def test_a_credential_name_is_one(self, name):
        assert sd.looks_like_credential_name(name)

    @pytest.mark.parametrize(
        "value,reason",
        [
            ("550e8400-e29b-41d4-a716-446655440000", "uuid"),
            ("sha512-" + RANDOM_40, "subresource_integrity_hash"),
            ("./fixtures/keys/service-account.json", "path_like"),
            ("${AWS_SECRET_ACCESS_KEY}", "interpolation"),
            ("os.environ['API_KEY']", "environment_read"),
            ("xxxxxxxxxxxxxxxxxxxxxxxx", "repeated_character"),
            ("your-api-key-goes-right-here", "placeholder_value"),
            ("data:image/png;base64," + RANDOM_40, "base64_asset"),
        ],
    )
    def test_the_named_exclusion_refuses_the_value(self, value, reason):
        assert sd.entropy_exclusion_reason("api_key", value) == reason
        assert types_in("src/cfg.py", f'api_key = "{value}"') == []

    def test_an_unsigned_jwt_is_not_a_credential_the_entropy_signal_may_claim(self):
        """The format signal refuses an `alg:none` token; the entropy signal has to agree.

        Anyone can mint a token with no signature, so it grants nothing. What made this a
        finding was the identifier: `authorization`, at 5.4 bits over 142 characters. The
        September 2026 measurement read two of these in juice-shop's forgery fixtures, and they
        are the case where the weaker signal was re-reporting under its own rule id exactly what
        the stronger one had examined and rejected.
        """
        unsigned = (
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0."
            "eyJkYXRhIjp7ImVtYWlsIjoiand0bjNkQCJ9LCJpYXQiOjE1MDg2Mzk2MTJ9."
        )
        assert not sd._verify_jwt(unsigned)
        assert sd.entropy_exclusion_reason("authorization", f"Bearer {unsigned}") == "unsigned_jwt"
        assert types_in("src/a.ts", f"req.headers = {{ authorization: 'Bearer {unsigned}' }}") == []

    def test_a_signed_jwt_is_still_reported_by_the_format_signal(self):
        """The exclusion is about the missing signature, not about the word `jwt`."""
        assert types_in("src/a.ts", f"const authToken = '{jwt()}';") == ["jwt"]

    def test_a_commit_digest_is_refused_by_its_identifier(self):
        assert sd.entropy_exclusion_reason("secret_hash", "a" * 39 + "b") == "digest_identifier"

    def test_a_low_entropy_word_is_not_a_secret(self):
        assert not sd.is_high_entropy_secret_value("correcthorsebatterystaple")

    def test_a_single_character_class_is_not_a_secret(self):
        assert not sd.is_high_entropy_secret_value("abcdefghijklmnopqrstuvwxyz")

    def test_a_short_hex_string_is_not_a_secret(self):
        assert not sd.is_high_entropy_secret_value("a7f3c9e1b4d2680f")

    def test_a_thirty_two_character_hex_key_is(self):
        assert sd.is_high_entropy_secret_value(RANDOM_32_HEX)


class TestSignalsDoNotDoubleReport:
    def test_a_line_the_format_signal_claimed_is_not_also_an_entropy_finding(self):
        matches = sd.secret_matches(
            "src/sms.py", patch_of(f'twilio_auth_token = "{RANDOM_32_HEX}"')
        )
        assert [match.signal for match in matches] == [sd.SIGNAL_FORMAT]

    def test_the_entropy_signal_still_covers_a_line_no_format_matched(self):
        matches = sd.secret_matches("src/cfg.py", patch_of(f'SESSION_SECRET = "{RANDOM_28}"'))
        assert [match.signal for match in matches] == [sd.SIGNAL_ENTROPY]


class TestPathModel:
    def test_the_entropy_signal_is_off_in_a_lockfile(self):
        assert sd.is_lockfile_path("pnpm-lock.yaml")
        assert types_in("pnpm-lock.yaml", f'  integritySecret: "{RANDOM_40}"') == []

    def test_the_entropy_signal_is_off_in_prose(self):
        assert types_in("docs/setup.md", f'SESSION_SECRET = "{RANDOM_28}"') == []

    def test_the_entropy_signal_is_off_in_a_json_document(self):
        assert types_in("fixtures/payload.json", f'"api_key": "{RANDOM_28}"') == []

    def test_the_format_signal_stays_on_in_prose(self):
        """A key that passes its own structural verification is a leak in a README too.

        This is the same argument `security_rules.SecurityRule.scans_prose` already makes.
        """
        assert types_in("README.md", f'Use `sk_live_{RANDOM_24}` as the key.') == [
            "stripe_live_key"
        ]

    def test_the_format_signal_stays_on_in_a_json_config(self):
        assert types_in("config/prod.json", f'"apiKey": "sk_live_{RANDOM_24}"') == [
            "stripe_live_key"
        ]

    def test_a_secret_in_test_code_is_informational_rather_than_blocking(self):
        result = analyze_tier1_payload(
            AnalyzePRRequest(
                repository_full_name="acme/app",
                pull_request_number=1,
                commit_sha="a" * 40,
                files=[
                    {
                        "path": "tests/test_billing.py",
                        "patch": patch_of(f'STRIPE_KEY = "sk_live_{RANDOM_24}"'),
                    }
                ],
            )
        )
        finding = next(f for f in result["findings"] if f["rule_id"] == sd.RULE_ID_FORMAT)
        assert finding["severity"] == "info"
        assert finding["original_severity"] == "critical"
        assert finding["in_test_code"] is True


class TestDotenv:
    def test_a_dotenv_carrying_a_credential_is_one_finding(self):
        assert types_in(".env", f"API_KEY={RANDOM_24}", f"DB_PASSWORD={RANDOM_28}") == [
            "dotenv_file"
        ]

    def test_a_dotenv_with_no_credential_in_it_is_not_a_finding(self):
        assert types_in(".env", "NODE_ENV=production", "PORT=3000") == []

    @pytest.mark.parametrize(
        "path", [".env.example", ".env.sample", ".env.template", ".env.dist", "app/.env.ci"]
    )
    def test_a_documented_placeholder_file_is_not_a_leak(self, path):
        assert types_in(path, f"API_KEY={RANDOM_24}") == []

    @pytest.mark.parametrize("path", [".env", ".env.local", ".env.production", "app/.env"])
    def test_a_real_environment_file_is(self, path):
        assert types_in(path, f"API_KEY={RANDOM_24}") == ["dotenv_file"]

    def test_a_placeholder_value_in_a_real_dotenv_is_not_a_leak(self):
        assert types_in(".env", "API_KEY=your-key-here", "SECRET=${FROM_CI}") == []

    def test_the_dotenv_finding_offers_no_fix_and_says_to_rotate(self):
        finding = sd.secret_findings(".env", patch_of(f"API_KEY={RANDOM_24}"))[0]
        assert finding["remediation_patch"] == ""
        assert finding["remediation"] == sd.REMEDIATION_ROTATE_ONLY
        assert finding["evidence_details"]["extra"]["fix_offered"] is False


class TestRoutingIntoTheCredentialFamily:
    """`families.rule_family` derives the family from the CWE, so the routing is the CWE plus
    a shape the templates in `remediation-service/src/sites.py` actually recognize."""

    def test_the_finding_carries_the_cwe_the_engine_reads(self):
        finding = sd.secret_findings("src/app.js", patch_of(f'const apiKey = "sk_live_{RANDOM_24}";'))[0]
        assert finding["cwe_id"] == "CWE-798"
        assert finding["internal_type"] == "hardcoded_secret"

    @pytest.mark.parametrize(
        "path,line",
        [
            ("src/app.js", f'const apiKey = "sk_live_{RANDOM_24}";'),
            ("src/app.ts", f'export const apiKey: string = "sk_live_{RANDOM_24}";'),
            ("src/app.js", f'  apiKey: "sk_live_{RANDOM_24}",'),
            ("src/settings.py", f'API_KEY = "sk_live_{RANDOM_24}"'),
        ],
    )
    def test_a_rewritable_shape_is_rewritable(self, path, line):
        assert sd.is_rewritable_credential_shape(path, line)

    @pytest.mark.parametrize(
        "path,line",
        [
            ("config/prod.json", f'  "apiKey": "sk_live_{RANDOM_24}",'),
            ("src/app.js", f'stripe("sk_live_{RANDOM_24}")'),
            ("src/settings.py", f'    API_KEY = "sk_live_{RANDOM_24}"'),
            ("src/app.js", f'const apiKey = `sk_live_${{prefix}}{RANDOM_24}`;'),
            ("deploy/values.yaml", f'  apiKey: sk_live_{RANDOM_24}'),
        ],
    )
    def test_an_unrewritable_shape_is_not(self, path, line):
        assert not sd.is_rewritable_credential_shape(path, line)

    def test_a_rewritable_finding_carries_the_environment_patch(self):
        finding = sd.secret_findings("src/app.js", patch_of(f'const apiKey = "sk_live_{RANDOM_24}";'))[0]
        assert finding["remediation_patch"] == "const apiKey = process.env.API_KEY;"
        assert finding["remediation"] == sd.REMEDIATION_MOVE_AND_ROTATE
        assert finding["evidence_details"]["auto_fix_eligible"] is True
        assert (
            finding["evidence_details"]["missing_control_type"]
            == "secret_manager_or_environment_variable"
        )

    def test_a_python_module_level_finding_carries_the_environment_patch(self):
        finding = sd.secret_findings("src/settings.py", patch_of(f'API_KEY = "sk_live_{RANDOM_24}"'))[0]
        assert finding["remediation_patch"] == 'API_KEY = os.getenv("API_KEY")'

    @pytest.mark.parametrize(
        "path,line",
        [
            ("config/prod.json", f'  "apiKey": "sk_live_{RANDOM_24}",'),
            ("src/keys.py", "-----BEGIN RSA PRIVATE KEY-----"),
        ],
    )
    def test_an_unrewritable_finding_offers_no_fix_and_says_to_rotate(self, path, line):
        finding = sd.secret_findings(path, patch_of(line))[0]
        assert finding["remediation_patch"] == ""
        assert finding["remediation"] == sd.REMEDIATION_ROTATE_ONLY
        assert finding["evidence_details"]["extra"]["fix_offered"] is False

    def test_every_finding_says_the_credential_must_be_rotated(self):
        for path, line in (
            ("src/app.js", f'const apiKey = "sk_live_{RANDOM_24}";'),
            ("src/keys.py", "-----BEGIN RSA PRIVATE KEY-----"),
            (".env", f"API_KEY={RANDOM_24}"),
            ("src/cfg.py", f'SESSION_SECRET = "{RANDOM_28}"'),
        ):
            finding = sd.secret_findings(path, patch_of(line))[0]
            assert "Rotate this credential now" in finding["remediation"]
            assert "does not un-leak it" in finding["remediation"]
            assert finding["evidence_details"]["extra"]["rotation_required"] is True


class TestEvidence:
    def test_the_evidence_line_does_not_carry_the_whole_credential(self):
        secret = f"sk_live_{RANDOM_24}"
        finding = sd.secret_findings("src/app.js", patch_of(f'const apiKey = "{secret}";'))[0]
        assert secret not in finding["evidence"]
        assert secret not in finding["description"]
        # The snippet keeps the author's line, because that is what the suggestion the App
        # publishes has to match, and what every other rule does.
        assert secret in finding["code_snippet"]

    def test_the_finding_records_which_signal_fired(self):
        extra = sd.secret_findings("src/app.js", patch_of(f'const apiKey = "sk_live_{RANDOM_24}";'))[0][
            "evidence_details"
        ]["extra"]
        assert extra["signal"] == sd.SIGNAL_FORMAT
        assert extra["secret_type"] == "stripe_live_key"
        assert "24 base62" in extra["structure_verified"]

    def test_the_entropy_finding_records_the_measurement_it_made(self):
        extra = sd.secret_findings("src/cfg.py", patch_of(f'SESSION_SECRET = "{RANDOM_28}"'))[0][
            "evidence_details"
        ]["extra"]
        assert extra["signal"] == sd.SIGNAL_ENTROPY
        assert extra["identifier"] == "SESSION_SECRET"
        assert extra["value_length"] == len(RANDOM_28)
        assert extra["entropy_bits_per_character"] >= 4.0


class TestCaps:
    def test_no_more_than_five_findings_per_file_and_signal(self):
        lines = [f'const key{index} = "sk_live_{RANDOM_24}{index}";' for index in range(9)]
        assert len(sd.secret_matches("src/app.js", patch_of(*lines))) == sd.MAX_FINDINGS_PER_FILE

    def test_the_same_value_twice_is_one_finding(self):
        line = f'const apiKey = "sk_live_{RANDOM_24}";'
        assert len(sd.secret_matches("src/app.js", patch_of(line, line))) == 1


class TestOneFingerprintDefinition:
    """Four modules need the fingerprint and none of them may import the others.

    `main` and `opengrep_runner` carried identical copies, and `secret_detection` reached into
    `main` for it, which made the import order decide which service's `main` answered when the
    Action puts the analysis service and the remediation service on `sys.path` together. It now
    lives in `finding_quality`; the other two are re-exports.
    """

    def test_every_module_uses_the_same_function(self):
        import finding_quality
        import main as analysis_main
        import opengrep_runner
        import secret_detection

        definition = finding_quality.make_fingerprint
        assert analysis_main.make_fingerprint is definition
        assert opengrep_runner.make_fingerprint is definition
        assert secret_detection.make_fingerprint is definition

    def test_the_fingerprint_is_the_one_the_comment_marker_already_used(self):
        """The published comment marker is this string, so its value is a compatibility
        contract with every comment the product has ever posted."""
        import hashlib

        import finding_quality

        expected = hashlib.sha256(b"rule|path.py|7|snippet").hexdigest()
        assert finding_quality.make_fingerprint("rule", "path.py", 7, "  snippet  ") == expected


class TestTierOneIntegration:
    def _tier1(self, path, *lines):
        return analyze_tier1_payload(
            AnalyzePRRequest(
                repository_full_name="acme/app",
                pull_request_number=1,
                commit_sha="a" * 40,
                files=[{"path": path, "patch": patch_of(*lines)}],
            )
        )

    def test_the_detector_reaches_the_tier_one_response(self):
        posted = {f["rule_id"] for f in self._tier1("src/app.js", f'const apiKey = "sk_live_{RANDOM_24}";')["findings"]}
        assert sd.RULE_ID_FORMAT in posted

    def test_the_legacy_credential_regex_defers_to_the_detector(self):
        """One leaked key is one finding, not two."""
        posted = [f["rule_id"] for f in self._tier1("src/app.js", f'const apiKey = "sk_live_{RANDOM_24}";')["findings"]]
        assert LEGACY_CREDENTIAL_RULE_ID not in posted

    def test_the_legacy_credential_regex_still_runs_where_the_detector_is_silent(self):
        posted = [f["rule_id"] for f in self._tier1("src/app.js", 'const password = "correcthorsebattery";')["findings"]]
        assert LEGACY_CREDENTIAL_RULE_ID in posted

    def test_both_signals_declare_a_posting_state(self):
        assert set(sd.POSTING) == {sd.RULE_ID_FORMAT, sd.RULE_ID_ENTROPY}
        for posting in sd.POSTING.values():
            assert posting in (sd.POSTING_POST, sd.POSTING_QUARANTINE)

    def test_a_quarantined_signal_would_be_withheld_by_the_one_filter(self):
        withheld = {
            rule_id for rule_id, posting in sd.POSTING.items() if posting == sd.POSTING_QUARANTINE
        }
        assert withheld <= QUARANTINED_RULE_IDS
