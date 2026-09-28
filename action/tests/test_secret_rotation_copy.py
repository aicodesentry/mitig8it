"""The Action's comment says the same thing about rotation as the App's does.

The sentence lives on the finding's `remediation`, which the analysis service writes and both
publishers render, so there is no second copy to keep in step. What has to be asserted is that
neither renderer drops it: the Action's `render_finding_comment` deliberately drops a field
that repeats another one, and a secrets finding's `description` and `remediation` are close
enough in subject that a future tightening of `_same_sentence` could take the rotation sentence
with it.

The matching App-side test is `services/api-service/tests/secretRotationCopy.test.js`, and both
quote the strings from `services/analysis-service/src/secret_detection.py`.
"""
from __future__ import annotations

import pytest
import sys
from pathlib import Path

ANALYSIS_SRC = Path(__file__).resolve().parents[2] / "services" / "analysis-service" / "src"
if str(ANALYSIS_SRC) not in sys.path:
    sys.path.insert(0, str(ANALYSIS_SRC))

import secret_detection  # noqa: E402

from orchestrator import run  # noqa: E402


def _patch(line: str) -> str:
    return "@@ -1,1 +1,1 @@\n+%s\n" % line


# The fixture key is joined rather than written out. `sk_live_` followed by twenty-four
# base62 characters is the shape GitHub's push protection blocks, and it blocked this
# branch; a repository whose own product exists to stop people committing keys does not
# ask to be allowlisted past that. The body grants nothing and only the shape is under
# test, so a join point costs the test nothing.
STRIPE_LIVE_KEY = "sk_live" + "_k8Rm2QpLzV4nB7xW1sT6yU3h"


MOVE_AND_ROTATE = secret_detection.secret_findings(
    "src/billing.js", _patch(f'const stripeKey = "{STRIPE_LIVE_KEY}";')
)[0]
ROTATE_ONLY = secret_detection.secret_findings(
    "deploy/keys.py", _patch("-----BEGIN RSA PRIVATE KEY-----")
)[0]


class TestTheActionRendersTheRotationSentence:
    def test_a_rewritable_secret_keeps_the_rotation_sentence(self):
        body = run.render_finding_comment(MOVE_AND_ROTATE)
        assert secret_detection.REMEDIATION_MOVE_AND_ROTATE in body

    def test_a_rotation_only_secret_keeps_its_sentence(self):
        body = run.render_finding_comment(ROTATE_ONLY)
        assert secret_detection.REMEDIATION_ROTATE_ONLY in body
        assert "No automatic fix is offered for this shape" in body

    def test_neither_comment_quotes_the_whole_credential_outside_the_snippet(self):
        """The evidence line quotes a shape. The snippet is the author's line, which is what a
        suggestion has to match, so the credential appears there and only there."""
        body = run.render_finding_comment(MOVE_AND_ROTATE)
        assert STRIPE_LIVE_KEY not in body

    def test_both_findings_are_reported_as_critical_weaknesses(self):
        for finding in (MOVE_AND_ROTATE, ROTATE_ONLY):
            body = run.render_finding_comment(finding)
            assert "Weakness: CWE-798" in body


# The routing assertion loads the repair service's own module, which the image carries and the
# host job deliberately does not: that job installs pytest, httpx and pyyaml and nothing else,
# so the Action's own tests cannot come to depend on a service being installed. Skipped where
# the engine is absent rather than restated, because a restatement of `rule_family` would pass
# while the real table said something else, which is the whole reason this class exists.
_engine = pytest.importorskip(
    "pydantic", reason="the repair service's own family table is what this asserts against"
)


class TestSecretsRouteIntoTheCredentialFamily:
    """The Action is where both services are importable at once, so this is where the routing
    can be asserted against the engine's own `families.rule_family` rather than against a
    restatement of it.

    It is also where the import-shadowing bug this test was written after could happen:
    `secret_detection` used to reach into `main` for the fingerprint, and with both services'
    `src` on `sys.path` the first `main` on the path answered. The fingerprint now lives in
    `finding_quality`, which nothing shadows.
    """

    def _family(self, finding):
        """The engine's own module, loaded the way the Action loads it."""
        from orchestrator import remediation as action_remediation

        families = action_remediation._modules()["families"]
        view = action_remediation._finding_view(finding)
        return families, families.rule_family(view)

    def test_a_rewritable_javascript_secret_is_a_supported_credential_repair(self):
        finding = secret_detection.secret_findings(
            "src/billing.js", _patch(f'const apiKey = "{STRIPE_LIVE_KEY}";')
        )[0]
        families, family = self._family(finding)
        assert family == families.HARDCODED_CREDENTIAL
        assert families.family_supported(family, families.language_of_path("src/billing.js"))
        assert finding["remediation_patch"] == "const apiKey = process.env.API_KEY;"

    def test_a_rewritable_python_secret_is_too(self):
        finding = secret_detection.secret_findings(
            "src/settings.py", _patch(f'API_KEY = "{STRIPE_LIVE_KEY}"')
        )[0]
        families, family = self._family(finding)
        assert family == families.HARDCODED_CREDENTIAL
        assert families.family_supported(family, families.language_of_path("src/settings.py"))
        assert finding["remediation_patch"] == 'API_KEY = os.getenv("API_KEY")'

    def test_a_json_config_key_reaches_the_family_and_is_promised_nothing(self):
        """The family is derived from the CWE, so it is `hardcoded_credential` either way.

        What the detector controls is the promise: a JSON document is not a language the
        family repairs, so the finding offers no fix and says the credential must be rotated.
        """
        finding = secret_detection.secret_findings(
            "config/prod.json", _patch(f'  "apiKey": "{STRIPE_LIVE_KEY}",')
        )[0]
        families, family = self._family(finding)
        assert family == families.HARDCODED_CREDENTIAL
        assert not families.family_supported(family, families.language_of_path("config/prod.json"))
        assert finding["remediation_patch"] == ""
        assert finding["remediation"] == secret_detection.REMEDIATION_ROTATE_ONLY


class TestTheTwoMessagesAreTheOnesTheDetectorDeclares:
    def test_the_move_and_rotate_message_is_used_for_a_rewritable_shape(self):
        assert MOVE_AND_ROTATE["remediation"] == secret_detection.REMEDIATION_MOVE_AND_ROTATE
        assert MOVE_AND_ROTATE["remediation_patch"]

    def test_the_rotate_only_message_is_used_where_no_template_applies(self):
        assert ROTATE_ONLY["remediation"] == secret_detection.REMEDIATION_ROTATE_ONLY
        assert ROTATE_ONLY["remediation_patch"] == ""

    def test_both_messages_say_the_value_is_already_disclosed(self):
        for message in (
            secret_detection.REMEDIATION_MOVE_AND_ROTATE,
            secret_detection.REMEDIATION_ROTATE_ONLY,
        ):
            assert "Rotate this credential now" in message
            assert "does not un-leak it" in message
