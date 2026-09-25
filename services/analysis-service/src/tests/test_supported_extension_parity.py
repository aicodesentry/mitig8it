"""The set of extensions tier 2 scans is written down three times, and all three must agree.

The list lives in three places because three different runtimes need it and none of them
can import the others:

* `opengrep_runner.SUPPORTED_EXTENSIONS` decides what the scanner is handed.
* `prAnalysisOrchestrator.js` decides what the orchestrator fetches content for, so an
  extension missing there never reaches the scanner however willing the scanner is.
* `prodfilters.py` mirrors the orchestrator so a replay describes production rather than
  an idealised version of it.

A divergence is silent in all three directions. An extension added only to the scanner
scans nothing, because no content arrives. An extension added only to the orchestrator
pays to fetch files the scanner drops. An extension added only to the replay makes the
harness report recall the product cannot deliver. Hence this test.

The fourth candidate, `fetchPullRequestFiles` in
`services/github-service/src/services/githubInternalOperations.js`, is deliberately not
here: it filters on status and on `dist/`/`node_modules` and never on extension, so it has
no copy of this list to keep in step.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from opengrep_runner import CODE_EXTENSIONS, SUPPORTED_EXTENSIONS, TEMPLATE_EXTENSIONS

REPO_ROOT = Path(__file__).resolve().parents[4]
ORCHESTRATOR_JS = REPO_ROOT / "services" / "api-service" / "src" / "services" / "prAnalysisOrchestrator.js"
PRODFILTERS_PY = REPO_ROOT / "scripts" / "replay" / "prodfilters.py"


def _load_prodfilters():
    spec = importlib.util.spec_from_file_location("prodfilters_under_test", PRODFILTERS_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _js_array(name: str) -> set[str]:
    """Read one `const <name> = [ ... ];` array of string literals out of the orchestrator.

    Parsed rather than imported: the orchestrator pulls in the database pool and the gRPC
    clients at import time, and a parity test should not need a database to answer.
    """
    source = ORCHESTRATOR_JS.read_text(encoding="utf-8")
    match = re.search(rf"const {name} = \[(.*?)\];", source, re.S)
    assert match, f"{name} is not declared in {ORCHESTRATOR_JS.name} in the form this test reads"
    return set(re.findall(r"'(\.[A-Za-z0-9]+)'", match.group(1)))


PRODFILTERS = _load_prodfilters()


class TestTheThreeCopiesAgree:
    def test_code_extensions_agree(self):
        assert _js_array("TIER2_CODE_EXTENSIONS") == CODE_EXTENSIONS
        assert PRODFILTERS.TIER2_CODE_EXTENSIONS == CODE_EXTENSIONS

    def test_template_extensions_agree(self):
        assert _js_array("TIER2_TEMPLATE_EXTENSIONS") == TEMPLATE_EXTENSIONS
        assert PRODFILTERS.TIER2_TEMPLATE_EXTENSIONS == TEMPLATE_EXTENSIONS

    def test_the_unions_agree(self):
        """What actually gates a file is the union, so the union is asserted too: the two
        halves could each be wrong in a way that cancels out."""
        combined = _js_array("TIER2_CODE_EXTENSIONS") | _js_array("TIER2_TEMPLATE_EXTENSIONS")
        assert combined == SUPPORTED_EXTENSIONS
        assert PRODFILTERS.TIER2_SUPPORTED_EXTENSIONS == SUPPORTED_EXTENSIONS

    def test_the_two_halves_do_not_overlap(self):
        assert CODE_EXTENSIONS & TEMPLATE_EXTENSIONS == set()

    def test_every_entry_is_a_lowercase_dotted_suffix(self):
        """`should_fetch_content` lowercases the suffix before the lookup, so an uppercase
        entry here would be unreachable."""
        for extension in SUPPORTED_EXTENSIONS:
            assert extension.startswith("."), extension
            assert extension == extension.lower(), extension


class TestTheOrchestratorActuallyGatesOnIt:
    """Parity between the lists is worth nothing if the replay stopped consulting them."""

    @pytest.mark.parametrize("path", ["app/views/layout.html", "views/products.ejs", "src/App.vue"])
    def test_a_template_file_is_fetched_for_tier2(self, path):
        assert PRODFILTERS.should_fetch_content(path) is True

    @pytest.mark.parametrize("path", ["README.md", "assets/logo.svg", "package-lock.json"])
    def test_an_unsupported_file_is_not_fetched(self, path):
        assert PRODFILTERS.should_fetch_content(path) is False

    def test_the_existing_exclusions_still_apply_to_templates(self):
        assert PRODFILTERS.should_fetch_content("node_modules/x/views/a.ejs") is False
        assert PRODFILTERS.should_fetch_content("dist/index.html") is False
