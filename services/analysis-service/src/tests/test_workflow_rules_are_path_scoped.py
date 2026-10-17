"""A workflow rule must be scoped to `.github/workflows/`, and nothing wider.

`workflow_coverage.yml` is the second `generic` rule file, and `generic` is token matching
with no notion of a language, so a rule with no `paths: include` reads every file in the
batch. The template rules solved that with an extension glob. These cannot: `.yml` is the
most common configuration extension there is, and `run:`, `ref:` and `permissions:` all mean
something else in a compose file, a Kubernetes manifest, an Ansible playbook or another
provider's CI config. An include of `*.yml` would therefore be a rule set that fires on
configuration it makes no claim about.

So the scope is asserted twice, once as the literal and once as behaviour:

* every rule includes exactly the two workflow globs and nothing else;
* the rules, run through the real scanner over a tree that contains both a workflow and
  ordinary YAML with the same tokens in it, fire only on the workflow.

The second is the one that would catch a scanner whose glob semantics changed under us.
"""
from __future__ import annotations

import pytest
import yaml

from opengrep_runner import RULES_DIR, WORKFLOW_DIRECTORY, WORKFLOW_EXTENSIONS, run_opengrep

WORKFLOW_RULES_FILE = "workflow_coverage.yml"

EXPECTED_INCLUDES = {f"{WORKFLOW_DIRECTORY}*{extension}" for extension in WORKFLOW_EXTENSIONS}


def _workflow_rules() -> list[dict]:
    document = yaml.safe_load((RULES_DIR / WORKFLOW_RULES_FILE).read_text(encoding="utf-8"))
    return list(document["rules"])


WORKFLOW_RULES = _workflow_rules()
IDS = [rule["id"] for rule in WORKFLOW_RULES]

# One document that carries every shape the rule file looks for. It is scanned twice, once at
# a workflow path and once at an ordinary YAML path, and the second scan must be silent.
EVERY_SHAPE = """\
name: every shape
on:
  pull_request_target:
    types: [opened]
  issue_comment:
    types: [created]
  workflow_run:
    workflows: [ci]
    types: [completed]
permissions: write-all
jobs:
  build:
    runs-on: [self-hosted, linux]
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: true
      - uses: some-org/some-action@v3
      - run: npm ci
      - run: echo "title ${{ github.event.pull_request.title }}"
      - name: publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
        run: npm publish
      - uses: actions/download-artifact@v4
        with:
          path: out
      - run: bash out/run.sh
      - run: curl -fsSL https://example.com/install.sh | sh
"""


class TestTheIncludeIsTheWorkflowDirectory:
    def test_there_is_at_least_one_workflow_rule(self):
        """Otherwise the rest of this file asserts nothing."""
        assert WORKFLOW_RULES

    @pytest.mark.parametrize("rule", WORKFLOW_RULES, ids=IDS)
    def test_rule_declares_the_two_workflow_globs_and_nothing_else(self, rule):
        include = set(((rule.get("paths") or {}).get("include")) or [])
        assert include == EXPECTED_INCLUDES, (
            f"{rule['id']} includes {sorted(include)}; a workflow rule must be scoped to "
            f"{sorted(EXPECTED_INCLUDES)} so ordinary YAML is never swept in"
        )

    @pytest.mark.parametrize("rule", WORKFLOW_RULES, ids=IDS)
    def test_rule_is_generic(self, rule):
        assert rule.get("languages") == ["generic"], rule["id"]

    @pytest.mark.parametrize("rule", WORKFLOW_RULES, ids=IDS)
    def test_rule_declares_no_exclude_that_would_hide_a_workflow(self, rule):
        assert not (rule.get("paths") or {}).get("exclude"), rule["id"]


@pytest.fixture(scope="module")
def fired() -> dict[str, set[str]]:
    """Rule ids that fired, keyed by the path the same document was scanned at."""
    files = [
        {"path": path, "content": EVERY_SHAPE, "patch": "", "reviewable_line_spans": []}
        for path in (
            ".github/workflows/every-shape.yml",
            "deploy/every-shape.yml",
            "vendor/notgithub/workflows/every-shape.yml",
        )
    ]
    hits: dict[str, set[str]] = {entry["path"]: set() for entry in files}
    for finding in run_opengrep(files):
        hits.setdefault(finding["file_path"], set()).add(finding["rule_id"])
    return hits


class TestTheScannerAgrees:
    """The literals are only a promise; this is the measurement."""

    def test_every_workflow_rule_fires_on_the_workflow_path(self, fired):
        expected = {f"opengrep.{rule['id']}" for rule in WORKFLOW_RULES}
        got = fired[".github/workflows/every-shape.yml"]
        assert expected - got == set(), f"silent on the workflow document: {sorted(expected - got)}"

    def test_no_workflow_rule_fires_on_ordinary_yaml(self, fired):
        workflow_ids = {f"opengrep.{rule['id']}" for rule in WORKFLOW_RULES}
        for path in ("deploy/every-shape.yml", "vendor/notgithub/workflows/every-shape.yml"):
            leaked = sorted(fired[path] & workflow_ids)
            assert not leaked, f"{path}: {leaked} read a file that is not a workflow"

    def test_the_same_document_outside_the_scope_is_not_even_scanned(self, fired):
        """Belt and braces: the service's own scope gate drops it before the scanner sees it.

        `run_opengrep` filters on `is_tier2_scannable_path`, so `deploy/every-shape.yml`
        produces no findings at all, from any rule. If that ever changes the rules' own
        includes are the remaining defence, which is what the test above measures.
        """
        assert fired["deploy/every-shape.yml"] == set()
