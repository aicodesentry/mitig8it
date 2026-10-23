# Mitig8it: one command for the tests, one for the numbers.
#
#   make deps    create the virtualenvs and install the node modules, the way CI does
#   make test    every suite, stopping at the first failure
#   make bench   every benchmark, ending in one summary table
#   make recall-ratchet   the vulnerable corpus against its recall baseline (downloads 23 trees)
#
# Prerequisites and what each target installs: CONTRIBUTING.md.

SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

PYTHON311 ?= python3.11
VENV_ANALYSIS := $(CURDIR)/.venv/analysis
VENV_REMEDIATION := $(CURDIR)/.venv/remediation
PY_ANALYSIS := $(VENV_ANALYSIS)/bin/python
PY_REMEDIATION := $(VENV_REMEDIATION)/bin/python
RESULTS := $(CURDIR)/benchmarks/results
RECALL_RESULTS := $(CURDIR)/scripts/replay/.cache/recall-results
DEV_EVAL_ARGS ?=

# The two Python environments are separate because they cannot be one. The analysis service pins
# semgrep 1.182.1, which requires opentelemetry-api~=1.37.0, and the remediation service pins
# opentelemetry-api==1.45.1. CI and the Action image isolate them for the same reason.

.PHONY: help deps test bench clean \
        test-analysis test-remediation test-api test-github test-frontend test-action test-harness \
        test-quality \
        bench-tier1 bench-tier2 bench-remediation-reference bench-remediation-engine-local bench-summary \
        recall-measure recall-ratchet recall-baseline dev-eval

help:
	@echo "make deps    create .venv/analysis and .venv/remediation and install node modules"
	@echo "make test    analysis, remediation, api, github, frontend, action, benchmark harness"
	@echo "make bench   tier 1 and tier 2 precision, remediation corpus under both adapters"
	@echo "make recall-ratchet   fail if a labelled vulnerability that was detected no longer is"
	@echo "make recall-baseline  re-measure the corpus and rewrite the recall baseline"
	@echo "make dev-eval   local repair evaluation; optional DEV_EVAL_ARGS='--baseline path.json'"
	@echo "make clean   remove the virtualenvs, the node modules and the benchmark reports"

# --- dependencies ------------------------------------------------------------------------------

deps:
	$(PYTHON311) -m venv $(VENV_ANALYSIS)
	$(PY_ANALYSIS) -m pip install --upgrade pip
	$(PY_ANALYSIS) -m pip install -r services/analysis-service/src/requirements-test.txt
	$(PY_ANALYSIS) -m pip install pytest httpx pyyaml
	$(PYTHON311) -m venv $(VENV_REMEDIATION)
	$(PY_REMEDIATION) -m pip install --upgrade pip
	$(PY_REMEDIATION) -m pip install -r services/remediation-service/requirements-test.txt
	cd frontend && npm ci
	cd services/api-service && npm ci
	cd services/github-service && npm ci
	@echo "deps ready. Run make test."

# --- tests -------------------------------------------------------------------------------------
# Each suite is its own target and they are listed in order, so make stops at the first failure.

test: test-analysis test-remediation test-api test-github test-frontend test-action test-harness test-quality
	@echo "all suites passed"

test-analysis:
	@echo "== analysis-service =="
	cd services/analysis-service/src && $(PY_ANALYSIS) -m pytest tests -q

test-remediation:
	@echo "== remediation-service =="
	$(PY_REMEDIATION) -m pytest services/remediation-service/tests -q

test-api:
	@echo "== api-service =="
	cd services/api-service && npm run lint && npm test -- --runInBand

test-github:
	@echo "== github-service =="
	cd services/github-service && npm run lint && npm test -- --runInBand

test-frontend:
	@echo "== frontend =="
	cd frontend && npm run lint && npm test && npm run build

test-action:
	@echo "== action =="
	cd action && $(PY_ANALYSIS) -m pytest tests -q

test-harness:
	@echo "== benchmark harness =="
	$(PY_REMEDIATION) -m pytest benchmarks/remediation/tests -q

test-quality:
	@echo "== offline quality gates =="
	$(PY_ANALYSIS) -m pytest benchmarks/test_detection_evaluation.py benchmarks/test_eval.py \
	  benchmarks/test_quality_gate.py \
	  benchmarks/test_production_readiness.py -q

# --- benchmarks --------------------------------------------------------------------------------

bench: bench-rule-quality bench-tier1 bench-tier2 bench-remediation-reference bench-remediation-engine-local bench-summary

.PHONY: bench-rule-quality
bench-rule-quality: | $(RESULTS)
	$(PY_ANALYSIS) -m benchmarks.rule_quality_gate --output $(RESULTS)/rule-quality.json

.PHONY: production-readiness quality-report
production-readiness: | $(RESULTS)
	$(PY_ANALYSIS) -m benchmarks.production_readiness --output $(RESULTS)/production-readiness.json

quality-report: | $(RESULTS)
	$(PY_ANALYSIS) -m benchmarks.production_readiness --report-only --output $(RESULTS)/production-readiness.json

$(RESULTS):
	mkdir -p $(RESULTS)

bench-tier1: | $(RESULTS)
	@echo "== tier 1 precision =="
	cd services/analysis-service/src && $(PY_ANALYSIS) -m pytest tests/test_tier1_precision_benchmark.py -q \
	  | tee $(RESULTS)/tier1-precision.txt

bench-tier2: | $(RESULTS)
	@echo "== tier 2 precision =="
	cd services/analysis-service/src && $(PY_ANALYSIS) -m pytest tests/test_tier2_precision_benchmark.py -q \
	  | tee $(RESULTS)/tier2-precision.txt

bench-remediation-reference: | $(RESULTS)
	@echo "== remediation corpus, reference adapter =="
	$(PY_REMEDIATION) benchmarks/remediation/evaluate.py --suite seed --adapter reference \
	  --output $(RESULTS)/remediation-reference.json > /dev/null
	@echo "report: benchmarks/results/remediation-reference.json"

bench-remediation-engine-local: | $(RESULTS)
	@echo "== remediation corpus, engine-local adapter =="
	$(PY_REMEDIATION) benchmarks/remediation/evaluate.py --suite seed --adapter engine-local \
	  --output $(RESULTS)/remediation-engine-local.json > /dev/null
	@echo "report: benchmarks/results/remediation-engine-local.json"

bench-summary:
	@$(PY_REMEDIATION) scripts/bench-summary.py

# --- recall ratchet ----------------------------------------------------------------------------
# Not part of make test or make bench: it downloads the 23 pinned trees of the vulnerable corpus
# into scripts/replay/.cache/snapshots on first use and scans all of them, which takes minutes.
# The scanner is found on PATH, so the analysis virtualenv's bin directory is put there.

recall-measure:
	@echo "== vulnerable corpus, snapshot run =="
	PATH="$(VENV_ANALYSIS)/bin:$$PATH" $(PY_ANALYSIS) scripts/replay/ratchet.py measure --results $(RECALL_RESULTS)

recall-ratchet: recall-measure
	@echo "== recall ratchet =="
	$(PY_ANALYSIS) scripts/replay/ratchet.py check $(RECALL_RESULTS)

recall-baseline: recall-measure
	@echo "== recall baseline =="
	$(PY_ANALYSIS) scripts/replay/ratchet.py update $(RECALL_RESULTS)

# Explicit developer entry point; not included in deployments or production dependencies.
dev-eval: | $(RESULTS)
	$(PY_REMEDIATION) -m benchmarks.remediation.dev_eval $(DEV_EVAL_ARGS)

# --- housekeeping ------------------------------------------------------------------------------

clean:
	rm -rf $(CURDIR)/.venv
	rm -rf frontend/node_modules services/api-service/node_modules services/github-service/node_modules
	rm -f $(RESULTS)/*.json $(RESULTS)/*.txt
	rm -rf $(RECALL_RESULTS)
