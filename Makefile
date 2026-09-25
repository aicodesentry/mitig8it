# Mitig8it: one command for the tests, one for the numbers.
#
#   make deps    create the virtualenvs and install the node modules, the way CI does
#   make test    every suite, stopping at the first failure
#   make bench   every benchmark, ending in one summary table
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

# The two Python environments are separate because they cannot be one. The analysis service pins
# semgrep 1.173.0, which requires opentelemetry-api~=1.37.0, and the remediation service pins
# opentelemetry-api==1.44.0. CI installs them separately for the same reason.

.PHONY: help deps test bench clean \
        test-analysis test-remediation test-api test-github test-frontend test-action test-harness \
        bench-tier1 bench-tier2 bench-remediation-reference bench-remediation-engine-local bench-summary

help:
	@echo "make deps    create .venv/analysis and .venv/remediation and install node modules"
	@echo "make test    analysis, remediation, api, github, frontend, action, benchmark harness"
	@echo "make bench   tier 1 and tier 2 precision, remediation corpus under both adapters"
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

test: test-analysis test-remediation test-api test-github test-frontend test-action test-harness
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

# --- benchmarks --------------------------------------------------------------------------------

bench: bench-tier1 bench-tier2 bench-remediation-reference bench-remediation-engine-local bench-summary

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

# --- housekeeping ------------------------------------------------------------------------------

clean:
	rm -rf $(CURDIR)/.venv
	rm -rf frontend/node_modules services/api-service/node_modules services/github-service/node_modules
	rm -f $(RESULTS)/*.json $(RESULTS)/*.txt
