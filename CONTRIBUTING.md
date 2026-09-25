# Contributing

Thank you for looking. This document says how to run what is here, and what a change has to carry
before it can be merged.

The short version: a rule needs a measurement, a fixture needs a proof, and a number needs a
document.

## Prerequisites

| Tool | Version | Why |
| --- | --- | --- |
| Python | 3.11 | Both Python services pin against it. `make deps` calls `python3.11`; override with `make PYTHON311=/path/to/python3.11 deps`. |
| Node | 22 LTS or later | The sandbox harness needs `module.stripTypeScriptTypes` and `registerHooks`. The exact version the service image uses is `ARG NODE_VERSION` in `services/remediation-service/Dockerfile`. |
| npm | Ships with Node | Every Node package is installed with `npm ci` from its lockfile. |
| Docker | Any recent version | Only for `docker compose` local development and for building the action image. Not needed for `make test` or `make bench`. |

Nothing else. No database, no cloud credentials and no model key is needed to run the tests or the
benchmarks: every suite that needs a database is a separate integration target, and every adapter
that would call a model is off by default and fails with the missing variable's name if you ask
for it.

## Running the tests

```sh
make deps
make test
```

`make deps` creates two virtualenvs under `.venv/` and runs `npm ci` in the frontend and the two
Node services. There are two virtualenvs because there cannot be one: the analysis service pins
semgrep 1.173.0, which requires `opentelemetry-api~=1.37.0`, and the remediation service pins
`opentelemetry-api==1.44.0`. CI installs them separately for the same reason.

`make test` runs the suites in this order and stops at the first failure: analysis service,
remediation service, api service, github service, frontend, action orchestrator, benchmark
harness. Each has its own target, so `make test-frontend` runs one of them.

Suites that need something `make test` does not provide, and that CI runs in their own jobs:

```sh
cd services/api-service && npm run test:integration:remediation   # needs a disposable _test database
cd services/api-service && npm run test:integration:access
cd services/api-service && npm run test:integration:lifecycle
cd services/github-service && npm run test:remediation
cd frontend && npm run test:remediation-browser                   # Playwright, fixtures only
node --test-reporter=tap services/remediation-service/tests/harness_spec.js
actionlint                                                        # lints the workflow files
```

## Running the benchmarks

```sh
make bench
```

It runs the tier 1 precision gate, the tier 2 precision gate, and the remediation corpus under the
reference and engine-local adapters, and prints one table. The dated reference output for that
table, with a section on what each row does and does not mean, is in
[docs/validation/README.md](docs/validation/README.md). Compare against that, not against an
intuition about what a good number looks like.

The bigger measurements are not in `make bench`, because they download and analyse 23 third-party
repositories and replay 165 pull requests against the GitHub API. Their commands are in
`benchmarks/vulnerable-corpus/README.md` and `scripts/replay/README.md`.

## Adding a rule

A rule is not merged because its pattern looks right. It is merged with a measurement, and the
posting policy decides from that measurement whether it reaches a reviewer.

1. **Write it in this repository.** Do not copy from `opengrep-rules` or `semgrep-rules`. Both are
   excluded on licence grounds and the reading is recorded in
   [docs/legal/third-party-rules.md](docs/legal/third-party-rules.md). A rule taken from either
   cannot be merged, whatever it does.
2. **Put it where its tier lives.** Tier 1 regex rules are `SECURITY_RULES` in
   `services/analysis-service/src/security_rules.py`. Tier 2 AST rules are the YAML files in
   `services/analysis-service/src/opengrep_rules/`. A tier 2 rule must declare a canonical
   `internal_type` from `taxonomy.py` and must not pass its own check id;
   `tests/test_tier2_rule_metadata.py` fails it if it does. A rule in `template_coverage.yml` must
   carry `paths: include`, because the scanner reads those files in `generic` mode and a rule
   without an include reads every file in the batch.
3. **Measure it.** Run the rule over the vulnerable corpus, adjudicate its findings by hand, and
   record the count and the precision. The command is in `benchmarks/vulnerable-corpus/README.md`.
4. **Let the policy decide.** The posting policy is: a rule with at least three adjudicated
   findings and precision below 0.8 is quarantined. A quarantined rule still runs and is still
   counted, so it can be re-measured; nothing it produces reaches a reviewer. To bring one back
   you need three adjudicated findings at or above the threshold, not an argument about the
   pattern. Set `precision` and `posting` on the rule and write the measurement into its
   `precision_evidence` string. `partition_by_posting_policy` in `main.py` is the one place that
   reads them.
5. **Add the cases.** Every finding you adjudicated true goes into
   `benchmarks/tier2-precision/cases.json` (or `tier1-precision` for a tier 1 rule) so the rule
   cannot stop matching silently, and every finding you adjudicated false goes in as a suppression
   case so it cannot start matching again.
6. **Write it down.** Add the measurement to the relevant document under `docs/validation/`, with
   the counts, the adjudicated sample and the decision. A rule whose precision is not written down
   anywhere cannot be reviewed.

## Adding a fixture

A fixture in `benchmarks/remediation/fixtures/` is a small repository with a known vulnerability
and a reviewed repair. Its shape is `fixture-schema.json`, and
`benchmarks/remediation/README.md` describes every fixture currently in the corpus.

1. Write the vulnerable `source` and the `reference_repair` beside it. If the repair touches more
   than one file, declare the extra files under `additional_units`, each with its own `source`,
   `reference_repair` and `finding`.
2. Give the finding a rule id and CWE the analysis service actually emits, from the OpenGrep rule
   packs or from `security_rules.py`. A fixture whose finding could never be produced measures
   nothing.
3. Write `verification_checks`: fixed argv the sandbox runs on both trees. A supported fixture's
   `exploit` check must exit non-zero on the vulnerable tree and zero on the repaired tree, and its
   `behavior` check must exit zero on both. Implement both modes in `tests/verify.js` or
   `tests/verify.py`.
4. If the correct outcome is an abstention, say so: a negative fixture passes by being refused, and
   a repair of it is a failure. Name the reason code you expect.
5. Run it under both adapters:

   ```sh
   .venv/remediation/bin/python benchmarks/remediation/evaluate.py --suite seed
   .venv/remediation/bin/python benchmarks/remediation/evaluate.py --suite seed --adapter engine-local
   ```

   `summary.unexpected_failures` must stay empty. If the fixture's reviewed repair is right and a
   defect in the engine stops the pipeline carrying it, record it in `known-failures.json` with the
   defect's file and line. That labels the failure; it does not turn it into a pass, and the case
   keeps counting against precision and coverage.

## Adding a repair family

A family is a class of vulnerability the engine can repair deterministically, with a generated
test that proves the repair. There are five today: `sql_parameterization`, `command_arguments`,
`path_containment`, `hardcoded_credential` and `code_injection_eval`.

1. Declare it in `LANGUAGE_FAMILIES` in `services/remediation-service/src/families.py`, per
   language. A family supported in one toolchain and not the other is normal.
2. Write the template that rewrites the sink, in `templates.py`, and the site model it needs in
   `sites.py`. A template that cannot name the sink must refuse with a reason code rather than
   guess; the refusal reasons are the useful output of this work, and
   `docs/validation/vulnerable-corpus-2026-09.md` is largely a record of where they land.
3. Write the proof generator: a test that fails on the vulnerable tree and passes on the repaired
   one. If no such test can exist, the correct answer is to refuse. A proof that cannot fail before
   the fix proves nothing after it.
4. Add fixtures for it in both languages, including at least one negative that must abstain.
5. Add the CWEs it covers to the rules that should carry it, and check
   `tests/test_tier2_rule_metadata.py` still passes: it fails a rule that declares a family its CWE
   does not produce.
6. Record the reach: how many findings in the corpus the template patches, how many the service
   writes a proof for, and how many verify end to end. The gap between those three is the honest
   part.

## Conventions

- **No em-dashes.** Anywhere: code, comments, commit messages, documentation. Use a comma, a
  colon, or a full stop.
- **No AI attribution in commits.** No `Co-Authored-By` trailer naming a model, no "generated with"
  line. A commit is authored by the person who sent it.
- **Commit messages say why.** The subject line is what changed; the body is the reason it changed
  and what was measured. The existing history is the model.
- **Numbers carry a link.** A claim about precision, recall, coverage or reach belongs next to the
  document that measured it. If there is no such document, the claim is not ready.
- **State the limit.** Where something is development-grade, say development-grade. The verified
  line on a repair says "development sandbox" because that is what it is.

## Reporting a false positive

A rule that fires on correct code is a defect with an owner, and it is the single most useful
thing to report. Use the false positive issue form, which asks for the rule id, the snippet and
why it is wrong. That is exactly what the adjudication step needs, so a good report goes straight
into the measurement.

## Security

Do not open an issue for a vulnerability in Mitig8it itself. [SECURITY.md](SECURITY.md) says where
to send it.
