# Licensing, for someone packaging this

The short answer: everything in this repository is Apache License 2.0, and there is no vendored
third-party source to reason about separately.

## What covers what

| Part | Licence | Notes |
| --- | --- | --- |
| Source code, all services, the Action, the frontend | Apache 2.0 | `LICENSE` at the repository root covers the tree. |
| Detection rules, `services/analysis-service/src/opengrep_rules/` | Apache 2.0 | Original work of this repository. See below, because this is the part a packager should check. |
| Documentation under `docs/`, `README.md`, the runbooks | Apache 2.0 | Same terms as the code. |
| Benchmark corpora under `benchmarks/` | Apache 2.0 | The fixtures are written here. The vulnerable corpus under `benchmarks/vulnerable-corpus/` contains no third-party source: it holds labels, adjudications and a fetcher that downloads each upstream repository at a pinned revision at run time. Those repositories keep their own licences and are recorded with them. |
| Dependencies | Their own | Declared in the lockfiles. The release workflow attaches an SPDX SBOM to each release, which is the artifact to audit rather than this document. |

## Why the rules deserve a sentence of their own

The rule files sit in a directory named `opengrep_rules/` and are written in a syntax that
OpenGrep and Semgrep both read. That naming is about the engine that evaluates them, not about
where they came from. Every rule was written in this repository.

Both public rule libraries were reviewed and deliberately excluded:
[docs/legal/third-party-rules.md](third-party-rules.md) records the reading. The Semgrep registry
rules are under a licence that forbids making them available as a service, and the OpenGrep fork
carries LGPL 2.1 plus the Commons Clause, which forbids selling a product whose value derives from
them. Neither is compatible with what this product does, so neither is used, and
[CONTRIBUTING.md](../../CONTRIBUTING.md) states that a rule copied from either cannot be merged
whatever it does.

The practical consequence for a packager: the rules ship under Apache 2.0 with the rest of the
tree, with no copyleft and no field-of-use restriction attached.

## Contributions

Contributors keep their copyright and sign off under the Developer Certificate of Origin, which is
reproduced verbatim as [DCO](../../DCO) at the repository root. There is no contributor licence
agreement and no copyright assignment. `.github/workflows/dco.yml` enforces the sign-off.

## What this document is not

It is not legal advice, and it is not a substitute for the SBOM. If you are shipping this
downstream, read the SBOM attached to the release for the dependency tree, and read
`third-party-rules.md` if the rule provenance matters to you.
