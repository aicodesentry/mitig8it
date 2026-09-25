# Known Limitations (V1)

- Deterministic rules are intentionally narrow and prioritize precision over broad recall.
- Dependency risk checks are pattern-based, not a full SBOM/CVE resolver.
- Inline comment dedupe is fingerprint-based and may miss nuanced semantic duplicates.
- RBAC is owner-scoped for dashboard users and does not yet model fine-grained org team membership.
- No billing/plan enforcement logic is included in this V1.
- LLM contextualization hook is not enabled by default in the current implementation.
- One analysis run reviews at most 200 analysable changed files. A larger pull request is
  reviewed to that cap rather than refused: the first 200 files in path order are
  analysed, the selection is the same on every run of the same head, and the check run
  summary states `Reviewed 200 of N changed files`. Findings in the files beyond the cap
  are not reported by that run.
