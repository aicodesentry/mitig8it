# History

Dated reviews and work packages, kept as they were written on their dates. None of them is
maintained against the current code, and nothing here should be read as a description of how the
system behaves today. They are kept because they record what was known and decided at the time,
which the current documents do not.

For what is true now, start at [docs/README.md](../README.md).

| Document | Date | What it is |
| --- | --- | --- |
| [PRODUCT-ANALYSIS-2026-08-08.md](PRODUCT-ANALYSIS-2026-08-08.md) | 8 Aug 2026 | Product analysis of the V1 scope. |
| [DEVELOPER-READINESS-REVIEW-2026-08-14.md](DEVELOPER-READINESS-REVIEW-2026-08-14.md) | 14 Aug 2026 | Readiness review, with file and line evidence for each finding. |
| [EXECUTION-PLAN-2026-08-17.md](EXECUTION-PLAN-2026-08-17.md) | 17 Aug 2026 | The plan of work derived from that review. |
| [TASK-01-fix-production-migrations.md](TASK-01-fix-production-migrations.md) | Aug 2026 | Work package: run migrations from the release image. |
| [TASK-02-fix-suppression-repo-scoping.md](TASK-02-fix-suppression-repo-scoping.md) | Aug 2026 | Work package: scope suppressions to a repository. |
| [TASK-03-fix-webhook-dedup.md](TASK-03-fix-webhook-dedup.md) | Aug 2026 | Work package: make webhook deduplication atomic and retryable. |
| [BUG-REVIEW-2026-09-05.md](BUG-REVIEW-2026-09-05.md) | 5 Sep 2026 | The bug review the hardening pass was scoped from. |
| [HARDENING-TRACKER.md](HARDENING-TRACKER.md) | Sep 2026 | Defect-to-fix tracker for that pass, including its residual risks. |
| [HARDENING-HANDOFF.md](HARDENING-HANDOFF.md) | Sep 2026 | Handoff notes for the same pass: commands, migration sequencing, verification limits. |

Residual risks recorded in `HARDENING-TRACKER.md` and `HARDENING-HANDOFF.md` that are still open
are carried forward in [docs/architecture/known-debt.md](../architecture/known-debt.md).
