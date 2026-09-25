-- The daily roll-up of the outcome log. It holds no fact of its own: every row is a
-- count recomputed from finding_outcomes and findings, so the table can be dropped and
-- rebuilt without losing anything. The reconciler recomputes a trailing window on every
-- pass, which is why the upsert below has to be idempotent rather than incremental.
--
-- Four grains live in the same table, distinguished by which key columns are NULL:
--   repository_id NULL, rule_id NULL -> the installation's total for the day
--   repository_id NULL, rule_id set  -> the installation's total for one rule
--   repository_id set,  rule_id NULL -> one repository's total
--   repository_id set,  rule_id set  -> the base grain
-- A finding belongs to exactly one repository and carries exactly one rule, so the
-- coarser grains are exact sums of the base grain, never approximations. findings.rule_id
-- is NOT NULL, so a NULL rule_id here always means "every rule" and never "unknown".

CREATE TABLE quality_metrics_daily (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT NOT NULL REFERENCES installations(id) ON DELETE CASCADE,
  repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
  rule_id VARCHAR(100),
  day DATE NOT NULL,

  -- Findings created on the day. The denominator of dismiss_rate.
  findings_new INTEGER NOT NULL DEFAULT 0,
  -- Distinct findings a fix was published for. The denominator of apply_rate.
  fixes_published INTEGER NOT NULL DEFAULT 0,
  -- Distinct findings applied from the workspace on the day.
  applied_in_app INTEGER NOT NULL DEFAULT 0,
  -- Distinct findings applied through GitHub's "Commit suggestion" on the day and not
  -- also applied in the app that day. The exclusion is what makes
  -- applied_in_app + applied_on_github an exact count of distinct findings applied,
  -- which both apply_rate and residual_rate depend on.
  applied_on_github INTEGER NOT NULL DEFAULT 0,
  dismissed INTEGER NOT NULL DEFAULT 0,
  accepted_risk INTEGER NOT NULL DEFAULT 0,
  suppressed INTEGER NOT NULL DEFAULT 0,
  thread_resolved INTEGER NOT NULL DEFAULT 0,
  -- A subset of thread_resolved: the reviewer closed the thread and the finding was
  -- never applied or re-analysed away. That is a rejection, so it counts as a dismissal.
  thread_resolved_without_fix INTEGER NOT NULL DEFAULT 0,
  fixed_by_reanalysis INTEGER NOT NULL DEFAULT 0,
  residual_after_apply INTEGER NOT NULL DEFAULT 0,

  computed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The upsert key. NULL is not distinct from NULL in a unique index only when it is
-- replaced by a sentinel, so the rollup grains collide with themselves and are updated
-- in place rather than inserted again on every recompute.
CREATE UNIQUE INDEX quality_metrics_daily_key ON quality_metrics_daily (
  installation_id,
  day,
  COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid),
  COALESCE(rule_id, '')
);

-- The read path: one installation, a trailing window of days.
CREATE INDEX idx_quality_metrics_daily_installation_day
  ON quality_metrics_daily (installation_id, day DESC);
CREATE INDEX idx_quality_metrics_daily_repository_day
  ON quality_metrics_daily (repository_id, day DESC) WHERE repository_id IS NOT NULL;
