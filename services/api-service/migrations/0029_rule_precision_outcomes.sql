-- Per-rule evidence of whether a rule was right, rolled up beside the counts it is made of.
-- Both columns are counts of distinct findings per day, recomputed from finding_outcomes
-- like every other column of this table, so they hold no fact of their own.
--
--   outcome_positive  the finding was real: a fix applied in the app or on GitHub, or a
--                     review thread resolved after the finding was fixed some other way
--   outcome_negative  the rule was wrong: a dismissal for wrong_rule_match or
--                     not_exploitable
--
-- Every other outcome (a test-code dismissal, an accepted risk, a suppression, a thread
-- resolved with no fix) says nothing about whether the rule matched a real defect and is
-- not counted in either. The analysis service combines the sums with each rule's corpus
-- measurement into the precision a finding carries (services/analysis-service/src/
-- rule_precision.py, docs/validation/fix-placement-and-calibration-2026-10.md).
--
-- Rows written before this migration read 0 in both columns until the reconciler's trailing
-- window recomputes them; days older than that window stay at 0.
ALTER TABLE quality_metrics_daily ADD COLUMN IF NOT EXISTS outcome_positive INTEGER NOT NULL DEFAULT 0;
ALTER TABLE quality_metrics_daily ADD COLUMN IF NOT EXISTS outcome_negative INTEGER NOT NULL DEFAULT 0;

-- The read the analysis path makes before triage: one installation's per-rule grain.
CREATE INDEX IF NOT EXISTS idx_quality_metrics_daily_rule_outcomes
  ON quality_metrics_daily (installation_id, rule_id, day DESC)
  WHERE repository_id IS NULL AND rule_id IS NOT NULL;
