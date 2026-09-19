-- A transient infrastructure fault (metadata token timeout, gRPC UNAVAILABLE) used
-- to fail an analysis run terminally. Automatic retries allocate a new attempt, so
-- each run records how many automatic attempts preceded it and when it may start.
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS auto_retry_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS not_before TIMESTAMP;

-- The queue orders pending work by eligibility, not by insertion time alone.
CREATE INDEX IF NOT EXISTS idx_analysis_runs_pending_not_before
  ON analysis_runs (COALESCE(not_before, created_at) ASC)
  WHERE status = 'pending';
