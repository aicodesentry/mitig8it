-- A job that ended in a terminal failure (inconclusive, failed, unsupported, cancelled,
-- superseded, dead_letter) must not shadow a later identical generation request. Only
-- in-flight and ready jobs keep the logical generation key, so an identical request
-- replays an in-flight or ready job and otherwise creates a fresh one.
DO $$
DECLARE
  constraint_name TEXT;
BEGIN
  SELECT conname INTO constraint_name
  FROM pg_constraint
  WHERE conrelid = 'remediation_jobs'::regclass
    AND contype = 'u'
    AND conkey = (
      SELECT array_agg(attnum ORDER BY ordinality)
      FROM unnest(ARRAY['repository_id','pull_request_id','analysis_run_id','head_sha','selection_hash','policy_version']) WITH ORDINALITY AS cols(name, ordinality)
      JOIN pg_attribute ON attrelid = 'remediation_jobs'::regclass AND attname = cols.name
    );
  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE remediation_jobs DROP CONSTRAINT %I', constraint_name);
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS remediation_jobs_active_generation_key
  ON remediation_jobs (repository_id, pull_request_id, analysis_run_id, head_sha, selection_hash, policy_version)
  WHERE state NOT IN ('cancelled','superseded','unsupported','inconclusive','failed','dead_letter');
