-- An automatic job that ended in a terminal failure must not block the next analysis
-- from queuing a fresh automatic job for the same head. Only in-flight and ready
-- automatic jobs hold the one-per-head key.
DROP INDEX IF EXISTS remediation_jobs_one_automatic_per_head;
CREATE UNIQUE INDEX IF NOT EXISTS remediation_jobs_one_automatic_per_head
  ON remediation_jobs (pull_request_id, head_sha)
  WHERE origin = 'automatic'
    AND state NOT IN ('cancelled','superseded','unsupported','inconclusive','failed','dead_letter');
