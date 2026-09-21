-- Automatic remediation jobs are created by the control plane after a completed
-- analysis, not by a user. created_by becomes nullable and origin records who asked.
-- The partial unique index enforces at most one automatic job per pull request head.
ALTER TABLE remediation_jobs ALTER COLUMN created_by DROP NOT NULL;
ALTER TABLE remediation_jobs ADD COLUMN IF NOT EXISTS origin VARCHAR(16) NOT NULL DEFAULT 'user';
ALTER TABLE remediation_jobs DROP CONSTRAINT IF EXISTS remediation_jobs_origin_check;
ALTER TABLE remediation_jobs ADD CONSTRAINT remediation_jobs_origin_check CHECK (origin IN ('user', 'automatic'));
CREATE UNIQUE INDEX IF NOT EXISTS remediation_jobs_one_automatic_per_head
  ON remediation_jobs (pull_request_id, head_sha) WHERE origin = 'automatic';

-- Verified fixes are published under each finding's inline comment once the job is
-- ready. The row records the head the sections were written for, so a retry updates
-- in place and a moved head is never written to.
ALTER TABLE remediation_jobs ADD COLUMN IF NOT EXISTS inline_fixes_published_at TIMESTAMPTZ;
ALTER TABLE remediation_jobs ADD COLUMN IF NOT EXISTS inline_fixes_head_sha VARCHAR(64);
