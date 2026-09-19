-- Forward-only additions for the merge controller. Every column is nullable or
-- defaulted so a feature-off writer from the previous release stays correct.

-- Merge intents gain their own fencing version, the blocker list the controller
-- persists and re-evaluates, the external operation identity recorded before the
-- guarded merge call, the observed merge revision and the evaluation timestamp.
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS state_version BIGINT NOT NULL DEFAULT 1;
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS merge_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS blockers JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS external_operation_id TEXT;
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS observed_merge_sha VARCHAR(64);
ALTER TABLE merge_intents ADD COLUMN IF NOT EXISTS last_evaluated_at TIMESTAMPTZ;

-- The sweep reads non-terminal intents ordered by the least recently evaluated.
CREATE INDEX IF NOT EXISTS idx_merge_intents_evaluation
  ON merge_intents (state, last_evaluated_at NULLS FIRST);

-- What this app actually published as its remediation verification check. The merge
-- gate reads this record; an absent record is a blocker, never an assumed pass.
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_check_run_id BIGINT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_check_status TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_check_conclusion TEXT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_check_head_sha VARCHAR(64);
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_check_published_at TIMESTAMPTZ;

-- Reviewed repair memory. Feedback is recorded as an observation; promotion to an
-- approved example requires human review and is never performed by this path.
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS job_id UUID REFERENCES remediation_jobs(id) ON DELETE CASCADE;
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS candidate_id UUID REFERENCES remediation_candidates(id) ON DELETE CASCADE;
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS actor_id UUID REFERENCES users(id);
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS head_sha VARCHAR(64);
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS outcome TEXT;
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS reason TEXT;
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS provenance JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE repair_memory ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- One observation per actor and candidate. A repeated submission revises that actor's
-- own observation instead of inflating the evidence with duplicates.
CREATE UNIQUE INDEX IF NOT EXISTS idx_repair_memory_actor_candidate
  ON repair_memory (candidate_id, actor_id) WHERE candidate_id IS NOT NULL AND actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_repair_memory_status_expiry ON repair_memory (status, expires_at);
