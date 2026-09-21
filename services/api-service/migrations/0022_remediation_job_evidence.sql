-- Durable repair evidence. The repair service runs on an execution backend whose own
-- record is short-lived, so once a job completed the agent trace, the check outcomes,
-- the token usage, the cost and the budget settlements were unrecoverable and the only
-- thing left was the candidate preview. This table keeps that evidence on the control
-- plane, bounded per row, so an operator can still answer why a finding was or was not
-- repaired long after the execution record is gone.
CREATE TABLE remediation_job_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  attempt INTEGER NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('agent_trace','usage','budget_reservation','groups','verification','candidate_evidence')),
  payload JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- One row per kind per attempt. A retried attempt keeps its own evidence rather than
  -- overwriting what an earlier attempt recorded.
  UNIQUE (job_id, attempt, kind)
);
ALTER TABLE remediation_job_evidence ADD CONSTRAINT remediation_job_evidence_job_tenant_repo_fkey
  FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);

CREATE INDEX idx_remediation_job_evidence_job ON remediation_job_evidence (job_id, attempt, kind);

-- The same tenant scope the other remediation tables force: the installation, the
-- remediation worker, or a user who holds access to the repository.
ALTER TABLE remediation_job_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_job_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY remediation_job_evidence_tenant_scope ON remediation_job_evidence
  USING (
    installation_id::text = current_setting('app.tenant_id', true)
    OR current_setting('app.remediation_worker', true) = '1'
    OR EXISTS (
      SELECT 1 FROM repository_access ra
      WHERE ra.repository_id = remediation_job_evidence.repository_id
        AND ra.user_id::text = current_setting('app.user_id', true)
    )
  )
  WITH CHECK (
    installation_id::text = current_setting('app.tenant_id', true)
    OR current_setting('app.remediation_worker', true) = '1'
  );
