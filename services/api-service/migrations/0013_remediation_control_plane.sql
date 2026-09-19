-- Durable control-plane state.  installation_id is the tenant boundary; repository_id
-- is repeated on every mutable aggregate so a bad join cannot cross repositories.
CREATE TABLE remediation_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  pull_request_id UUID NOT NULL REFERENCES pull_requests(id),
  analysis_run_id UUID NOT NULL REFERENCES analysis_runs(id),
  head_sha VARCHAR(64) NOT NULL,
  base_sha VARCHAR(64) NOT NULL,
  selection_hash VARCHAR(64) NOT NULL,
  finding_snapshot_ids UUID[] NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('queued','snapshotting','retrieving','planning','generating','verifying','ready','cancelled','superseded','unsupported','inconclusive','failed','dead_letter')),
  stage TEXT NOT NULL,
  state_version BIGINT NOT NULL DEFAULT 1,
  fencing_token BIGINT NOT NULL DEFAULT 1,
  lease_owner TEXT,
  lease_expires_at TIMESTAMPTZ,
  external_execution_id TEXT,
  attempt_count INTEGER NOT NULL DEFAULT 0,
  revision_count INTEGER NOT NULL DEFAULT 0,
  deadline_at TIMESTAMPTZ NOT NULL,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  policy_version TEXT NOT NULL,
  policy_manifest JSONB NOT NULL,
  cancellation_reason TEXT,
  failure_reason JSONB,
  created_by UUID NOT NULL REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (repository_id, pull_request_id, analysis_run_id, head_sha, selection_hash, policy_version)
);
ALTER TABLE remediation_jobs ADD CONSTRAINT remediation_jobs_tenant_repo_key UNIQUE (id, installation_id, repository_id);

CREATE TABLE remediation_candidates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  candidate_version INTEGER NOT NULL,
  finding_snapshot_ids UUID[] NOT NULL,
  artifact_digest VARCHAR(128) NOT NULL,
  context_manifest_digest VARCHAR(128) NOT NULL,
  file_manifest JSONB NOT NULL,
  preview JSONB NOT NULL,
  verification_level TEXT NOT NULL,
  rejection_reason JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (job_id, candidate_version),
  UNIQUE (job_id, artifact_digest)
);

CREATE TABLE remediation_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  stage TEXT NOT NULL,
  attempt_number INTEGER NOT NULL,
  fencing_token BIGINT NOT NULL,
  input_digest VARCHAR(128),
  output_digest VARCHAR(128),
  outcome TEXT,
  duration_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  UNIQUE (job_id, stage, attempt_number)
);
ALTER TABLE remediation_attempts ADD CONSTRAINT remediation_attempts_job_tenant_repo_fkey FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);

CREATE TABLE verification_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id UUID REFERENCES remediation_candidates(id) ON DELETE SET NULL,
  job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  candidate_digest VARCHAR(128),
  original_tree_sha VARCHAR(64) NOT NULL,
  candidate_tree_sha VARCHAR(64),
  base_sha VARCHAR(64) NOT NULL,
  verifier_identity TEXT,
  policy_version TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('passed','failed','inconclusive','unsupported')),
  evidence_digest VARCHAR(128),
  coverage_gaps JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE remediation_actions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id UUID NOT NULL REFERENCES remediation_jobs(id),
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  pull_request_id UUID NOT NULL REFERENCES pull_requests(id),
  actor_id UUID NOT NULL REFERENCES users(id),
  actor_login TEXT NOT NULL,
  action_type TEXT NOT NULL CHECK (action_type IN ('apply','apply_and_merge')),
  head_sha VARCHAR(64) NOT NULL,
  base_sha VARCHAR(64) NOT NULL,
  batch_manifest_digest VARCHAR(128) NOT NULL,
  candidate_ids UUID[] NOT NULL,
  idempotency_key VARCHAR(255) NOT NULL,
  payload_hash VARCHAR(64) NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('requested','revalidating','committing','applied','checking','completed','cancelled','superseded','blocked','reconciling','failed')),
  external_operation_id TEXT,
  observed_commit_sha VARCHAR(64),
  failure_reason JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (actor_id, repository_id, idempotency_key)
);

CREATE TABLE merge_intents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action_id UUID NOT NULL UNIQUE REFERENCES remediation_actions(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  actor_id UUID NOT NULL REFERENCES users(id),
  approved_manifest_digest VARCHAR(128) NOT NULL,
  approved_head_sha VARCHAR(64) NOT NULL,
  approved_base_sha VARCHAR(64) NOT NULL,
  applied_sha VARCHAR(64),
  merge_method TEXT NOT NULL DEFAULT 'squash',
  expires_at TIMESTAMPTZ NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('waiting_for_application','waiting_for_checks','eligible','merging','merged','cancelled','expired','superseded','blocked','reconciling')),
  latest_policy_checks JSONB NOT NULL DEFAULT '{}'::jsonb,
  cancellation_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE workflow_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  aggregate_id UUID NOT NULL,
  aggregate_type TEXT NOT NULL,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID REFERENCES repositories(id),
  sequence BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (aggregate_id, sequence)
);

CREATE TABLE workflow_outbox (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  aggregate_id UUID NOT NULL,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID REFERENCES repositories(id),
  event_sequence BIGINT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','dispatching','delivered','dead_letter')),
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at TIMESTAMPTZ,
  last_error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (aggregate_id, event_sequence)
);

CREATE TABLE usage_reservations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  job_id UUID NOT NULL REFERENCES remediation_jobs(id) ON DELETE CASCADE,
  stage TEXT NOT NULL,
  reservation_key VARCHAR(128) NOT NULL,
  reserved_amount NUMERIC(12,4) NOT NULL CHECK (reserved_amount >= 0),
  actual_amount NUMERIC(12,4), provider_request_id TEXT,
  state TEXT NOT NULL CHECK (state IN ('reserved','settled','released','reconciliation_needed')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), settled_at TIMESTAMPTZ,
  UNIQUE (job_id, stage, reservation_key)
);
ALTER TABLE usage_reservations ADD CONSTRAINT usage_reservations_job_tenant_repo_fkey FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);

ALTER TABLE remediation_candidates ADD CONSTRAINT remediation_candidates_job_tenant_repo_fkey FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);
ALTER TABLE verification_runs ADD CONSTRAINT verification_runs_job_tenant_repo_fkey FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);
ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_job_tenant_repo_fkey FOREIGN KEY (job_id, installation_id, repository_id) REFERENCES remediation_jobs(id, installation_id, repository_id);
ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_tenant_repo_key UNIQUE (id, installation_id, repository_id);
ALTER TABLE merge_intents ADD CONSTRAINT merge_intents_action_tenant_repo_fkey FOREIGN KEY (action_id, installation_id, repository_id) REFERENCES remediation_actions(id, installation_id, repository_id);

CREATE TABLE repair_memory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id), weakness_signature TEXT NOT NULL,
  source_digest VARCHAR(128) NOT NULL, patch_digest VARCHAR(128) NOT NULL,
  verification_outcome TEXT NOT NULL, reviewer_id UUID REFERENCES users(id), status TEXT NOT NULL,
  expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_remediation_jobs_runnable ON remediation_jobs (state, next_attempt_at) WHERE state IN ('queued','snapshotting','retrieving','planning','generating','verifying');
CREATE INDEX idx_remediation_jobs_lease ON remediation_jobs (lease_expires_at) WHERE lease_expires_at IS NOT NULL;
CREATE INDEX idx_remediation_jobs_pr_head ON remediation_jobs (repository_id, pull_request_id, head_sha);
CREATE INDEX idx_outbox_pending ON workflow_outbox (next_attempt_at) WHERE status = 'pending';
CREATE INDEX idx_usage_reservations_tenant ON usage_reservations (installation_id, created_at DESC);

-- New-table RLS is deliberately forced. Every API/worker query sets app.tenant_id
-- transaction-locally; a missing context is deny-by-default.
DO $$ DECLARE table_name TEXT; BEGIN
  FOREACH table_name IN ARRAY ARRAY['remediation_jobs','remediation_candidates','remediation_attempts','verification_runs','remediation_actions','merge_intents','workflow_events','workflow_outbox','usage_reservations','repair_memory'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format($policy$
      CREATE POLICY %I_tenant_scope ON %I
      USING (
        installation_id::text = current_setting('app.tenant_id', true)
        OR current_setting('app.remediation_worker', true) = '1'
        OR EXISTS (
          SELECT 1 FROM repository_access ra
          WHERE ra.repository_id = %I.repository_id
            AND ra.user_id::text = current_setting('app.user_id', true)
        )
      )
      WITH CHECK (
        installation_id::text = current_setting('app.tenant_id', true)
        OR current_setting('app.remediation_worker', true) = '1'
      )
    $policy$, table_name, table_name, table_name);
  END LOOP;
END $$;
