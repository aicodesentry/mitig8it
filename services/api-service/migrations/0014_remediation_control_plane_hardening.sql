-- Additive hardening for the remediation control plane. Nothing here rewrites
-- 0013 rows; every column is nullable or defaulted so an older writer stays safe.

-- A revalidation failure is terminal and machine-readable, not a silent retry.
ALTER TABLE remediation_actions DROP CONSTRAINT IF EXISTS remediation_actions_state_check;
ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_state_check
  CHECK (state IN ('requested','revalidating','committing','applied','checking','completed',
                   'cancelled','superseded','blocked','reconciling','failed','rejected'));

-- Observed GitHub result and the deduplicated verification analysis for the new head.
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS observed_tree_oid VARCHAR(64);
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_analysis_run_id UUID REFERENCES analysis_runs(id);
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS verification_head_sha VARCHAR(64);
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_actions_verification_head
  ON remediation_actions (id, verification_head_sha) WHERE verification_head_sha IS NOT NULL;

-- Outbox quarantine keeps the machine-readable reason separate from the transport error.
ALTER TABLE workflow_outbox ADD COLUMN IF NOT EXISTS dead_letter_reason TEXT;

-- One logical writer per pull request. The row is the lease; expiry means a crashed
-- writer cannot wedge a pull request forever.
CREATE TABLE IF NOT EXISTS remediation_writer_leases (
  pull_request_id UUID PRIMARY KEY REFERENCES pull_requests(id) ON DELETE CASCADE,
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  action_id UUID REFERENCES remediation_actions(id) ON DELETE SET NULL,
  owner_id UUID REFERENCES users(id),
  acquired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remediation_writer_leases_expiry ON remediation_writer_leases (expires_at);

CREATE INDEX IF NOT EXISTS idx_remediation_actions_reconciling ON remediation_actions (state, updated_at);
CREATE INDEX IF NOT EXISTS idx_workflow_outbox_dispatching ON workflow_outbox (status, updated_at);
CREATE INDEX IF NOT EXISTS idx_merge_intents_expiry ON merge_intents (state, expires_at);
CREATE INDEX IF NOT EXISTS idx_workflow_events_aggregate ON workflow_events (aggregate_id, sequence DESC);

DO $$ BEGIN
  EXECUTE 'ALTER TABLE remediation_writer_leases ENABLE ROW LEVEL SECURITY';
  EXECUTE 'ALTER TABLE remediation_writer_leases FORCE ROW LEVEL SECURITY';
  EXECUTE $policy$
    CREATE POLICY remediation_writer_leases_tenant_scope ON remediation_writer_leases
    USING (
      installation_id::text = current_setting('app.tenant_id', true)
      OR current_setting('app.remediation_worker', true) = '1'
      OR EXISTS (
        SELECT 1 FROM repository_access ra
        WHERE ra.repository_id = remediation_writer_leases.repository_id
          AND ra.user_id::text = current_setting('app.user_id', true)
      )
    )
    WITH CHECK (
      installation_id::text = current_setting('app.tenant_id', true)
      OR current_setting('app.remediation_worker', true) = '1'
    )
  $policy$;
END $$;
