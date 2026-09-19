CREATE TABLE IF NOT EXISTS remediation_service_executions (
    execution_id text PRIMARY KEY,
    job_id text NOT NULL,
    tenant_id text NOT NULL,
    repository_id text NOT NULL,
    fencing_token bigint,
    request_digest text NOT NULL,
    request_artifact_uri text NOT NULL,
    result_artifact_uri text,
    state text NOT NULL CHECK (state IN ('queued', 'running', 'ready', 'unsupported', 'inconclusive', 'failed', 'cancelled')),
    lease_owner text,
    lease_expires_at timestamptz,
    attempt integer NOT NULL DEFAULT 0,
    checkpoint_version integer NOT NULL DEFAULT 0,
    checkpoint_artifact_uri text,
    charged_tokens bigint NOT NULL DEFAULT 0 CHECK (charged_tokens >= 0),
    actual_tokens bigint NOT NULL DEFAULT 0 CHECK (actual_tokens >= 0),
    charged_usd numeric(14,8) NOT NULL DEFAULT 0 CHECK (charged_usd >= 0),
    actual_usd numeric(14,8) NOT NULL DEFAULT 0 CHECK (actual_usd >= 0),
    pending_call_sequence integer,
    pending_reserved_tokens bigint,
    pending_reserved_usd numeric(14,8),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (job_id, fencing_token)
);

CREATE INDEX IF NOT EXISTS remediation_service_executions_runnable_idx
    ON remediation_service_executions (state, lease_expires_at, created_at)
    WHERE state IN ('queued', 'running');

ALTER TABLE remediation_service_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_service_executions FORCE ROW LEVEL SECURITY;

CREATE POLICY remediation_service_worker_policy ON remediation_service_executions
    USING (current_setting('app.remediation_worker', true) = 'on')
    WITH CHECK (current_setting('app.remediation_worker', true) = 'on');

-- Grant this table only to the dedicated non-BYPASSRLS remediation runtime role.
-- That role is not shared with public API traffic; the internal service sets the
-- transaction-local worker marker on every short transaction.
