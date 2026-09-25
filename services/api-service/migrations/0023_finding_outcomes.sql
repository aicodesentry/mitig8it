-- The durable record of what happened to every finding and to every published fix.
-- It is append-only: no writer updates or deletes a row. A replayed webhook, a retried
-- reconciler step, or a re-run analysis lands on the replay key below and is ignored,
-- so the log can be rebuilt by replay without double counting.
--
-- installation_id is the tenant boundary and repository_id travels with it under the
-- same composite foreign key style migration 0013 introduced, so a bad join can never
-- cross a repository. Row level security is deliberately not enabled here, exactly as
-- on findings, suppressions and audit_logs: those writers use the plain request pool
-- and set no app.tenant_id, and a forced policy would reject their inserts. The scope
-- of a read is enforced in the query, by the installations the caller can reach.

-- The composite parent key the outcome rows reference.
CREATE UNIQUE INDEX IF NOT EXISTS repositories_id_installation_key
  ON repositories (id, installation_id);

CREATE TABLE finding_outcomes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  installation_id BIGINT NOT NULL REFERENCES installations(id),
  repository_id UUID NOT NULL REFERENCES repositories(id),
  pull_request_id UUID REFERENCES pull_requests(id) ON DELETE SET NULL,
  -- A finding row can be removed when a repository is disconnected. The outcome
  -- survives it, which is why the fingerprint and the rule identity are copied here
  -- rather than joined for.
  finding_id UUID REFERENCES findings(id) ON DELETE SET NULL,
  fingerprint VARCHAR(64) NOT NULL,
  rule_id VARCHAR(100),
  cwe_id VARCHAR(20),
  severity VARCHAR(20),
  confidence DECIMAL(3,2),
  -- The finding's category, which is the rule family the learning loop groups by.
  family TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN (
    'fix_published','applied_in_app','applied_on_github','dismissed','accepted_risk',
    'suppressed','thread_resolved','thread_unresolved','fixed_by_reanalysis','reopened',
    'marked_fixed','residual_after_apply'
  )),
  source TEXT NOT NULL CHECK (source IN (
    'workspace','github_thread','github_push','reanalysis','remediation','suppression'
  )),
  -- For a dismissal: not_exploitable, test_or_sample_code, wrong_rule_match or other.
  reason TEXT,
  actor_login TEXT,
  candidate_id UUID,
  action_id UUID,
  job_id UUID,
  commit_sha VARCHAR(64),
  external_id TEXT,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE finding_outcomes ADD CONSTRAINT finding_outcomes_tenant_repo_fkey
  FOREIGN KEY (repository_id, installation_id) REFERENCES repositories (id, installation_id);

-- The replay key. finding_id is nullable and NULLs are distinct in a unique index, so
-- the sentinel and the fingerprint carry the identity when the finding row is gone.
-- The fingerprint never weakens the key while finding_id is set, because a finding's
-- fingerprint is fixed for the life of the row.
CREATE UNIQUE INDEX finding_outcomes_replay_key ON finding_outcomes (
  COALESCE(finding_id, '00000000-0000-0000-0000-000000000000'::uuid),
  fingerprint,
  outcome,
  source,
  COALESCE(external_id, '')
);

CREATE INDEX idx_finding_outcomes_installation_created ON finding_outcomes (installation_id, created_at);
CREATE INDEX idx_finding_outcomes_installation_rule_created ON finding_outcomes (installation_id, rule_id, created_at);
CREATE INDEX idx_finding_outcomes_finding ON finding_outcomes (finding_id);
CREATE INDEX idx_finding_outcomes_pull_request ON finding_outcomes (pull_request_id, outcome);

-- A reply on a review thread carries only the root comment's id, never its body, so the
-- root comment of each finding is remembered the first time the bot's own marked
-- comment is observed. Without it a "not an issue" reply cannot be tied to a finding.
CREATE INDEX IF NOT EXISTS idx_findings_inline_comment
  ON findings (inline_comment_id) WHERE inline_comment_id IS NOT NULL;
