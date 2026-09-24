-- The Mitig8it GitHub App no longer holds write access to repository contents, so it
-- cannot create a commit on a pull request branch and cannot merge a pull request.
-- Every verified fix is published as a GitHub suggestion block; GitHub's own "Commit
-- suggestion" button applies it under the developer's identity.
--
-- The historical rows stay: `apply` and `apply_and_merge` actions that were created
-- while the in-app write path existed remain readable, and so does every merge intent.
-- Only the set of action types that may be created from here on changes. The new
-- `observed_apply` type is written by the push webhook when it sees a commit
-- co-authored by the app, and it is what the residual report and the verification
-- check hang off.

ALTER TABLE remediation_actions DROP CONSTRAINT IF EXISTS remediation_actions_action_type_check;
ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_action_type_check
  CHECK (action_type IN ('apply', 'apply_and_merge', 'observed_apply'));

-- One observed action per applied commit, per pull request. A redelivered push webhook
-- records nothing new.
CREATE UNIQUE INDEX IF NOT EXISTS idx_remediation_actions_observed_commit
  ON remediation_actions (pull_request_id, idempotency_key)
  WHERE action_type = 'observed_apply';
