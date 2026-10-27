-- An observed_apply action records a commit someone made on GitHub by pressing "Commit
-- suggestion" on a published fix. That person need not have a Mitig8it account, and
-- the job the fix came from usually has no human creator either (automatic jobs leave
-- remediation_jobs.created_by NULL since 0020). There is no users row to point at, so
-- actor_id NOT NULL made every such insert fail and rolled back the whole push webhook.
--
-- actor_id becomes nullable for observed_apply only. The historical in-app apply and
-- apply_and_merge actions were always taken by a signed-in user and still must name
-- one. actor_login keeps the GitHub identity for every row.
ALTER TABLE remediation_actions ALTER COLUMN actor_id DROP NOT NULL;
ALTER TABLE remediation_actions ADD CONSTRAINT remediation_actions_actor_required
  CHECK (actor_id IS NOT NULL OR action_type = 'observed_apply');
