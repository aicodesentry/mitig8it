-- Records one entry per worker attempt on a durable execution: which worker claimed it, when,
-- when the attempt ended, and why. A dead-lettered execution has no result artifact, so before
-- this column the only account of a spent recovery budget was `worker_attempts_exhausted` with
-- nothing behind it.
--
-- The entries hold lease bookkeeping only: attempt number, worker id, and UTC timestamps. No
-- tenant, repository, source, provider output, or secret material is stored, and nothing here
-- is used for authorization.
ALTER TABLE remediation_service_executions
    ADD COLUMN IF NOT EXISTS attempt_history jsonb NOT NULL DEFAULT '[]'::jsonb;
