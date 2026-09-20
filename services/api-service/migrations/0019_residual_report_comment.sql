-- One residual report comment per applied action. The comment is published when the
-- fresh analysis of the applied head completes and is updated in place on retry, so
-- the row records which GitHub comment carries the report for which head.
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS residual_comment_id BIGINT;
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS residual_comment_head_sha VARCHAR(64);
ALTER TABLE remediation_actions ADD COLUMN IF NOT EXISTS residual_comment_published_at TIMESTAMPTZ;
