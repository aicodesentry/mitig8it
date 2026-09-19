-- Current finding state and immutable evidence for historical reports are separate.
CREATE TABLE analysis_run_findings (
  analysis_run_id UUID NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL,
  snapshot JSONB NOT NULL,
  PRIMARY KEY (analysis_run_id, finding_id)
);
INSERT INTO analysis_run_findings (analysis_run_id, finding_id, snapshot)
SELECT analysis_run_id, id, to_jsonb(findings) FROM findings WHERE analysis_run_id IS NOT NULL;

ALTER TABLE findings ADD COLUMN suppression_applied BOOLEAN NOT NULL DEFAULT FALSE;
-- Legacy automatic dismissals used the matching suppression reason. Preserve manual
-- dismissals without that evidence; already deleted legacy suppressions cannot be inferred.
UPDATE findings f SET suppression_applied = TRUE
WHERE f.status = 'dismissed' AND EXISTS (
  SELECT 1 FROM suppressions s WHERE s.repository_id = f.repository_id
    AND s.fingerprint = f.fingerprint AND s.reason = f.dismissal_reason
);
