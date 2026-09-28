-- gRPC status codes were persisted as JSON numbers by older remediation jobs.
-- Keep existing failure reasons intact while normalising numeric codes to their names.
UPDATE remediation_jobs
SET failure_reason = jsonb_set(
  failure_reason,
  '{code}',
  to_jsonb(
    CASE (failure_reason->>'code')::integer
      WHEN 3 THEN 'INVALID_ARGUMENT'
      WHEN 9 THEN 'FAILED_PRECONDITION'
      ELSE failure_reason->>'code'
    END
  )
)
WHERE jsonb_typeof(failure_reason->'code') = 'number'
  AND (failure_reason->>'code') IN ('3', '9');

-- Older remediation attempts can also contain numeric gRPC outcomes.
UPDATE remediation_attempts
SET outcome = CASE outcome
  WHEN '3' THEN 'INVALID_ARGUMENT'
  WHEN '9' THEN 'FAILED_PRECONDITION'
  ELSE outcome
END
WHERE outcome IN ('3', '9');
