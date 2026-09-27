-- gRPC status codes 3 and 9 were persisted as JSON numbers by older remediation jobs.
-- Keep the existing failure reason intact while normalising those codes to their names.
UPDATE remediation_jobs
SET failure_reason = jsonb_set(
  failure_reason,
  '{code}',
  to_jsonb(
    CASE (failure_reason->>'code')::integer
      WHEN 3 THEN 'INVALID_ARGUMENT'
      WHEN 9 THEN 'FAILED_PRECONDITION'
    END
  )
)
WHERE jsonb_typeof(failure_reason->'code') = 'number'
  AND (failure_reason->>'code') IN ('3', '9');
