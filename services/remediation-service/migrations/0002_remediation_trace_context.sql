-- Persists the W3C trace context captured at repair intake so the worker resumes the job
-- with a span link back to the originating request instead of starting an unrelated trace.
-- Section 10 of docs/architecture/agentic-remediation-implementation-plan.md requires span
-- links for resumed asynchronous stages.
--
-- Only the traceparent header value is stored. It carries no tenant, repository, source, or
-- secret material, and it is not used for authorization.
ALTER TABLE remediation_service_executions
    ADD COLUMN IF NOT EXISTS trace_context text;
