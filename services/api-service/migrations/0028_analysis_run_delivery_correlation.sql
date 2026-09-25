-- The webhook delivery that caused a review is the identifier an operator has in hand
-- when GitHub shows a redelivery and the question is "what did we do with it". The
-- analysis queue breaks the request scope, so the delivery has to travel on the row
-- rather than in memory: the process that claims the run is rarely the one that took
-- the webhook, and after an instance restart it never is.
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS delivery_id TEXT;

-- Looking a run up by the delivery an operator pasted from GitHub is the whole point.
CREATE INDEX IF NOT EXISTS idx_analysis_runs_delivery_id
  ON analysis_runs (delivery_id)
  WHERE delivery_id IS NOT NULL;
