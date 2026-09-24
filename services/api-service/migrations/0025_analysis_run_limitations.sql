-- A scanner that could only parse part of one file still analysed every other
-- file. The run records what it could not do, so the check run and the review
-- can say which files were only partially analysed instead of either staying
-- silent or failing the whole analysis closed.
ALTER TABLE analysis_runs ADD COLUMN IF NOT EXISTS analysis_limitations JSONB NOT NULL DEFAULT '[]'::jsonb;
