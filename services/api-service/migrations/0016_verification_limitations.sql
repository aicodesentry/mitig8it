-- Verification runs record the checks that were not executed so previews can state
-- coverage limits honestly instead of implying complete verification.
ALTER TABLE verification_runs ADD COLUMN IF NOT EXISTS limitations JSONB NOT NULL DEFAULT '[]'::jsonb;
