#!/bin/sh
# The action's entrypoint. Its only jobs are to translate the model inputs into the environment
# the repair engine reads, and to hand over to the orchestrator.
set -eu

# The repair agent is enabled by the presence of a key and by nothing else. When no key is given
# these stay unset, the engine gets a provider that abstains, and only template repairs run.
if [ -n "${INPUT_MODEL_API_KEY:-}" ]; then
  REPAIR_LLM_API_KEY="${INPUT_MODEL_API_KEY}"
  REPAIR_LLM_MODEL="${INPUT_MODEL:-gpt-4o-mini}"
  export REPAIR_LLM_API_KEY REPAIR_LLM_MODEL
  if [ -n "${INPUT_MODEL_PROVIDER:-}" ]; then
    REPAIR_LLM_BASE_URL="${INPUT_MODEL_PROVIDER}"
    export REPAIR_LLM_BASE_URL
  fi
  # Tier 3 triage uses the same key, through the analysis service's own variables.
  LLM_API_KEY="${INPUT_MODEL_API_KEY}"
  LLM_TRIAGE_ENABLED=true
  export LLM_API_KEY LLM_TRIAGE_ENABLED
  if [ -n "${INPUT_MODEL:-}" ]; then
    LLM_MODEL="${INPUT_MODEL}"
    export LLM_MODEL
  fi
else
  LLM_TRIAGE_ENABLED=false
  export LLM_TRIAGE_ENABLED
fi

mkdir -p "${SANDBOX_LOCAL_WORKSPACE_ROOT:-/tmp/mitig8it-sandbox}"

cd /opt/mitig8it/action
exec python -m orchestrator.run
