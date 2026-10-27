#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

git -C "$ROOT_DIR" config core.hooksPath .githooks
chmod +x "$ROOT_DIR/.githooks/pre-push"
chmod +x "$ROOT_DIR/.githooks/commit-msg"

cat <<'EOF'
Git hooks installed.

Active hook path:
- .githooks

Current protection:
- blocks direct pushes to main
- blocks direct pushes to master
- refuses a commit message with no Signed-off-by matching its author, which is what
  the DCO check fails the pull request for, only sooner and without a rebase
- refuses an assistant attribution trailer and an em-dash, which have no CI check

Use feature branches and PRs for integration to main.
EOF
