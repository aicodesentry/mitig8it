#!/usr/bin/env bash
# The repository settings this project depends on, as one command.
#
#   scripts/setup-repository.sh            report what is set and what is not
#   scripts/setup-repository.sh --apply    make the changes
#
# Every setting here needs repository admin. A token with push access gets 404 on all of them,
# which is indistinguishable from "not found", so this script checks admin first and says so
# rather than reporting a permissions problem as an absent setting.
#
# Two things it deliberately does not do. The Actions "require approval for workflow runs" policy
# has no stable REST endpoint, so it is printed as a UI step instead of guessed at. And it never
# relaxes a setting: every action here either adds protection or is a no-op.

set -euo pipefail

REPO="${REPO:-aicodesentry/mitig8it}"
BRANCH="${BRANCH:-main}"
REQUIRED_CHECK="${REQUIRED_CHECK:-Required CI}"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

say()  { printf '%s\n' "$*"; }
ok()   { printf '  ok      %s\n' "$*"; }
todo() { printf '  TODO    %s\n' "$*"; }
did()  { printf '  applied %s\n' "$*"; }

say "Repository: ${REPO}"
say ""

# --- admin check ---------------------------------------------------------------------------------
# Without this every check below reports "absent" when the truth is "cannot see".
admin="$(gh api "repos/${REPO}" --jq '.permissions.admin' 2>/dev/null || echo "unknown")"
if [ "${admin}" != "true" ]; then
  say "This token does not have admin on ${REPO} (permissions.admin=${admin})."
  say "Every setting below needs admin. Re-run as the repository owner, or do them in Settings."
  say ""
fi

# --- 1. branch protection ------------------------------------------------------------------------
# Required CI is an aggregating job that already reports on every pull request. Until a branch rule
# names it, it is a status nobody has to satisfy: a red CI does not stop a merge.
say "1. Branch protection on ${BRANCH}, requiring '${REQUIRED_CHECK}'"
if gh api "repos/${REPO}/branches/${BRANCH}/protection" >/dev/null 2>&1; then
  current="$(gh api "repos/${REPO}/branches/${BRANCH}/protection" \
    --jq '[.required_status_checks.contexts[]?] | join(", ")' 2>/dev/null || echo "")"
  ok "protection exists; required checks: ${current:-none}"
  case "${current}" in
    *"${REQUIRED_CHECK}"*) ok "'${REQUIRED_CHECK}' is required" ;;
    *) todo "'${REQUIRED_CHECK}' is NOT in the required checks" ;;
  esac
elif [ "${APPLY}" = "1" ] && [ "${admin}" = "true" ]; then
  # CODEOWNERS already names an owner for every path, so owner review is required rather than a
  # plain approval count. enforce_admins stays false: a solo maintainer who cannot merge their own
  # hotfix will turn the whole rule off, which protects nothing.
  gh api -X PUT "repos/${REPO}/branches/${BRANCH}/protection" --input - >/dev/null <<JSON
{
  "required_status_checks": { "strict": false, "contexts": ["${REQUIRED_CHECK}"] },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "require_code_owner_reviews": true,
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": false
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
  did "branch protection set, '${REQUIRED_CHECK}' required"
else
  todo "no branch protection; '${REQUIRED_CHECK}' blocks nothing today"
fi
say ""

# --- 2. private vulnerability reporting ------------------------------------------------------------
# SECURITY.md sends reporters to an email address. This gives them a private channel on the
# repository itself, which is where someone who just found a bug will look first.
say "2. Private vulnerability reporting"
pvr="$(gh api "repos/${REPO}/private-vulnerability-reporting" --jq '.enabled' 2>/dev/null || echo "unknown")"
if [ "${pvr}" = "true" ]; then
  ok "enabled"
elif [ "${APPLY}" = "1" ] && [ "${admin}" = "true" ]; then
  gh api -X PUT "repos/${REPO}/private-vulnerability-reporting" >/dev/null
  did "enabled"
else
  todo "disabled (enabled=${pvr}); SECURITY.md points at email only"
fi
say ""

# --- 3. the ready-to-merge label -------------------------------------------------------------------
# .github/workflows/auto-update-pr-branches.yml updates only pull requests carrying this label.
# Without the label that path is a permanent no-op, which is safe but silent.
say "3. 'ready-to-merge' label"
if gh api "repos/${REPO}/labels/ready-to-merge" >/dev/null 2>&1; then
  ok "exists"
elif [ "${APPLY}" = "1" ]; then
  gh api -X POST "repos/${REPO}/labels" \
    -f name='ready-to-merge' -f color='0E8A16' \
    -f description='auto-update-pr-branches keeps this PR current with main' >/dev/null
  did "created"
else
  todo "missing; the auto-update workflow's automatic path does nothing until it exists"
fi
say ""

# --- 4. things with no API, or no API worth guessing at ---------------------------------------------
say "4. By hand, in the UI"
say "   Settings, Actions, General, Fork pull request workflows: turn off the approval"
say "   requirement for workflow runs. While it is on, a bot's merge commit and an outside"
say "   contributor's push both land as action_required and the pull request reports no checks"
say "   at all, which reads as a broken CI rather than a queue."
say ""
say "   Packages, mitig8it-action, Package settings, Change visibility, Public. Only after the"
say "   first release exists. A private package makes every user's pull fail and fall back to"
say "   building from source, which is the cold start the release exists to remove."
say "   docs/releasing.md step 4.1 says the same thing and is the authority."
say ""

[ "${APPLY}" = "1" ] || say "Nothing was changed. Re-run with --apply to make the changes above."
