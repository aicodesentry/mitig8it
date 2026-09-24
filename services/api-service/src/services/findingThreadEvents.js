const findingsDb = require('../db/findings');
const findingOutcomes = require('../db/findingOutcomes');
const { appBotLogin } = require('./githubAppIdentity');
const logger = require('../utils/logger');

// What a reviewer does to a finding on GitHub itself: resolving the bot's review thread,
// replying "not an issue" to it, or pressing "Commit suggestion" on a published fix.
// Every function here reads only the webhook payload and the database, never GitHub, so
// it runs inside the delivery transaction the webhook route already holds.

// The marker the analysis writes at the top of every inline finding comment.
const FINDING_MARKER = /<!--\s*mitig8it-finding:([0-9a-f]{40,64})\s*-->/i;

// A reply that dismisses the finding. Matched on the trimmed, lower-cased body so a
// reviewer's capitalisation or trailing explanation does not change the meaning.
const DISMISS_PREFIXES = ['not an issue', 'false positive', '/mitig8it dismiss'];

const DEFAULT_REPLY_REASON = 'wrong_rule_match';

function markerFingerprint(body) {
  const match = FINDING_MARKER.exec(String(body || ''));
  return match ? match[1].toLowerCase() : null;
}

function normalizedBody(body) {
  return String(body || '').trim().toLowerCase();
}

function isDismissCommand(body) {
  const text = normalizedBody(body);
  return DISMISS_PREFIXES.some((prefix) => text.startsWith(prefix));
}

// The reply dismisses with wrong_rule_match unless it names one of the four reasons.
function replyDismissalReason(body) {
  const text = normalizedBody(body);
  for (const candidate of findingOutcomes.DISMISSAL_REASONS) {
    if (text.includes(candidate)) return candidate;
  }
  if (text.includes('not exploitable') || text.includes('false positive')) return 'not_exploitable';
  if (text.includes('test code') || text.includes('sample code')) return 'test_or_sample_code';
  return DEFAULT_REPLY_REASON;
}

// The comment a thread hangs from. GitHub sends the thread's comments in order and only
// the root has no in_reply_to_id, but neither the array nor the field is guaranteed, so
// the first comment is the fallback.
function threadRootComment(thread) {
  const comments = Array.isArray(thread?.comments) ? thread.comments.filter(Boolean) : [];
  if (!comments.length) return null;
  return comments.find((comment) => comment.in_reply_to_id == null) || comments[0];
}

// The fingerprint any comment in the thread carries, preferring the root's.
function threadFingerprint(thread) {
  const root = threadRootComment(thread);
  const fromRoot = markerFingerprint(root?.body);
  if (fromRoot) return { fingerprint: fromRoot, comment: root };
  const comments = Array.isArray(thread?.comments) ? thread.comments.filter(Boolean) : [];
  for (const comment of comments) {
    const fingerprint = markerFingerprint(comment.body);
    if (fingerprint) return { fingerprint, comment };
  }
  return { fingerprint: null, comment: root };
}

// GitHub's "Commit suggestion" button commits on the reviewer's behalf and credits the
// comment's author as a co-author. The app's own bot login is what identifies those
// commits; it comes from the configured slug, never from a literal.
function isCommitSuggestionCommit(commit, botLogin) {
  const message = String(commit?.message || '');
  if (!message) return false;
  const needle = `co-authored-by: ${String(botLogin || '').toLowerCase()}`;
  return message
    .split('\n')
    .some((line) => line.trim().toLowerCase().startsWith(needle));
}

function commitSuggestionCommits(payload, botLogin = appBotLogin()) {
  const commits = Array.isArray(payload?.commits) ? payload.commits.filter(Boolean) : [];
  return commits.filter((commit) => isCommitSuggestionCommit(commit, botLogin));
}

function changedPaths(commit) {
  const modified = Array.isArray(commit?.modified) ? commit.modified : [];
  const added = Array.isArray(commit?.added) ? commit.added : [];
  return [...new Set([...modified, ...added].filter((path) => typeof path === 'string' && path))];
}

// --- Database-facing handlers -----------------------------------------------------

async function resolveRepository(client, repositoryGithubId) {
  if (!repositoryGithubId) return null;
  const result = await client.query(
    'SELECT id, installation_id FROM repositories WHERE github_id = $1', [repositoryGithubId]
  );
  return result.rows[0] || null;
}

async function resolvePullRequest(client, repositoryId, prNumber) {
  if (!repositoryId || prNumber == null) return null;
  const result = await client.query(
    'SELECT id FROM pull_requests WHERE repository_id = $1 AND pr_number = $2', [repositoryId, prNumber]
  );
  return result.rows[0] || null;
}

/**
 * pull_request_review_thread, actions resolved and unresolved. The thread's root comment
 * carries the finding marker; a thread that is not ours is ignored.
 */
async function handleReviewThread(client, payload) {
  const action = payload?.action;
  if (action !== 'resolved' && action !== 'unresolved') return { handled: false, reason: 'action_ignored' };

  const repository = await resolveRepository(client, payload?.repository?.id);
  if (!repository) return { handled: false, reason: 'repository_unknown' };
  const pullRequest = await resolvePullRequest(client, repository.id, payload?.pull_request?.number);
  if (!pullRequest) return { handled: false, reason: 'pull_request_unknown' };

  const { fingerprint, comment } = threadFingerprint(payload?.thread);
  if (!fingerprint) return { handled: false, reason: 'not_a_finding_thread' };

  // Remembering the root comment is what lets a later plain reply be tied to a finding.
  if (comment?.id) {
    await findingsDb.rememberInlineComment({
      repositoryId: repository.id, pullRequestId: pullRequest.id, fingerprint, commentId: comment.id,
    }, client);
  }

  const finding = await findingsDb.findByPullRequestFingerprint({
    repositoryId: repository.id, pullRequestId: pullRequest.id, fingerprint,
  }, client);
  if (!finding) return { handled: false, reason: 'finding_unknown', fingerprint };

  const recorded = await findingOutcomes.recordOutcome(client, {
    ...findingOutcomes.identityOf(finding),
    repositoryId: repository.id,
    installationId: repository.installation_id,
    pullRequestId: pullRequest.id,
    outcome: action === 'resolved' ? 'thread_resolved' : 'thread_unresolved',
    source: 'github_thread',
    actorLogin: payload?.sender?.login || null,
    externalId: payload?.thread?.node_id || (comment?.id != null ? String(comment.id) : null),
    details: { thread_action: action },
  });

  return { handled: true, outcome_id: recorded, finding_id: finding.id, fingerprint };
}

/**
 * pull_request_review_comment, action created. Two jobs:
 *  - the app's own marked comment is remembered, so replies to it can be resolved;
 *  - a reply that dismisses the finding sets its status and records the dismissal.
 */
async function handleReviewComment(client, payload) {
  if (payload?.action !== 'created') return { handled: false, reason: 'action_ignored' };
  const comment = payload?.comment;
  if (!comment) return { handled: false, reason: 'no_comment' };

  const repository = await resolveRepository(client, payload?.repository?.id);
  if (!repository) return { handled: false, reason: 'repository_unknown' };
  const pullRequest = await resolvePullRequest(client, repository.id, payload?.pull_request?.number);
  if (!pullRequest) return { handled: false, reason: 'pull_request_unknown' };

  const fingerprint = markerFingerprint(comment.body);
  if (fingerprint && comment.in_reply_to_id == null) {
    const remembered = await findingsDb.rememberInlineComment({
      repositoryId: repository.id, pullRequestId: pullRequest.id, fingerprint, commentId: comment.id,
    }, client);
    return { handled: remembered, reason: 'finding_comment_remembered', fingerprint };
  }

  if (comment.in_reply_to_id == null) return { handled: false, reason: 'not_a_reply' };
  if (!isDismissCommand(comment.body)) return { handled: false, reason: 'not_a_command' };

  const finding = await findingsDb.findByInlineCommentId({
    repositoryId: repository.id, pullRequestId: pullRequest.id, commentId: comment.in_reply_to_id,
  }, client);
  if (!finding) return { handled: false, reason: 'thread_root_unknown' };

  const reason = replyDismissalReason(comment.body);
  await client.query(
    `UPDATE findings SET status = 'dismissed', dismissal_reason = $2, suppression_applied = FALSE,
       updated_at = NOW() WHERE id = $1`,
    [finding.id, reason]
  );

  const recorded = await findingOutcomes.recordOutcome(client, {
    ...findingOutcomes.identityOf(finding),
    repositoryId: repository.id,
    installationId: repository.installation_id,
    pullRequestId: pullRequest.id,
    outcome: 'dismissed',
    source: 'github_thread',
    reason,
    actorLogin: payload?.sender?.login || comment.user?.login || null,
    externalId: String(comment.id),
    details: { in_reply_to_id: String(comment.in_reply_to_id) },
  });

  return { handled: true, outcome_id: recorded, finding_id: finding.id, reason };
}

/**
 * The push webhook. A commit GitHub created from "Commit suggestion" on one of the app's
 * published fixes applies that fix outside the workspace. It is recorded as applied on
 * GitHub, never as fixed: the re-analysis of the new head is what establishes that.
 */
async function handleCommitSuggestions(client, payload, { botLogin = appBotLogin() } = {}) {
  const commits = commitSuggestionCommits(payload, botLogin);
  if (!commits.length) return { handled: false, reason: 'no_suggestion_commits' };

  const repository = await resolveRepository(client, payload?.repository?.id);
  if (!repository) return { handled: false, reason: 'repository_unknown' };

  const ref = String(payload?.ref || '');
  if (!ref.startsWith('refs/heads/')) return { handled: false, reason: 'not_a_branch' };
  const branch = ref.slice('refs/heads/'.length);

  const pullRequests = await client.query(
    `SELECT id FROM pull_requests WHERE repository_id = $1 AND head_branch = $2 AND state = 'open'`,
    [repository.id, branch]
  );
  if (!pullRequests.rowCount) return { handled: false, reason: 'no_open_pull_request' };

  let recorded = 0;
  for (const pullRequest of pullRequests.rows) {
    for (const commit of commits) {
      const paths = changedPaths(commit);
      if (!paths.length) continue;
      const candidates = await findingsDb.listByPullRequestPaths({
        repositoryId: repository.id, pullRequestId: pullRequest.id, paths,
      }, client);
      if (!candidates.length) continue;
      // Only a finding whose fix this app published can have been applied by pressing
      // "Commit suggestion" on it.
      const published = await client.query(
        `SELECT DISTINCT finding_id FROM finding_outcomes
          WHERE pull_request_id = $1 AND outcome = 'fix_published' AND finding_id = ANY($2::uuid[])`,
        [pullRequest.id, candidates.map((finding) => finding.id)]
      );
      const publishedIds = new Set(published.rows.map((row) => String(row.finding_id)));
      const applied = candidates.filter((finding) => publishedIds.has(String(finding.id)));
      if (!applied.length) continue;
      const ids = await findingOutcomes.recordOutcomesForFindings(client, applied, {
        repositoryId: repository.id,
        installationId: repository.installation_id,
        pullRequestId: pullRequest.id,
        outcome: 'applied_on_github',
        source: 'github_push',
        actorLogin: payload?.sender?.login || commit.author?.username || null,
        commitSha: commit.id || null,
        externalId: commit.id || null,
        details: { branch, paths },
      });
      recorded += ids.length;
    }
  }

  if (recorded) {
    logger.info('Verified fixes applied on GitHub through Commit suggestion', {
      repository_id: repository.id, commits: commits.length, findings: recorded,
    });
  }
  return { handled: recorded > 0, recorded, commits: commits.length };
}

module.exports = {
  FINDING_MARKER,
  DISMISS_PREFIXES,
  markerFingerprint,
  isDismissCommand,
  replyDismissalReason,
  threadRootComment,
  threadFingerprint,
  isCommitSuggestionCommit,
  commitSuggestionCommits,
  changedPaths,
  handleReviewThread,
  handleReviewComment,
  handleCommitSuggestions,
};
