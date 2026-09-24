#!/usr/bin/env node
// Publish a review from inside the runner, using the github-service's own publishing code.
//
// The orchestrator writes a request file and runs this. Nothing here reimplements publishing:
// the check run, the inline finding comments, the suggestion blocks and their Verified line all
// come from services/github-service, called with a workflow-token identity provider installed
// into its seam. What this file owns is the request shape and the Markdown of the review body,
// which in production is assembled by the api-service against its database.
//
// Re-running is expected and must be cheap. Every function called below finds its own previous
// output by marker and edits it in place, so a second run on the same head changes nothing.

const path = require('path');
const fs = require('fs');

const { createWorkflowTokenProvider, CHECK_RUN_NAME } = require('./tokenProvider');

function serviceRoot() {
  const configured = process.env.MITIG8IT_GITHUB_SERVICE_ROOT;
  if (configured) return configured;
  const packaged = '/opt/mitig8it/services/github-service';
  if (fs.existsSync(packaged)) return packaged;
  return path.resolve(__dirname, '../../services/github-service');
}

// The github-service modules are loaded when publishing starts, not when this file is required.
// They pull in axios and the rest of the service's runtime dependencies, which exist in the
// action's image but not in a bare checkout. Deferring them keeps the body builders below
// importable on their own, so the tests that pin the review's wording need no npm install.
function service() {
  const root = serviceRoot();
  return {
    githubIdentity: require(path.join(root, 'src/services/githubIdentity')),
    operations: require(path.join(root, 'src/services/githubInternalOperations')),
  };
}

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

// --- the review body -------------------------------------------------------------------

function severityTable(counts) {
  const rows = SEVERITY_ORDER
    .filter((severity) => counts[severity] > 0)
    .map((severity) => `| ${severity} | ${counts[severity]} |`);
  if (rows.length === 0) return '';
  return ['', '| Severity | Count |', '| --- | --- |', ...rows, ''].join('\n');
}

function buildReviewBody(request) {
  const { counts, findings, fixes } = request;
  const runtime = SEVERITY_ORDER.reduce((total, key) => total + (counts[key] || 0), 0);
  const lines = ['<!-- mitig8it-review -->'];
  lines.push(runtime > 0
    ? `### Mitig8it - ${runtime} finding${runtime === 1 ? '' : 's'} detected`
    : '### Mitig8it - no security issues found');
  lines.push(severityTable(counts));

  if (counts.info > 0) {
    lines.push(`${counts.info} finding${counts.info === 1 ? '' : 's'} in test code are reported as informational and do not affect the check.`);
  }

  if (request.modelConfigured) {
    lines.push(`Fixes were generated with model assistance. ${fixes} suggestion${fixes === 1 ? '' : 's'} attached.`);
  } else {
    // Stated on every run without a key, because a reader is entitled to know which half of the
    // product ran. Template repairs are deterministic; the agent loop never started.
    lines.push('No model key was configured, so only template fixes were produced and nothing left this runner.');
  }

  lines.push('');
  lines.push(`<sub>Analyzed by <strong>Mitig8it</strong> running as a GitHub Action in this repository's own runner. ${findings} finding${findings === 1 ? '' : 's'} reviewed.</sub>`);
  return lines.filter((line) => line !== undefined).join('\n');
}

function checkRunSummary(request) {
  const { counts } = request;
  const blocking = (counts.critical || 0) + (counts.high || 0);
  const parts = [
    `Mitig8it found ${SEVERITY_ORDER.reduce((t, k) => t + (counts[k] || 0), 0)} runtime findings `
    + `(${counts.critical || 0} critical, ${counts.high || 0} high, ${counts.medium || 0} medium, ${counts.low || 0} low).`,
  ];
  if (counts.info > 0) parts.push(`${counts.info} informational findings in test code.`);
  // What the repository asked not to be reviewed is part of what the check reports: a reader
  // who sees no finding on a directory is entitled to know whether it was clean or skipped.
  const excluded = Number(request.excludedFiles || 0);
  if (excluded > 0) parts.push(`${excluded} file${excluded === 1 ? '' : 's'} excluded by .mitig8it.yml.`);
  return {
    // `fail-on: none` keeps a neutral conclusion so a security review never blocks a merge that
    // the repository did not ask it to block.
    conclusion: request.failConclusion,
    title: blocking > 0
      ? `${blocking} critical/high finding${blocking === 1 ? '' : 's'}`
      : 'No blocking security findings',
    summary: parts.join(' '),
  };
}

// --- stale review threads --------------------------------------------------------------
//
// Re-running has to converge on the current finding set, not accumulate. github-service's
// `postInlineComment` already handles the finding that is still there: it finds its own comment
// by the `mitig8it-finding:<fingerprint>` marker and edits it in place. Nothing handled the
// finding that went away. Its thread stayed open forever, so a second run over a changed finding
// set left the first run's threads beside the second run's, and a pull request accumulated a
// thread per finding per run. The self-review reached 74 open threads this way, none resolved.
//
// Resolving a review thread is GraphQL-only; there is no REST endpoint for it, and nothing else
// in this repository speaks GraphQL, so the client is here. `minimizeComment` is the fallback,
// because a token that may resolve is not guaranteed to be a token that may minimize or the
// other way round, and a thread that can be neither is reported rather than silently left.

// GitHub Actions sets GITHUB_GRAPHQL_URL, and it differs on Enterprise Server, so it is read
// rather than hardcoded the way the REST base is.
const GRAPHQL_URL = process.env.GITHUB_GRAPHQL_URL || 'https://api.github.com/graphql';
const FINDING_MARKER = /<!--\s*mitig8it-finding:([^\s>]+)\s*-->/;

const THREADS_QUERY = `query($owner:String!,$repo:String!,$number:Int!,$cursor:String){
  repository(owner:$owner,name:$repo){
    pullRequest(number:$number){
      reviewThreads(first:100,after:$cursor){
        pageInfo{hasNextPage endCursor}
        nodes{id isResolved comments(first:1){nodes{id body author{login}}}}
      }
    }
  }
}`;

const RESOLVE_MUTATION = `mutation($id:ID!){resolveReviewThread(input:{threadId:$id}){thread{id isResolved}}}`;
const MINIMIZE_MUTATION = `mutation($id:ID!){minimizeComment(input:{subjectId:$id,classifier:OUTDATED}){minimizedComment{isMinimized}}}`;

function createGraphQLClient({ token, url = GRAPHQL_URL, fetchImpl }) {
  const call = fetchImpl || globalThis.fetch;
  if (typeof call !== 'function') throw new Error('this runtime has no fetch to reach the GraphQL API with');
  return async function graphql(query, variables) {
    const response = await call(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'mitig8it-action',
      },
      body: JSON.stringify({ query, variables }),
    });
    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) throw new Error(`GraphQL HTTP ${response.status}`);
    if (payload?.errors?.length) throw new Error(payload.errors.map((e) => e.message).join('; '));
    if (!payload?.data) throw new Error('GraphQL returned no data');
    return payload.data;
  };
}

// The fingerprint a thread was opened for, or null when the thread is not one of ours. The
// author check is what keeps this from ever touching a human's thread: only the first comment
// counts, because a reply from a reviewer must not make their thread look like ours.
function threadFingerprint(thread, botLogin) {
  const first = thread?.comments?.nodes?.[0];
  if (!first || first.author?.login !== botLogin) return null;
  const match = FINDING_MARKER.exec(String(first.body || ''));
  return match ? match[1] : null;
}

async function ourReviewThreads({ graphql, owner, repo, prNumber, botLogin }) {
  const threads = [];
  let cursor = null;
  for (let page = 0; page < 20; page += 1) {
    const data = await graphql(THREADS_QUERY, { owner, repo, number: prNumber, cursor });
    const connection = data?.repository?.pullRequest?.reviewThreads;
    if (!connection) break;
    for (const node of connection.nodes || []) {
      const fingerprint = threadFingerprint(node, botLogin);
      if (!fingerprint) continue;
      threads.push({
        id: node.id,
        commentId: node.comments?.nodes?.[0]?.id || null,
        isResolved: Boolean(node.isResolved),
        fingerprint,
      });
    }
    if (!connection.pageInfo?.hasNextPage) break;
    cursor = connection.pageInfo.endCursor;
  }
  return threads;
}

// Threads this action opened for findings the current run did not report. A run that found
// nothing resolves everything it had open, which is the whole point: the pull request should
// end up showing what is true now.
function selectStaleThreads(threads, activeFingerprints) {
  const active = new Set(activeFingerprints || []);
  return threads.filter((thread) => !thread.isResolved && !active.has(thread.fingerprint));
}

async function reconcileReviewThreads(request, { graphql }) {
  const [owner, repo] = request.repository_full_name.split('/');
  const outcome = { resolved: 0, minimized: 0, errors: [] };
  const threads = await ourReviewThreads({
    graphql,
    owner,
    repo,
    prNumber: request.pr_number,
    botLogin: request.bot_login,
  });
  for (const thread of selectStaleThreads(threads, request.active_fingerprints)) {
    try {
      await graphql(RESOLVE_MUTATION, { id: thread.id });
      outcome.resolved += 1;
    } catch (error) {
      if (!thread.commentId) {
        outcome.errors.push(`thread ${thread.fingerprint}: ${error.message}`);
        continue;
      }
      try {
        await graphql(MINIMIZE_MUTATION, { id: thread.commentId });
        outcome.minimized += 1;
      } catch (fallbackError) {
        outcome.errors.push(`thread ${thread.fingerprint}: ${error.message}; ${fallbackError.message}`);
      }
    }
  }
  return outcome;
}

// --- publishing ------------------------------------------------------------------------

async function publish(request, { fetchImpl, graphql } = {}) {
  const { githubIdentity, operations } = service();
  githubIdentity.useProvider(createWorkflowTokenProvider({
    token: request.token,
    repositoryFullName: request.repository_full_name,
    botLogin: request.bot_login,
  }));

  const [owner, repo] = request.repository_full_name.split('/');
  const base = {
    owner,
    repo,
    pr_number: request.pr_number,
    installation_id: request.installation_id,
    commit_sha: request.head_sha,
  };
  const results = { review: null, inline: [], fixes: null, check: null, threads: null, errors: [] };

  // 1. The summary review. REQUEST_CHANGES would demand a dismissal from a human before merge,
  // which an action installed by five lines of YAML has not earned, so the action always
  // comments and lets `fail-on` carry the blocking decision.
  try {
    results.review = await operations.submitPullRequestReview({
      ...base,
      body: buildReviewBody(request),
      event: 'COMMENT',
      comments: [],
    });
  } catch (error) {
    results.errors.push(`review: ${error.message}`);
  }

  // 2. One inline comment per finding, each carrying its fingerprint marker so a re-run edits
  // the comment it wrote last time instead of stacking a new one beside it.
  for (const comment of request.inline_comments || []) {
    try {
      const posted = await operations.postInlineComment({
        ...base,
        path: comment.path,
        line: comment.line,
        body: comment.body,
      });
      results.inline.push({ path: comment.path, line: comment.line, comment_id: posted.comment_id });
    } catch (error) {
      results.errors.push(`inline ${comment.path}:${comment.line}: ${error.message}`);
    }
  }

  // 2b. Threads this action opened for findings that are no longer reported. Without this the
  // pull request only ever grows: the finding that went away keeps its open thread, and the
  // fingerprint carries the line number, so any push that shifts a line retires every marker at
  // once and the whole previous run is orphaned. Failing here is reported and never fatal: a
  // review that published is worth more than a tidy thread list.
  try {
    const client = graphql || createGraphQLClient({ token: request.token, fetchImpl });
    results.threads = await reconcileReviewThreads(request, { graphql: client });
    for (const error of results.threads.errors) results.errors.push(`thread: ${error}`);
  } catch (error) {
    results.errors.push(`threads: ${error.message}`);
  }

  // 3. Suggestion blocks under the finding comments, rendered by the service's own builder so
  // the Verified line states the level this run actually achieved.
  if ((request.fix_sections || []).length > 0) {
    try {
      results.fixes = await operations.publishFindingFixSections({
        repository_full_name: request.repository_full_name,
        actor_login: request.actor_login,
        installation_id: request.installation_id,
        pr_number: request.pr_number,
        head_sha: request.head_sha,
        base_sha: request.base_sha,
        action_id: request.action_id,
        idempotency_key: request.idempotency_key,
        manifest_digest: request.manifest_digest,
        sections: request.fix_sections,
      });
    } catch (error) {
      results.errors.push(`fixes: ${error.message}`);
    }
  }

  // 4. The check run last, so its conclusion describes a review that is already visible.
  try {
    const summary = checkRunSummary(request);
    results.check = await operations.createCheckRun({
      owner,
      repo,
      installation_id: request.installation_id,
      head_sha: request.head_sha,
      conclusion: summary.conclusion,
      title: summary.title,
      summary: summary.summary,
    });
  } catch (error) {
    results.errors.push(`check run: ${error.message}`);
  }

  return results;
}

async function main() {
  const requestPath = process.argv[2];
  if (!requestPath) {
    process.stderr.write('usage: publish.js <request.json>\n');
    process.exit(2);
  }
  const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
  const results = await publish(request);
  process.stdout.write(`${JSON.stringify(results, null, 2)}\n`);
  if (results.errors.length > 0) {
    for (const error of results.errors) process.stderr.write(`publish error: ${error}\n`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`publish failed: ${error.stack || error.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  publish,
  buildReviewBody,
  checkRunSummary,
  createGraphQLClient,
  reconcileReviewThreads,
  selectStaleThreads,
  threadFingerprint,
  CHECK_RUN_NAME,
};
