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

const root = serviceRoot();
const githubIdentity = require(path.join(root, 'src/services/githubIdentity'));
const operations = require(path.join(root, 'src/services/githubInternalOperations'));

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

// --- publishing ------------------------------------------------------------------------

async function publish(request) {
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
  const results = { review: null, inline: [], fixes: null, check: null, errors: [] };

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

module.exports = { publish, buildReviewBody, checkRunSummary, CHECK_RUN_NAME };
