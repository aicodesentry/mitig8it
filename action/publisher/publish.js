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

// --- the numbers -----------------------------------------------------------------------
//
// One arithmetic for the whole review. On pygoat the September trial read four numbers for one
// run: the check title said "32 critical/high findings", the check summary said "37 runtime
// findings", the review body said "37 findings detected" and sixteen comments sat on the diff.
// Every one was explicable and no two agreed, which leaves a reader reconstructing the sums
// before they can trust any of them. The orchestrator now computes them once and sends them as
// `totals`; nothing below derives a number of its own.

function totalsOf(request) {
  const totals = request.totals;
  if (totals && typeof totals === 'object') return totals;
  // An older orchestrator against a newer publisher: derive the same shape rather than render
  // a review with holes in it.
  const counts = request.counts || {};
  const runtime = SEVERITY_ORDER.reduce((total, key) => total + (counts[key] || 0), 0);
  const inline = (request.inline_comments || []).length;
  const unanchored = (request.unanchored_findings || []).length;
  return {
    runtime,
    critical: counts.critical || 0,
    high: counts.high || 0,
    medium: counts.medium || 0,
    low: counts.low || 0,
    informational: counts.info || 0,
    blocking: (counts.critical || 0) + (counts.high || 0),
    inline,
    unanchored,
  };
}

function plural(count, noun) {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

// The orchestrator's `scope_summary`, in the publisher's own words, from the same numbers.
// `analysed` is the count "files in scope" was meant to be; `skipped` is the rest of the change,
// counted rather than hidden, and deliberately not called unreviewed, because the regex tier
// still reads its patch.
function scopeSummary(scope) {
  const number = (key) => Number(scope?.[key] || 0);
  if (!['analysed', 'excluded', 'skipped', 'vendored'].some((key) => number(key))) return '';
  const parts = [`${plural(number('analysed'), 'file')} analysed`];
  if (number('skipped')) {
    parts.push(`${number('skipped')} read as a patch only (the scanner has no deep rules for those file types)`);
  }
  if (number('excluded')) parts.push(`${number('excluded')} excluded by .mitig8it.yml`);
  if (number('vendored')) parts.push(`${number('vendored')} skipped as build output or a vendored dependency`);
  return `${parts.join(', ')}.`;
}

function breakdown(totals) {
  return `${totals.critical} critical, ${totals.high} high, ${totals.medium} medium, ${totals.low} low`;
}

// --- the review body -------------------------------------------------------------------

function severityTable(totals) {
  const rows = SEVERITY_ORDER
    .filter((severity) => totals[severity] > 0)
    .map((severity) => `| ${severity} | ${totals[severity]} |`);
  if (rows.length === 0) return '';
  return ['', '| Severity | Count |', '| --- | --- |', ...rows, ''].join('\n');
}

// Where a reader can look at the code a finding names, pinned to the commit that was reviewed.
// GITHUB_SERVER_URL is read rather than hardcoded because it differs on Enterprise Server, the
// same reason GITHUB_GRAPHQL_URL is read below.
function permalink(request, path, line) {
  const server = String(process.env.GITHUB_SERVER_URL || 'https://github.com').replace(/\/$/, '');
  const encoded = String(path).split('/').map(encodeURIComponent).join('/');
  return `${server}/${request.repository_full_name}/blob/${request.head_sha}/${encoded}#L${line}`;
}

// The findings with nowhere to go, named. GitHub will not accept an inline comment on a line
// the pull request did not change, and pointing at the nearest changed line would point at the
// wrong code, so the action does not try. What it used to do instead was count them and say
// nothing: 28 of the trial's 93 findings, including twelve on pygoat and five criticals on
// nodejs-goof, existed only as a number in a summary. A location and a link is the least that
// makes one of them actionable.
const UNANCHORED_HEADING = 'Findings on lines this pull request did not change';
const UNANCHORED_ROW_CAP = 50;

function unanchoredSection(request, totals) {
  const findings = request.unanchored_findings || [];
  if (!findings.length) return [];
  const shown = findings.slice(0, UNANCHORED_ROW_CAP);
  const lines = [
    '',
    `#### ${UNANCHORED_HEADING} (${totals.unanchored})`,
    '',
    'GitHub accepts an inline comment only on a line the pull request touches, and a comment on '
    + 'the nearest line that it does touch would point at the wrong code. These are listed here '
    + 'instead, against the commit that was reviewed.',
    '',
    '| Severity | Rule | Location |',
    '| --- | --- | --- |',
  ];
  for (const finding of shown) {
    const rule = finding.rule ? `\`${String(finding.rule).replace(/[`|]/g, '')}\`` : '-';
    const location = `[${String(finding.path).replace(/[|]/g, '')}:${finding.line}](${permalink(request, finding.path, finding.line)})`;
    lines.push(`| ${finding.severity || 'unknown'} | ${rule} | ${location} |`);
  }
  if (findings.length > shown.length) {
    lines.push('');
    lines.push(`${plural(findings.length - shown.length, 'further finding')} not listed here.`);
  }
  return lines;
}

function buildReviewBody(request) {
  const totals = totalsOf(request);
  const { fixes } = request;
  const lines = ['<!-- mitig8it-review -->'];
  lines.push(totals.runtime > 0
    ? `### Mitig8it - ${plural(totals.runtime, 'finding')} detected`
    : '### Mitig8it - no security issues found');
  lines.push(severityTable(totals));

  if (totals.runtime > 0) {
    lines.push(totals.unanchored > 0
      ? `${plural(totals.inline, 'finding')} annotated on the diff below; `
        + `${totals.unanchored} on lines this pull request did not change, listed underneath.`
      : `All ${plural(totals.runtime, 'finding')} are annotated on the diff below.`);
  }

  // Counted, never annotated. An informational finding is a finding in test code: worth knowing
  // about, not worth a comment on the diff, because eighteen of them buried the three runtime
  // findings on the self-review. The summary is where they live, and it says they were not posted
  // so a reader is not left wondering why a count has no comments behind it.
  if (totals.informational > 0) {
    lines.push(`${plural(totals.informational, 'informational finding')} in test code, not posted.`);
  }

  if (request.modelConfigured) {
    lines.push(`Fixes were generated with model assistance. ${plural(fixes, 'suggestion')} attached.`);
  } else {
    // Stated on every run without a key, because a reader is entitled to know which half of the
    // product ran. Template repairs are deterministic; the agent loop never started.
    lines.push('No model key was configured, so only template fixes were produced and nothing left this runner.');
  }

  lines.push(...unanchoredSection(request, totals));

  lines.push('');
  lines.push(`<sub>Analyzed by <strong>Mitig8it</strong> running as a GitHub Action in this repository's own runner. ${plural(totals.runtime, 'finding')} reported.</sub>`);
  return lines.filter((line) => line !== undefined).join('\n');
}

function checkRunSummary(request) {
  const totals = totalsOf(request);
  // "1 runtime findings" is what the trial read, and "runtime finding" is internal vocabulary:
  // nothing told a first user it meant "not in test code". The plural agrees with the number
  // and the noun says what it means.
  const parts = [
    `Mitig8it found ${plural(totals.runtime, 'finding')} outside test code (${breakdown(totals)}).`,
  ];
  if (totals.runtime > 0) {
    parts.push(totals.unanchored > 0
      ? `${totals.inline} of them are annotated on the diff and ${totals.unanchored} are on lines `
        + 'this pull request did not change, listed in the review body.'
      : 'All of them are annotated on the diff.');
  }
  if (totals.informational > 0) {
    parts.push(`${plural(totals.informational, 'informational finding')} in test code, not posted.`);
  }
  // What the review looked at, and what it did not. A reader who sees no finding on a directory
  // is entitled to know whether it was clean, excluded or never read whole; the trial's clean
  // repositories reported "12 files in scope" with the workflow YAML and the README among them,
  // and `excluded_file_count` only ever counted `.mitig8it.yml` matches, so with no config file
  // the line README.md promised never appeared at all.
  const scope = request.scope || {};
  const scopeLine = scopeSummary(scope);
  if (scopeLine) parts.push(scopeLine);
  else {
    const excluded = Number(request.excludedFiles || 0);
    if (excluded > 0) parts.push(`${plural(excluded, 'file')} excluded by .mitig8it.yml.`);
  }
  return {
    // `fail-on: none` keeps a neutral conclusion so a security review never blocks a merge that
    // the repository did not ask it to block.
    conclusion: request.failConclusion,
    // The same total the summary and the review body state, with the blocking share beside it
    // rather than in place of it.
    title: totals.runtime > 0
      ? `${plural(totals.runtime, 'finding')}, ${totals.blocking} critical or high`
      : 'No security findings',
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
// in this repository speaks GraphQL, so the client is here. The workflow token cannot resolve
// one: the trial's third commit fixed a finding for real and the log read "0 resolved, 1
// minimized", with the thread left `isResolved=false, isOutdated=true`. A minimized thread still
// counts as unresolved, so a repository with "all conversations must be resolved" was blocked by
// a finding its author had already fixed, by a review that could not undo what it had said.
//
// So the fallback is to delete our own comment, which is what github-service's
// `retireInlineComments` does for the App and what removes the thread outright rather than
// folding it away. Only comments carrying our marker for a fingerprint this run no longer
// reports are touched, and one carrying a published fix is kept: that is reviewer-visible work
// and housekeeping must not take it away.

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

// A comment that carries a published fix is kept whatever else is true of it. The marker is
// github-service's own; `retireInlineComments` refuses to delete one for the same reason.
const FIX_MARKER = '<!-- mitig8it-fix:';

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

// REST and GraphQL do not spell a bot's login the same way. `user.login` on a review comment is
// `github-actions[bot]`; `Bot.login` in GraphQL is `github-actions`, with no suffix. Matching the
// REST spelling against the GraphQL one found zero threads on every run, and because nothing was
// logged it looked exactly like having nothing to do: 94 threads open, 0 resolved, silence.
//
// So the marker is the identity now. Only this action writes `mitig8it-finding:<fingerprint>`,
// and only the first comment of a thread is read, because a reviewer quoting the marker in a
// reply must not make their thread look like ours. The author is a secondary guard: a login that
// is present and is clearly somebody else's still rejects the thread, compared with the suffix
// removed from both sides so the two spellings agree.
function normalizeLogin(login) {
  return String(login || '').toLowerCase().replace(/\[bot\]$/, '');
}

function threadFingerprint(thread, botLogin) {
  const first = thread?.comments?.nodes?.[0];
  if (!first) return null;
  const match = FINDING_MARKER.exec(String(first.body || ''));
  if (!match) return null;
  const author = normalizeLogin(first.author?.login);
  const expected = normalizeLogin(botLogin);
  // An absent author (a deleted account) is not evidence against us; a different one is.
  if (author && expected && author !== expected) return null;
  return match[1];
}

async function ourReviewThreads({ graphql, owner, repo, prNumber, botLogin, counters }) {
  const threads = [];
  let cursor = null;
  for (let page = 0; page < 20; page += 1) {
    const data = await graphql(THREADS_QUERY, { owner, repo, number: prNumber, cursor });
    const connection = data?.repository?.pullRequest?.reviewThreads;
    if (!connection) break;
    for (const node of connection.nodes || []) {
      if (counters) counters.seen += 1;
      const fingerprint = threadFingerprint(node, botLogin);
      if (!fingerprint) continue;
      threads.push({
        id: node.id,
        commentId: node.comments?.nodes?.[0]?.id || null,
        // The body is carried so publishing can tell an unchanged comment from a changed one
        // without asking GitHub for the comment list again, once per finding.
        body: String(node.comments?.nodes?.[0]?.body || ''),
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

// Everything the publish needs to know about what this pull request already carries, from one
// walk of its review threads: which findings already have a comment of ours and what that
// comment says, and which of our threads the current run no longer reports.
async function surveyReviewThreads(request, { graphql }) {
  const [owner, repo] = request.repository_full_name.split('/');
  // Every number the run needs to explain itself: how many threads the pull request has, how
  // many carry our marker, and what became of the stale ones. A reconciliation that matches
  // nothing now says so out loud instead of looking like a run with nothing to do.
  const counters = {
    seen: 0, ours: 0, stale: 0, resolved: 0, minimized: 0, retired: 0, kept: 0, failed: 0, errors: [],
  };
  const threads = await ourReviewThreads({
    graphql,
    owner,
    repo,
    prNumber: request.pr_number,
    botLogin: request.bot_login,
    counters,
  });
  counters.ours = threads.length;
  const stale = selectStaleThreads(threads, request.active_fingerprints);
  counters.stale = stale.length;
  return { counters, threads, stale, byFingerprint: new Map(threads.map((t) => [t.fingerprint, t])) };
}

// A thread this run no longer reports, closed the best way the token allows: resolved when it
// can be, and otherwise removed by deleting the comment that opened it. A comment carrying a
// published fix is kept either way and counted apart, so the summary line never claims to have
// tidied something it deliberately left.
async function reconcileReviewThreads(survey, { graphql, operations, base }) {
  const { counters, stale } = survey;
  const doomed = [];
  for (const thread of stale) {
    if (String(thread.body || '').includes(FIX_MARKER)) {
      counters.kept += 1;
      continue;
    }
    try {
      await graphql(RESOLVE_MUTATION, { id: thread.id });
      counters.resolved += 1;
    } catch (error) {
      doomed.push({ thread, error });
    }
  }
  if (doomed.length && operations?.retireInlineComments) {
    try {
      const retired = await operations.retireInlineComments({
        owner: base.owner,
        repo: base.repo,
        pr_number: base.pr_number,
        installation_id: base.installation_id,
        fingerprints: doomed.map((item) => item.thread.fingerprint),
      });
      counters.retired += Number(retired?.retired || 0);
      counters.kept += Number(retired?.kept || 0);
      const unaccounted = doomed.length - Number(retired?.retired || 0) - Number(retired?.kept || 0);
      if (unaccounted > 0) {
        counters.failed += unaccounted;
        counters.errors.push(`thread ${doomed[0].thread.fingerprint}: ${doomed[0].error.message}`);
      }
    } catch (error) {
      counters.failed += doomed.length;
      counters.errors.push(`thread ${doomed[0].thread.fingerprint}: ${doomed[0].error.message}; ${error.message}`);
    }
  } else if (doomed.length) {
    counters.failed += doomed.length;
    counters.errors.push(`thread ${doomed[0].thread.fingerprint}: ${doomed[0].error.message}`);
  }
  return counters;
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
  const results = {
    review: null, inline: [], fixes: null, check: null, threads: null,
    posted: 0, edited: 0, unchanged: 0, errors: [],
  };

  // 1. What the pull request already carries, in one walk of its review threads. This is the
  // same listing the stale-thread reconciliation needs, read once and used for both: which
  // findings already have a comment of ours, what those comments say, and which of our threads
  // this run no longer reports.
  //
  // Without GraphQL the survey is absent and every comment goes through `postInlineComment`,
  // which is slower and correct. Degrading into the old path is better than degrading into a
  // duplicate comment.
  let survey = null;
  let graphqlClient = null;
  try {
    graphqlClient = graphql || createGraphQLClient({ token: request.token, fetchImpl });
    survey = await surveyReviewThreads(request, { graphql: graphqlClient });
  } catch (error) {
    results.threads = {
      seen: 0, ours: 0, stale: 0, resolved: 0, minimized: 0, retired: 0, kept: 0,
      failed: 0, errors: [], unavailable: error.message,
    };
  }

  // 2. Sort the comments into the three things that can be true of one: it is new, it is on the
  // pull request already and says something different, or it is on the pull request already and
  // says exactly what this run would write.
  const inline = request.inline_comments || [];
  const fresh = [];
  const changed = [];
  for (const comment of inline) {
    const existing = survey?.byFingerprint.get(comment.fingerprint) || null;
    if (!survey) {
      changed.push(comment);
      continue;
    }
    if (!existing) {
      fresh.push(comment);
      continue;
    }
    // What `postInlineComment` would write, computed with the service's own function, so a
    // comment carrying a published fix is compared against the body that keeps the fix.
    const next = operations.withPreservedFixBlocks(comment.body, existing.body);
    if (next === existing.body) {
      results.unchanged += 1;
      continue;
    }
    changed.push(comment);
  }

  // 3. One review: the summary body and every new comment, in a single event.
  //
  // Each new comment used to be its own POST to /pulls/{n}/comments, and GitHub wraps each of
  // those in a review of its own. juice-shop's pull request ended up with 28 "github-actions
  // reviewed" entries in its timeline for 26 comments, and publishing was the slowest phase of
  // the job: 39 of its 209 seconds. REQUEST_CHANGES would demand a dismissal from a human
  // before merge, which an action installed by five lines of YAML has not earned, so the event
  // stays COMMENT and `fail-on` carries the blocking decision.
  try {
    results.review = await operations.submitPullRequestReview({
      ...base,
      body: buildReviewBody(request),
      event: 'COMMENT',
      comments: fresh.map((comment) => ({ path: comment.path, line: comment.line, body: comment.body })),
    });
    results.posted = fresh.length;
    for (const comment of fresh) results.inline.push({ path: comment.path, line: comment.line, comment_id: 0 });
  } catch (error) {
    results.errors.push(`review: ${error.message}`);
  }

  // 4. The comments that already exist and have changed, edited in place by their marker. This
  // is a PATCH and creates no review, so the timeline stays at one entry per run.
  for (const comment of changed) {
    try {
      const posted = await operations.postInlineComment({
        ...base,
        path: comment.path,
        line: comment.line,
        body: comment.body,
      });
      results.edited += 1;
      results.inline.push({ path: comment.path, line: comment.line, comment_id: posted.comment_id });
    } catch (error) {
      results.errors.push(`inline ${comment.path}:${comment.line}: ${error.message}`);
    }
  }

  // 5. Threads this action opened for findings that are no longer reported. Without this the
  // pull request only ever grows: the finding that went away keeps its open thread, and the
  // fingerprint carries the line number, so any push that shifts a line retires every marker at
  // once and the whole previous run is orphaned. Failing here is reported and never fatal: a
  // review that published is worth more than a tidy thread list.
  //
  // A reconciliation failure stays out of `results.errors`, which is what decides this process's
  // exit code and therefore whether the whole action run fails. Tidying threads is housekeeping
  // and a token is not guaranteed to be allowed to do it; failing the job over it would throw
  // away a review that published perfectly. The counters below carry the failure instead, and
  // the orchestrator states it on the one summary line it logs.
  if (survey) {
    try {
      results.threads = await reconcileReviewThreads(survey, { graphql: graphqlClient, operations, base });
    } catch (error) {
      results.threads = { ...survey.counters, unavailable: error.message };
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

module.exports = {
  publish,
  buildReviewBody,
  checkRunSummary,
  createGraphQLClient,
  normalizeLogin,
  reconcileReviewThreads,
  selectStaleThreads,
  surveyReviewThreads,
  threadFingerprint,
  UNANCHORED_HEADING,
  CHECK_RUN_NAME,
};
