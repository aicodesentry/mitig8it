const remediationDb = require('../db/remediation');
const logger = require('../utils/logger');
const { GitHubRemediationClient } = require('./githubRemediationClient');

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function location(item) {
  const path = item.file_path || 'unknown file';
  return item.line_start ? `${path}:${item.line_start}` : path;
}

function plural(count, singular, pluralForm = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

// One report, used verbatim as the pull request comment body and as the verification
// check summary. It states what was applied and what is still open, and never claims
// more than the fresh analysis of the applied head established.
function buildReport({ action, analysis, applied = [], unsupported = [] }) {
  const commit = action.verification_head_sha || action.observed_commit_sha || 'unknown';
  const lines = [];
  lines.push(`Applied by an explicit request from @${action.actor_login} in commit ${commit.slice(0, 12)}.`);
  lines.push('');
  lines.push(`Applied (${plural(applied.length, 'fix', 'fixes')}):`);
  if (!applied.length) lines.push('- none');
  for (const item of applied) lines.push(`- ${item.title || item.finding_id || 'finding'} in ${location(item)}`);
  lines.push('');
  if (analysis.analysisState !== 'completed') {
    lines.push(`Remaining open findings: not established (analysis of the applied commit is ${analysis.analysisState}).`);
  } else {
    const open = Array.isArray(analysis.open) ? analysis.open : [];
    const blocking = open.filter((f) => !f.informational);
    const informational = open.filter((f) => f.informational);
    lines.push(`Remaining open findings in the pull request's changed files: ${blocking.length}${informational.length ? ` (plus ${plural(informational.length, 'informational finding')} in test code)` : ''}.`);
    const byFile = new Map();
    for (const finding of blocking) {
      const path = finding.file_path || 'unknown file';
      if (!byFile.has(path)) byFile.set(path, []);
      byFile.get(path).push(finding);
    }
    for (const [path, findings] of [...byFile.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      lines.push(`- ${path}`);
      findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
      for (const finding of findings) {
        const where = finding.line_start ? ` (line ${finding.line_start})` : '';
        lines.push(`  - ${finding.severity || 'unknown'}: ${finding.title || finding.rule_id || finding.id}${where}`);
      }
    }
    if (informational.length) {
      lines.push('- Informational, test code (listed, not blocking):');
      for (const finding of informational) lines.push(`  - ${finding.title || finding.rule_id || finding.id} in ${location(finding)}`);
    }
  }
  if (unsupported.length) {
    lines.push('');
    lines.push(`Not repaired automatically (${unsupported.length}):`);
    for (const item of unsupported) {
      lines.push(`- ${item.title || item.finding_id || 'finding'} in ${location(item)}: ${item.reason}`);
    }
  }
  lines.push('');
  lines.push('Merging stays a human action on GitHub.');
  return lines.join('\n');
}

async function reportForAction(action) {
  const analysis = await remediationDb.blockingFindingsForAction(action);
  const { applied, unsupported } = await remediationDb.appliedReportForAction(action);
  return { analysis, applied, unsupported, text: buildReport({ action, analysis, applied, unsupported }) };
}

// Published once the action is completed, that is once the fresh analysis of the
// applied head finished. One comment per action: the adapter updates it in place when
// it already exists, so a retry never leaves a second copy.
async function publishResidualComment(actionId, options = {}) {
  const context = await remediationDb.actionCheckContext(actionId);
  if (!context) return null;
  const { action } = context;
  if (action.state !== 'completed') return { published: false, reason: 'action_not_completed' };
  const headSha = action.verification_head_sha || action.observed_commit_sha;
  if (!headSha) return { published: false, reason: 'applied_commit_unknown' };
  const report = await reportForAction(action);
  if (report.analysis.analysisState !== 'completed') return { published: false, reason: 'verification_analysis_incomplete' };
  const client = options.githubClient || new GitHubRemediationClient();
  try {
    const result = await client.publishComment({
      installation_id: Number(action.installation_id), repository_full_name: action.repository_full_name,
      actor_login: action.actor_login, pr_number: Number(action.pr_number), head_sha: headSha, base_sha: action.base_sha,
      manifest_digest: action.batch_manifest_digest, action_id: action.id, idempotency_key: action.idempotency_key,
      external_id: action.id, body: `### Mitig8it remediation report\n\n${report.text}`,
    });
    if (result?.state !== 'published') {
      logger.warn('Remediation residual comment publication was not confirmed', { action_id: action.id, state: result?.state || 'unknown' });
      return { published: false, reason: result?.reason || 'not_published' };
    }
    await remediationDb.recordResidualComment(action, { commentId: result.comment_id, headSha });
    return { published: true, comment_id: result.comment_id, updated: Boolean(result.updated), text: report.text };
  } catch (error) {
    logger.error('Remediation residual comment could not be published', { action_id: action.id, error: error.message });
    return { published: false, reason: 'publication_failed', error: error.message };
  }
}

async function publishPendingResidualComments(options = {}) {
  const ids = await remediationDb.listActionsNeedingResidualComment(options.limit || 25);
  let published = 0;
  for (const id of ids) {
    const result = await publishResidualComment(id, options);
    if (result?.published) published += 1;
  }
  return { attempted: ids.length, published };
}

module.exports = { buildReport, reportForAction, publishResidualComment, publishPendingResidualComments };
