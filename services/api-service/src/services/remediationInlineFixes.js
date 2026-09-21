const remediationDb = require('../db/remediation');
const policy = require('./remediationPolicy');
const logger = require('../utils/logger');
const { GitHubRemediationClient } = require('./githubRemediationClient');

const MAX_DIFF_CHARS = 6000;

function splitLines(text) {
  const normalized = String(text ?? '').replace(/\r\n/g, '\n');
  if (!normalized) return [];
  const lines = normalized.split('\n');
  if (lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function countHunks(unifiedDiff) {
  return (String(unifiedDiff || '').match(/^@@ /gm) || []).length;
}

// The smallest contiguous region of the original that the replacement changes, as one
// hunk on the original's line numbers. A pure insertion is anchored to a neighbouring
// line, preferring the finding's own line, because a suggestion must replace at least
// one line. Returns null when nothing changes or the original is empty.
function computeHunk(original, replacement, preferredLine) {
  const before = splitLines(original);
  const after = splitLines(replacement);
  let prefix = 0;
  while (prefix < before.length && prefix < after.length && before[prefix] === after[prefix]) prefix += 1;
  let suffix = 0;
  while (suffix < before.length - prefix && suffix < after.length - prefix
    && before[before.length - 1 - suffix] === after[after.length - 1 - suffix]) suffix += 1;
  const startLine = prefix + 1;
  const endLine = before.length - suffix;
  const replacementLines = after.slice(prefix, after.length - suffix);
  if (endLine >= startLine) {
    return { start_line: startLine, end_line: endLine, original_lines: before.slice(prefix, before.length - suffix), replacement_lines: replacementLines };
  }
  if (!replacementLines.length || !before.length) return null;
  // Insertion between original lines `prefix` and `prefix + 1`.
  const previous = prefix;
  const next = prefix + 1;
  if (next <= before.length && (Number(preferredLine) === next || previous < 1)) {
    return { start_line: next, end_line: next, original_lines: [before[next - 1]], replacement_lines: [...replacementLines, before[next - 1]] };
  }
  return { start_line: previous, end_line: previous, original_lines: [before[previous - 1]], replacement_lines: [before[previous - 1], ...replacementLines] };
}

function evidenceLines(candidate) {
  const evidence = candidate.preview?.evidence || {};
  const tests = (Array.isArray(evidence.generated_tests) ? evidence.generated_tests : [])
    .map((test) => test?.path || test?.name).filter(Boolean);
  const limitations = Array.isArray(evidence.limitations) ? evidence.limitations : [];
  const lines = [];
  lines.push(tests.length
    ? `Regression test ${tests.join(', ')}: failed on the original code, passed on the fix.`
    : 'Generated regression test: failed on the original code, passed on the fix.');
  const syntaxNotRun = limitations.some((item) => /syntax check (skipped|unavailable)/i.test(String(item)));
  lines.push(syntaxNotRun ? 'Syntax check: not run (see limitations).' : 'Syntax check: passed on the fixed file.');
  if (evidence.evidence_digest) lines.push(`Evidence digest: ${String(evidence.evidence_digest).slice(0, 12)}.`);
  return lines;
}

function truncateDiff(diff) {
  const text = String(diff || '');
  if (text.length <= MAX_DIFF_CHARS) return text;
  return `${text.slice(0, MAX_DIFF_CHARS)}\n... (diff truncated; the full change is in the Mitig8it preview)`;
}

function previewUrl(job) {
  const base = String(process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/$/, '');
  return `${base}/dashboard/pull-requests/${job.pull_request_id}/findings`;
}

// One section per candidate and per finding it proves, plus one line per finding the
// repair service reported as skipped. A candidate is offered as a suggestion only when
// the whole verified fix is one contiguous region of the finding's own file; anything
// else is shown as a diff with the reason, because a partial suggestion would not be
// the fix that was verified.
function buildSections({ job, candidates = [], findings = [] }) {
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  const sections = [];
  for (const candidate of candidates) {
    if (candidate.rejection_reason) continue;
    const changes = Array.isArray(candidate.preview?.changes) ? candidate.preview.changes : [];
    const evidence = candidate.preview?.evidence || {};
    const limitations = Array.isArray(evidence.limitations) ? evidence.limitations.map(String) : [];
    for (const findingId of candidate.finding_snapshot_ids || []) {
      const finding = byId.get(findingId);
      if (!finding?.fingerprint) continue;
      const change = changes.find((item) => item?.path === finding.file_path) || null;
      let hunk = null;
      let reason = '';
      if (!change) reason = 'changes_other_file';
      else if (changes.length > 1) reason = 'multiple_files';
      else if (countHunks(change.unified_diff) > 1) reason = 'multiple_regions';
      else {
        hunk = computeHunk(change.original, change.replacement, finding.line_start);
        if (!hunk) reason = 'no_line_change';
      }
      sections.push({
        candidate_id: candidate.id,
        finding_fingerprint: finding.fingerprint,
        path: finding.file_path || '',
        finding_line: Number(finding.line_start) || 0,
        hunk,
        unified_diff: truncateDiff(changes.map((item) => item?.unified_diff || '').filter(Boolean).join('\n')),
        not_suggestable_reason: reason,
        behavior_preserved: String(candidate.preview?.reasoning?.intended_behavior || candidate.preview?.rationale || ''),
        evidence: evidenceLines(candidate),
        limitations,
        skipped_reason: '',
        verification_level: String(candidate.verification_level || evidence.verification_level || ''),
      });
    }
  }
  const skipped = Array.isArray(job?.failure_reason?.skipped) ? job.failure_reason.skipped : [];
  const covered = new Set(sections.map((section) => section.finding_fingerprint));
  for (const item of skipped) {
    const finding = byId.get(item?.finding_id);
    if (!finding?.fingerprint || covered.has(finding.fingerprint)) continue;
    covered.add(finding.fingerprint);
    sections.push({
      candidate_id: '', finding_fingerprint: finding.fingerprint, path: finding.file_path || '', finding_line: Number(finding.line_start) || 0,
      hunk: null, unified_diff: '', not_suggestable_reason: '', behavior_preserved: '', evidence: [], limitations: [],
      skipped_reason: String(item.message || item.code || 'no verified fix'), verification_level: '',
    });
  }
  return sections;
}

// Publishes the sections of a ready job under the finding comments of its head. The
// adapter updates each comment in place by candidate marker, so a retry never writes
// a second copy. Refusals are reported, not thrown; transport failures propagate so
// the outbox retries them.
async function publishInlineFixes(jobId, options = {}) {
  if (!policy.capabilities().publish) return { published: false, reason: 'publish_disabled' };
  const context = await remediationDb.jobPublishContext(jobId);
  if (!context) return null;
  const { job } = context;
  if (job.state !== 'ready') return { published: false, reason: 'job_not_ready' };
  if (job.current_head_sha && job.current_head_sha !== job.head_sha) return { published: false, reason: 'head_moved' };
  if (job.installation_status !== 'active' || job.repository_active === false) return { published: false, reason: 'installation_or_repository_inactive' };
  const sections = buildSections(context);
  if (!sections.length) return { published: false, reason: 'nothing_to_publish' };
  const client = options.githubClient || new GitHubRemediationClient();
  const result = await client.publishFindingFixSections({
    installation_id: Number(job.installation_id), repository_full_name: job.repository_full_name,
    actor_login: job.creator_login || 'system', pr_number: Number(job.pr_number), head_sha: job.head_sha, base_sha: job.base_sha,
    manifest_digest: context.manifestDigest || remediationDb.hash({ job: job.id }),
    action_id: `inline-fix-${job.id}`, idempotency_key: `inline-fix:${job.id}:${job.state_version}`,
    preview_url: previewUrl(job), sections,
  });
  if (result?.state !== 'published') {
    logger.warn('Inline fix publication was not confirmed', { job_id: job.id, state: result?.state || 'unknown', reason: result?.reason || null });
    return { published: false, reason: result?.reason || 'not_published' };
  }
  await remediationDb.recordInlineFixesPublished(job, { headSha: job.head_sha });
  logger.info('Verified fixes published under the finding comments', { job_id: job.id, sections: sections.length });
  return { published: true, results: Array.isArray(result.results) ? result.results : [], sections: sections.length };
}

module.exports = { publishInlineFixes, buildSections, computeHunk, evidenceLines, countHunks };
