const { pool } = require('../config/database');
const axios = require('axios');
const logger = require('../utils/logger');
const { AnalysisGrpcClient } = require('../clients/analysisGrpcClient');
const { GitHubGrpcClient } = require('../clients/githubGrpcClient');
const { calculateFingerprint, normalizeFinding } = require('./findingUtils');
const { validateSuggestedFix, __private: validatorPrivate } = require('./suggestedFixValidator');
const findingsDb = require('../db/findings');
const analysisRunsDb = require('../db/analysisRuns');
const repositoriesDb = require('../db/repositories');
const remediationAutoGenerate = require('./remediationAutoGenerate');

const TIER2_SUPPORTED_EXTENSIONS = new Set([
  '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
  '.cs', '.c', '.cpp', '.h', '.hpp', '.rs', '.swift', '.kt',
]);

function markdownEscape(text) {
  return String(text || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// Findings in test code are reported but never block: they carry the
// informational severity and keep their original scanner severity alongside.
const INFORMATIONAL_SEVERITY = 'info';
const INLINE_COMMENT_CAP = 40;

// Mirrors services/analysis-service/src/test_code_scope.py.
const TEST_CODE_PATH_PATTERNS = [
  /(^|\/)tests?\//,
  /(^|\/)__tests?__\//,
  /(^|\/)test_.*\.(py|js|jsx|ts|tsx|go|java|rb|php|cs)$/,
  /\.(test|spec)\.(js|jsx|ts|tsx|py|go|java|rb|php|cs)$/,
];

function normalizePathForScope(path) {
  return String(path || '').trim().replace(/\\/g, '/').toLowerCase();
}

function isTestCodePath(path) {
  const normalized = normalizePathForScope(path);
  if (!normalized) return false;
  return TEST_CODE_PATH_PATTERNS.some((pattern) => pattern.test(normalized));
}

function countTestCodeFiles(files) {
  const paths = new Set();
  for (const file of files || []) {
    const path = normalizePathForScope(file?.path);
    if (path && isTestCodePath(path)) paths.add(path);
  }
  return paths.size;
}

function isInfoFinding(finding) {
  if (!finding) return false;
  if (String(finding.severity || '').toLowerCase() === INFORMATIONAL_SEVERITY) return true;
  const extra = finding.evidence_details && finding.evidence_details.extra;
  return Boolean(extra && extra.in_test_code);
}

function originalSeverity(finding) {
  const extra = (finding && finding.evidence_details && finding.evidence_details.extra) || {};
  return String(finding?.original_severity || extra.original_severity || '').toLowerCase();
}

function summarizeFindings(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const categories = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    categories[finding.category] = (categories[finding.category] || 0) + 1;
  }
  return { counts, categories };
}

function blockingCount(counts) {
  return (counts.critical || 0) + (counts.high || 0);
}

function severityIcon(severity) {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' }[severity] || '⚪';
}

const normalizeSuggestionPatch = validatorPrivate.normalizePatch;
const looksLikeUnifiedDiff = validatorPrivate.looksLikeUnifiedDiff;
const buildRepoAwareRemediation = validatorPrivate.buildRepoAwareRemediation;
let analysisGrpcClient = null;
let githubGrpcClient = null;

function useGrpcTransport() {
  return String(process.env.INTERNAL_SERVICE_TRANSPORT || '').toLowerCase() === 'grpc';
}

function getAnalysisGrpcClient() {
  if (!analysisGrpcClient) {
    analysisGrpcClient = new AnalysisGrpcClient();
  }
  return analysisGrpcClient;
}

function getGitHubGrpcClient() {
  if (!githubGrpcClient) {
    githubGrpcClient = new GitHubGrpcClient();
  }
  return githubGrpcClient;
}

function shouldRenderSuggestion(finding, suggestionPatch) {
  if (!suggestionPatch) return false;
  if (suggestionPatch.includes('```')) return false;

  const lineStart = Number(finding.line_start || 0);
  if (!lineStart) return false;
  const lineEnd = Number(finding.line_end || lineStart);
  const anchorSpan = Math.max(1, lineEnd - lineStart + 1);

  const patchLines = suggestionPatch.split('\n').length;
  if (patchLines > 8) return false;

  if (patchLines < anchorSpan) return false;
  if (patchLines > anchorSpan + 3) return false;

  return true;
}

function inferCodeFenceLanguage(filePath) {
  const path = String(filePath || '').toLowerCase();
  if (path.endsWith('.py')) return 'python';
  if (path.endsWith('.ts') || path.endsWith('.tsx')) return 'ts';
  if (path.endsWith('.js') || path.endsWith('.jsx')) return 'javascript';
  if (path.endsWith('.go')) return 'go';
  if (path.endsWith('.java')) return 'java';
  if (path.endsWith('.rb')) return 'ruby';
  if (path.endsWith('.cs')) return 'csharp';
  if (path.endsWith('.php')) return 'php';
  return '';
}

function shouldRenderFixCodeBlock(suggestionPatch) {
  if (!suggestionPatch) return false;
  if (suggestionPatch.includes('```')) return false;
  if (looksLikeUnifiedDiff(suggestionPatch)) return false;
  if (suggestionPatch.split('\n').length > 20) return false;
  return true;
}

function findingUpdateSignature(finding) {
  return JSON.stringify({
    fingerprint: finding?.fingerprint || '',
    severity: finding?.severity || '',
    confidence: Number(finding?.confidence || 0),
    title: finding?.title || '',
    evidence: finding?.evidence || '',
    remediation: finding?.remediation || '',
    remediation_patch: finding?.remediation_patch || '',
    line_start: Number(finding?.line_start || 0),
    line_end: Number(finding?.line_end || 0),
  });
}

function didTier3MeaningfullyChangeFindings(previousFindings, nextFindings) {
  const previous = Array.isArray(previousFindings) ? previousFindings : [];
  const next = Array.isArray(nextFindings) ? nextFindings : [];

  if (previous.length !== next.length) return true;

  const previousByFingerprint = new Map(
    previous.map((finding) => [finding?.fingerprint || '', findingUpdateSignature(finding)])
  );

  for (const finding of next) {
    const fingerprint = finding?.fingerprint || '';
    if (!previousByFingerprint.has(fingerprint)) return true;
    if (previousByFingerprint.get(fingerprint) !== findingUpdateSignature(finding)) return true;
  }

  return false;
}

function buildTestCodeSummaryLines({ testFilesScanned, infoFindings, infoCommentsOmitted }) {
  const lines = [];
  if (testFilesScanned <= 0 && infoFindings <= 0) return lines;

  lines.push(
    `${severityIcon('info')} ${testFilesScanned} test file${testFilesScanned === 1 ? '' : 's'} scanned; `
    + `${infoFindings} informational finding${infoFindings === 1 ? '' : 's'} in test code. `
    + 'Informational findings never block this check.'
  );
  if (infoCommentsOmitted > 0) {
    lines.push(
      '',
      `${infoCommentsOmitted} informational comment${infoCommentsOmitted === 1 ? ' was' : 's were'} `
      + 'omitted from the inline annotations so runtime findings keep their place.'
    );
  }
  lines.push('');
  return lines;
}

function buildReviewBody(findings, runId, options = {}) {
  const all = findings || [];
  const runtimeFindings = all.filter((finding) => !isInfoFinding(finding));
  const infoFindings = all.filter(isInfoFinding);
  const { counts } = summarizeFindings(runtimeFindings);
  const total = runtimeFindings.length;
  const hasBlocking = blockingCount(counts) > 0;
  const testCodeLines = buildTestCodeSummaryLines({
    testFilesScanned: Number(options.testFilesScanned || 0),
    infoFindings: infoFindings.length,
    infoCommentsOmitted: Number(options.infoCommentsOmitted || 0),
  });

  if (total === 0) {
    return [
      '<!-- mitig8it-review -->',
      '### 🛡️ Mitig8it — No security issues found',
      '',
      'This PR passed all security checks.',
      '',
      ...testCodeLines,
      `<sub>Run \`${runId.slice(0, 8)}\`</sub>`,
    ].join('\n');
  }

  const placement = buildPlacementLine(total, options);

  return [
    '<!-- mitig8it-review -->',
    `### 🛡️ Mitig8it — ${total} finding${total === 1 ? '' : 's'} detected`,
    '',
    hasBlocking ? '**Resolve critical and high severity issues before merging.**' : 'No blocking issues. Review at your discretion.',
    '',
    `| ${severityIcon('critical')} Critical | ${severityIcon('high')} High | ${severityIcon('medium')} Medium | ${severityIcon('low')} Low |`,
    '|---|---|---|---|',
    `| **${counts.critical || 0}** | **${counts.high || 0}** | **${counts.medium || 0}** | **${counts.low || 0}** |`,
    '',
    ...testCodeLines,
    placement.sentence,
    '',
    `<sub>Analyzed by <strong>Mitig8it</strong> · Run \`${runId.slice(0, 8)}\` · ${placement.short}</sub>`,
  ].join('\n');
}

// How many of the runtime findings are annotated on their lines and how many appear in
// this summary only. A finding stays summary only when its line is outside the diff or
// its evidence is below the inline threshold; without the counts, all are taken as inline.
function buildPlacementLine(total, options = {}) {
  const inline = options.inlineCount == null ? total : Math.max(0, Math.min(total, Number(options.inlineCount) || 0));
  const summaryOnly = Math.max(0, total - inline);
  const noun = (count) => `${count} finding${count === 1 ? '' : 's'}`;
  if (!summaryOnly) {
    return {
      sentence: total === 1 ? 'The finding is annotated inline on the affected line below.' : `All ${total} findings are annotated inline on the affected lines below.`,
      short: `${inline} of ${total} annotated inline`,
    };
  }
  const why = 'the line is outside the diff or the evidence is below the inline threshold';
  return {
    sentence: `${noun(inline)} ${inline === 1 ? 'is' : 'are'} annotated inline on the affected lines below; ${noun(summaryOnly)} ${summaryOnly === 1 ? 'is' : 'are'} listed here only (${why}), with details in the Mitig8it dashboard.`,
    short: `${inline} of ${total} annotated inline`,
  };
}

function buildReviewComment(finding, options = {}) {
  const suggestionPatch = normalizeSuggestionPatch(finding.remediation_patch);
  const suggestionValidation = validateSuggestedFix({
    finding,
    filePatch: options.filePatch || '',
    tierLabel: options.tierLabel || 'manual',
    repoProfile: options.repoProfile || null,
  });
  const repoAwareRemediation =
    buildRepoAwareRemediation(finding, options.repoProfile || null)
    || finding.remediation
    || 'Apply input validation and secure handling.';
  const inTestCode = isInfoFinding(finding);
  const scannerSeverity = originalSeverity(finding);
  const headline = inTestCode
    ? `${severityIcon('info')} **INFORMATIONAL — TEST CODE** — ${markdownEscape(finding.title)}`
    : `${severityIcon(finding.severity)} **${finding.severity.toUpperCase()}** — ${markdownEscape(finding.title)}`;
  const lines = [
    headline,
    '',
    `> ${markdownEscape(finding.evidence || finding.description)}`,
    '',
    finding.cwe_id ? `**CWE:** ${finding.cwe_id}` : null,
    `**Confidence:** ${Math.round(Number(finding.confidence) * 100)}%`,
    inTestCode
      ? `_In test code${scannerSeverity ? `; scanner severity ${scannerSeverity}` : ''}. Informational only, it does not block this pull request._`
      : null,
  ];

  const showSuggestion = shouldRenderSuggestion(finding, suggestionPatch) && suggestionValidation.ok;
  const showFixCodeBlock = !showSuggestion && shouldRenderFixCodeBlock(suggestionPatch);
  const codeFenceLanguage = inferCodeFenceLanguage(finding.file_path);

  if (showSuggestion) {
    lines.push('', '```suggestion', suggestionPatch, '```');
  } else {
    lines.push('', `**Fix:** ${markdownEscape(repoAwareRemediation)}`);
    if (showFixCodeBlock) {
      lines.push('', `\`\`\`${codeFenceLanguage}`, suggestionPatch, '```');
    }
  }

  return lines.filter(Boolean).join('\n');
}

const extractReviewableLines = validatorPrivate.extractReviewableLines;
const extractReviewableLineSpans = validatorPrivate.extractReviewableLineSpans;

function fileExtension(path) {
  const match = String(path || '').toLowerCase().match(/(\.[^./]+)$/);
  return match ? match[1] : '';
}

function shouldFetchFullFileContent(file) {
  const path = String(file?.path || '');
  const ext = fileExtension(path);
  if (!TIER2_SUPPORTED_EXTENSIONS.has(ext)) return false;
  if (path.startsWith('dist/') || path.includes('node_modules/')) return false;
  if (path.endsWith('.min.js') || path.endsWith('.min.css')) return false;
  return true;
}

function buildTier2FilePayload(file, contentByPath = new Map()) {
  const content = contentByPath.get(file.path);
  return {
    ...file,
    content: typeof content === 'string' ? content : '',
    reviewable_line_spans: extractReviewableLineSpans(file.patch),
  };
}

async function enrichFilesForTier2({ files, repositoryFullName, installationId, commitSha }) {
  const sourceFiles = Array.isArray(files) ? files : [];
  const candidates = sourceFiles.filter(shouldFetchFullFileContent);
  const contentByPath = new Map();

  if (candidates.length > 0) {
    try {
      const response = await githubServiceRequest('/internal/github/files/content', {
        repository_full_name: repositoryFullName,
        installation_id: installationId,
        ref: commitSha,
        paths: candidates.map((file) => file.path),
      });

      for (const file of response.files || []) {
        if (!file?.path || typeof file.content !== 'string') continue;
        contentByPath.set(file.path, file.content);
      }
    } catch (error) {
      throw new Error(`Required source content retrieval failed: ${error.message}`);
    }
    if (candidates.some(file => !contentByPath.has(file.path))) {
      throw new Error('Required source content response is incomplete');
    }
  }

  return sourceFiles.map((file) => buildTier2FilePayload(file, contentByPath));
}

function severityRank(severity) {
  return { critical: 4, high: 3, medium: 2, low: 1, info: 0 }[String(severity || '').toLowerCase()] || 0;
}

function isInfoComment(comment) {
  return String(comment?.severity || '').toLowerCase() === INFORMATIONAL_SEVERITY;
}

function compareReviewComments(a, b) {
  // Runtime findings always come before informational test-code findings, so a
  // comment cap drops informational comments first.
  if (isInfoComment(a) !== isInfoComment(b)) {
    return isInfoComment(a) ? 1 : -1;
  }

  const pathCompare = String(a.path || '').localeCompare(String(b.path || ''));
  if (pathCompare !== 0) return pathCompare;

  if (Boolean(a.hasSuggestion) !== Boolean(b.hasSuggestion)) {
    return a.hasSuggestion ? -1 : 1;
  }

  const lineDiff = Number(a.line || 0) - Number(b.line || 0);
  if (lineDiff !== 0) return lineDiff;

  const severityDiff = severityRank(b.severity) - severityRank(a.severity);
  if (severityDiff !== 0) return severityDiff;

  return String(a.body || '').localeCompare(String(b.body || ''));
}

function prioritizeReviewComments(reviewComments) {
  return [...(reviewComments || [])].sort(compareReviewComments);
}

function hasTier3RenderableSuggestions(findings, files, repoProfile) {
  const filePatchByPath = new Map((files || []).map((f) => [f.path, f.patch || '']));
  return (findings || []).some((finding) => {
    const suggestionPatch = normalizeSuggestionPatch(finding.remediation_patch);
    if (!shouldRenderSuggestion(finding, suggestionPatch)) return false;

    const validation = validateSuggestedFix({
      finding,
      filePatch: filePatchByPath.get(finding.file_path) || '',
      tierLabel: 'Tier 3',
      repoProfile,
    });
    return validation.ok;
  });
}

function evidenceDetailsForFinding(finding) {
  const details = finding?.evidence_details;
  return details && typeof details === 'object' ? details : {};
}

function normalizedAnalysisScope(finding) {
  const details = evidenceDetailsForFinding(finding);
  return String(finding?.analysis_scope || details.analysis_scope || 'pattern').trim().toLowerCase();
}

function hasTaintTraceEvidence(finding) {
  const details = evidenceDetailsForFinding(finding);
  const traceSteps = Array.isArray(details.trace_steps) ? details.trace_steps : [];
  return Boolean(
    traceSteps.length > 0
    || details.trace_summary
    || finding?.trace_summary
    || (finding?.source && finding?.sink)
    || (details.source_type && details.sink_type)
  );
}

function explainInlineCommentDecision(finding) {
  const status = String(finding?.status || 'open').trim().toLowerCase();
  if (status !== 'open') {
    return { eligible: false, reason: `status_${status || 'unknown'}` };
  }

  if (finding?.is_baseline) {
    return { eligible: false, reason: 'baseline_finding' };
  }

  const confidence = Number(finding?.confidence || 0);
  if (confidence < 0.7) {
    return { eligible: false, reason: 'confidence_below_inline_threshold' };
  }

  const details = evidenceDetailsForFinding(finding);
  const sanitizerStatus = String(details.sanitizer_status || '').trim().toLowerCase();
  if (['allowlisted', 'sanitized', 'validated'].includes(sanitizerStatus)) {
    return { eligible: false, reason: 'validated_sanitizer_present' };
  }

  const analysisScope = normalizedAnalysisScope(finding);
  const evidenceStrength = String(details.evidence_strength || '').trim().toLowerCase();
  const traceQuality = String(details.trace_quality || '').trim().toLowerCase();
  const confidenceBasis = String(details.confidence_basis || '').trim().toLowerCase();

  if (analysisScope.startsWith('taint')) {
    if (confidence < 0.8) {
      return { eligible: false, reason: 'taint_confidence_below_inline_threshold' };
    }
    if (
      traceQuality === 'weak'
      || evidenceStrength === 'weak'
      || confidenceBasis.includes('weak_trace')
      || !hasTaintTraceEvidence(finding)
    ) {
      return { eligible: false, reason: 'weak_taint_trace' };
    }
    return { eligible: true, reason: 'strong_taint_evidence' };
  }

  if (analysisScope === 'ast-pattern' || analysisScope === 'ast') {
    if (confidence < 0.85) {
      return { eligible: false, reason: 'ast_pattern_confidence_below_inline_threshold' };
    }
    if (evidenceStrength && ['low', 'weak'].includes(evidenceStrength)) {
      return { eligible: false, reason: 'ast_pattern_evidence_too_weak' };
    }
    return { eligible: true, reason: 'ast_pattern_inline_basis' };
  }

  if (analysisScope === 'pattern') {
    if (confidence < 0.9) {
      return { eligible: false, reason: 'pattern_confidence_below_inline_threshold' };
    }
    return { eligible: true, reason: 'high_confidence_pattern' };
  }

  return { eligible: false, reason: 'unsupported_analysis_scope' };
}

function shouldPostInlineComment(finding) {
  return explainInlineCommentDecision(finding).eligible;
}

function buildSurfaceDecisions({ files, findings }) {
  const reviewableLinesByFile = new Map((files || []).map((file) => [
    file.path,
    extractReviewableLines(file.patch),
  ]));

  return (findings || []).map((finding) => {
    const findingId = finding?.id || finding?.finding_id || finding?.fingerprint || null;
    const status = String(finding?.status || 'open').trim().toLowerCase();

    if (status !== 'open') {
      return {
        findingId,
        surfaceDecision: 'suppressed',
        surfaceReason: `status_${status || 'unknown'}`,
      };
    }

    if (finding?.is_baseline) {
      return {
        findingId,
        surfaceDecision: 'suppressed',
        surfaceReason: 'baseline_finding',
      };
    }

    const reviewableLines = reviewableLinesByFile.get(finding?.file_path);
    if (!reviewableLines) {
      return {
        findingId,
        surfaceDecision: 'summary_only',
        surfaceReason: 'file_not_reviewable',
      };
    }

    if (!reviewableLines.has(finding?.line_start || 1)) {
      return {
        findingId,
        surfaceDecision: 'summary_only',
        surfaceReason: 'line_not_reviewable',
      };
    }

    const inlineDecision = explainInlineCommentDecision(finding);
    return {
      findingId,
      surfaceDecision: inlineDecision.eligible ? 'inline' : 'summary_only',
      surfaceReason: inlineDecision.reason,
    };
  });
}

async function persistSurfaceDecisions(surfaceDecisions) {
  for (const decision of surfaceDecisions || []) {
    if (!decision.findingId) continue;
    await findingsDb.mergeEvidenceDetails(decision.findingId, {
      surface_decision: decision.surfaceDecision,
      surface_reason: decision.surfaceReason,
    });
  }
}

function isTransientServiceError(error) {
  const code = String(error?.code || '').toUpperCase();
  if (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND'].includes(code)) {
    return true;
  }
  const status = Number(error?.response?.status || 0);
  return status >= 500 || /ECONNREFUSED|ECONNRESET|ETIMEDOUT|EAI_AGAIN|ENOTFOUND|502|503|504/.test(error?.message || '');
}

async function githubServiceRequest(path, payload) {
  if (useGrpcTransport()) {
    const client = getGitHubGrpcClient();
    const methods = {
      '/internal/github/pulls/files': () => client.fetchPullRequestFiles(payload),
      '/internal/github/files/content': () => client.fetchFileContents(payload),
      '/internal/github/reviews/submit': () => client.submitPullRequestReview(payload),
      '/internal/github/comments/inline': () => client.postInlineComment(payload),
      '/internal/github/check-runs': () => client.createCheckRun(payload),
    };

    if (!methods[path]) {
      throw new Error(`Unsupported GitHub gRPC operation for ${path}`);
    }
    return methods[path]();
  }

  const baseUrl = process.env.GITHUB_SERVICE_URL || 'http://github-service:3002';
  const internalSecret = process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  if (!internalSecret) {
    throw new Error('Missing GITHUB_SERVICE_INTERNAL_SECRET');
  }

  const requestConfig = {
    timeout: 45000,
    headers: { 'x-internal-secret': internalSecret },
  };
  let lastError = null;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    try {
      const response = await axios.post(`${baseUrl}${path}`, payload, requestConfig);
      return response.data;
    } catch (error) {
      lastError = error;
      if (!isTransientServiceError(error) || attempt === 3) break;
    }
  }

  if (isTransientServiceError(lastError)) {
    throw new Error(`GitHub service unreachable after 3 attempts: ${lastError.message}`);
  }
  throw lastError;
}

async function submitReviewWithFallback({
  owner,
  repo,
  prNumber,
  installationId,
  commitSha,
  reviewBody,
  event,
}) {
  return githubServiceRequest('/internal/github/reviews/submit', {
    owner,
    repo,
    pr_number: prNumber,
    installation_id: installationId,
    commit_sha: commitSha,
    body: reviewBody,
    event,
    comments: [],
  });
}

function dedupeInlineComments(reviewComments) {
  const seen = new Set();
  const deduped = [];
  for (const comment of reviewComments) {
    const key = `${comment.path}:${comment.line}:${comment.body}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(comment);
  }
  return deduped;
}

// Runtime findings keep their inline slots; informational comments are the
// first to fall outside the cap, and the summary says how many were omitted.
function planInlineComments(reviewComments, cap = INLINE_COMMENT_CAP) {
  const deduped = dedupeInlineComments(prioritizeReviewComments(reviewComments));
  const selected = deduped.slice(0, cap);
  const omitted = deduped.slice(cap);

  return {
    comments: selected,
    infoOmitted: omitted.filter(isInfoComment).length,
    runtimeOmitted: omitted.filter((comment) => !isInfoComment(comment)).length,
  };
}

async function postInlineCommentsIndividually({
  owner,
  repo,
  prNumber,
  installationId,
  commitSha,
  reviewComments,
  runId,
}) {
  const dedupedComments = Array.isArray(reviewComments)
    ? planInlineComments(reviewComments).comments
    : [];
  let posted = 0;

  for (const comment of dedupedComments) {
    try {
      await githubServiceRequest('/internal/github/comments/inline', {
        owner,
        repo,
        pr_number: prNumber,
        installation_id: installationId,
        commit_sha: commitSha,
        path: comment.path,
        line: comment.line,
        body: comment.body,
      });
      posted += 1;
    } catch (error) {
      logger.error('Failed to post inline PR comment', {
        runId,
        prNumber,
        path: comment.path,
        line: comment.line,
        error: error.message,
      });
    }
  }

  return { attempted: dedupedComments.length, posted };
}

function analysisServiceHeaders() {
  const internalSecret =
    process.env.ANALYSIS_SERVICE_INTERNAL_SECRET || process.env.GITHUB_SERVICE_INTERNAL_SECRET;

  if (!internalSecret) {
    throw new Error('Missing ANALYSIS_SERVICE_INTERNAL_SECRET or GITHUB_SERVICE_INTERNAL_SECRET');
  }

  return {
    'x-internal-secret': internalSecret,
  };
}

async function upsertFinding({ finding, runId, pullRequestId, repositoryId, installationId, prNumber, commitSha, isBaseline }) {
  const normalized = normalizeFinding(finding);
  const fingerprint = normalized.fingerprint || calculateFingerprint(normalized);

  const existing = await findingsDb.findByFingerprint({
    repositoryId,
    pullRequestId,
    fingerprint,
  });

  return findingsDb.upsert({
    id: existing?.id || null,
    runId,
    pullRequestId,
    prNumber,
    commitSha,
    repositoryId,
    installationId,
    fingerprint,
    ruleId: normalized.rule_id,
    internalType: normalized.internal_type,
    title: normalized.title,
    description: normalized.description,
    category: normalized.category,
    cweId: normalized.cwe_id || null,
    owaspCategory: normalized.owasp_category || null,
    taxonomyMappings: normalized.taxonomy_mappings,
    taxonomyVersions: normalized.taxonomy_versions,
    severity: normalized.severity,
    confidence: Number(normalized.confidence || 0.4),
    exploitability: normalized.exploitability || 'medium',
    filePath: normalized.file_path,
    lineStart: normalized.line_start || null,
    lineEnd: normalized.line_end || null,
    codeSnippet: normalized.code_snippet || null,
    analysisScope: normalized.analysis_scope || 'pattern',
    evidenceDetails: normalized.evidence_details || {},
    evidence: normalized.evidence || null,
    exploitScenario: normalized.exploit_scenario || null,
    remediation: normalized.remediation || null,
    remediationPatch: normalized.remediation_patch || null,
    isBaseline,
  });
}

async function applySuppressions(findingRows, repositoryId) {
  const suppressions = await findingsDb.getActiveSuppressions(repositoryId);
  const byFingerprint = new Map(suppressions.map((row) => [row.fingerprint, row]));

  const result = [];
  for (const finding of findingRows) {
    const suppression = byFingerprint.get(finding.fingerprint);
    if (suppression && finding.status === 'open') {
      await findingsDb.dismiss(finding.id, suppression.reason);
      result.push({ ...finding, status: 'dismissed', dismissal_reason: suppression.reason });
    } else {
      result.push(finding);
    }
  }
  return result;
}

async function callAnalysisTier(tierPath, payload, timeout) {
  if (useGrpcTransport()) {
    const client = getAnalysisGrpcClient();
    const methods = {
      '/analyze/pr': () => client.analyzePullRequest(payload, timeout),
      '/analyze/pr/tier1': () => client.analyzeTier1(payload, timeout),
      '/analyze/pr/tier2': () => client.analyzeTier2(payload, timeout),
      '/analyze/pr/tier3': () => client.triageFindings(payload, timeout),
    };

    if (!methods[tierPath]) {
      throw new Error(`Unsupported analysis gRPC operation for ${tierPath}`);
    }
    return methods[tierPath]();
  }

  const baseUrl = process.env.ANALYSIS_SERVICE_URL || 'http://analysis-service:8001';
  const response = await axios.post(`${baseUrl}${tierPath}`, payload, {
    timeout,
    headers: analysisServiceHeaders(),
  });
  return response.data;
}

async function persistAndFilter({ findings, files, runId, pullRequestId, repositoryId, installationId, prNumber, commitSha, baselineSet }) {
  const completedCount = await analysisRunsDb.countCompletedRuns(repositoryId, runId);
  const shouldMarkBaselineSet = !baselineSet && completedCount === 0;

  const persisted = [];
  for (const finding of findings) {
    const saved = await upsertFinding({
      finding, runId, pullRequestId, repositoryId, installationId, prNumber, commitSha,
      isBaseline: false,
    });
    persisted.push(saved);
  }

  const activeFingerprints = persisted.map((f) => f.fingerprint);
  await findingsDb.markFixed({ repositoryId, pullRequestId, activeFingerprints });

  const postSuppression = await applySuppressions(persisted, repositoryId);
  await persistSurfaceDecisions(buildSurfaceDecisions({ files, findings: postSuppression }));
  const actionable = postSuppression.filter((f) => f.status === 'open' && !f.is_baseline);

  return { actionable, shouldMarkBaselineSet, findingRows: postSuppression };
}

async function postReviewToGitHub({ actionable, files, owner, repo, prNumber, installationId, commitSha, runId, tierLabel, repoProfile }) {
  const counts = summarizeFindings(actionable).counts;
  const highOrCritical = blockingCount(counts);
  const testFilesScanned = countTestCodeFiles(files);

  let reviewResp = {};
  try {
    const filePatchByPath = new Map(files.map((f) => [f.path, f.patch || '']));
    const suggestionStats = { rendered: 0, noPatch: 0, gateRejected: 0, validatorRejected: 0 };
    const rejectionReasons = {};
    const inlineFindingIds = new Set(
      buildSurfaceDecisions({ files, findings: actionable })
        .filter((decision) => decision.surfaceDecision === 'inline')
        .map((decision) => decision.findingId)
    );
    const reviewComments = actionable
      .filter((f) => inlineFindingIds.has(f.id || f.finding_id || f.fingerprint))
      .map((f) => {
        const filePatch = filePatchByPath.get(f.file_path) || '';
        const suggestionPatch = normalizeSuggestionPatch(f.remediation_patch);
        const suggestionValidation = validateSuggestedFix({
          finding: f,
          filePatch,
          tierLabel,
          repoProfile,
        });
        const gatePassed = shouldRenderSuggestion(f, suggestionPatch);
        const hasSuggestion = gatePassed && suggestionValidation.ok;

        if (hasSuggestion) {
          suggestionStats.rendered += 1;
        } else if (!suggestionPatch) {
          suggestionStats.noPatch += 1;
        } else if (!gatePassed) {
          suggestionStats.gateRejected += 1;
        } else {
          suggestionStats.validatorRejected += 1;
          const reason = suggestionValidation.reason || 'unknown';
          rejectionReasons[reason] = (rejectionReasons[reason] || 0) + 1;
        }

        return {
          path: f.file_path,
          line: f.line_start || 1,
          severity: f.severity,
          hasSuggestion,
          body: `<!-- mitig8it-finding:${f.fingerprint} -->\n` + buildReviewComment(f, {
            filePatch,
            tierLabel,
            repoProfile,
          }),
        };
      });

    if (reviewComments.length > 0) {
      logger.info(`${tierLabel}: suggestion render outcomes`, {
        runId,
        prNumber,
        total: reviewComments.length,
        ...suggestionStats,
        validatorReasons: rejectionReasons,
      });
    }

    const inlinePlan = planInlineComments(reviewComments);
    if (inlinePlan.infoOmitted > 0 || inlinePlan.runtimeOmitted > 0) {
      logger.info(`${tierLabel}: inline comment cap reached`, {
        runId,
        prNumber,
        cap: INLINE_COMMENT_CAP,
        infoOmitted: inlinePlan.infoOmitted,
        runtimeOmitted: inlinePlan.runtimeOmitted,
      });
    }

    const reviewBody = buildReviewBody(actionable, runId, {
      testFilesScanned,
      infoCommentsOmitted: inlinePlan.infoOmitted,
      inlineCount: inlinePlan.comments.filter((comment) => !isInfoComment(comment)).length,
    });

    reviewResp = await submitReviewWithFallback({
      owner, repo, prNumber, installationId, commitSha,
      reviewBody,
      event: highOrCritical > 0 ? 'REQUEST_CHANGES' : 'COMMENT',
    });

    const inlineResult = await postInlineCommentsIndividually({
      owner, repo, prNumber, installationId, commitSha, reviewComments, runId,
    });

    if (inlineResult.attempted > inlineResult.posted) {
      throw new Error(`Inline finding publication incomplete: ${inlineResult.posted}/${inlineResult.attempted} posted`);
    }
  } catch (reviewErr) {
    throw reviewErr;
  }

  return { reviewResp, counts, highOrCritical, testFilesScanned };
}

// gRPC status codes that describe the transport, not the request.
const TRANSIENT_GRPC_STATUS = new Set([4, 14]); // DEADLINE_EXCEEDED, UNAVAILABLE
const TRANSIENT_ERROR_CODES = new Set(['ECONNRESET', 'ETIMEDOUT']);
const MAX_AUTOMATIC_ANALYSIS_RETRIES = 3;
const RETRY_BACKOFF_STEP_MS = 30_000;
const RETRY_BACKOFF_CAP_MS = 5 * 60_000;

// Failures the pipeline raises on purpose. These fail closed whatever the
// underlying cause was, so they are never eligible for an automatic retry.
const FAIL_CLOSED_MESSAGE_PREFIXES = [
  'Required source content',
  'Incomplete analysis response',
  'Invalid GitHub file response',
  'Inline finding publication incomplete',
];

// Only infrastructure faults qualify. Content, scanner and persistence failures
// fail closed by design and must never be retried into a passing check run.
function isTransientInfrastructureError(error) {
  if (!error) return false;

  const failClosed = FAIL_CLOSED_MESSAGE_PREFIXES.some(
    (prefix) => String(error.message || '').startsWith(prefix)
  );
  if (failClosed) return false;

  if (typeof error.code === 'number' && TRANSIENT_GRPC_STATUS.has(error.code)) return true;
  if (typeof error.code === 'string' && TRANSIENT_ERROR_CODES.has(error.code)) return true;

  const message = String(error.message || '');
  if (/\b14 UNAVAILABLE\b/.test(message)) return true;
  if (/\b4 DEADLINE_EXCEEDED\b/.test(message)) return true;
  // The observed Cloud Run failure: call credentials could not mint an identity token.
  if (/\b2 UNKNOWN\b/.test(message) && /metadata token/i.test(message)) return true;
  if (/ECONNRESET|socket hang up|connection reset/i.test(message)) return true;

  return false;
}

function transientRetryDelayMs(priorRetries) {
  return Math.min(RETRY_BACKOFF_CAP_MS, RETRY_BACKOFF_STEP_MS * (priorRetries + 1));
}

async function runAnalysisJob(payload) {
  const {
    analysis_run_id: runId,
    repository_id: repositoryId,
    repository_full_name: repositoryFullName,
    installation_id: installationId,
    pull_request_id: pullRequestId,
    pull_request_number: prNumber,
    commit_sha: commitSha,
    baseline_set: baselineSet,
  } = payload;
  const [owner, repo] = repositoryFullName.split('/');
  const analysisPayload = { repository_full_name: repositoryFullName, pull_request_number: prNumber, commit_sha: commitSha };

  let allFindings = [];
  let files = [];
  let tier2Files = [];
  let lastCounts = {};
  let lastHighOrCritical = 0;
  let testFilesScanned = 0;
  let reviewResp = {};
  let checkRunResp = {};
  let shouldMarkBaselineSet = false;
  // Once a result exists, persistence and publication have begun; a retry from
  // that point could duplicate feedback, so only earlier faults are retryable.
  let analysisResultProduced = false;

  try {
    // ── Fetch PR files ────────────────────────────────────────────────
    const filesResp = await githubServiceRequest('/internal/github/pulls/files', {
      repository_full_name: repositoryFullName,
      pull_request_number: prNumber,
      installation_id: installationId,
      commit_sha: commitSha,
    });
    if (!Array.isArray(filesResp?.files)) throw new Error('Invalid GitHub file response');
    files = filesResp.files;
    tier2Files = await enrichFilesForTier2({
      files,
      repositoryFullName,
      installationId,
      commitSha,
    });

    // Required analysis and persistence must all succeed before final publication.
    const requiredTier = async (path, data, timeout) => {
      const result = await callAnalysisTier(path, data, timeout);
      if (!result || !Array.isArray(result.findings)) throw new Error(`Incomplete analysis response: ${path}`);
      return result;
    };
    const tier1 = await requiredTier('/analyze/pr/tier1', { ...analysisPayload, files }, 30000);
    const tier2 = await requiredTier('/analyze/pr/tier2', { ...analysisPayload, files: tier2Files }, 60000);
    allFindings = [...tier1.findings, ...tier2.findings];
    let repoProfile = {};
    try {
      const profile = await repositoriesDb.getProfile(repositoryId);
      if (profile?.profile_status === 'ready') repoProfile = profile.profile_data || {};
      else await repositoriesDb.queueUrgentProfiling(repositoryId, { run_id: runId, pr_number: prNumber });
    } catch (error) {
      logger.warn('Failed to fetch repo profile', { runId, error: error.message });
    }
    const tier3 = await requiredTier('/analyze/pr/tier3', {
      ...analysisPayload, findings: allFindings,
      file_patches: Object.fromEntries(files.map(file => [file.path, file.patch || ''])),
      repo_profile: repoProfile,
    }, 120000);
    allFindings = [...new Map(tier3.findings.map(finding => [
      finding.fingerprint || calculateFingerprint(normalizeFinding(finding)), finding,
    ])).values()];
    analysisResultProduced = true;
    const final = await persistAndFilter({
      findings: allFindings, files, runId, pullRequestId, repositoryId, installationId, prNumber, commitSha, baselineSet,
    });
    shouldMarkBaselineSet = final.shouldMarkBaselineSet;
    await findingsDb.snapshotRun(runId, final.findingRows);
    const result = await postReviewToGitHub({
      actionable: final.actionable, files, owner, repo, prNumber, installationId, commitSha, runId,
      tierLabel: 'Tier 3', repoProfile,
    });
    reviewResp = result.reviewResp;
    lastCounts = result.counts;
    lastHighOrCritical = result.highOrCritical;
    testFilesScanned = result.testFilesScanned;

    // ── Check run + completion ────────────────────────────────────────
    try {
      const finalCounts = Object.keys(lastCounts).length > 0
        ? lastCounts
        : { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const infoCount = allFindings.filter(isInfoFinding).length;
      const finalTotal = allFindings.length - infoCount;
      const summaryLines = [
        `Mitig8it found ${finalTotal} runtime finding${finalTotal === 1 ? '' : 's'} `
        + `(${finalCounts.critical || 0} critical, ${finalCounts.high || 0} high, `
        + `${finalCounts.medium || 0} medium, ${finalCounts.low || 0} low).`,
      ];
      if (testFilesScanned > 0 || infoCount > 0) {
        summaryLines.push(
          `${testFilesScanned} test file${testFilesScanned === 1 ? '' : 's'} scanned; `
          + `${infoCount} informational finding${infoCount === 1 ? '' : 's'} in test code `
          + '(never blocking).'
        );
      }
      checkRunResp = await githubServiceRequest('/internal/github/check-runs', {
        owner, repo, installation_id: installationId, head_sha: commitSha,
        // Informational findings never contribute to the conclusion.
        conclusion: lastHighOrCritical > 0 ? 'failure' : 'success',
        title: lastHighOrCritical > 0 ? `${lastHighOrCritical} critical/high finding${lastHighOrCritical === 1 ? '' : 's'}` : 'No blocking security findings',
        summary: summaryLines.join(' '),
      });
    } catch (checkErr) {
      throw checkErr;
    }

    await analysisRunsDb.markCompleted(runId, {
      findingsCount: allFindings.length,
      counts: lastCounts,
      filesAnalyzed: files.length,
      checkRunId: checkRunResp.check_run_id,
      reviewId: reviewResp.review_id,
    });

    if (shouldMarkBaselineSet) {
      await analysisRunsDb.markBaselineSet(repositoryId);
    }

    // The analysis is published and completed at this point. Automatic remediation
    // is queued afterwards and never fails the run: the helper reports refusals, and
    // even an unexpected throw is logged rather than surfaced as an analysis failure.
    try {
      await remediationAutoGenerate.enqueueForCompletedAnalysis({ pullRequestId, analysisRunId: runId });
    } catch (enqueueError) {
      logger.warn('Automatic remediation enqueue failed after analysis completion', { analysis_run_id: runId, error: enqueueError.message });
    }

    // This run re-rendered the inline finding comments of its head. A ready job that
    // had already published its verified fixes under them is not re-queued, so its
    // sections are written again here; the publication is idempotent.
    try {
      await remediationAutoGenerate.republishInlineFixesForCompletedAnalysis({ pullRequestId, headSha: commitSha });
    } catch (republishError) {
      logger.warn('Inline fix republication failed after analysis completion', { analysis_run_id: runId, error: republishError.message });
    }
  } catch (error) {
    const priorRetries = Number(payload.auto_retry_count || 0);
    const retryable = !analysisResultProduced
      && isTransientInfrastructureError(error)
      && priorRetries < MAX_AUTOMATIC_ANALYSIS_RETRIES;

    if (retryable) {
      const delayMs = transientRetryDelayMs(priorRetries);
      try {
        const requeued = await analysisRunsDb.requeueAfterTransientFailure(runId, {
          errorMessage: error.message,
          delayMs,
        });
        logger.warn('PR analysis hit a transient infrastructure failure; re-queued', {
          runId, repositoryId, prNumber, error: error.message,
          attempt: priorRetries + 1, maxRetries: MAX_AUTOMATIC_ANALYSIS_RETRIES,
          delayMs, retryRunId: requeued?.id || null,
        });
        // The queue poller picks the retry up once not_before elapses.
        return;
      } catch (requeueError) {
        logger.error('Failed to re-queue a transient analysis failure', {
          runId, repositoryId, error: requeueError.message,
        });
      }
    }

    logger.error('PR analysis orchestration failed', {
      runId, repositoryId, error: error.message, automaticRetries: priorRetries,
    });
    await analysisRunsDb.markFailed(runId, error.message);
    try {
      await githubServiceRequest('/internal/github/check-runs', {
        owner, repo, installation_id: installationId, head_sha: commitSha,
        conclusion: 'failure', title: 'Security analysis incomplete',
        summary: 'Required analysis or result publication failed. Retry this analysis run.',
      });
    } catch (checkError) {
      logger.error('Failed to publish incomplete analysis check', { runId, error: checkError.message });
    }
  }
}

let analysisQueueTimer = null;
let analysisQueueDrainScheduled = false;
let activeAnalysisWorkers = 0;

function analysisQueueConcurrency() {
  const parsed = Number(process.env.ANALYSIS_QUEUE_CONCURRENCY || 1);
  const requested = Number.isFinite(parsed) && parsed >= 1 ? Math.floor(parsed) : 1;
  const poolMax = Number(pool.options?.max || 20);
  // Each scan retains a session lease. Leave connections for persistence and API work.
  const leaseCapacity = Math.max(0, Math.floor(poolMax) - 2);
  return Math.min(requested, leaseCapacity);
}

function analysisQueueStaleMinutes() {
  const parsed = Number(process.env.ANALYSIS_QUEUE_STALE_MINUTES || 20);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 20;
}

async function processQueuedAnalysisRun() {
  const payload = await analysisRunsDb.claimNextQueuedRun(analysisQueueStaleMinutes());
  if (!payload) {
    return { processed: false };
  }

  logger.info('Claimed queued analysis run', {
    runId: payload.analysis_run_id,
    repositoryId: payload.repository_id,
    prNumber: payload.pull_request_number,
  });

  try {
    await runAnalysisJob(payload);
    return { processed: true, runId: payload.analysis_run_id };
  } finally {
    await payload.releaseLease?.();
  }
}

function drainAnalysisQueue() {
  const concurrency = analysisQueueConcurrency();

  while (activeAnalysisWorkers < concurrency) {
    activeAnalysisWorkers += 1;
    let shouldContinue = false;

    processQueuedAnalysisRun()
      .then((result) => {
        shouldContinue = result.processed;
      })
      .catch((error) => {
        logger.error('Analysis queue worker failed', { error: error.message });
      })
      .finally(() => {
        activeAnalysisWorkers -= 1;
        if (shouldContinue) {
          notifyAnalysisQueued();
        }
      });
  }
}

function notifyAnalysisQueued() {
  if (analysisQueueDrainScheduled) return;

  analysisQueueDrainScheduled = true;
  setImmediate(() => {
    analysisQueueDrainScheduled = false;
    drainAnalysisQueue();
  });
}

function startAnalysisQueueWorker(intervalMs = Number(process.env.ANALYSIS_QUEUE_POLL_INTERVAL_MS || 5000)) {
  if (analysisQueueTimer) return analysisQueueTimer;

  const safeIntervalMs = Number.isFinite(intervalMs) && intervalMs > 0 ? intervalMs : 5000;
  logger.info('Analysis queue worker started', {
    intervalMs: safeIntervalMs,
    concurrency: analysisQueueConcurrency(),
    staleAfterMinutes: analysisQueueStaleMinutes(),
  });

  notifyAnalysisQueued();
  analysisQueueTimer = setInterval(notifyAnalysisQueued, safeIntervalMs);
  return analysisQueueTimer;
}

function triggerAnalysisJob(payload) {
  setImmediate(() => {
    runAnalysisJob(payload).catch((error) => {
      logger.error('Unhandled analysis background failure', {
        runId: payload.analysis_run_id,
        error: error.message,
      });
    });
  });
}

module.exports = {
  callAnalysisTier,
  triggerAnalysisJob,
  notifyAnalysisQueued,
  processQueuedAnalysisRun,
  startAnalysisQueueWorker,
  __private: {
    buildReviewBody,
    buildReviewComment,
    buildTier2FilePayload,
    compareReviewComments,
    didTier3MeaningfullyChangeFindings,
    enrichFilesForTier2,
    fileExtension,
    githubServiceRequest,
    hasTier3RenderableSuggestions,
    isTransientInfrastructureError,
    transientRetryDelayMs,
    MAX_AUTOMATIC_ANALYSIS_RETRIES,
    buildSurfaceDecisions,
    countTestCodeFiles,
    explainInlineCommentDecision,
    isInfoFinding,
    isTestCodePath,
    normalizeSuggestionPatch,
    planInlineComments,
    prioritizeReviewComments,
    severityIcon,
    summarizeFindings,
    shouldFetchFullFileContent,
    shouldPostInlineComment,
    shouldRenderSuggestion,
    validateSuggestedFix,
  },
};
