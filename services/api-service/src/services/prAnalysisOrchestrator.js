const { pool } = require('../config/database');
const axios = require('axios');
const logger = require('../utils/logger');
const requestContext = require('../utils/requestContext');
const analysisMetrics = require('./analysisMetrics');
const { AnalysisGrpcClient } = require('../clients/analysisGrpcClient');
const { GitHubGrpcClient } = require('../clients/githubGrpcClient');
const { calculateFingerprint, normalizeFinding } = require('./findingUtils');
const { validateSuggestedFix, __private: validatorPrivate } = require('./suggestedFixValidator');
const findingsDb = require('../db/findings');
const analysisRunsDb = require('../db/analysisRuns');
const repositoriesDb = require('../db/repositories');
const remediationAutoGenerate = require('./remediationAutoGenerate');

// Mirrors CODE_EXTENSIONS and TEMPLATE_EXTENSIONS in
// services/analysis-service/src/opengrep_runner.py, and the same two sets in
// scripts/replay/prodfilters.py. Template files are scanned in the scanner's `generic`
// mode by template_coverage.yml, not by a language parser.
// services/analysis-service/src/tests/test_supported_extension_parity.py fails if the
// three copies disagree.
const TIER2_CODE_EXTENSIONS = [
  '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', '.rb', '.php',
  '.cs', '.c', '.cpp', '.h', '.hpp', '.rs', '.swift', '.kt',
];

const TIER2_TEMPLATE_EXTENSIONS = [
  '.html', '.htm', '.ejs', '.erb', '.hbs', '.handlebars', '.mustache',
  '.dust', '.njk', '.jinja', '.jinja2', '.j2', '.twig', '.vue', '.svelte', '.pug',
];

const TIER2_SUPPORTED_EXTENSIONS = new Set([
  ...TIER2_CODE_EXTENSIONS,
  ...TIER2_TEMPLATE_EXTENSIONS,
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

// The scanner reports a file it could only parse partially, or gave up on after
// a timeout, as a limitation rather than as a failed scan. Everything else in
// the pull request was analysed normally, so the run says which files were not
// and carries on. A limitation never turns the check run red on its own.
const LIMITATION_LABELS = {
  partial_parse: 'partially analysed',
  not_analyzed: 'not fully analysed',
};

function normalizeLimitations(limitations) {
  if (!Array.isArray(limitations)) return [];
  const byKey = new Map();
  for (const limitation of limitations) {
    if (!limitation || typeof limitation !== 'object') continue;
    const path = typeof limitation.path === 'string' ? limitation.path : '';
    if (!path) continue;
    const kind = LIMITATION_LABELS[limitation.kind] ? limitation.kind : 'not_analyzed';
    const key = `${path}::${kind}`;
    if (byKey.has(key)) continue;
    const line = Number(limitation.line);
    byKey.set(key, {
      path,
      kind,
      type: typeof limitation.type === 'string' ? limitation.type : '',
      message: typeof limitation.message === 'string' ? limitation.message.slice(0, 200) : '',
      line: Number.isFinite(line) && line > 0 ? line : null,
    });
  }
  return [...byKey.values()];
}

// "cwe-vul.py (lexical error at line 127)" - enough for a reader to open the
// file and see why the scanner stopped there.
function describeLimitation(limitation) {
  const name = limitation.path.split('/').pop() || limitation.path;
  const reason = (limitation.type || LIMITATION_LABELS[limitation.kind]).toLowerCase();
  const detail = [reason, limitation.line ? `at line ${limitation.line}` : '']
    .filter(Boolean)
    .join(' ');
  return detail ? `${name} (${detail})` : name;
}

function buildLimitationSummaryLine(limitations) {
  const normalized = normalizeLimitations(limitations);
  if (normalized.length === 0) return '';

  const partial = normalized.filter((limitation) => limitation.kind === 'partial_parse');
  const skipped = normalized.filter((limitation) => limitation.kind !== 'partial_parse');
  const clauses = [];
  if (partial.length > 0) {
    clauses.push(
      `${partial.length} file${partial.length === 1 ? '' : 's'} partially analysed: `
      + partial.map(describeLimitation).join(', ')
    );
  }
  if (skipped.length > 0) {
    clauses.push(
      `${skipped.length} file${skipped.length === 1 ? '' : 's'} not fully analysed: `
      + skipped.map(describeLimitation).join(', ')
    );
  }
  return `${clauses.join('; ')}.`;
}

// Counted here, never annotated on the diff. The sentence says the findings were not
// posted so a reader is not left hunting for comments behind a count, and it is the
// sentence the Action prints for the same findings.
function buildTestCodeSummaryLines({ testFilesScanned, infoFindings }) {
  const lines = [];
  if (testFilesScanned <= 0 && infoFindings <= 0) return lines;

  lines.push(
    `${severityIcon('info')} ${testFilesScanned} test file${testFilesScanned === 1 ? '' : 's'} scanned; `
    + `${infoFindings} informational finding${infoFindings === 1 ? '' : 's'} in test code, not posted. `
    + 'Informational findings never block this check.'
  );
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
  });
  const limitationLine = buildLimitationSummaryLine(options.limitations);
  const limitationLines = limitationLine ? [`${severityIcon('info')} ${limitationLine}`, ''] : [];

  if (total === 0) {
    return [
      '<!-- mitig8it-review -->',
      '### 🛡️ Mitig8it — No security issues found',
      '',
      'This PR passed all security checks.',
      '',
      ...testCodeLines,
      ...limitationLines,
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
    ...limitationLines,
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
  // Nothing sends an informational finding here any more: `explainInlineCommentDecision`
  // refuses it before a comment is built. The branch stays because it is the wording this
  // product puts on a test-code finding, and a renderer that silently dressed one up as
  // blocking would be a worse thing to leave behind than an unreached branch.
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

// `.mitig8it.yml` in the repository under review. Reading it here, before the files reach any
// scanner, is what makes an exclusion mean "never analysed" rather than "analysed and hidden".
const repositoryConfig = require('./repositoryConfig');

// The file lives at the repository root of the head commit. It is fetched through the same
// content path the tier 2 enrichment uses, and an absent file is the common case rather than an
// error: `fetchFileContents` simply returns nothing for it.
async function loadRepositoryExclusions({ repositoryFullName, installationId, commitSha }) {
  let text = null;
  try {
    const response = await githubServiceRequest('/internal/github/files/content', {
      repository_full_name: repositoryFullName,
      installation_id: installationId,
      ref: commitSha,
      paths: [repositoryConfig.CONFIG_FILENAME],
    });
    for (const file of response?.files || []) {
      if (file?.path === repositoryConfig.CONFIG_FILENAME && typeof file.content === 'string') text = file.content;
    }
  } catch (_error) {
    // A repository that has no such file, or a content read that failed, reviews everything. It
    // is the safe direction: the alternative is a run that silently reviewed nothing.
    return { exclusions: new repositoryConfig.Exclusions(), problem: null };
  }
  if (text === null) return { exclusions: new repositoryConfig.Exclusions(), problem: null };
  try {
    return { exclusions: repositoryConfig.parse(text), problem: null };
  } catch (error) {
    return { exclusions: new repositoryConfig.Exclusions(), problem: `${error.message}; nothing was excluded` };
  }
}

// { kept, excluded } over the changed-file entries the adapter returned.
function applyExclusions(files, exclusions) {
  const source = Array.isArray(files) ? files : [];
  if (!exclusions || exclusions.empty) return { kept: source, excluded: [] };
  const kept = [];
  const excluded = [];
  for (const file of source) {
    if (exclusions.matches(String(file?.path || ''))) excluded.push(file);
    else kept.push(file);
  }
  return { kept, excluded };
}

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

// Every comment that reaches this comparator is a runtime finding's: an informational
// finding is refused inline by `explainInlineCommentDecision` and never becomes one. The
// informational tie-break that used to lead this function went with it.
function compareReviewComments(a, b) {
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

  // A finding in test code is never annotated on the diff, whatever its evidence. It is
  // reported as a count in the check summary and the review body, which say it was not
  // posted. One self-review put eighteen of them across `services/*/tests` on a pull
  // request whose point was three runtime findings, and they were what a reader had to
  // dig through to reach them. A comment on test code with no fix behind it is noise.
  if (isInfoFinding(finding)) {
    return { eligible: false, reason: 'informational_test_code' };
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

    // Decided before the diff is consulted, because being informational is why this
    // finding is not annotated; whether its line happens to be reviewable is not.
    if (isInfoFinding(finding)) {
      return {
        findingId,
        surfaceDecision: 'summary_only',
        surfaceReason: 'informational_test_code',
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
      '/internal/github/comments/retire': () => client.retireInlineComments(payload),
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
    headers: { 'x-internal-secret': internalSecret, ...requestContext.toHeaders() },
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

// The comments one review may carry, in priority order, and how many the cap left out.
// All of them are runtime findings' now, so the cap costs a runtime comment whenever it
// bites and the run says so in the log.
function planInlineComments(reviewComments, cap = INLINE_COMMENT_CAP) {
  const deduped = dedupeInlineComments(prioritizeReviewComments(reviewComments));

  return {
    comments: deduped.slice(0, cap),
    omitted: Math.max(0, deduped.length - cap),
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

// An informational finding is still open and still reported, so nothing marks it fixed
// and nothing else retires the comment an earlier version of this service left on the
// diff for it. This does, by fingerprint, on every run: the finding is not annotated any
// more, so neither is the pull request left carrying a comment that says it is.
//
// Housekeeping never fails a review that published. A failure is logged and the next
// analysis of the pull request tries again.
async function retireInformationalComments({ owner, repo, prNumber, installationId, findings, runId, tierLabel }) {
  const fingerprints = (findings || [])
    .filter(isInfoFinding)
    .map((finding) => finding.fingerprint)
    .filter(Boolean);
  if (fingerprints.length === 0) return { retired: 0, kept: 0 };

  try {
    const result = await githubServiceRequest('/internal/github/comments/retire', {
      owner,
      repo,
      pr_number: prNumber,
      installation_id: installationId,
      fingerprints,
    });
    logger.info(`${tierLabel}: informational inline comments retired`, {
      runId,
      prNumber,
      candidates: fingerprints.length,
      retired: Number(result?.retired || 0),
      kept: Number(result?.kept || 0),
    });
    return result;
  } catch (error) {
    logger.warn('Failed to retire informational inline comments', {
      runId,
      prNumber,
      candidates: fingerprints.length,
      error: error.message,
    });
    return { retired: 0, kept: 0 };
  }
}

function analysisServiceHeaders() {
  const internalSecret =
    process.env.ANALYSIS_SERVICE_INTERNAL_SECRET || process.env.GITHUB_SERVICE_INTERNAL_SECRET;

  if (!internalSecret) {
    throw new Error('Missing ANALYSIS_SERVICE_INTERNAL_SECRET or GITHUB_SERVICE_INTERNAL_SECRET');
  }

  return {
    'x-internal-secret': internalSecret,
    ...requestContext.toHeaders(),
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
  await findingsDb.markFixed({
    repositoryId, pullRequestId, activeFingerprints, analysisRunId: runId, commitSha,
  });

  const postSuppression = await applySuppressions(persisted, repositoryId);
  await persistSurfaceDecisions(buildSurfaceDecisions({ files, findings: postSuppression }));
  const actionable = postSuppression.filter((f) => f.status === 'open' && !f.is_baseline);

  return { actionable, shouldMarkBaselineSet, findingRows: postSuppression };
}

async function postReviewToGitHub({ actionable, files, owner, repo, prNumber, installationId, commitSha, runId, tierLabel, repoProfile, limitations }) {
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
    if (inlinePlan.omitted > 0) {
      logger.info(`${tierLabel}: inline comment cap reached`, {
        runId,
        prNumber,
        cap: INLINE_COMMENT_CAP,
        omitted: inlinePlan.omitted,
      });
    }

    const reviewBody = buildReviewBody(actionable, runId, {
      testFilesScanned,
      inlineCount: inlinePlan.comments.length,
      limitations,
    });

    reviewResp = await submitReviewWithFallback({
      owner, repo, prNumber, installationId, commitSha,
      reviewBody,
      event: highOrCritical > 0 ? 'REQUEST_CHANGES' : 'COMMENT',
    });

    const inlineResult = await postInlineCommentsIndividually({
      owner, repo, prNumber, installationId, commitSha, reviewComments, runId,
    });

    await retireInformationalComments({
      owner, repo, prNumber, installationId, findings: actionable, runId, tierLabel,
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

// A metric label must come from a closed set. `triggered_by` is written by our own
// inserts today, but a future value must degrade to one extra series, not to one
// series per value anyone ever writes.
const KNOWN_TRIGGERS = new Set(['webhook', 'auto_retry', 'manual', 'api']);

function triggerLabel(payload) {
  const trigger = String(payload?.triggered_by || 'unknown');
  return KNOWN_TRIGGERS.has(trigger) ? trigger : 'other';
}

// The reason an operator acts on, not the message they would have to read. Each value
// points at a different owner: our analysis tiers, GitHub, the network, or a bug.
function failureReason(error, { analysisResultProduced }) {
  const message = String(error?.message || '');
  if (message.startsWith('Incomplete analysis response')) return 'analysis_incomplete';
  if (message.startsWith('Invalid GitHub file response')) return 'github_files_invalid';
  if (message.startsWith('Inline finding publication incomplete')) return 'publication_incomplete';
  if (isTransientInfrastructureError(error)) return 'infrastructure';
  return analysisResultProduced ? 'publication_failed' : 'unhandled';
}

function observeFindingsPosted(counts = {}) {
  for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
    const count = Number(counts[severity] || 0);
    if (count > 0) analysisMetrics.findingsPosted.labels(severity).inc(count);
  }
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
  const startedAt = process.hrtime.bigint();
  const elapsedSeconds = () => Number(process.hrtime.bigint() - startedAt) / 1e9;
  analysisMetrics.runsStarted.labels(triggerLabel(payload)).inc();

  let allFindings = [];
  let files = [];
  let excludedFileCount = 0;
  // Limitations the run must state rather than hide. `file_cap`: a pull request over the
  // adapter's cap is reviewed as far as the cap allows, and the check summary says how many of
  // how many files that was. `path_exclusion`: the repository's own `.mitig8it.yml` kept files
  // out of the analysis, and the summary says how many, so silence about a directory is never
  // mistaken for a clean bill of health.
  let analysisLimitations = [];
  let tier2Files = [];
  let lastCounts = {};
  let lastHighOrCritical = 0;
  let testFilesScanned = 0;
  let limitations = [];
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
    if (filesResp.limitation?.message) {
      analysisLimitations = [filesResp.limitation];
      logger.warn('Analysis run is limited', {
        runId, kind: filesResp.limitation.kind, message: filesResp.limitation.message,
      });
    }

    // Excluded before enrichment, so the content of an excluded file is never even fetched.
    const { exclusions, problem: configProblem } = await loadRepositoryExclusions({
      repositoryFullName, installationId, commitSha,
    });
    if (configProblem) logger.warn('Repository configuration was not used', { runId, message: configProblem });
    const exclusionResult = applyExclusions(files, exclusions);
    excludedFileCount = exclusionResult.excluded.length;
    files = exclusionResult.kept;
    const exclusionLimitation = repositoryConfig.exclusionLimitation(excludedFileCount);
    if (exclusionLimitation) {
      analysisLimitations = [...analysisLimitations, exclusionLimitation];
      logger.info('Paths were excluded by repository configuration', {
        runId, excluded: excludedFileCount,
      });
    }
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
    // A file the scanner could only parse partially is a gap in coverage, not a
    // failed scan. The run reports it instead of implying complete analysis.
    limitations = normalizeLimitations([
      ...(tier1.analysis_limitations || []),
      ...(tier2.analysis_limitations || []),
    ]);
    if (limitations.length > 0) {
      logger.warn('Analysis reported coverage limitations', { runId, prNumber, limitations });
    }
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
      tierLabel: 'Tier 3', repoProfile, limitations,
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
          + `${infoCount} informational finding${infoCount === 1 ? '' : 's'} in test code, not posted.`
        );
      }
      // A limitation is a coverage note, never a reason to fail the check. Two disjoint
      // sources reach the summary. `analysisLimitations` is run-scoped and carries no
      // path: a pull request over the adapter's file cap is reviewed as far as the cap
      // allows, and the summary says how many of how many files that was. `limitations`
      // is per file: the scanner could not fully read one file, or hit a ceiling on it.
      // A partial review says so on the check itself, because reporting a clean result
      // on a pull request the run only partly read would be the dishonest outcome.
      for (const limitation of analysisLimitations) summaryLines.push(`${limitation.message}.`);
      const limitationLine = buildLimitationSummaryLine(limitations);
      if (limitationLine) summaryLines.push(limitationLine);
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
      limitations,
    });

    analysisMetrics.runsCompleted.inc();
    analysisMetrics.runDuration.labels('completed').observe(elapsedSeconds());
    observeFindingsPosted(lastCounts);

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
        // Counted apart from a terminal failure. The review has not failed for the
        // author yet, and the failure-ratio alert must not fire on work that is
        // still on its way to succeeding.
        analysisMetrics.runsFailed.labels('transient_retried').inc();
        analysisMetrics.runDuration.labels('retried').observe(elapsedSeconds());
        // The queue poller picks the retry up once not_before elapses.
        return;
      } catch (requeueError) {
        logger.error('Failed to re-queue a transient analysis failure', {
          runId, repositoryId, error: requeueError.message,
        });
      }
    }

    const reason = failureReason(error, { analysisResultProduced });
    analysisMetrics.runsFailed.labels(reason).inc();
    analysisMetrics.runDuration.labels('failed').observe(elapsedSeconds());
    logger.error('PR analysis orchestration failed', {
      runId, repositoryId, reason, error: error.message, automaticRetries: priorRetries,
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
let analysisQueueGaugeTimer = null;
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

  // The queue breaks the request scope: the process that claims a run is usually not
  // the one that took the webhook. Re-establishing the context from the row is what
  // keeps a review's logs joined to the delivery that asked for it.
  return requestContext.runWith(
    { delivery_id: payload.delivery_id, analysis_run_id: payload.analysis_run_id },
    async () => {
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
  );
}

// The queue gauges the stall alert reads. Observed on its own slow cadence rather than
// on the poll interval: one extra aggregate query a minute, not one every five seconds.
async function observeAnalysisQueue() {
  try {
    analysisMetrics.observeQueue(await analysisRunsDb.getQueueStats());
  } catch (error) {
    // A gauge that cannot be refreshed goes stale; it must never stop the workers.
    logger.warn('Analysis queue gauge refresh failed', { error: error.message });
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

  observeAnalysisQueue();
  const gaugeIntervalMs = Number(process.env.ANALYSIS_QUEUE_GAUGE_INTERVAL_MS || 60000);
  analysisQueueGaugeTimer = setInterval(
    observeAnalysisQueue,
    Number.isFinite(gaugeIntervalMs) && gaugeIntervalMs > 0 ? gaugeIntervalMs : 60000
  );
  if (typeof analysisQueueGaugeTimer.unref === 'function') analysisQueueGaugeTimer.unref();

  return analysisQueueTimer;
}

function triggerAnalysisJob(payload) {
  // The context is captured here, where the caller's is still in scope, so the
  // background run logs under the delivery that triggered it.
  const inherited = { delivery_id: payload.delivery_id, analysis_run_id: payload.analysis_run_id };
  setImmediate(() => {
    requestContext.runWith(inherited, () => runAnalysisJob(payload)).catch((error) => {
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
  observeAnalysisQueue,
  processQueuedAnalysisRun,
  startAnalysisQueueWorker,
  __private: {
    applyExclusions,
    loadRepositoryExclusions,
    buildLimitationSummaryLine,
    failureReason,
    observeFindingsPosted,
    triggerLabel,
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
    normalizeLimitations,
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
