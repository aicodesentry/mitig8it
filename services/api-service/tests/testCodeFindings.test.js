jest.mock('axios', () => ({ post: jest.fn() }));
jest.mock('../src/db/findings', () => ({
  findByFingerprint: jest.fn().mockResolvedValue(null),
  upsert: jest.fn(),
  markFixed: jest.fn(),
  getActiveSuppressions: jest.fn().mockResolvedValue([]),
  mergeEvidenceDetails: jest.fn(),
  snapshotRun: jest.fn(),
}));
jest.mock('../src/db/analysisRuns', () => ({
  countCompletedRuns: jest.fn().mockResolvedValue(1),
  markCompleted: jest.fn(),
  markFailed: jest.fn(),
}));
jest.mock('../src/db/repositories', () => ({
  getProfile: jest.fn().mockResolvedValue({ profile_status: 'ready', profile_data: {} }),
}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const axios = require('axios');
const findingsDb = require('../src/db/findings');
const runs = require('../src/db/analysisRuns');
const { triggerAnalysisJob, __private } = require('../src/services/prAnalysisOrchestrator');

const payload = {
  analysis_run_id: 'run-info-1',
  repository_id: 'repo1',
  repository_full_name: 'owner/repo',
  installation_id: 1,
  pull_request_id: 'pr1',
  pull_request_number: 1,
  commit_sha: 'sha1',
  baseline_set: true,
};

const calls = (part) => axios.post.mock.calls.filter(([url]) => url.includes(part));
const drain = () => new Promise((resolve) => setTimeout(resolve, 40));

const RUNTIME_FINDING = {
  fingerprint: 'fp-runtime',
  severity: 'critical',
  confidence: 0.95,
  title: 'SQL injection',
  rule_id: 'sql.injection',
  category: 'SQL injection',
  description: 'Raw query built from request input',
  evidence: 'Raw query built from request input',
  file_path: 'services/orders.js',
  line_start: 1,
  line_end: 1,
  code_snippet: 'db.query("SELECT * FROM o WHERE id = " + req.query.id)',
  analysis_scope: 'pattern',
};

const TEST_CODE_FINDING = {
  fingerprint: 'fp-test',
  severity: 'info',
  original_severity: 'critical',
  confidence: 0.95,
  title: 'Hardcoded credential',
  rule_id: 'secrets.hardcoded',
  category: 'secrets',
  description: 'Hardcoded credential in test fixture',
  evidence: 'Hardcoded credential in test fixture',
  file_path: 'test_security.py',
  line_start: 1,
  line_end: 1,
  code_snippet: 'password = "hunter2"',
  analysis_scope: 'pattern',
  evidence_details: { extra: { in_test_code: true, original_severity: 'critical' } },
};

const FILES = {
  'services/orders.js': '@@ -0,0 +1 @@\n+db.query("SELECT * FROM o WHERE id = " + req.query.id)',
  'test_security.py': '@@ -0,0 +1 @@\n+password = "hunter2"',
};

function mockRun(tierFindings, filePaths) {
  axios.post.mockImplementation(async (url) => {
    if (url.includes('/pulls/files')) {
      return { data: { files: filePaths.map((path) => ({ path, patch: FILES[path], additions: 1 })) } };
    }
    if (url.includes('/files/content')) {
      return { data: { files: filePaths.map((path) => ({ path, content: FILES[path].split('\n')[1].slice(1) })) } };
    }
    if (url.includes('/tier')) return { data: { findings: tierFindings } };
    return { data: { review_id: 1, check_run_id: 1 } };
  });

  findingsDb.upsert.mockImplementation(async (row) => ({
    id: row.fingerprint,
    fingerprint: row.fingerprint,
    status: 'open',
    is_baseline: false,
    severity: row.severity,
    confidence: row.confidence,
    title: row.title,
    rule_id: row.ruleId,
    category: row.category,
    description: row.description,
    evidence: row.evidence,
    file_path: row.filePath,
    line_start: row.lineStart,
    line_end: row.lineEnd,
    code_snippet: row.codeSnippet,
    analysis_scope: row.analysisScope,
    evidence_details: row.evidenceDetails,
    remediation: row.remediation,
    remediation_patch: row.remediationPatch,
  }));
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.INTERNAL_SERVICE_TRANSPORT = 'http';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-secret';
  findingsDb.findByFingerprint.mockResolvedValue(null);
});

describe('test-code findings are informational', () => {
  test('a run with only informational findings still concludes success', async () => {
    mockRun([TEST_CODE_FINDING], ['test_security.py']);

    triggerAnalysisJob(payload);
    await drain();

    const checkRuns = calls('/check-runs');
    expect(checkRuns).toHaveLength(1);
    expect(checkRuns[0][1].conclusion).toBe('success');
    expect(checkRuns[0][1].title).toBe('No blocking security findings');
    expect(checkRuns[0][1].summary).toContain('1 test file scanned; 1 informational finding in test code, not posted.');
    expect(checkRuns[0][1].summary).toContain('0 runtime findings');
    expect(runs.markCompleted).toHaveBeenCalled();
  });

  // A comment on test code with no fix behind it is noise, so the run that finds nothing
  // else annotates nothing at all and says as much where the count is.
  test('a run with only informational findings posts no inline comment and says so', async () => {
    mockRun([TEST_CODE_FINDING], ['test_security.py']);

    triggerAnalysisJob(payload);
    await drain();

    expect(calls('/comments/inline')).toHaveLength(0);
    expect(calls('/reviews/submit')[0][1].body).toContain('1 informational finding in test code, not posted.');
    expect(calls('/check-runs')[0][1].summary).toContain('1 informational finding in test code, not posted.');
  });

  // The comment an earlier version of this service posted for the same finding. The
  // finding is still open, so nothing marks it fixed and nothing else would remove it.
  test('the comment an earlier run posted for an informational finding is retired', async () => {
    mockRun([RUNTIME_FINDING, TEST_CODE_FINDING], ['services/orders.js', 'test_security.py']);

    triggerAnalysisJob(payload);
    await drain();

    const retire = calls('/comments/retire');
    expect(retire).toHaveLength(1);
    expect(retire[0][1].fingerprints).toEqual(['fp-test']);
    expect(retire[0][1].pr_number).toBe(1);
    // The runtime finding keeps its comment.
    expect(calls('/comments/inline').map(([, body]) => body.path)).toEqual(['services/orders.js']);
  });

  test('a run without informational findings retires nothing', async () => {
    mockRun([RUNTIME_FINDING], ['services/orders.js']);

    triggerAnalysisJob(payload);
    await drain();

    expect(calls('/comments/retire')).toHaveLength(0);
  });

  test('a runtime finding alongside informational findings fails the check', async () => {
    mockRun([RUNTIME_FINDING, TEST_CODE_FINDING], ['services/orders.js', 'test_security.py']);

    triggerAnalysisJob(payload);
    await drain();

    const checkRuns = calls('/check-runs');
    expect(checkRuns).toHaveLength(1);
    expect(checkRuns[0][1].conclusion).toBe('failure');
    expect(checkRuns[0][1].title).toBe('1 critical/high finding');
    expect(checkRuns[0][1].summary).toContain('1 runtime finding');
    expect(checkRuns[0][1].summary).toContain('1 informational finding in test code, not posted.');
    expect(calls('/reviews/submit')[0][1].event).toBe('REQUEST_CHANGES');
  });
});

describe('summary and comment rendering', () => {
  test('summarizeFindings counts the informational severity', () => {
    const { counts } = __private.summarizeFindings([
      { severity: 'info', category: 'secrets' },
      { severity: 'critical', category: 'SQL injection' },
    ]);

    expect(counts.info).toBe(1);
    expect(counts.critical).toBe(1);
  });

  test('the summary comment reports test files and informational findings', () => {
    const body = __private.buildReviewBody(
      [RUNTIME_FINDING, ...Array.from({ length: 16 }, (_, i) => ({ ...TEST_CODE_FINDING, fingerprint: `fp-${i}` }))],
      'run-uuid-1',
      { testFilesScanned: 3 }
    );

    expect(body).toContain('3 test files scanned; 16 informational findings in test code, not posted.');
    expect(body).toContain('Informational findings never block this check.');
    // The severity table counts runtime findings only.
    expect(body).toContain('Mitig8it — 1 finding detected');
  });

  test('a clean run with scanned test files still reports them', () => {
    const body = __private.buildReviewBody([], 'run-uuid-1', { testFilesScanned: 2 });

    expect(body).toContain('No security issues found');
    expect(body).toContain('2 test files scanned; 0 informational findings in test code, not posted.');
  });

  test('informational comments carry a marker and no red icon', () => {
    const body = __private.buildReviewComment(TEST_CODE_FINDING, { tierLabel: 'Tier 3' });

    expect(body).toContain('ℹ️');
    expect(body).toContain('INFORMATIONAL — TEST CODE');
    expect(body).toContain('scanner severity critical');
    expect(body).toContain('does not block this pull request');
    expect(body).not.toContain('🔴');
  });

  test('runtime comments are unchanged', () => {
    const body = __private.buildReviewComment(RUNTIME_FINDING, { tierLabel: 'Tier 3' });

    expect(body).toContain('🔴 **CRITICAL**');
    expect(body).not.toContain('INFORMATIONAL');
  });
});

describe('the inline comment gate and the cap', () => {
  const runtimeComment = (index) => ({
    path: `services/file${index}.js`,
    line: 1,
    severity: 'high',
    hasSuggestion: false,
    body: `runtime-${index}`,
  });

  // The one rule that keeps informational findings off the diff. Everything downstream
  // of it, the comparator and the cap, only ever sees runtime findings.
  test('the inline gate refuses an informational finding whatever its evidence', () => {
    const decision = __private.explainInlineCommentDecision({
      ...TEST_CODE_FINDING,
      status: 'open',
      confidence: 0.99,
      analysis_scope: 'pattern',
    });

    expect(decision).toEqual({ eligible: false, reason: 'informational_test_code' });
  });

  test('an informational finding is a summary-only surface decision, not an inline one', () => {
    const decisions = __private.buildSurfaceDecisions({
      files: [{ path: 'test_security.py', patch: FILES['test_security.py'] }],
      findings: [{ ...TEST_CODE_FINDING, id: 'finding-1', status: 'open' }],
    });

    expect(decisions).toEqual([{
      findingId: 'finding-1',
      surfaceDecision: 'summary_only',
      surfaceReason: 'informational_test_code',
    }]);
  });

  test('the cap reports how many runtime comments it left out', () => {
    const plan = __private.planInlineComments(Array.from({ length: 48 }, (_, i) => runtimeComment(i)));

    expect(plan.comments).toHaveLength(40);
    expect(plan.omitted).toBe(8);
  });

  test('nothing is omitted below the cap', () => {
    const plan = __private.planInlineComments([runtimeComment(1), runtimeComment(2)]);

    expect(plan.comments).toHaveLength(2);
    expect(plan.omitted).toBe(0);
  });
});

describe('test path detection', () => {
  test.each([
    'services/api-service/tests/orchestrator.test.js',
    'frontend/src/pages/__tests__/Page.test.jsx',
    'test_vuln.go',
    'widget.spec.ts',
  ])('%s is test code', (path) => {
    expect(__private.isTestCodePath(path)).toBe(true);
  });

  test.each(['services/orders.js', 'main.py', 'util/format.js'])('%s is runtime code', (path) => {
    expect(__private.isTestCodePath(path)).toBe(false);
  });

  test('counts distinct test files from the PR file list', () => {
    expect(__private.countTestCodeFiles([
      { path: 'test_vuln.go' },
      { path: 'test_security.py' },
      { path: 'services/orders.js' },
    ])).toBe(2);
  });

  test('isInfoFinding recognises both the severity and the scanner marker', () => {
    expect(__private.isInfoFinding({ severity: 'info' })).toBe(true);
    expect(__private.isInfoFinding({ severity: 'critical', evidence_details: { extra: { in_test_code: true } } })).toBe(true);
    expect(__private.isInfoFinding({ severity: 'critical' })).toBe(false);
  });
});
