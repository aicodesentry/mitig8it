/**
 * A file the scanner could only parse partially must not cost the whole run.
 *
 * The analysis service reports such a file as a limitation instead of failing
 * the tier. The orchestrator persists those limitations on the analysis run and
 * states them in the check run summary and the review comment, and the check
 * stays green when a limitation is the only thing out of the ordinary.
 */
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
  markBaselineSet: jest.fn(),
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
  analysis_run_id: 'run-limitation-1',
  repository_id: 'repo1',
  repository_full_name: 'owner/repo',
  installation_id: 1,
  pull_request_id: 'pr1',
  pull_request_number: 135,
  commit_sha: 'sha1',
  baseline_set: true,
};

const calls = (part) => axios.post.mock.calls.filter(([url]) => url.includes(part));
const drain = () => new Promise((resolve) => setTimeout(resolve, 40));

const LEXICAL_LIMITATION = {
  path: 'services/cwe-vul.py',
  kind: 'partial_parse',
  type: 'Lexical error',
  message: 'Lexical error at line services/cwe-vul.py:127:\n unrecognized symbol in string',
  line: 127,
};

const FINDING = {
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

const FILES = {
  'services/orders.js': '@@ -0,0 +1 @@\n+db.query("SELECT * FROM o WHERE id = " + req.query.id)',
  'services/cwe-vul.py': '@@ -0,0 +1 @@\n+import os',
};

function mockRun({ findings = [], limitations = [] } = {}) {
  const filePaths = Object.keys(FILES);
  axios.post.mockImplementation(async (url) => {
    if (url.includes('/pulls/files')) {
      return { data: { files: filePaths.map((path) => ({ path, patch: FILES[path], additions: 1 })) } };
    }
    if (url.includes('/files/content')) {
      return { data: { files: filePaths.map((path) => ({ path, content: FILES[path].split('\n')[1].slice(1) })) } };
    }
    if (url.includes('/tier1')) return { data: { findings: [], analysis_limitations: [] } };
    if (url.includes('/tier2')) return { data: { findings, analysis_limitations: limitations } };
    // Tier 3 triages what the earlier tiers produced; it reports no limitations.
    if (url.includes('/tier3')) return { data: { findings } };
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

describe('scanner limitations reach the check run and the review', () => {
  test('a partial parse is stated in the check summary and does not fail the check', async () => {
    mockRun({ limitations: [LEXICAL_LIMITATION] });

    triggerAnalysisJob(payload);
    await drain();

    const checkRuns = calls('/check-runs');
    expect(checkRuns).toHaveLength(1);
    expect(checkRuns[0][1].conclusion).toBe('success');
    expect(checkRuns[0][1].title).toBe('No blocking security findings');
    expect(checkRuns[0][1].summary).toContain('1 file partially analysed: cwe-vul.py (lexical error at line 127)');
  });

  test('the findings from the other files survive the limitation', async () => {
    mockRun({ findings: [FINDING], limitations: [LEXICAL_LIMITATION] });

    triggerAnalysisJob(payload);
    await drain();

    const checkRuns = calls('/check-runs');
    expect(checkRuns[0][1].conclusion).toBe('failure');
    expect(checkRuns[0][1].summary).toContain('1 runtime finding');
    expect(checkRuns[0][1].summary).toContain('1 file partially analysed: cwe-vul.py (lexical error at line 127)');
  });

  test('the review summary comment carries the same line', async () => {
    mockRun({ findings: [FINDING], limitations: [LEXICAL_LIMITATION] });

    triggerAnalysisJob(payload);
    await drain();

    const reviews = calls('/reviews/submit');
    expect(reviews).toHaveLength(1);
    expect(reviews[0][1].body).toContain('1 file partially analysed: cwe-vul.py (lexical error at line 127)');
  });

  test('the limitations are persisted on the analysis run', async () => {
    mockRun({ findings: [FINDING], limitations: [LEXICAL_LIMITATION] });

    triggerAnalysisJob(payload);
    await drain();

    expect(runs.markCompleted).toHaveBeenCalledWith('run-limitation-1', expect.objectContaining({
      limitations: [{
        path: 'services/cwe-vul.py',
        kind: 'partial_parse',
        type: 'Lexical error',
        message: LEXICAL_LIMITATION.message,
        line: 127,
      }],
    }));
  });

  test('a clean run persists an empty limitation list and says nothing extra', async () => {
    mockRun({ findings: [FINDING] });

    triggerAnalysisJob(payload);
    await drain();

    expect(runs.markCompleted).toHaveBeenCalledWith('run-limitation-1', expect.objectContaining({ limitations: [] }));
    expect(calls('/check-runs')[0][1].summary).not.toContain('partially analysed');
    expect(calls('/reviews/submit')[0][1].body).not.toContain('partially analysed');
  });
});

describe('limitation rendering', () => {
  const { buildLimitationSummaryLine, normalizeLimitations, buildReviewBody } = __private;

  test('a timeout reads as a file that was not fully analysed', () => {
    const line = buildLimitationSummaryLine([
      { path: 'services/huge.ts', kind: 'not_analyzed', type: 'Timeout', message: 'timed out', line: null },
    ]);
    expect(line).toBe('1 file not fully analysed: huge.ts (timeout).');
  });

  test('partial parses and skipped files are reported separately', () => {
    const line = buildLimitationSummaryLine([
      { path: 'a/one.py', kind: 'partial_parse', type: 'Lexical error', line: 12 },
      { path: 'b/two.py', kind: 'partial_parse', type: 'Syntax error', line: 3 },
      { path: 'c/three.ts', kind: 'not_analyzed', type: 'Out of memory' },
    ]);
    expect(line).toBe(
      '2 files partially analysed: one.py (lexical error at line 12), two.py (syntax error at line 3); '
      + '1 file not fully analysed: three.ts (out of memory).'
    );
  });

  test('nothing is rendered when there are no limitations', () => {
    expect(buildLimitationSummaryLine([])).toBe('');
    expect(buildLimitationSummaryLine(undefined)).toBe('');
    expect(buildLimitationSummaryLine(null)).toBe('');
  });

  test('malformed entries are dropped and duplicates collapse', () => {
    expect(normalizeLimitations([
      null,
      'nonsense',
      { kind: 'partial_parse' },
      { path: 'a.py', kind: 'partial_parse', type: 'Lexical error', line: 5 },
      { path: 'a.py', kind: 'partial_parse', type: 'Lexical error', line: 5 },
      { path: 'a.py', kind: 'not_analyzed', type: 'Timeout' },
    ])).toEqual([
      { path: 'a.py', kind: 'partial_parse', type: 'Lexical error', message: '', line: 5 },
      { path: 'a.py', kind: 'not_analyzed', type: 'Timeout', message: '', line: null },
    ]);
  });

  test('an unrecognised kind is reported as a file that was not fully analysed', () => {
    expect(normalizeLimitations([{ path: 'a.py', kind: 'something-new', type: 'Whatever' }])[0].kind)
      .toBe('not_analyzed');
  });

  test('the clean review body still states the limitation', () => {
    const body = buildReviewBody([], 'run-abcdef12', { limitations: [LEXICAL_LIMITATION] });
    expect(body).toContain('No security issues found');
    expect(body).toContain('1 file partially analysed: cwe-vul.py (lexical error at line 127)');
  });
});
