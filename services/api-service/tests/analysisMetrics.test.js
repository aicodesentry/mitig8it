const axios = require('axios');

jest.mock('axios');
jest.mock('../src/db/repositories', () => ({
  getProfile: jest.fn().mockResolvedValue({ profile_status: 'ready', profile_data: {} }),
  queueUrgentProfiling: jest.fn(),
}));
jest.mock('../src/config/database', () => ({
  pool: { query: jest.fn() },
  transaction: jest.fn(),
}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), error: jest.fn(), warn: jest.fn() }));
jest.mock('../src/services/remediationAutoGenerate', () => ({
  enqueueForCompletedAnalysis: jest.fn(async () => ({ enqueued: false, reason: 'generate_disabled' })),
  republishInlineFixesForCompletedAnalysis: jest.fn(async () => ({ republished: 0 })),
}));

const { pool } = require('../src/config/database');
const analysisMetrics = require('../src/services/analysisMetrics');

const BASE_PAYLOAD = {
  analysis_run_id: 'run-uuid-1',
  repository_id: 'repo-uuid-1',
  repository_full_name: 'owner/repo',
  installation_id: 12345,
  pull_request_id: 'pr-uuid-1',
  pull_request_number: 42,
  commit_sha: 'abc123def456',
  baseline_set: true,
  triggered_by: 'webhook',
};

function flushAsync() {
  return new Promise((resolve) => setTimeout(resolve, 300));
}

function setupAxiosMocks(routes) {
  axios.post.mockImplementation((url) => {
    for (const route of routes) {
      if (url.includes(route.pattern)) {
        if (route.error) return Promise.reject(route.error);
        return Promise.resolve({ data: route.data });
      }
    }
    return Promise.resolve({ data: {} });
  });
}

// prom-client counters are process-global, so every assertion is a delta rather than
// an absolute: a test that asserted an absolute value would pass or fail depending on
// which other test ran first.
async function counterValue(metric, labels = {}) {
  const collected = await metric.get();
  const match = collected.values.find((value) =>
    Object.entries(labels).every(([key, expected]) => value.labels[key] === expected));
  return match ? match.value : 0;
}

async function gaugeValue(metric) {
  const collected = await metric.get();
  return collected.values[0] ? collected.values[0].value : 0;
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.GITHUB_SERVICE_URL = 'http://github-service:3002';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-secret';
  process.env.ANALYSIS_SERVICE_URL = 'http://analysis-service:8001';
  delete process.env.INTERNAL_SERVICE_TRANSPORT;
});

describe('analysis run metrics', () => {
  test('findings posted is counted per severity from the published review counts', async () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');
    const highBefore = await counterValue(analysisMetrics.findingsPosted, { severity: 'high' });
    const lowBefore = await counterValue(analysisMetrics.findingsPosted, { severity: 'low' });

    __private.observeFindingsPosted({ critical: 0, high: 2, medium: 0, low: 1 });

    expect(await counterValue(analysisMetrics.findingsPosted, { severity: 'high' })).toBe(highBefore + 2);
    expect(await counterValue(analysisMetrics.findingsPosted, { severity: 'low' })).toBe(lowBefore + 1);
    // A severity with no findings must not create a series that reads as a real zero.
    expect(await counterValue(analysisMetrics.findingsPosted, { severity: 'critical' })).toBe(0);
  });

  test('a completed run moves started and completed', async () => {
    const startedBefore = await counterValue(analysisMetrics.runsStarted, { trigger: 'webhook' });
    const completedBefore = await counterValue(analysisMetrics.runsCompleted);

    setupAxiosMocks([
      { pattern: '/pulls/files', data: { files: [{ path: 'src/app.js', patch: '@@ -1 +1 @@\n+eval(x)', additions: 1, deletions: 0, status: 'modified', content: 'eval(x)\n' }] } },
      { pattern: '/files/content', data: { files: [{ path: 'src/app.js', content: 'eval(x)\n' }] } },
      { pattern: '/tier1', data: { findings: [] } },
      { pattern: '/tier2', data: { findings: [] } },
      {
        pattern: '/tier3',
        data: {
          findings: [{
            rule_id: 'code.injection.eval',
            internal_type: 'code_injection',
            title: 'Code injection via eval',
            severity: 'high',
            confidence: 0.9,
            file_path: 'src/app.js',
            line_start: 1,
            evidence: 'eval(x)',
            remediation: 'Do not eval user input.',
          }],
        },
      },
      { pattern: '/reviews/submit', data: { review_id: 77 } },
      { pattern: '/check-runs', data: { check_run_id: 88 } },
    ]);
    pool.query.mockResolvedValue({ rowCount: 1, rows: [{ count: 3, id: 'finding-1', fingerprint: 'fp-1', severity: 'high', status: 'open' }] });

    const { triggerAnalysisJob } = require('../src/services/prAnalysisOrchestrator');
    triggerAnalysisJob(BASE_PAYLOAD);
    await flushAsync();

    expect(await counterValue(analysisMetrics.runsStarted, { trigger: 'webhook' })).toBe(startedBefore + 1);
    expect(await counterValue(analysisMetrics.runsCompleted)).toBe(completedBefore + 1);
  });

  test('an unreachable GitHub service counts a failure under the infrastructure reason', async () => {
    const before = await counterValue(analysisMetrics.runsFailed, { reason: 'infrastructure' });

    axios.post.mockRejectedValue(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }));
    pool.query.mockResolvedValue({ rowCount: 1, rows: [] });

    const { triggerAnalysisJob } = require('../src/services/prAnalysisOrchestrator');
    // auto_retry_count at the cap so the run fails terminally instead of re-queueing.
    triggerAnalysisJob({ ...BASE_PAYLOAD, auto_retry_count: 99 });
    await flushAsync();

    expect(await counterValue(analysisMetrics.runsFailed, { reason: 'infrastructure' })).toBe(before + 1);
  });

  test('an unknown trigger degrades to one extra series rather than one per value', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');
    expect(__private.triggerLabel({ triggered_by: 'webhook' })).toBe('webhook');
    expect(__private.triggerLabel({ triggered_by: 'something-new' })).toBe('other');
    expect(__private.triggerLabel({})).toBe('other');
  });

  test('failure reasons name an owner rather than repeating the message', () => {
    const { __private } = require('../src/services/prAnalysisOrchestrator');
    expect(__private.failureReason(new Error('Incomplete analysis response: /analyze/pr/tier1'), {}))
      .toBe('analysis_incomplete');
    expect(__private.failureReason(new Error('Invalid GitHub file response'), {}))
      .toBe('github_files_invalid');
    expect(__private.failureReason(Object.assign(new Error('boom'), { code: 'ECONNRESET' }), {}))
      .toBe('infrastructure');
    expect(__private.failureReason(new Error('anything else'), { analysisResultProduced: true }))
      .toBe('publication_failed');
    expect(__private.failureReason(new Error('anything else'), { analysisResultProduced: false }))
      .toBe('unhandled');
  });
});

describe('analysis queue stall gauge', () => {
  test('a backlog with no recent start is stalled', async () => {
    const stalled = analysisMetrics.observeQueue({
      pending: 2, running: 0, oldest_pending_seconds: 900, seconds_since_last_start: 1200,
    });
    expect(stalled).toBe(true);
    expect(await gaugeValue(analysisMetrics.runsStalled)).toBe(1);
  });

  test('a backlog that is being worked through is not stalled', async () => {
    const stalled = analysisMetrics.observeQueue({
      pending: 40, running: 4, oldest_pending_seconds: 900, seconds_since_last_start: 30,
    });
    expect(stalled).toBe(false);
    expect(await gaugeValue(analysisMetrics.runsStalled)).toBe(0);
  });

  test('an empty queue is never stalled, however long since the last run', async () => {
    expect(analysisMetrics.observeQueue({
      pending: 0, running: 0, oldest_pending_seconds: 0, seconds_since_last_start: null,
    })).toBe(false);
    expect(await gaugeValue(analysisMetrics.secondsSinceLastRunStarted)).toBe(-1);
  });

  test('work waiting on a service that has never started a run reads as stalled', () => {
    expect(analysisMetrics.observeQueue({
      pending: 1, running: 0, oldest_pending_seconds: 3600, seconds_since_last_start: null,
    })).toBe(true);
  });
});
