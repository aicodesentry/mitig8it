jest.mock('axios', () => ({ post: jest.fn() }));
jest.mock('../src/db/findings', () => ({
  findByFingerprint: jest.fn(), upsert: jest.fn(), markFixed: jest.fn(),
  getActiveSuppressions: jest.fn().mockResolvedValue([]), mergeEvidenceDetails: jest.fn(),
  snapshotRun: jest.fn(),
}));
jest.mock('../src/db/analysisRuns', () => ({
  countCompletedRuns: jest.fn().mockResolvedValue(1),
  markCompleted: jest.fn(),
  markFailed: jest.fn(),
  requeueAfterTransientFailure: jest.fn().mockResolvedValue({ id: 'retry-run', auto_retry_count: 1 }),
}));
jest.mock('../src/db/repositories', () => ({
  getProfile: jest.fn().mockResolvedValue({ profile_status: 'ready', profile_data: {} }),
}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const axios = require('axios');
const runs = require('../src/db/analysisRuns');
const findings = require('../src/db/findings');
const logger = require('../src/utils/logger');
const { triggerAnalysisJob, __private } = require('../src/services/prAnalysisOrchestrator');

const basePayload = {
  analysis_run_id: 'run1', repository_id: 'repo1', repository_full_name: 'owner/repo',
  installation_id: 1, pull_request_id: 'pr1', pull_request_number: 1,
  commit_sha: 'sha1', baseline_set: true,
};
const calls = (part) => axios.post.mock.calls.filter(([url]) => url.includes(part));
const drain = () => new Promise((resolve) => setTimeout(resolve, 30));

// The live failure: the gRPC call credentials generator could not mint an identity
// token, so the analysis service was never reached.
const metadataTokenError = () => new Error(
  '2 UNKNOWN: Getting metadata from plugin failed with error: Metadata token request timed out'
);

function failTier(error, tier = 'tier1') {
  const original = axios.post.getMockImplementation();
  axios.post.mockImplementation((url, ...args) => (
    url.includes(`/${tier}`) ? Promise.reject(error) : original(url, ...args)
  ));
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.INTERNAL_SERVICE_TRANSPORT = 'http';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'test-secret';
  axios.post.mockImplementation(async (url) => ({
    data: url.includes('/pulls/files') ? { files: [], commit_sha: 'sha1' }
      : url.includes('/tier') ? { findings: [] }
        : { review_id: 1, check_run_id: 1 },
  }));
});

describe('transient failure classification', () => {
  test.each([
    ['metadata token UNKNOWN', metadataTokenError()],
    ['gRPC UNAVAILABLE message', new Error('14 UNAVAILABLE: No connection established')],
    ['gRPC DEADLINE_EXCEEDED message', new Error('4 DEADLINE_EXCEEDED: Deadline exceeded')],
    ['gRPC UNAVAILABLE status code', Object.assign(new Error('rpc failed'), { code: 14 })],
    ['connection reset', Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' })],
    ['socket hang up', new Error('socket hang up')],
  ])('%s is transient', (_label, error) => {
    expect(__private.isTransientInfrastructureError(error)).toBe(true);
  });

  test.each([
    ['scanner outage', new Error('analysis unavailable')],
    ['incomplete tier response', new Error('Incomplete analysis response: /analyze/pr/tier2')],
    ['content retrieval', new Error('Required source content retrieval failed: 14 UNAVAILABLE')],
    ['malformed file response', new Error('Invalid GitHub file response')],
    ['publication failure', new Error('Inline finding publication incomplete: 0/1 posted')],
    ['gRPC INVALID_ARGUMENT', Object.assign(new Error('3 INVALID_ARGUMENT: bad request'), { code: 3 })],
    ['missing error', null],
  ])('%s is not transient', (_label, error) => {
    expect(__private.isTransientInfrastructureError(error)).toBe(false);
  });

  test('backoff is 30s per attempt and capped at five minutes', () => {
    expect(__private.transientRetryDelayMs(0)).toBe(30_000);
    expect(__private.transientRetryDelayMs(1)).toBe(60_000);
    expect(__private.transientRetryDelayMs(2)).toBe(90_000);
    expect(__private.transientRetryDelayMs(20)).toBe(300_000);
  });
});

describe('transient analysis failures are re-queued', () => {
  test('a metadata token failure re-queues a new attempt instead of failing terminally', async () => {
    failTier(metadataTokenError());

    triggerAnalysisJob(basePayload);
    await drain();

    expect(runs.requeueAfterTransientFailure).toHaveBeenCalledWith('run1', {
      errorMessage: expect.stringContaining('Metadata token request timed out'),
      delayMs: 30_000,
    });
    expect(runs.markFailed).not.toHaveBeenCalled();
    expect(runs.markCompleted).not.toHaveBeenCalled();
    // No verdict is published while the analysis is still pending a retry.
    expect(calls('/check-runs')).toHaveLength(0);
    expect(logger.warn).toHaveBeenCalledWith(
      'PR analysis hit a transient infrastructure failure; re-queued',
      expect.objectContaining({ attempt: 1, delayMs: 30_000, retryRunId: 'retry-run' })
    );
  });

  test('each automatic attempt backs off further', async () => {
    failTier(metadataTokenError());

    triggerAnalysisJob({ ...basePayload, auto_retry_count: 2 });
    await drain();

    expect(runs.requeueAfterTransientFailure).toHaveBeenCalledWith('run1', {
      errorMessage: expect.any(String),
      delayMs: 90_000,
    });
  });

  test('the fourth failure exhausts the retry budget and fails closed', async () => {
    failTier(metadataTokenError());

    triggerAnalysisJob({ ...basePayload, auto_retry_count: 3 });
    await drain();

    expect(runs.requeueAfterTransientFailure).not.toHaveBeenCalled();
    expect(runs.markFailed).toHaveBeenCalledWith('run1', expect.stringContaining('Metadata token'));
    expect(calls('/check-runs')).toHaveLength(1);
    expect(calls('/check-runs')[0][1]).toMatchObject({
      conclusion: 'failure', title: 'Security analysis incomplete',
    });
  });

  test('a scanner outage is not retried', async () => {
    failTier(new Error('analysis unavailable'), 'tier2');

    triggerAnalysisJob(basePayload);
    await drain();

    expect(runs.requeueAfterTransientFailure).not.toHaveBeenCalled();
    expect(runs.markFailed).toHaveBeenCalled();
    expect(calls('/check-runs')[0][1].title).toBe('Security analysis incomplete');
  });

  test('a persistence failure is not retried', async () => {
    findings.snapshotRun.mockRejectedValueOnce(new Error('14 UNAVAILABLE: snapshot write lost'));

    triggerAnalysisJob(basePayload);
    await drain();

    // The message looks transient, but a result already existed: retrying could
    // republish feedback, so the run fails closed.
    expect(runs.requeueAfterTransientFailure).not.toHaveBeenCalled();
    expect(runs.markFailed).toHaveBeenCalled();
    expect(runs.markCompleted).not.toHaveBeenCalled();
  });

  test('a transport failure after publication is not retried', async () => {
    const original = axios.post.getMockImplementation();
    axios.post.mockImplementation((url, ...args) => (
      url.includes('/check-runs')
        ? Promise.reject(Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' }))
        : original(url, ...args)
    ));

    triggerAnalysisJob(basePayload);
    await drain();

    expect(runs.requeueAfterTransientFailure).not.toHaveBeenCalled();
    expect(runs.markFailed).toHaveBeenCalled();
    expect(runs.markCompleted).not.toHaveBeenCalled();
  });

  test('a failed re-queue falls back to the terminal failure path', async () => {
    runs.requeueAfterTransientFailure.mockRejectedValueOnce(new Error('queue write failed'));
    failTier(metadataTokenError());

    triggerAnalysisJob(basePayload);
    await drain();

    expect(runs.markFailed).toHaveBeenCalledWith('run1', expect.stringContaining('Metadata token'));
    expect(calls('/check-runs')[0][1].title).toBe('Security analysis incomplete');
  });
});
