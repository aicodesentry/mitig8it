jest.mock('../src/config/database', () => ({ pool: { options: { max: 20 } } }));
jest.mock('../src/db/analysisRuns', () => ({ claimNextQueuedRun: jest.fn() }));
jest.mock('../src/db/findings', () => ({}));
jest.mock('../src/db/repositories', () => ({}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const originalConcurrency = process.env.ANALYSIS_QUEUE_CONCURRENCY;
afterAll(() => {
  if (originalConcurrency === undefined) delete process.env.ANALYSIS_QUEUE_CONCURRENCY;
  else process.env.ANALYSIS_QUEUE_CONCURRENCY = originalConcurrency;
});

test.each([
  ['100', 20, 18],
  ['3', 20, 3],
  ['100', 5, 3],
  ['invalid', 20, 1],
  ['0.5', 20, 1],
  ['100', 2, 0],
])('configured concurrency %s with pool size %i starts only %i lease holders', async (configured, poolSize, expected) => {
  jest.resetModules();
  const { pool } = require('../src/config/database');
  const runs = require('../src/db/analysisRuns');
  pool.options.max = poolSize;
  // Keep each worker in its claim, simulating retained lease connections.
  runs.claimNextQueuedRun.mockImplementation(() => new Promise(() => {}));
  process.env.ANALYSIS_QUEUE_CONCURRENCY = configured;
  const { notifyAnalysisQueued } = require('../src/services/prAnalysisOrchestrator');
  notifyAnalysisQueued();
  await new Promise(resolve => setImmediate(resolve));
  expect(runs.claimNextQueuedRun).toHaveBeenCalledTimes(expected);
});
