jest.mock('../src/config/database', () => ({ pool: { connect: jest.fn(), query: jest.fn(), end: jest.fn() } }));
jest.mock('../src/db/remediation', () => ({ claimNextJob: jest.fn(), claimNextAction: jest.fn() }));
jest.mock('../src/services/remediationWorkflow', () => ({ executeClaimedJob: jest.fn() }));
jest.mock('../src/services/remediationActionWorker', () => ({ executeClaimedAction: jest.fn() }));
jest.mock('../src/services/remediationOutbox', () => ({
  registerDefaultHandlers: jest.fn(),
  createDispatcher: jest.fn(() => 'dispatcher'),
  processPending: jest.fn(async () => []),
}));
jest.mock('../src/services/remediationReconciler', () => ({ startReconciler: jest.fn(() => jest.fn()) }));

const remediationDb = require('../src/db/remediation');
const outbox = require('../src/services/remediationOutbox');
const { startReconciler } = require('../src/services/remediationReconciler');
const { startRemediationWorker, assertWorkerEnabled } = require('../src/workers');

const flush = async () => { for (let i = 0; i < 6; i += 1) await Promise.resolve(); };

beforeEach(() => {
  jest.clearAllMocks();
  jest.useFakeTimers();
  remediationDb.claimNextJob.mockResolvedValue(null);
  remediationDb.claimNextAction.mockResolvedValue(null);
});

afterEach(() => {
  jest.clearAllTimers();
  jest.useRealTimers();
});

test('start registers the outbox handlers, resolves one dispatcher, and starts the reconciler', async () => {
  const stop = startRemediationWorker({ workerId: 'worker-1', intervalMs: 5000 });
  expect(outbox.registerDefaultHandlers).toHaveBeenCalledTimes(1);
  expect(outbox.registerDefaultHandlers.mock.calls[0][0]).toMatchObject({ workerId: 'worker-1' });
  expect(typeof outbox.registerDefaultHandlers.mock.calls[0][0].executeClaimedJob).toBe('function');
  expect(typeof outbox.registerDefaultHandlers.mock.calls[0][0].executeClaimedAction).toBe('function');
  expect(outbox.createDispatcher).toHaveBeenCalledTimes(1);
  expect(startReconciler).toHaveBeenCalledTimes(1);
  stop();
});

test('the loop polls the outbox and both claim queues on every interval', async () => {
  const stop = startRemediationWorker({ workerId: 'worker-2', intervalMs: 5000 });
  jest.advanceTimersByTime(0);
  await flush();
  expect(outbox.processPending).toHaveBeenCalledWith({ limit: 20, dispatcher: 'dispatcher' });
  expect(remediationDb.claimNextJob).toHaveBeenCalledWith('worker-2');
  expect(remediationDb.claimNextAction).toHaveBeenCalledWith('worker-2');

  jest.advanceTimersByTime(5000);
  await flush();
  expect(outbox.processPending).toHaveBeenCalledTimes(2);
  stop();
});

test('stop clears the pending timer, stops the reconciler, and schedules no further ticks', async () => {
  const stopReconciler = jest.fn();
  startReconciler.mockReturnValueOnce(stopReconciler);
  const stop = startRemediationWorker({ workerId: 'worker-3', intervalMs: 5000 });
  jest.advanceTimersByTime(0);
  await flush();
  const ticksBeforeStop = outbox.processPending.mock.calls.length;

  stop();
  expect(stopReconciler).toHaveBeenCalledTimes(1);
  expect(jest.getTimerCount()).toBe(0);

  jest.advanceTimersByTime(60000);
  await flush();
  expect(outbox.processPending).toHaveBeenCalledTimes(ticksBeforeStop);
});

test('a failing tick is logged and the loop keeps its schedule', async () => {
  outbox.processPending.mockRejectedValueOnce(new Error('transient'));
  const stop = startRemediationWorker({ workerId: 'worker-4', intervalMs: 5000 });
  jest.advanceTimersByTime(0);
  await flush();
  expect(jest.getTimerCount()).toBe(1);
  jest.advanceTimersByTime(5000);
  await flush();
  expect(outbox.processPending).toHaveBeenCalledTimes(2);
  stop();
});

test('the standalone entry point still refuses to run without REMEDIATION_WORKER_ENABLED', () => {
  const previous = process.env.REMEDIATION_WORKER_ENABLED;
  delete process.env.REMEDIATION_WORKER_ENABLED;
  expect(() => assertWorkerEnabled()).toThrow(/REMEDIATION_WORKER_ENABLED=true/);
  process.env.REMEDIATION_WORKER_ENABLED = 'true';
  expect(() => assertWorkerEnabled()).not.toThrow();
  if (previous === undefined) delete process.env.REMEDIATION_WORKER_ENABLED;
  else process.env.REMEDIATION_WORKER_ENABLED = previous;
});
