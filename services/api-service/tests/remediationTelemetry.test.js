const { safeAttributes, withSpan, injectTrace } = require('../src/utils/telemetry');

test('telemetry drops source, arbitrary errors, secrets, nested data and log injection', () => {
  expect(safeAttributes({ stage: 'verify\n', input_tokens: 123, source: 'SECRET_CANARY',
    authorization: 'Bearer SECRET_CANARY', error: 'private source', job_id: { token: 'secret' } }))
    .toEqual({ stage: 'verify', input_tokens: 123 });
});

test('instrumentation preserves workflow results and errors without an exporter', async () => {
  await expect(withSpan('remediation.stage', { stage: 'verify' }, async () => 42)).resolves.toBe(42);
  const failure = new Error('SECRET_CANARY');
  await expect(withSpan('remediation.stage', {}, async () => { throw failure; })).rejects.toBe(failure);
  expect(injectTrace()).not.toHaveProperty('baggage');
});
