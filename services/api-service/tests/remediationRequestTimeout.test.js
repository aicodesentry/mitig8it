/**
 * `request_timeout_seconds` is the sandbox deadline for one verification and the policy is
 * its single source: the repair service forwards it to the broker as `deadline_seconds` and
 * waits a fixed margin longer for the response. These tests pin the value to what a real
 * verification needs, so it cannot drift back to a number that times out client-side.
 */
const { DEFAULT_POLICY, getPolicy } = require('../src/services/remediationPolicy');

// The check budgets the repair service applies per run (src/verification/checks.py) and the
// bounds the repair request schema accepts (contracts/repair-request.schema.json).
const REGRESSION_TEST_TIMEOUT_SECONDS = 60;
const SYNTAX_CHECK_TIMEOUT_SECONDS = 30;
const REPOSITORY_TEST_TIMEOUT_SECONDS = 300;
const SCHEMA_MINIMUM = 10;
const SCHEMA_MAXIMUM = 1800;

describe('remediation request timeout', () => {
  test('covers every check on both trees, including repository tests when enabled', () => {
    const perTree = REGRESSION_TEST_TIMEOUT_SECONDS + SYNTAX_CHECK_TIMEOUT_SECONDS + REPOSITORY_TEST_TIMEOUT_SECONDS;
    expect(DEFAULT_POLICY.request_timeout_seconds).toBeGreaterThanOrEqual(2 * perTree);
  });

  test('is the job runtime ceiling, so the job limit and not the transport bounds a verification', () => {
    expect(DEFAULT_POLICY.request_timeout_seconds).toBe(DEFAULT_POLICY.max_runtime_minutes * 60);
  });

  test('stays within the repair request schema bounds', () => {
    expect(DEFAULT_POLICY.request_timeout_seconds).toBeGreaterThanOrEqual(SCHEMA_MINIMUM);
    expect(DEFAULT_POLICY.request_timeout_seconds).toBeLessThanOrEqual(SCHEMA_MAXIMUM);
  });

  test('is sent to the repair service unchanged', () => {
    expect(getPolicy().request_timeout_seconds).toBe(DEFAULT_POLICY.request_timeout_seconds);
  });
});
