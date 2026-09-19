/**
 * A repository-specific verification profile is optional once every candidate must ship its
 * own agent-generated regression test. These tests pin that relaxation so a deployment with
 * no REMEDIATION_VERIFICATION_CHECKS_JSON is still "configured" and still sends the repair
 * service a policy that demands the generated reproducer.
 */
const POLICY_ENV = [
  'REMEDIATION_SERVICE_URL', 'REMEDIATION_SERVICE_INTERNAL_SECRET', 'GITHUB_SERVICE_URL',
  'GITHUB_SERVICE_INTERNAL_SECRET', 'REMEDIATION_SANDBOX_IMAGE_DIGEST',
  'REMEDIATION_VERIFICATION_CHECKS_JSON', 'REMEDIATION_ALLOWED_RULE_FAMILIES_JSON',
  'REMEDIATION_INPUT_USD_PER_MILLION_TOKENS', 'REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS',
  'REMEDIATION_REQUIRE_GENERATED_REGRESSION_TEST', 'REMEDIATION_RUN_REPOSITORY_TESTS',
];

function configure() {
  process.env.REMEDIATION_SERVICE_URL = 'http://repair';
  process.env.REMEDIATION_SERVICE_INTERNAL_SECRET = 'repair';
  process.env.GITHUB_SERVICE_URL = 'http://github';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'github';
  process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = 'sha256:aaaa';
  process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = '["sql_parameterization"]';
  process.env.REMEDIATION_INPUT_USD_PER_MILLION_TOKENS = '3';
  process.env.REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS = '15';
}

describe('remediation verification policy', () => {
  let saved;
  let policy;

  beforeEach(() => {
    saved = Object.fromEntries(POLICY_ENV.map((name) => [name, process.env[name]]));
    POLICY_ENV.forEach((name) => { delete process.env[name]; });
    configure();
    jest.resetModules();
    policy = require('../src/services/remediationPolicy');
  });

  afterEach(() => {
    POLICY_ENV.forEach((name) => {
      if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
    });
  });

  test('an absent verification profile is an empty list, not an unconfigured service', () => {
    const current = policy.getPolicy();
    expect(current.verification_checks).toEqual([]);
    expect(current.require_generated_regression_test).toBe(true);
    expect(current.repair_service_configured).toBe(true);
  });

  test('an unparseable verification profile is also an empty list', () => {
    process.env.REMEDIATION_VERIFICATION_CHECKS_JSON = 'not json';
    const current = policy.getPolicy();
    expect(current.verification_checks).toEqual([]);
    expect(current.repair_service_configured).toBe(true);
  });

  test('a declared verification profile is still passed through unchanged', () => {
    process.env.REMEDIATION_VERIFICATION_CHECKS_JSON = '[{"check_id":"exploit","kind":"exploit","argv":["npm","run","exploit"]}]';
    const current = policy.getPolicy();
    expect(current.verification_checks).toHaveLength(1);
    expect(current.verification_checks[0].check_id).toBe('exploit');
    expect(current.repair_service_configured).toBe(true);
  });

  test('opting out of generated regression tests restores the profile requirement', () => {
    process.env.REMEDIATION_REQUIRE_GENERATED_REGRESSION_TEST = 'false';
    const current = policy.getPolicy();
    expect(current.require_generated_regression_test).toBe(false);
    expect(current.verification_checks).toBeNull();
    expect(current.repair_service_configured).toBe(false);
  });

  test('running the repository test suite is opt-in', () => {
    expect(policy.getPolicy().run_repository_tests).toBe(false);
    process.env.REMEDIATION_RUN_REPOSITORY_TESTS = 'true';
    expect(policy.getPolicy().run_repository_tests).toBe(true);
  });

  test('the repair request policy carries both generated-test fields', () => {
    const { repairPolicy } = require('../src/services/remediationWorkflow');
    const selected = repairPolicy({ ...policy.DEFAULT_POLICY, ...policy.getPolicy() });
    expect(selected.require_generated_regression_test).toBe(true);
    expect(selected.run_repository_tests).toBe(false);
    expect(selected.verification_checks).toEqual([]);
  });
});
