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
  'REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION', 'REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION',
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

  test('a declared allowed-families list is passed through, even a narrower one', () => {
    expect(policy.getPolicy().allowed_rule_families).toEqual(['sql_parameterization']);
    expect(policy.getPolicy().repair_service_configured).toBe(true);
  });

  test('an absent allowed-families list takes the service default, which includes the Python families', () => {
    delete process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON;
    const current = policy.getPolicy();
    expect(current.allowed_rule_families).toEqual([
      'sql_parameterization', 'command_arguments', 'path_containment', 'hardcoded_credential', 'code_injection_eval',
    ]);
    expect(current.allowed_rule_families).toEqual([...policy.DEFAULT_POLICY.allowed_rule_families]);
    expect(current.repair_service_configured).toBe(true);
    process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = 'not json';
    expect(policy.getPolicy().allowed_rule_families).toEqual([...policy.DEFAULT_POLICY.allowed_rule_families]);
  });

  test('the repair request policy carries both generated-test fields', () => {
    const { repairPolicy } = require('../src/services/remediationWorkflow');
    const selected = repairPolicy({ ...policy.DEFAULT_POLICY, ...policy.getPolicy() });
    expect(selected.require_generated_regression_test).toBe(true);
    expect(selected.run_repository_tests).toBe(false);
    expect(selected.verification_checks).toEqual([]);
    expect(selected.max_revisions).toBe(2);
  });

  // The three levels the repair service can report. `independent_sandbox` is the
  // Kubernetes/gVisor sandbox and always passes. `isolated_job` is the Cloud Run job sandbox:
  // separate containers, a check user holding none of the job's credentials, and a network the
  // job's own probes measured as unreachable, so it passes by default and an operator who will
  // accept nothing weaker than gVisor turns it off. `development_unverified` is repository code
  // running in the service's own container and stays off unless an operator opts in.
  describe('which verification levels may be applied', () => {
    test('the isolated Cloud Run job sandbox is accepted by default and the development sandbox is not', () => {
      expect(policy.allowIsolatedJobVerification()).toBe(true);
      expect(policy.allowDevelopmentVerification()).toBe(false);
      expect(policy.verificationLevelPermitted('independent_sandbox')).toBe(true);
      expect(policy.verificationLevelPermitted('isolated_job')).toBe(true);
      expect(policy.verificationLevelPermitted('development_unverified')).toBe(false);
    });

    test('an operator can refuse everything below the gVisor sandbox', () => {
      process.env.REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION = 'false';
      expect(policy.allowIsolatedJobVerification()).toBe(false);
      expect(policy.verificationLevelPermitted('isolated_job')).toBe(false);
      expect(policy.verificationLevelPermitted('independent_sandbox')).toBe(true);
    });

    test('allowing the development sandbox does not change the isolated job level either way', () => {
      process.env.REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION = 'true';
      expect(policy.verificationLevelPermitted('development_unverified')).toBe(true);
      expect(policy.verificationLevelPermitted('isolated_job')).toBe(true);
    });

    test('a level this control plane does not know is never permitted', () => {
      expect(policy.verificationLevelPermitted('some_level_from_the_future')).toBe(false);
      expect(policy.verificationLevelPermitted('')).toBe(false);
      expect(policy.verificationLevelPermitted(undefined)).toBe(false);
      expect(policy.verificationLevelPermitted('none')).toBe(false);
    });

    test('the capability report states both verification flags', () => {
      expect(policy.capabilityReport().isolated_job_verification_allowed).toBe(true);
      expect(policy.capabilityReport().development_verification_allowed).toBe(false);
      process.env.REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION = 'false';
      expect(policy.capabilityReport().isolated_job_verification_allowed).toBe(false);
    });

    test('the repair request policy tells the repair service which levels it may report', () => {
      const { repairPolicy } = require('../src/services/remediationWorkflow');
      const selected = repairPolicy({ ...policy.DEFAULT_POLICY, ...policy.getPolicy() });
      expect(selected.allow_isolated_job_verification).toBe(true);
      expect(selected.allow_development_verification).toBe(false);
    });

    test('a control plane that refuses the level says so in the request it sends', () => {
      process.env.REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION = 'false';
      const { repairPolicy } = require('../src/services/remediationWorkflow');
      const selected = repairPolicy({ ...policy.DEFAULT_POLICY, ...policy.getPolicy() });
      expect(selected.allow_isolated_job_verification).toBe(false);
    });
  });
});
