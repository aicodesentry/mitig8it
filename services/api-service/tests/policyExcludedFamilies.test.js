const ENV = { ...process.env };

// workflow_hardening shipped switched off in production: the deployment pins an explicit
// REMEDIATION_ALLOWED_RULE_FAMILIES_JSON written before the family existed, and the only
// symptom on the pull request was a skip line saying the family was disabled by policy.
// An operator's explicit list is still honoured; what changes is that the gap is visible.
describe('a repair family this build ships that the policy leaves out', () => {
  beforeEach(() => { jest.resetModules(); process.env = { ...ENV }; });
  afterAll(() => { process.env = ENV; });

  const report = () => require('../src/services/remediationPolicy').capabilityReport();

  test('an explicit list written before a family existed reports the gap', () => {
    process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = JSON.stringify([
      'sql_parameterization', 'command_arguments', 'path_containment',
      'hardcoded_credential', 'code_injection_eval',
    ]);
    expect(report().rule_families_excluded_by_policy).toEqual(['workflow_hardening']);
  });

  test('no list means nothing is excluded, because the build default is every family', () => {
    delete process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON;
    expect(report().rule_families_excluded_by_policy).toEqual([]);
  });

  test('an operator narrowing the list on purpose is reported, not overridden', () => {
    process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = JSON.stringify(['sql_parameterization']);
    const out = report();
    expect(out.rule_families_excluded_by_policy).toContain('workflow_hardening');
    expect(out.rule_families_excluded_by_policy).toContain('path_containment');
    expect(require('../src/services/remediationPolicy').getPolicy().allowed_rule_families)
      .toEqual(['sql_parameterization']);
  });
});
