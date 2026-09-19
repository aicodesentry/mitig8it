// The repair service publishes the JSON schema of its RepairRequest model at
// services/remediation-service/contracts/repair-request.schema.json (kept in sync by a
// Python test). This test proves the payload the control plane builds satisfies it, so a
// field the other side rejects fails here instead of in production.
const path = require('path');
const crypto = require('crypto');
const Ajv2020 = require('ajv/dist/2020');

const schema = require(path.resolve(__dirname, '../../remediation-service/contracts/repair-request.schema.json'));

describe('repair request contract', () => {
  const previous = { ...process.env };
  beforeAll(() => {
    Object.assign(process.env, {
      REMEDIATION_ENABLED: 'true', REMEDIATION_GENERATE_ENABLED: 'true',
      REMEDIATION_SERVICE_URL: 'https://repair.example.run.app', REMEDIATION_SERVICE_INTERNAL_SECRET: 's',
      GITHUB_SERVICE_URL: 'https://github.example.run.app', GITHUB_SERVICE_INTERNAL_SECRET: 's',
      REMEDIATION_SANDBOX_IMAGE_DIGEST: `registry.example/mitig8it/remediation@sha256:${'a'.repeat(64)}`,
      REMEDIATION_VERIFICATION_CHECKS_JSON: '[]',
      REMEDIATION_ALLOWED_RULE_FAMILIES_JSON: '["sql_parameterization","command_arguments","path_containment"]',
      REMEDIATION_INPUT_USD_PER_MILLION_TOKENS: '0.15', REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS: '0.60',
    });
  });
  afterAll(() => { process.env = previous; });

  test('a first-attempt payload built from a live-shaped job validates against the repair service schema', () => {
    const policy = require('../src/services/remediationPolicy');
    const { buildPayload } = require('../src/services/remediationWorkflow');
    const manifest = policy.getPolicy();
    const content = 'const x = 1;\n';
    const job = {
      id: crypto.randomUUID(), installation_id: 128402824, repository_id: crypto.randomUUID(), repository_full_name: 'owner/repo',
      pull_request_id: crypto.randomUUID(), pr_number: 122, head_sha: '9'.repeat(40), base_sha: 'e'.repeat(40), analysis_run_id: crypto.randomUUID(),
      stage: 'snapshotting', fencing_token: 1, attempt_count: 0, policy_version: manifest.version, policy_manifest: manifest,
    };
    const snapshot = {
      files: [{ path: 'services/accounts.js', content, sha: crypto.createHash('sha256').update(content).digest('hex') }],
      treeEntries: [{ path: 'services/accounts.js', mode: '100644', type: 'blob', sha: '1'.repeat(40) }],
      headTreeOid: '2'.repeat(40),
    };
    const findings = [{ id: crypto.randomUUID(), file_path: 'services/accounts.js', line_start: 14, line_end: 17, severity: 'high', rule_id: 'sql.injection.raw_query', title: 'SQL injection', cwe: 'CWE-89' }];
    const payload = buildPayload(job, snapshot, findings);

    const ajv = new Ajv2020({ strict: false, validateFormats: false, allErrors: true });
    const valid = ajv.validate(schema, payload);
    expect(ajv.errors || []).toEqual([]);
    expect(valid).toBe(true);
    expect(payload.attempt).toBe(1);
    expect(payload.policy.supported_platform).toBe('linux');
  });
});
