// Automatic generation after analysis: gated by both flags, one job per head, bounded
// by the file limit and the installation budget, and never throwing into the caller.
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));

const { pool } = require('../src/config/database');
const connect = pool.connect;
const remediationDb = require('../src/db/remediation');
const policy = require('../src/services/remediationPolicy');
const autoGenerate = require('../src/services/remediationAutoGenerate');

const PR = '11111111-1111-4111-8111-111111111111';
const RUN = '22222222-2222-4222-8222-222222222222';
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const FLAGS = {
  REMEDIATION_ENABLED: 'true', REMEDIATION_GENERATE_ENABLED: 'true', REMEDIATION_PUBLISH_ENABLED: 'true',
  REMEDIATION_SERVICE_URL: 'http://repair', REMEDIATION_SERVICE_INTERNAL_SECRET: 'secret',
  GITHUB_SERVICE_URL: 'http://github', GITHUB_SERVICE_INTERNAL_SECRET: 'secret',
  REMEDIATION_SANDBOX_IMAGE_DIGEST: 'sha256:abc', REMEDIATION_VERIFICATION_CHECKS_JSON: '["unit"]',
  REMEDIATION_ALLOWED_RULE_FAMILIES_JSON: '["sql_parameterization"]',
  REMEDIATION_INPUT_USD_PER_MILLION_TOKENS: '1', REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS: '2',
};

function snapshot(id, overrides = {}) {
  return { finding_id: id, snapshot: { id, file_path: `src/${id}.js`, severity: 'high', fingerprint: `fp-${id}`, ...overrides } };
}

// A scripted transaction client. Each query is answered by the first matching script
// entry; the SQL and parameters of every call stay available for assertions.
function scriptedClient(script) {
  const calls = [];
  const client = {
    query: jest.fn(async (text, params) => {
      calls.push({ text, params });
      for (const [pattern, response] of script) {
        if (text.includes(pattern)) return typeof response === 'function' ? response(text, params) : response;
      }
      return { rowCount: 0, rows: [] };
    }),
    release: jest.fn(),
  };
  connect.mockResolvedValue(client);
  return { client, calls };
}

const prRow = { id: PR, repository_id: 'repo-1', head_sha: HEAD, base_sha: BASE, installation_id: 42, is_active: true, installation_status: 'active' };

beforeEach(() => {
  jest.clearAllMocks();
  for (const [name, value] of Object.entries(FLAGS)) process.env[name] = value;
});

afterAll(() => { for (const name of Object.keys(FLAGS)) delete process.env[name]; });

test('auto_generate requires both the generate and publish flags and both dependencies', () => {
  expect(policy.capabilityReport().auto_generate).toEqual({ enabled: true, reason: null });
  process.env.REMEDIATION_PUBLISH_ENABLED = 'false';
  expect(policy.capabilityReport().auto_generate).toEqual({ enabled: false, reason: 'feature_flag_off' });
  process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
  delete process.env.GITHUB_SERVICE_URL;
  expect(policy.capabilityReport().auto_generate).toEqual({ enabled: false, reason: 'dependency_not_configured' });
});

test('nothing is queued while generate or publish is off, and the database is not touched', async () => {
  process.env.REMEDIATION_PUBLISH_ENABLED = 'false';
  expect(await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN })).toEqual({ enqueued: false, reason: 'publish_disabled' });
  process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
  process.env.REMEDIATION_GENERATE_ENABLED = 'false';
  expect(await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN })).toEqual({ enqueued: false, reason: 'generate_disabled' });
  expect(connect).not.toHaveBeenCalled();
});

test('one automatic job is queued for the open findings of the completed head, without a user, in worker scope', async () => {
  const { calls } = scriptedClient([
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings arf JOIN findings f', { rowCount: 2, rows: [snapshot('f2', { severity: 'medium' }), snapshot('f1')] }],
    ['FROM usage_reservations', { rows: [{ amount: '0.5' }] }],
    ['INSERT INTO remediation_jobs', (text, params) => ({ rowCount: 1, rows: [{ id: 'job-1', created: true, state_version: 1, installation_id: 42, repository_id: 'repo-1', head_sha: HEAD, finding_snapshot_ids: params[7] }] })],
  ]);
  const result = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN });
  expect(result).toEqual({ enqueued: true, job_id: 'job-1', findings: 2 });
  expect(calls.some((call) => call.text.includes("set_config('app.remediation_worker', '1', true)"))).toBe(true);
  expect(calls.some((call) => call.text.includes("set_config('app.user_id'"))).toBe(false);
  const insert = calls.find((call) => call.text.includes('INSERT INTO remediation_jobs'));
  expect(insert.text).toContain("NULL,'automatic'");
  // Selection is ordered by severity and hashed over the sorted finding ids.
  expect(insert.params[7]).toEqual(['f1', 'f2']);
  expect(insert.params[6]).toBe(remediationDb.hash(['f1', 'f2']));
  const audit = calls.find((call) => call.text.includes('INSERT INTO audit_logs'));
  expect(audit.params[0]).toBeNull();
  expect(calls.some((call) => call.text.includes('INSERT INTO workflow_outbox') && call.params[4] === 'remediation.queued')).toBe(true);
});

test('an existing automatic job for the head means nothing is inserted, whatever its state', async () => {
  const { calls } = scriptedClient([
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 1, rows: [{ id: 'job-0', state: 'unsupported' }] }],
  ]);
  const result = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN });
  expect(result).toEqual({ enqueued: false, reason: 'exists', job_id: 'job-0' });
  expect(calls.some((call) => call.text.includes('INSERT INTO remediation_jobs'))).toBe(false);
});

test('the selection is bounded to the policy file limit by severity and refused without budget or open findings', async () => {
  const many = [];
  for (let index = 0; index < 8; index += 1) many.push(snapshot(`f${index}`, { severity: index < 2 ? 'critical' : 'low' }));
  const inserts = [];
  scriptedClient([
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings arf JOIN findings f', { rowCount: many.length, rows: many }],
    ['FROM usage_reservations', { rows: [{ amount: '0' }] }],
    ['INSERT INTO remediation_jobs', (text, params) => { inserts.push(params); return { rowCount: 1, rows: [{ id: 'job-2', created: true, state_version: 1, installation_id: 42, repository_id: 'repo-1' }] }; }],
  ]);
  const bounded = await remediationDb.createAutomaticJob({ pullRequestId: PR, analysisRunId: RUN, policy: { ...policy.getPolicy(), max_files: 3 } });
  expect(bounded.kind).toBe('ok');
  expect(inserts[0][7]).toEqual(['f0', 'f1', 'f2']);

  scriptedClient([
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings arf JOIN findings f', { rowCount: 1, rows: [snapshot('f1')] }],
    ['FROM usage_reservations', { rows: [{ amount: '2' }] }],
  ]);
  expect(await remediationDb.createAutomaticJob({ pullRequestId: PR, analysisRunId: RUN, policy: policy.getPolicy() })).toMatchObject({ kind: 'budget_exhausted' });

  scriptedClient([
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings arf JOIN findings f', { rowCount: 0, rows: [] }],
  ]);
  expect(await remediationDb.createAutomaticJob({ pullRequestId: PR, analysisRunId: RUN, policy: policy.getPolicy() })).toEqual({ kind: 'unsupported', reason: 'no_open_findings' });
});

test('a claimed job without any actor login stops before the snapshot envelope is sent', async () => {
  const { loadSnapshot } = require('../src/services/remediationWorkflow');
  await expect(loadSnapshot({ id: 'job-3', installation_id: 42, repository_full_name: 'owner/repo', creator_login: null, pr_number: 1, head_sha: HEAD, base_sha: BASE }))
    .rejects.toMatchObject({ code: 'ACTOR_UNAVAILABLE' });
});

test('a database failure is reported, never thrown into the analysis', async () => {
  connect.mockRejectedValue(new Error('connection refused'));
  const result = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN });
  expect(result).toEqual({ enqueued: false, reason: 'enqueue_failed', error: 'connection refused' });
});
