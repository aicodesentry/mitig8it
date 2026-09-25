// What a failed or partly unsupported stage leaves behind. Job 085f74f4 went inconclusive
// with failure_reason `{"code": 9, "message": "Repair stage could not be completed safely"}`,
// which named neither the stage that failed nor the adapter's 422 behind it, so the cause
// had to be reconstructed from three services' logs. The reason now carries the underlying
// error, and a finding whose source the snapshot could not carry is skipped by name rather
// than taking the whole job down with it.
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  hash: () => 'a'.repeat(64),
  scopedTransaction: jest.fn(),
  reserveUsage: jest.fn(),
  settleUsage: jest.fn(),
  usageCost: jest.fn(() => 0),
  recordAttempt: jest.fn(),
  heartbeat: jest.fn(),
  completeStage: jest.fn(),
  recordSkippedFindings: jest.fn(),
  deferForExternalExecution: jest.fn(),
}));
jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn() }));
jest.mock('../src/services/remediationServiceClient', () => ({ RemediationServiceClient: jest.fn() }));

const logger = require('../src/utils/logger');
const remediationDb = require('../src/db/remediation');
const { GitHubRemediationClient } = require('../src/services/githubRemediationClient');
const { RemediationServiceClient } = require('../src/services/remediationServiceClient');
const { executeClaimedJob, MAX_REASON_MESSAGE_CHARS } = require('../src/services/remediationWorkflow');

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const TREE = 'c'.repeat(40);
const FLAGS = {
  REMEDIATION_ENABLED: 'true', REMEDIATION_GENERATE_ENABLED: 'true',
  REMEDIATION_SERVICE_URL: 'http://repair', REMEDIATION_SERVICE_INTERNAL_SECRET: 'secret',
  GITHUB_SERVICE_URL: 'http://github', GITHUB_SERVICE_INTERNAL_SECRET: 'secret',
  REMEDIATION_SANDBOX_IMAGE_DIGEST: 'sha256:abc', REMEDIATION_VERIFICATION_CHECKS_JSON: '["unit"]',
  REMEDIATION_ALLOWED_RULE_FAMILIES_JSON: '["sql_parameterization"]',
  REMEDIATION_INPUT_USD_PER_MILLION_TOKENS: '1', REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS: '2',
};

function job(overrides = {}) {
  return {
    id: 'job-1', installation_id: 42, repository_id: 'repo-1', repository_full_name: 'owner/repo', creator_login: 'nebullii',
    pull_request_id: 'pr-1', pr_number: 135, analysis_run_id: 'run-1', head_sha: HEAD, base_sha: BASE,
    stage: 'snapshotting', attempt_count: 0, revision_count: 0, fencing_token: 1, policy_version: 'v1',
    policy_manifest: { max_attempts: 3, max_revisions: 2, max_files: 5 }, ...overrides,
  };
}

// The findings the job selected, as `selectedFindings` reads them out of the run snapshot.
function withFindings(findings) {
  remediationDb.scopedTransaction.mockImplementation(async (_scope, fn) => fn({
    query: async () => ({ rows: findings.map((finding) => ({ finding_id: finding.id, snapshot: finding })) }),
  }));
}

function withSnapshot(response) {
  const snapshot = jest.fn(async () => response);
  GitHubRemediationClient.mockImplementation(() => ({ snapshot }));
  return snapshot;
}

beforeEach(() => {
  jest.clearAllMocks();
  for (const [name, value] of Object.entries(FLAGS)) process.env[name] = value;
  remediationDb.reserveUsage.mockResolvedValue({ id: 'reservation-1' });
  remediationDb.completeStage.mockResolvedValue(true);
  remediationDb.recordSkippedFindings.mockResolvedValue([]);
});

afterAll(() => { for (const name of Object.keys(FLAGS)) delete process.env[name]; });

// --- The failure reason names the failure --------------------------------------------

test('a failed stage records the underlying error and code, and logs both with the job id', async () => {
  withFindings([{ id: 'f-js', file_path: 'services/orders.js' }]);
  withSnapshot({ head_sha: HEAD, base_sha: BASE, head_tree_oid: TREE, skipped: [],
    files: [{ path: 'services/orders.js', content: 'const q = 1;\n', sha: 'e'.repeat(40) }],
    tree_entries: [{ path: 'services/orders.js', mode: '100644', type: 'blob', sha: 'e'.repeat(40) }] });
  const failure = Object.assign(new Error('Finding source is unsupported or missing from the immutable tree'),
    { code: 'ERR_BAD_REQUEST', response: { status: 422 } });
  RemediationServiceClient.mockImplementation(() => ({ repair: jest.fn(async () => { throw failure; }) }));

  await executeClaimedJob(job());

  const [, completion] = remediationDb.completeStage.mock.calls[0];
  expect(completion.state).toBe('inconclusive');
  expect(completion.reason).toEqual({
    code: 'ERR_BAD_REQUEST',
    message: 'Finding source is unsupported or missing from the immutable tree',
    status: 422,
    retryable: false,
  });
  expect(logger.warn).toHaveBeenCalledWith('Repair stage could not be completed safely', expect.objectContaining({
    job_id: 'job-1', stage: 'snapshotting', state: 'inconclusive', code: 'ERR_BAD_REQUEST', status: 422,
    error: 'Finding source is unsupported or missing from the immutable tree',
  }));
});

test('a long error message is bounded and a transient failure is queued again rather than ended', async () => {
  withFindings([{ id: 'f-js', file_path: 'services/orders.js' }]);
  withSnapshot({ head_sha: HEAD, base_sha: BASE, head_tree_oid: TREE, skipped: [],
    files: [{ path: 'services/orders.js', content: 'const q = 1;\n', sha: 'e'.repeat(40) }],
    tree_entries: [{ path: 'services/orders.js', mode: '100644', type: 'blob', sha: 'e'.repeat(40) }] });
  const failure = Object.assign(new Error('x'.repeat(900)), { response: { status: 503 } });
  RemediationServiceClient.mockImplementation(() => ({ repair: jest.fn(async () => { throw failure; }) }));

  await executeClaimedJob(job());

  const [, completion] = remediationDb.completeStage.mock.calls[0];
  expect(completion.state).toBe('queued');
  expect(completion.reason.retryable).toBe(true);
  expect(completion.reason.code).toBe('repair_failure');
  expect(completion.reason.message).toHaveLength(MAX_REASON_MESSAGE_CHARS);
  expect(MAX_REASON_MESSAGE_CHARS).toBe(300);
});

// --- An unavailable source is one finding's loss --------------------------------------

test('a finding whose source the snapshot could not carry is skipped and the rest are still repaired', async () => {
  withFindings([
    { id: 'f-cs', file_path: 'TestVuln.cs' },
    { id: 'f-js', file_path: 'services/orders.js' },
    { id: 'f-py', file_path: 'main.py' },
  ]);
  const snapshot = withSnapshot({
    head_sha: HEAD, base_sha: BASE, head_tree_oid: TREE,
    files: [{ path: 'services/orders.js', content: 'const q = 1;\n', sha: 'e'.repeat(40) },
      { path: 'main.py', content: 'x = 1\n', sha: 'f'.repeat(40) }],
    tree_entries: [{ path: 'services/orders.js', mode: '100644', type: 'blob', sha: 'e'.repeat(40) }],
    skipped: [{ path: 'TestVuln.cs', code: 'affected_source_missing', message: 'The finding source is unsupported or missing from the immutable tree.' }],
  });
  const repair = jest.fn(async () => ({ state: 'ready', head_sha: HEAD, base_sha: BASE, manifest_digest: 'd'.repeat(64),
    candidates: [{ artifact_digest: 'a'.repeat(64), finding_ids: ['f-js'], verification: { status: 'passed' } }], evidence: {} }));
  RemediationServiceClient.mockImplementation(() => ({ repair }));

  await executeClaimedJob(job());

  // Every finding path is still requested; which ones the tree carries is the adapter's answer.
  expect(snapshot).toHaveBeenCalledWith(expect.objectContaining({ finding_paths: ['TestVuln.cs', 'services/orders.js', 'main.py'] }));
  // The skip is written when it is found, so it outlives this attempt and reaches the pull request.
  expect(remediationDb.recordSkippedFindings).toHaveBeenCalledWith(expect.objectContaining({ id: 'job-1' }), [{
    finding_id: 'f-cs', code: 'affected_source_missing',
    message: 'The finding source is unsupported or missing from the immutable tree.', stage: 'snapshot',
  }]);
  expect(logger.warn).toHaveBeenCalledWith('Findings were skipped because the immutable tree does not carry their source',
    expect.objectContaining({ job_id: 'job-1', skipped: 1, paths: ['TestVuln.cs'] }));
  // The repair still runs, on the findings whose sources the snapshot does carry.
  expect(repair.mock.calls[0][0].findings.map((finding) => finding.id)).toEqual(['f-js', 'f-py']);
  expect(remediationDb.completeStage.mock.calls[0][1].state).toBe('ready');
});

test('a snapshot that carries no selected source at all still ends the stage', async () => {
  withFindings([{ id: 'f-cs', file_path: 'TestVuln.cs' }]);
  withSnapshot({ head_sha: HEAD, base_sha: BASE, head_tree_oid: TREE, files: [], tree_entries: [],
    skipped: [{ path: 'TestVuln.cs', code: 'affected_source_missing', message: 'missing' }] });
  const repair = jest.fn();
  RemediationServiceClient.mockImplementation(() => ({ repair }));

  await executeClaimedJob(job());

  expect(repair).not.toHaveBeenCalled();
  const [, completion] = remediationDb.completeStage.mock.calls[0];
  expect(completion.reason).toMatchObject({ code: 'SNAPSHOT_UNAVAILABLE',
    message: 'Exact source snapshot does not cover the selected findings within policy' });
});
