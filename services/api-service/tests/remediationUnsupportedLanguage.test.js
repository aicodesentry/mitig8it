// Pull request 135 of nebullii/test-only carried 33 findings across five files: 12 in
// TestVuln.cs, 12 in TestVuln.java, 5 in cwe-vul.py, 3 in services/orders.js and 1 in
// main.py. The automatic job took all 33, the snapshot refused because the C# and Java
// sources are not in the tree it selects, and the job went inconclusive six seconds later,
// so the nine findings in supported languages got no fix either. A finding no toolchain can
// check is a per-finding skip, exactly as the documented abstain table says.
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));

const fs = require('fs');
const path = require('path');
const { pool } = require('../src/config/database');
const logger = require('../src/utils/logger');
const remediationDb = require('../src/db/remediation');
const languages = require('../src/services/remediationLanguages');
const policy = require('../src/services/remediationPolicy');
const autoGenerate = require('../src/services/remediationAutoGenerate');

const connect = pool.connect;
const PR = '11111111-1111-4111-8111-111111111111';
const RUN = '22222222-2222-4222-8222-222222222222';
const USER = '33333333-3333-4333-8333-333333333333';
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

function snapshot(id, filePath, severity = 'high') {
  return { finding_id: id, snapshot: { id, file_path: filePath, severity, fingerprint: `fp-${id}` } };
}

// The finding set of pull request 135, one row per affected file.
const MIXED = [
  snapshot('f-cs', 'TestVuln.cs', 'critical'),
  snapshot('f-java', 'TestVuln.java', 'critical'),
  snapshot('f-js', 'services/orders.js'),
  snapshot('f-py', 'cwe-vul.py'),
  snapshot('f-main', 'main.py', 'medium'),
];
const UNSUPPORTED_ONLY = [snapshot('f-cs', 'TestVuln.cs', 'critical'), snapshot('f-java', 'TestVuln.java', 'critical')];

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
  return { calls };
}

const prRow = { id: PR, repository_id: 'repo-1', head_sha: HEAD, base_sha: BASE, installation_id: 42, is_active: true, installation_status: 'active' };

function automaticScript(rows, extra = []) {
  return [
    ['FROM pull_requests pr', { rowCount: 1, rows: [prRow] }],
    ['FROM analysis_runs WHERE id = $1', { rowCount: 1, rows: [{ id: RUN }] }],
    ["origin = 'automatic'", { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings arf JOIN findings f', { rowCount: rows.length, rows }],
    ['FROM usage_reservations', { rows: [{ amount: '0' }] }],
    ['INSERT INTO remediation_jobs', (text, params) => ({ rowCount: 1, rows: [{ id: 'job-1', created: true, state_version: 1, installation_id: 42, repository_id: 'repo-1', head_sha: HEAD, finding_snapshot_ids: params[7] }] })],
    ...extra,
  ];
}

beforeEach(() => {
  jest.clearAllMocks();
  for (const [name, value] of Object.entries(FLAGS)) process.env[name] = value;
});

afterAll(() => { for (const name of Object.keys(FLAGS)) delete process.env[name]; });

// --- The rule itself ---------------------------------------------------------------

// The control plane may not decide support differently from the service that performs the
// repair. This reads the repair service's own suffix sets and fails on any drift.
test('the supported suffixes are exactly the ones the repair service reads from families.py', () => {
  const source = fs.readFileSync(path.join(__dirname, '../../remediation-service/src/families.py'), 'utf8');
  const suffixes = (name) => {
    const match = source.match(new RegExp(`${name} = frozenset\\(\\{([^}]*)\\}\\)`));
    if (!match) throw new Error(`families.py no longer declares ${name}`);
    return new Set(match[1].split(',').map((item) => item.trim().replace(/^["']|["']$/g, '')).filter(Boolean));
  };
  expect(languages.JAVASCRIPT_SUFFIXES).toEqual(suffixes('JAVASCRIPT_SUFFIXES'));
  expect(languages.PYTHON_SUFFIXES).toEqual(suffixes('PYTHON_SUFFIXES'));
  expect([...languages.JAVASCRIPT_SUFFIXES].sort()).toEqual(['.cjs', '.js', '.jsx', '.mjs', '.ts', '.tsx']);
  expect([...languages.PYTHON_SUFFIXES]).toEqual(['.py']);
});

test('a path is read for its language exactly as PurePosixPath reads it', () => {
  expect(languages.languageOfPath('services/orders.js')).toBe('javascript');
  expect(languages.languageOfPath('app/routes.TSX')).toBe('javascript');
  expect(languages.languageOfPath('main.py')).toBe('python');
  for (const unsupported of ['TestVuln.cs', 'TestVuln.java', 'Makefile', 'src/.py', 'README.md', '', null]) {
    expect(languages.languageOfPath(unsupported)).toBeNull();
  }
});

// --- Automatic selection -----------------------------------------------------------

test('a mixed-language analysis queues a job for the supported findings and records the rest as skips', async () => {
  const { calls } = scriptedClient(automaticScript(MIXED));
  const created = await remediationDb.createAutomaticJob({ pullRequestId: PR, analysisRunId: RUN, policy: policy.getPolicy() });

  expect(created.kind).toBe('ok');
  expect(created.selected).toEqual(['f-py', 'f-js', 'f-main']);
  expect(created.skipped).toEqual([
    { finding_id: 'f-cs', code: 'unsupported_language', message: languages.UNSUPPORTED_LANGUAGE_MESSAGE, stage: 'selection' },
    { finding_id: 'f-java', code: 'unsupported_language', message: languages.UNSUPPORTED_LANGUAGE_MESSAGE, stage: 'selection' },
  ]);

  const insert = calls.find((call) => call.text.includes('INSERT INTO remediation_jobs'));
  // The job's immutable selection carries no unsupported finding, so the snapshot it asks
  // for names only sources the tree can be expected to hold.
  expect(insert.params[7]).toEqual(['f-py', 'f-js', 'f-main']);
  expect(insert.params[6]).toBe(remediationDb.hash(['f-js', 'f-main', 'f-py']));
  // The skips are on the job from the moment it is created, which is what publishes the
  // `No automatic fix: unsupported_language` lines under those findings.
  expect(JSON.parse(insert.params[11]).skipped.map((item) => item.finding_id)).toEqual(['f-cs', 'f-java']);
  const audit = calls.find((call) => call.text.includes('INSERT INTO audit_logs'));
  expect(JSON.parse(audit.params[5]).skipped_findings).toEqual(['f-cs', 'f-java']);
});

test('an analysis with no supported finding queues no job at all and says so', async () => {
  const { calls } = scriptedClient(automaticScript(UNSUPPORTED_ONLY));
  const result = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN });

  expect(result).toEqual({ enqueued: false, reason: 'no_supported_findings', job_id: null, skipped: 2 });
  expect(calls.some((call) => call.text.includes('INSERT INTO remediation_jobs'))).toBe(false);
  // A queued job is not silently absent: the line that would have reported the queue
  // reports the refusal and how many findings it covered.
  expect(logger.info).toHaveBeenCalledWith(
    'No automatic remediation job queued after analysis: every open finding is in a language no repair toolchain can check',
    expect.objectContaining({ pull_request_id: PR, analysis_run_id: RUN, skipped_unsupported_language: 2 })
  );
  expect(logger.info).not.toHaveBeenCalledWith('Automatic remediation job queued after analysis', expect.anything());
});

test('the queue log line counts the findings taken and the findings skipped for language', async () => {
  scriptedClient(automaticScript(MIXED));
  const result = await autoGenerate.enqueueForCompletedAnalysis({ pullRequestId: PR, analysisRunId: RUN });
  expect(result).toEqual({ enqueued: true, job_id: 'job-1', findings: 3, skipped: 2 });
  expect(logger.info).toHaveBeenCalledWith('Automatic remediation job queued after analysis',
    expect.objectContaining({ job_id: 'job-1', findings: 3, skipped_unsupported_language: 2 }));
});

test('an analysis with no open finding at all is still reported as such, not as a language refusal', async () => {
  scriptedClient(automaticScript([]));
  expect(await remediationDb.createAutomaticJob({ pullRequestId: PR, analysisRunId: RUN, policy: policy.getPolicy() }))
    .toEqual({ kind: 'unsupported', reason: 'no_open_findings' });
});

// --- A user's own request ----------------------------------------------------------

function requestedScript(rows) {
  return [
    ['FROM pull_requests pr', { rowCount: 1, rows: [{ ...prRow, pr_state: 'open', repository_full_name: 'owner/repo' }] }],
    ['FROM analysis_runs', { rowCount: 1, rows: [{ id: RUN, commit_sha: HEAD }] }],
    ['FROM analysis_run_findings WHERE analysis_run_id', { rowCount: rows.length, rows }],
    ['INSERT INTO remediation_jobs', (text, params) => ({ rowCount: 1, rows: [{ id: 'job-9', created: true, state_version: 1, installation_id: 42, repository_id: 'repo-1', head_sha: HEAD, finding_snapshot_ids: params[7] }] })],
  ];
}

test('a user request for a mixed selection gets a job for the supported findings and the skips back', async () => {
  const { calls } = scriptedClient(requestedScript(MIXED));
  const created = await remediationDb.createJob({
    pullRequestId: PR, userId: USER, findingIds: MIXED.map((row) => row.finding_id), policy: policy.getPolicy(),
  });

  expect(created.kind).toBe('ok');
  expect(created.snapshots.map((row) => row.finding_id)).toEqual(['f-js', 'f-py', 'f-main']);
  expect(created.skipped.map((item) => item.finding_id)).toEqual(['f-cs', 'f-java']);
  const insert = calls.find((call) => call.text.includes('INSERT INTO remediation_jobs'));
  expect(insert.params[7]).toEqual(['f-js', 'f-py', 'f-main']);
  expect(JSON.parse(insert.params[12]).skipped.map((item) => item.code)).toEqual(['unsupported_language', 'unsupported_language']);
});

test('a user request naming only unsupported findings creates no job and names the reason', async () => {
  const { calls } = scriptedClient(requestedScript(UNSUPPORTED_ONLY));
  const created = await remediationDb.createJob({
    pullRequestId: PR, userId: USER, findingIds: UNSUPPORTED_ONLY.map((row) => row.finding_id), policy: policy.getPolicy(),
  });
  expect(created.kind).toBe('unsupported');
  expect(created.reason).toBe('no_supported_findings');
  expect(created.skipped.map((item) => item.finding_id)).toEqual(['f-cs', 'f-java']);
  expect(calls.some((call) => call.text.includes('INSERT INTO remediation_jobs'))).toBe(false);
});

// --- The skips outlive the attempt --------------------------------------------------

// `completeStage` replaces failure_reason wholesale with the repair service's reason, so
// without this the selection skips would vanish the moment the job reached a state.
test('a completion keeps the skips the control plane decided and never repeats a finding', () => {
  const selection = { skipped: [
    { finding_id: 'f-cs', code: 'unsupported_language', message: 'no toolchain', stage: 'selection' },
    { finding_id: 'f-java', code: 'unsupported_language', message: 'no toolchain', stage: 'selection' },
  ] };

  expect(remediationDb.mergeCarriedSkips(selection, null)).toEqual(selection);
  expect(remediationDb.mergeCarriedSkips(selection, { code: 'ready' })).toEqual({ code: 'ready', skipped: selection.skipped });

  const reported = { code: 'ready', skipped: [{ finding_id: 'f-js', code: 'not_repaired', message: 'no test reproduced it' }] };
  const merged = remediationDb.mergeCarriedSkips(selection, reported);
  expect(merged.skipped.map((item) => item.finding_id)).toEqual(['f-js', 'f-cs', 'f-java']);

  // The repair service's own word about a finding wins over the carried one.
  const overlapping = { code: 'ready', skipped: [{ finding_id: 'f-cs', code: 'affected_source_missing', message: 'gone' }] };
  expect(remediationDb.mergeCarriedSkips(selection, overlapping).skipped).toEqual([
    { finding_id: 'f-cs', code: 'affected_source_missing', message: 'gone' },
    { finding_id: 'f-java', code: 'unsupported_language', message: 'no toolchain', stage: 'selection' },
  ]);

  // A job with nothing carried is untouched, so an ordinary completion writes what it was given.
  expect(remediationDb.mergeCarriedSkips(null, { code: 'boom' })).toEqual({ code: 'boom' });
  expect(remediationDb.mergeCarriedSkips({ code: 'boom' }, null)).toBeNull();
});

// --- The skip reaches the pull request ----------------------------------------------

// A skipped finding is not in `finding_snapshot_ids`, so the job's finding snapshots have
// to cover it as well, or the `No automatic fix` line has no finding to sit under and the
// skip is recorded in the database and seen nowhere.
test('a job publishes a No automatic fix line for a finding it never selected', async () => {
  const buildSections = require('../src/services/remediationInlineFixes').buildSections;
  const jobRow = {
    id: 'job-1', installation_id: 42, repository_id: 'repo-1', analysis_run_id: RUN, head_sha: HEAD,
    finding_snapshot_ids: ['f-js'],
    failure_reason: { skipped: [{ finding_id: 'f-cs', code: 'unsupported_language', message: languages.UNSUPPORTED_LANGUAGE_MESSAGE, stage: 'selection' }] },
  };
  const rows = {
    'f-js': { file_path: 'services/orders.js', title: 'SQL injection', fingerprint: 'fp-js', line_start: 3, line_end: 3 },
    'f-cs': { file_path: 'TestVuln.cs', title: 'SQL injection', fingerprint: 'fp-cs', line_start: 11, line_end: 11 },
  };
  let requested = [];
  scriptedClient([
    ['FROM remediation_jobs j', { rowCount: 1, rows: [jobRow] }],
    ['FROM remediation_candidates', { rowCount: 0, rows: [] }],
    ['FROM verification_runs', { rowCount: 0, rows: [] }],
    ['FROM analysis_run_findings WHERE analysis_run_id', (text, params) => {
      requested = params[1];
      return { rowCount: requested.length, rows: requested.map((id) => ({ finding_id: id, snapshot: rows[id] })) };
    }],
  ]);

  const context = await remediationDb.jobPublishContext('job-1');
  // Both the selected finding and the skipped one are read, so the publisher can name both.
  expect(requested).toEqual(['f-js', 'f-cs']);
  expect(context.findings.map((finding) => finding.id)).toEqual(['f-js', 'f-cs']);

  const sections = buildSections({ job: jobRow, candidates: [], findings: context.findings });
  expect(sections).toEqual([expect.objectContaining({
    finding_fingerprint: 'fp-cs', path: 'TestVuln.cs', candidate_id: '',
    skipped_reason: languages.UNSUPPORTED_LANGUAGE_MESSAGE,
  })]);
});
