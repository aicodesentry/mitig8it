// A ready job publishes its verified fixes under the finding comments: one section per
// candidate and finding with a suggestion when the fix is one contiguous region of the
// finding's file, a diff with the reason otherwise, and one line per skipped finding.
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  jobPublishContext: jest.fn(), recordInlineFixesPublished: jest.fn(async () => {}),
  hash: (value) => require('crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex'),
  claimJobById: jest.fn(), claimActionById: jest.fn(),
}));
jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn(() => ({})) }));
jest.mock('../src/services/mergeController', () => ({ evaluateForPullRequest: jest.fn(), publishVerificationCheck: jest.fn(), evaluateForAction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));

const remediationDb = require('../src/db/remediation');
const inline = require('../src/services/remediationInlineFixes');
const outbox = require('../src/services/remediationOutbox');

const JOB = '66666666-6666-4666-8666-666666666666';
const HEAD = 'e'.repeat(40);
const FLAGS = {
  REMEDIATION_ENABLED: 'true', REMEDIATION_GENERATE_ENABLED: 'true', REMEDIATION_PUBLISH_ENABLED: 'true',
  REMEDIATION_SERVICE_URL: 'http://repair', REMEDIATION_SERVICE_INTERNAL_SECRET: 'secret',
  GITHUB_SERVICE_URL: 'http://github', GITHUB_SERVICE_INTERNAL_SECRET: 'secret',
  REMEDIATION_SANDBOX_IMAGE_DIGEST: 'sha256:abc', REMEDIATION_VERIFICATION_CHECKS_JSON: '["unit"]',
  REMEDIATION_ALLOWED_RULE_FAMILIES_JSON: '["sql_parameterization"]',
  REMEDIATION_INPUT_USD_PER_MILLION_TOKENS: '1', REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS: '2',
  FRONTEND_URL: 'https://app.example.test/',
};

const ORIGINAL = ['const db = require("./db");', 'async function order(id) {', '  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);', '  return rows[0];', '}', 'module.exports = { order };'].join('\n') + '\n';
const FIXED = ORIGINAL.replace('db.query(`SELECT * FROM orders WHERE id = ${id}`)', "db.query('SELECT * FROM orders WHERE id = $1', [id])");

function candidate(overrides = {}) {
  return {
    id: '77777777-7777-4777-8777-777777777777', finding_snapshot_ids: ['f1'], artifact_digest: 'a'.repeat(64), rejection_reason: null,
    verification_level: 'development_unverified',
    preview: {
      changes: [{ path: 'services/orders.js', original: ORIGINAL, replacement: FIXED, unified_diff: '--- a/services/orders.js\n+++ b/services/orders.js\n@@ -3 +3 @@\n-  old\n+  new' }],
      rationale: 'Parameterize the query.',
      reasoning: { intended_behavior: 'The order lookup returns the same row for the same id.' },
      evidence: { status: 'passed', evidence_digest: 'c'.repeat(64), verification_level: 'development_unverified',
        generated_tests: [{ path: 'tests/orders.regression.test.js' }],
        limitations: ['verification ran in the development local sandbox without network, kernel, or filesystem isolation'] },
    },
    ...overrides,
  };
}

function context(overrides = {}) {
  return {
    job: { id: JOB, state: 'ready', state_version: 7, installation_id: 42, repository_id: 'repo-1', pull_request_id: 'pr-1', head_sha: HEAD, current_head_sha: HEAD,
      base_sha: 'b'.repeat(40), repository_full_name: 'owner/repo', repository_active: true, installation_status: 'active', pr_number: 9, creator_login: null,
      failure_reason: { skipped: [{ finding_id: 'f2', code: 'unsupported_rule_family', message: 'This finding is outside the enabled repair families.' }] } },
    candidates: [candidate()],
    verification: { outcome: 'passed', limitations: [] },
    manifestDigest: 'd'.repeat(64),
    findings: [
      { id: 'f1', title: 'SQL injection', file_path: 'services/orders.js', line_start: 3, line_end: 3, fingerprint: 'fp-sql' },
      { id: 'f2', title: 'Open redirect', file_path: 'services/orders.js', line_start: 20, line_end: 20, fingerprint: 'fp-redirect' },
    ],
    ...overrides,
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  for (const [name, value] of Object.entries(FLAGS)) process.env[name] = value;
});
afterAll(() => { for (const name of Object.keys(FLAGS)) delete process.env[name]; });

test('computeHunk finds the smallest contiguous region and anchors a pure insertion to the finding line', () => {
  expect(inline.computeHunk(ORIGINAL, FIXED, 3)).toEqual({
    start_line: 3, end_line: 3,
    original_lines: ['  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);'],
    replacement_lines: ["  const rows = await db.query('SELECT * FROM orders WHERE id = $1', [id]);"],
  });
  const inserted = ORIGINAL.replace('  return rows[0];', '  if (!rows.length) return null;\n  return rows[0];');
  expect(inline.computeHunk(ORIGINAL, inserted, 4)).toEqual({
    start_line: 4, end_line: 4, original_lines: ['  return rows[0];'], replacement_lines: ['  if (!rows.length) return null;', '  return rows[0];'],
  });
  expect(inline.computeHunk(ORIGINAL, inserted, 3)).toEqual({
    start_line: 3, end_line: 3, original_lines: ['  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);'],
    replacement_lines: ['  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);', '  if (!rows.length) return null;'],
  });
  expect(inline.computeHunk(ORIGINAL, ORIGINAL, 3)).toBeNull();
});

test('sections carry a suggestion hunk, the behavior line, evidence, limitations, and one line per skipped finding', () => {
  const sections = inline.buildSections(context());
  expect(sections).toHaveLength(2);
  expect(sections[0]).toMatchObject({
    candidate_id: '77777777-7777-4777-8777-777777777777', finding_fingerprint: 'fp-sql', path: 'services/orders.js', finding_line: 3,
    hunk: { start_line: 3, end_line: 3 }, not_suggestable_reason: '', verification_level: 'development_unverified',
    behavior_preserved: 'The order lookup returns the same row for the same id.',
    evidence: ['Regression test tests/orders.regression.test.js: failed on the original code, passed on the fix.', 'Syntax check: passed on the fixed file.', 'Evidence digest: cccccccccccc.'],
    limitations: ['verification ran in the development local sandbox without network, kernel, or filesystem isolation'],
  });
  expect(sections[0].unified_diff).toContain('@@ -3 +3 @@');
  expect(sections[1]).toMatchObject({ candidate_id: '', finding_fingerprint: 'fp-redirect', skipped_reason: 'This finding is outside the enabled repair families.', hunk: null });
});

test('a fix touching several regions or files is sent as a diff with the reason, and stale candidates are not offered', () => {
  const regions = inline.buildSections(context({ candidates: [candidate({ preview: { ...candidate().preview, changes: [{ ...candidate().preview.changes[0], unified_diff: '@@ -3 +3 @@\n-a\n+b\n@@ -40 +40 @@\n-c\n+d' }] } })] }));
  expect(regions[0]).toMatchObject({ hunk: null, not_suggestable_reason: 'multiple_regions' });
  const files = inline.buildSections(context({ candidates: [candidate({ preview: { ...candidate().preview, changes: [candidate().preview.changes[0], { path: 'lib/util.js', original: 'a\n', replacement: 'b\n', unified_diff: '@@ -1 +1 @@\n-a\n+b' }] } })] }));
  expect(files[0]).toMatchObject({ hunk: null, not_suggestable_reason: 'multiple_files' });
  expect(files[0].unified_diff).toContain('@@ -1 +1 @@');
  const stale = inline.buildSections(context({ candidates: [candidate({ rejection_reason: { code: 'head_changed' } })] }));
  expect(stale.map((section) => section.finding_fingerprint)).toEqual(['fp-redirect']);
});

test('publication sends every section once with a stable idempotency key and records the head it was written for', async () => {
  remediationDb.jobPublishContext.mockResolvedValue(context());
  const github = { publishFindingFixSections: jest.fn(async () => ({ state: 'published', results: [{ finding_fingerprint: 'fp-sql', mode: 'suggestion', updated: true }] })) };
  const first = await inline.publishInlineFixes(JOB, { githubClient: github });
  expect(first).toMatchObject({ published: true, sections: 2 });
  const payload = github.publishFindingFixSections.mock.calls[0][0];
  expect(payload).toMatchObject({
    installation_id: 42, repository_full_name: 'owner/repo', actor_login: 'system', pr_number: 9, head_sha: HEAD, base_sha: 'b'.repeat(40),
    manifest_digest: 'd'.repeat(64), action_id: `inline-fix-${JOB}`, idempotency_key: `inline-fix:${JOB}:7`,
    preview_url: 'https://app.example.test/dashboard/pull-requests/pr-1/findings',
  });
  expect(payload.sections.map((section) => section.finding_fingerprint)).toEqual(['fp-sql', 'fp-redirect']);
  expect(remediationDb.recordInlineFixesPublished).toHaveBeenCalledWith(context().job, { headSha: HEAD });

  // A retry produces the identical request: the adapter's candidate markers make the write idempotent.
  await inline.publishInlineFixes(JOB, { githubClient: github });
  expect(github.publishFindingFixSections.mock.calls[1][0]).toEqual(payload);
});

test('publication is refused when the flag is off, the job is not ready, or the head moved, without any GitHub call', async () => {
  const github = { publishFindingFixSections: jest.fn() };
  process.env.REMEDIATION_PUBLISH_ENABLED = 'false';
  expect(await inline.publishInlineFixes(JOB, { githubClient: github })).toEqual({ published: false, reason: 'publish_disabled' });
  process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
  remediationDb.jobPublishContext.mockResolvedValue(context({ job: { ...context().job, state: 'superseded' } }));
  expect(await inline.publishInlineFixes(JOB, { githubClient: github })).toEqual({ published: false, reason: 'job_not_ready' });
  remediationDb.jobPublishContext.mockResolvedValue(context({ job: { ...context().job, current_head_sha: 'f'.repeat(40) } }));
  expect(await inline.publishInlineFixes(JOB, { githubClient: github })).toEqual({ published: false, reason: 'head_moved' });
  expect(github.publishFindingFixSections).not.toHaveBeenCalled();
  expect(remediationDb.recordInlineFixesPublished).not.toHaveBeenCalled();
});

test('an unconfirmed adapter result is reported and not recorded', async () => {
  remediationDb.jobPublishContext.mockResolvedValue(context());
  const github = { publishFindingFixSections: jest.fn(async () => ({ state: 'stale', reason: 'head_moved', results: [] })) };
  expect(await inline.publishInlineFixes(JOB, { githubClient: github })).toEqual({ published: false, reason: 'head_moved' });
  expect(remediationDb.recordInlineFixesPublished).not.toHaveBeenCalled();
});

test('the outbox routes remediation.ready to the publication and records refusals as handled', async () => {
  outbox.registerDefaultHandlers({ executeClaimedJob: async () => {}, executeClaimedAction: async () => {}, workerId: 'test' });
  const handler = outbox.resolveHandler('remediation.ready');
  const { GitHubRemediationClient } = require('../src/services/githubRemediationClient');
  const publish = jest.fn(async () => ({ state: 'published', results: [] }));
  GitHubRemediationClient.mockImplementation(() => ({ publishFindingFixSections: publish }));
  remediationDb.jobPublishContext.mockResolvedValue(context());
  expect(await handler({ aggregate_id: JOB })).toEqual({ status: 'executed', sections: 2 });
  expect(publish).toHaveBeenCalledTimes(1);
  remediationDb.jobPublishContext.mockResolvedValue(null);
  expect(await handler({ aggregate_id: JOB })).toEqual({ status: 'skipped', reason: 'job_not_found' });
  // A transport failure propagates so the outbox retries with backoff.
  remediationDb.jobPublishContext.mockResolvedValue(context());
  publish.mockRejectedValueOnce(Object.assign(new Error('ECONNREFUSED'), { code: 'ECONNREFUSED' }));
  await expect(handler({ aggregate_id: JOB })).rejects.toThrow('ECONNREFUSED');
});
