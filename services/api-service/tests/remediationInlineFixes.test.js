// A ready job publishes its verified fixes under the finding comments: one section per
// candidate and finding with a suggestion when the fix is one contiguous region of the
// finding's file, a diff with the reason otherwise, and one line per skipped finding.
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  jobPublishContext: jest.fn(), recordInlineFixesPublished: jest.fn(async () => {}),
  hash: (value) => require('crypto').createHash('sha256').update(JSON.stringify(value)).digest('hex'),
  claimJobById: jest.fn(), claimActionById: jest.fn(),
}));
jest.mock('../src/db/findings', () => ({ listByAnalysisRun: jest.fn(async () => []) }));
jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn(() => ({})) }));
jest.mock('../src/services/mergeController', () => ({ evaluateForPullRequest: jest.fn(), publishVerificationCheck: jest.fn(), evaluateForAction: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));

const remediationDb = require('../src/db/remediation');
const findingsDb = require('../src/db/findings');
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

test('computeRegions lists every contiguous region on the original line numbers, insertions anchored to the line after them', () => {
  const twoRegions = ORIGINAL.replace('const db = require("./db");', 'const db = require("./db");\nconst { execFile } = require("child_process");')
    .replace('db.query(`SELECT * FROM orders WHERE id = ${id}`)', "db.query('SELECT * FROM orders WHERE id = $1', [id])");
  expect(inline.computeRegions(ORIGINAL, twoRegions, 3)).toEqual([
    { start_line: 1, end_line: 1, original_lines: ['const db = require("./db");'], replacement_lines: ['const db = require("./db");', 'const { execFile } = require("child_process");'] },
    { start_line: 3, end_line: 3, original_lines: ['  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);'], replacement_lines: ["  const rows = await db.query('SELECT * FROM orders WHERE id = $1', [id]);"] },
  ]);
  // A replacement that grows one line into three is one region; an unchanged file has none.
  const grown = ORIGINAL.replace('  return rows[0];', '  if (!rows.length) return null;\n  if (rows.length > 1) return null;\n  return rows[0];');
  expect(inline.computeRegions(ORIGINAL, grown, 4)).toEqual([
    { start_line: 4, end_line: 4, original_lines: ['  return rows[0];'], replacement_lines: ['  if (!rows.length) return null;', '  if (rows.length > 1) return null;', '  return rows[0];'] },
  ]);
  expect(inline.computeRegions(ORIGINAL, ORIGINAL, 3)).toEqual([]);
  expect(inline.computeRegions('', 'x\n', 1)).toEqual([]);
});

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

test('sections carry a suggestion hunk, the stated intent, the proof, evidence, limitations, and one line per skipped finding', () => {
  const sections = inline.buildSections(context());
  expect(sections).toHaveLength(2);
  expect(sections[0]).toMatchObject({
    candidate_id: '77777777-7777-4777-8777-777777777777', finding_fingerprint: 'fp-sql', path: 'services/orders.js', finding_line: 3,
    hunk: { start_line: 3, end_line: 3 }, not_suggestable_reason: '', verification_level: 'development_unverified',
    stated_intent: 'The order lookup returns the same row for the same id.',
    proof: 'regression test tests/orders.regression.test.js asserts that the SQL injection at services/orders.js:3 is no longer reproducible; it failed on the original code and passed on the fix.',
    evidence: ['Regression test tests/orders.regression.test.js: failed on the original code, passed on the fix.', 'Syntax check: passed on the fixed file.', 'Evidence digest: cccccccccccc.'],
    limitations: ['verification ran in the development local sandbox without network, kernel, or filesystem isolation'],
    finding_ids: ['f1'], covered_by: '', finding_body: '',
  });
  expect(sections[0]).not.toHaveProperty('behavior_preserved');
  expect(sections[0].unified_diff).toContain('@@ -3 +3 @@');
  expect(sections[1]).toMatchObject({ candidate_id: '', finding_fingerprint: 'fp-redirect', skipped_reason: 'This finding is outside the enabled repair families.', hunk: null, finding_ids: ['f2'] });
});

test('the proof line quotes a test that states its own assertion and picks the test written for the finding', () => {
  const stated = candidate({ preview: { ...candidate().preview, evidence: { ...candidate().preview.evidence, generated_tests: [
    { path: 'tests/other.test.js', finding_id: 'f9' },
    { path: 'tests/orders.regression.test.js', finding_id: 'f1', assertion: 'a quoted id cannot change the WHERE clause.' },
  ] } } });
  expect(inline.proofLine(stated, context().findings[0]))
    .toBe('regression test tests/orders.regression.test.js asserts that a quoted id cannot change the WHERE clause; it failed on the original code and passed on the fix.');
  expect(inline.proofLine(candidate({ preview: { ...candidate().preview, evidence: {} } }), context().findings[0]))
    .toBe('the generated regression test failed on the original code and passed on the fix.');
});

// Two findings on the same lines of the same file (two rules for one traversal): the
// candidate that proves one of them changes those lines for both. The other finding is
// published as fixed together with the proven one, never as having no automatic fix.
test('a finding on the same lines as a proven finding is covered by that candidate instead of reported as skipped', () => {
  const findings = [
    { id: 'f1', title: 'Path traversal', rule_id: 'js/path-traversal', file_path: 'services/orders.js', line_start: 35, line_end: 35, fingerprint: 'fp-traversal' },
    { id: 'f3', title: 'Uncontrolled path', rule_id: 'js/uncontrolled-path', file_path: 'services/orders.js', line_start: 35, line_end: 36, fingerprint: 'fp-uncontrolled' },
    { id: 'f2', title: 'Open redirect', rule_id: 'js/open-redirect', file_path: 'services/orders.js', line_start: 20, line_end: 20, fingerprint: 'fp-redirect' },
    { id: 'f4', title: 'Path traversal', rule_id: 'js/path-traversal', file_path: 'lib/other.js', line_start: 35, line_end: 35, fingerprint: 'fp-other-file' },
  ];
  const job = { ...context().job, failure_reason: { skipped: [
    { finding_id: 'f3', code: 'no_candidate', message: 'No candidate proved this finding.' },
    { finding_id: 'f2', code: 'unsupported_rule_family', message: 'This finding is outside the enabled repair families.' },
  ] } };
  const sections = inline.buildSections(context({ job, findings }));
  expect(sections.map((section) => [section.finding_fingerprint, section.candidate_id, section.covered_by, section.skipped_reason])).toEqual([
    ['fp-traversal', '77777777-7777-4777-8777-777777777777', '', ''],
    ['fp-uncontrolled', '77777777-7777-4777-8777-777777777777', 'js/path-traversal', ''],
    ['fp-redirect', '', '', 'This finding is outside the enabled repair families.'],
  ]);
  expect(sections[0].finding_ids).toEqual(['f1', 'f3']);
  expect(sections[1]).toMatchObject({ path: 'services/orders.js', finding_line: 35, finding_ids: ['f1', 'f3'], hunk: null, unified_diff: '' });
  expect(inline.sameLines(findings[0], findings[3])).toBe(false);
  expect(inline.sameLines({ file_path: 'a.js', line_start: 10, line_end: 12 }, { file_path: 'a.js', line_start: 12 })).toBe(true);
  expect(inline.sameLines({ file_path: 'a.js', line_start: 10, line_end: 12 }, { file_path: 'a.js', line_start: 13 })).toBe(false);
});

// The finding comment text travels with every section that carries or is covered by a
// fix, rendered by the analysis's own comment builder from the snapshotted finding, so
// the adapter can create the comment for a finding the analysis kept summary only.
test('sections with a fix carry the finding comment text the analysis would render; skipped findings carry none', async () => {
  findingsDb.listByAnalysisRun.mockResolvedValueOnce([
    { id: 'f1', fingerprint: 'fp-sql', title: 'SQL injection', severity: 'high', confidence: 0.85, cwe_id: 'CWE-89', file_path: 'services/orders.js', line_start: 3, line_end: 3,
      description: 'User input reaches the query.', evidence: 'Template literal in db.query', remediation: 'Use a parameterized query.', remediation_patch: null },
    { id: 'f2', fingerprint: 'fp-redirect', title: 'Open redirect', severity: 'medium', confidence: 0.7, file_path: 'services/orders.js', line_start: 20, description: 'x' },
  ]);
  const job = { ...context().job, analysis_run_id: 'run-1' };
  const sections = await inline.attachFindingBodies(job, inline.buildSections(context({ job })));
  expect(findingsDb.listByAnalysisRun).toHaveBeenCalledWith('run-1');
  expect(sections[0].finding_body).toContain('**HIGH** — SQL injection');
  expect(sections[0].finding_body).toContain('> Template literal in db.query');
  expect(sections[0].finding_body).toContain('**CWE:** CWE-89');
  expect(sections[0].finding_body).toContain('**Confidence:** 85%');
  expect(sections[0].finding_body).toContain('**Fix:** Use a parameterized query.');
  expect(sections[0].finding_body).not.toContain('mitig8it-finding');
  expect(sections[1].finding_body).toBe('');

  // No analysis run, or an unreadable snapshot, leaves the sections without bodies rather than failing the publication.
  expect((await inline.attachFindingBodies(context().job, inline.buildSections(context())))[0].finding_body).toBe('');
  findingsDb.listByAnalysisRun.mockRejectedValueOnce(new Error('connection lost'));
  expect((await inline.attachFindingBodies(job, inline.buildSections(context({ job }))))[0].finding_body).toBe('');
});

test('a fix touching several files is sent as a diff with the reason, and stale candidates are not offered', () => {
  const files = inline.buildSections(context({ candidates: [candidate({ preview: { ...candidate().preview, changes: [candidate().preview.changes[0], { path: 'lib/util.js', original: 'a\n', replacement: 'b\n', unified_diff: '@@ -1 +1 @@\n-a\n+b' }] } })] }));
  expect(files[0]).toMatchObject({ hunk: null, not_suggestable_reason: 'multiple_files' });
  expect(files[0].unified_diff).toContain('@@ -1 +1 @@');
  const stale = inline.buildSections(context({ candidates: [candidate({ rejection_reason: { code: 'head_changed' } })] }));
  expect(stale.map((section) => section.finding_fingerprint)).toEqual(['fp-redirect']);
});

// The repair service emits one candidate per proven finding, each carrying only that finding's
// hunks, its own regression test, and an evidence summary in full sentences. A candidate whose
// hunk lies on the finding's line becomes a suggestion; one that also adds an import elsewhere
// in the file is shown as a diff with the reason.
const TEXT_PY = [
  'import sqlite3', '', 'def get_user(user_id):', '    query = "SELECT * FROM users WHERE id = " + user_id', '    return execute_query(query)', '',
  '# Hardcoded credentials', 'API_KEY = "placeholder-not-a-key"', 'PASSWORD = "admin123"', '', '# Insecure eval', 'def process_input(user_input):',
  '    result = eval(user_input)', '    return result',
].join('\n') + '\n';
const CREDENTIAL_FIXED = TEXT_PY.replace('API_KEY = "placeholder-not-a-key"', 'import os\nAPI_KEY = os.environ["API_KEY"]');
const EVAL_FIXED = TEXT_PY.replace('import sqlite3\n', 'import sqlite3\nimport ast\n').replace('eval(user_input)', 'ast.literal_eval(user_input)');

function perFindingCandidate(id, findingId, replacement, unifiedDiff) {
  return candidate({
    id, finding_snapshot_ids: [findingId],
    preview: {
      changes: [{ path: 'text.py', original: TEXT_PY, replacement, unified_diff: unifiedDiff }],
      rationale: 'One finding, one candidate.',
      reasoning: { intended_behavior: 'Legitimate input behaves as before.' },
      evidence: {
        status: 'passed', evidence_digest: `sha256:${findingId.padEnd(64, '0')}`, verification_level: 'development_unverified',
        generated_tests: [{ path: `.mitig8it/regression/${findingId}.test.py`, finding_id: findingId }],
        limitations: ["the repository's original test suite was not run"],
        summary: [
          `Regression test .mitig8it/regression/${findingId}.test.py failed on the original code and passed on the fix.`,
          'Syntax check (generated_python_syntax) passed on the fix.',
          "Not run: the repository's original test suite was not run.",
        ],
      },
    },
  });
}

test('per-finding candidates each get their own section: a suggestion on the finding line, plus an extra hunk when the fix also adds an import elsewhere', () => {
  const sections = inline.buildSections(context({
    candidates: [
      perFindingCandidate('c-cred', 'f-cred', CREDENTIAL_FIXED, '--- a/text.py\n+++ b/text.py\n@@ -8 +8,2 @@\n-API_KEY = "placeholder-not-a-key"\n+import os\n+API_KEY = os.environ["API_KEY"]'),
      perFindingCandidate('c-eval', 'f-eval', EVAL_FIXED, '--- a/text.py\n+++ b/text.py\n@@ -1 +1,2 @@\n import sqlite3\n+import ast\n@@ -13 +14 @@\n-    result = eval(user_input)\n+    result = ast.literal_eval(user_input)'),
    ],
    findings: [
      { id: 'f-cred', title: 'Hardcoded credential', file_path: 'text.py', line_start: 8, line_end: 8, fingerprint: 'fp-cred' },
      { id: 'f-eval', title: 'Code injection via eval', file_path: 'text.py', line_start: 13, line_end: 13, fingerprint: 'fp-eval' },
    ],
  }));
  expect(sections.map((section) => [section.finding_fingerprint, section.candidate_id])).toEqual([['fp-cred', 'c-cred'], ['fp-eval', 'c-eval']]);
  expect(sections[0]).toMatchObject({
    path: 'text.py', finding_line: 8, not_suggestable_reason: '',
    hunk: { start_line: 8, end_line: 8, original_lines: ['API_KEY = "placeholder-not-a-key"'], replacement_lines: ['import os', 'API_KEY = os.environ["API_KEY"]'] },
    evidence: [
      'Regression test .mitig8it/regression/f-cred.test.py failed on the original code and passed on the fix.',
      'Syntax check (generated_python_syntax) passed on the fix.',
      "Not run: the repository's original test suite was not run.",
      'Evidence digest: sha256:f-cre.',
    ],
  });
  expect(sections[0].unified_diff).not.toContain('literal_eval');
  expect(sections[0].extra_hunks).toEqual([]);
  // The eval fix is two regions: the finding's line is the hunk, the added import travels as an extra hunk.
  expect(sections[1]).toMatchObject({
    path: 'text.py', finding_line: 13, not_suggestable_reason: '',
    hunk: { start_line: 13, end_line: 13, original_lines: ['    result = eval(user_input)'], replacement_lines: ['    result = ast.literal_eval(user_input)'] },
    extra_hunks: [{ start_line: 1, end_line: 1, original_lines: ['import sqlite3'], replacement_lines: ['import sqlite3', 'import ast'] }],
  });
  expect(sections[1].unified_diff).toContain('ast.literal_eval');
  expect(sections[1].evidence[0]).toBe('Regression test .mitig8it/regression/f-eval.test.py failed on the original code and passed on the fix.');
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

// A finding the analysis kept summary only has no comment for the adapter to update. The
// publication sends the comment text with the section so the adapter creates the comment
// on the finding's line, or as a pull request comment when that line is outside the diff,
// and the result says which happened.
test('publication carries the finding text for a finding without a comment and reports created and fallback comments', async () => {
  findingsDb.listByAnalysisRun.mockResolvedValue([
    { id: 'f1', fingerprint: 'fp-sql', title: 'SQL injection', severity: 'high', confidence: 0.85, file_path: 'services/orders.js', line_start: 3, description: 'User input reaches the query.' },
  ]);
  remediationDb.jobPublishContext.mockResolvedValue(context({ job: { ...context().job, analysis_run_id: 'run-1' } }));
  const github = { publishFindingFixSections: jest.fn(async (payload) => ({ state: 'published', results: [
    { finding_fingerprint: 'fp-sql', candidate_id: payload.sections[0].candidate_id, comment_id: 501, mode: 'suggestion', updated: true, reason: '', created: true, placement: 'inline' },
    { finding_fingerprint: 'fp-redirect', candidate_id: '', comment_id: 0, mode: 'comment_not_found', updated: false, reason: 'no finding comment carries this marker', created: false, placement: '' },
  ] })) };
  const result = await inline.publishInlineFixes(JOB, { githubClient: github });
  expect(result).toMatchObject({ published: true, sections: 2, comments_created: 1, pull_request_comments_created: 0, unplaced: 1 });
  const [payload] = github.publishFindingFixSections.mock.calls[0];
  expect(payload.sections[0]).toMatchObject({ path: 'services/orders.js', finding_line: 3, finding_ids: ['f1'] });
  expect(payload.sections[0].finding_body).toContain('**HIGH** — SQL injection');
  expect(payload.sections[1].finding_body).toBe('');

  // The diff-range fallback: the adapter placed the fix in a pull request comment because the line is outside the diff.
  github.publishFindingFixSections.mockResolvedValueOnce({ state: 'published', results: [
    { finding_fingerprint: 'fp-sql', candidate_id: 'c', comment_id: 601, mode: 'diff', updated: true, reason: "this finding's line is not part of the pull request diff", created: true, placement: 'pull_request' },
  ] });
  expect(await inline.publishInlineFixes(JOB, { githubClient: github })).toMatchObject({ published: true, comments_created: 0, pull_request_comments_created: 1, unplaced: 0 });
  findingsDb.listByAnalysisRun.mockReset();
  findingsDb.listByAnalysisRun.mockResolvedValue([]);
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

// The outcome log entry a publication produces. One row per finding the published
// candidate covers, and nothing at all for a finding no candidate repaired.
describe('publishedFixOutcomes', () => {
  const JOB_ROW = {
    id: JOB, repository_id: 'r-1', installation_id: 42, pull_request_id: 'pr-1', head_sha: HEAD,
  };
  const finding = (id, overrides = {}) => ({
    id, fingerprint: `${id}`.padEnd(64, '0'), rule_id: 'sql-injection', cwe_id: 'CWE-89',
    severity: 'high', confidence: 0.9, category: 'injection', repository_id: 'r-1',
    installation_id: 42, pull_request_id: 'pr-1', ...overrides,
  });

  test('records one fix_published per finding the candidate covers', () => {
    const outcomes = inline.publishedFixOutcomes({
      job: JOB_ROW,
      findings: [finding('f-1'), finding('f-2')],
      sections: [{ candidate_id: 'c-1', finding_ids: ['f-1', 'f-2'] }],
    });

    expect(outcomes).toHaveLength(2);
    expect(outcomes[0]).toMatchObject({
      findingId: 'f-1', outcome: 'fix_published', source: 'remediation',
      candidateId: 'c-1', externalId: 'c-1', jobId: JOB, repositoryId: 'r-1',
      installationId: 42, pullRequestId: 'pr-1', commitSha: HEAD, ruleId: 'sql-injection',
    });
  });

  test('a section with no candidate is a skipped finding and publishes nothing', () => {
    expect(inline.publishedFixOutcomes({
      job: JOB_ROW,
      findings: [finding('f-1')],
      sections: [{ candidate_id: '', finding_ids: ['f-1'] }],
    })).toEqual([]);
  });

  test('the same finding under the same candidate is recorded once', () => {
    const outcomes = inline.publishedFixOutcomes({
      job: JOB_ROW,
      findings: [finding('f-1')],
      sections: [
        { candidate_id: 'c-1', finding_ids: ['f-1'] },
        { candidate_id: 'c-1', finding_ids: ['f-1'] },
      ],
    });
    expect(outcomes).toHaveLength(1);
  });

  test('the same finding under two candidates is recorded once per candidate', () => {
    const outcomes = inline.publishedFixOutcomes({
      job: JOB_ROW,
      findings: [finding('f-1')],
      sections: [
        { candidate_id: 'c-1', finding_ids: ['f-1'] },
        { candidate_id: 'c-2', finding_ids: ['f-1'] },
      ],
    });
    expect(outcomes.map((outcome) => outcome.candidateId)).toEqual(['c-1', 'c-2']);
  });

  test('a finding with no snapshot behind it is skipped rather than recorded blank', () => {
    expect(inline.publishedFixOutcomes({
      job: JOB_ROW, findings: [], sections: [{ candidate_id: 'c-1', finding_ids: ['f-9'] }],
    })).toEqual([]);
  });
});
