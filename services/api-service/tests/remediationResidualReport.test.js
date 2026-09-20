jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  actionCheckContext: jest.fn(), blockingFindingsForAction: jest.fn(), appliedReportForAction: jest.fn(),
  recordResidualComment: jest.fn(async () => ({})), listActionsNeedingResidualComment: jest.fn(async () => []),
}));
jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn(() => ({})) }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));

const remediationDb = require('../src/db/remediation');
const report = require('../src/services/remediationResidualReport');

const ACTION_ID = '22222222-2222-4222-8222-222222222222';
const APPLIED = 'a'.repeat(40);
const action = {
  id: ACTION_ID, installation_id: 42, repository_id: '33333333-3333-4333-8333-333333333333', state: 'completed',
  actor_login: 'nebullii', repository_full_name: 'owner/repo', pr_number: 7, head_sha: 'e'.repeat(40), base_sha: 'b'.repeat(40),
  batch_manifest_digest: 'd'.repeat(64), idempotency_key: 'idempotency-key', observed_commit_sha: APPLIED, verification_head_sha: APPLIED,
  candidate_ids: ['77777777-7777-4777-8777-777777777777'], job_id: '66666666-6666-4666-8666-666666666666',
};
const analysis = { analysisState: 'completed', blocking: 2, open: [
  { id: 'f1', title: 'Command injection', file_path: 'services/orders.js', line_start: 20, severity: 'high', informational: false },
  { id: 'f2', title: 'Path traversal', file_path: 'services/orders.js', line_start: 40, severity: 'medium', informational: false },
  { id: 'f3', title: 'Hardcoded secret', file_path: 'tests/orders.test.js', line_start: 3, severity: 'info', informational: true },
] };
const applied = [{ finding_id: 'f0', title: 'SQL injection', file_path: 'services/customers.js', line_start: 12, severity: 'high' }];
const unsupported = [{ finding_id: 'f4', title: 'Open redirect', file_path: 'services/orders.js', line_start: 55, reason: 'unsupported_rule_family' }];

beforeEach(() => {
  jest.clearAllMocks();
  remediationDb.actionCheckContext.mockResolvedValue({ action, candidates: [] });
  remediationDb.blockingFindingsForAction.mockResolvedValue(analysis);
  remediationDb.appliedReportForAction.mockResolvedValue({ applied, unsupported });
});

test('the report lists what was applied and what remains open by file and severity, with reasons for unrepaired items', () => {
  const text = report.buildReport({ action, analysis, applied, unsupported });
  expect(text).toContain('Applied by an explicit request from @nebullii in commit aaaaaaaaaaaa.');
  expect(text).toContain('Applied (1 fix):\n- SQL injection in services/customers.js:12');
  expect(text).toContain("Remaining open findings in the pull request's changed files: 2 (plus 1 informational finding in test code).");
  expect(text).toContain('- services/orders.js\n  - high: Command injection (line 20)\n  - medium: Path traversal (line 40)');
  expect(text).toContain('- Informational, test code (listed, not blocking):\n  - Hardcoded secret in tests/orders.test.js:3');
  expect(text).toContain('Not repaired automatically (1):\n- Open redirect in services/orders.js:55: unsupported_rule_family');
  expect(text.trim().endsWith('Merging stays a human action on GitHub.')).toBe(true);
});

test('an incomplete analysis is reported as not established, never as clean', () => {
  const text = report.buildReport({ action, analysis: { analysisState: 'running' }, applied, unsupported: [] });
  expect(text).toContain('Remaining open findings: not established (analysis of the applied commit is running).');
});

test('one comment per action: publication uses the action id as external id and records the comment', async () => {
  const github = { publishComment: jest.fn(async () => ({ state: 'published', comment_id: 501, updated: false })) };
  const first = await report.publishResidualComment(ACTION_ID, { githubClient: github });
  expect(first.published).toBe(true);
  const payload = github.publishComment.mock.calls[0][0];
  expect(payload.external_id).toBe(ACTION_ID);
  expect(payload.head_sha).toBe(APPLIED);
  expect(payload.body).toContain('### Mitig8it remediation report');
  expect(payload.body).toContain('SQL injection in services/customers.js:12');
  expect(remediationDb.recordResidualComment).toHaveBeenCalledWith(action, { commentId: 501, headSha: APPLIED });

  github.publishComment.mockResolvedValue({ state: 'published', comment_id: 501, updated: true });
  const second = await report.publishResidualComment(ACTION_ID, { githubClient: github });
  expect(second).toEqual(expect.objectContaining({ published: true, updated: true, comment_id: 501 }));
  expect(github.publishComment.mock.calls[1][0].external_id).toBe(ACTION_ID);
});

test('nothing is posted before the action is completed or while the analysis is incomplete', async () => {
  const github = { publishComment: jest.fn() };
  remediationDb.actionCheckContext.mockResolvedValue({ action: { ...action, state: 'checking' }, candidates: [] });
  expect(await report.publishResidualComment(ACTION_ID, { githubClient: github })).toEqual({ published: false, reason: 'action_not_completed' });
  remediationDb.actionCheckContext.mockResolvedValue({ action, candidates: [] });
  remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'running' });
  expect(await report.publishResidualComment(ACTION_ID, { githubClient: github })).toEqual({ published: false, reason: 'verification_analysis_incomplete' });
  expect(github.publishComment).not.toHaveBeenCalled();
  expect(remediationDb.recordResidualComment).not.toHaveBeenCalled();
});

test('a publication failure is reported and never recorded as published', async () => {
  const github = { publishComment: jest.fn().mockRejectedValue(new Error('gateway')) };
  const result = await report.publishResidualComment(ACTION_ID, { githubClient: github });
  expect(result.published).toBe(false);
  expect(remediationDb.recordResidualComment).not.toHaveBeenCalled();
});

test('the pending sweep republishes only actions whose report is missing for their head', async () => {
  remediationDb.listActionsNeedingResidualComment.mockResolvedValue([ACTION_ID]);
  const github = { publishComment: jest.fn(async () => ({ state: 'published', comment_id: 9, updated: true })) };
  const result = await report.publishPendingResidualComments({ githubClient: github, limit: 5 });
  expect(result).toEqual({ attempted: 1, published: 1 });
  expect(remediationDb.listActionsNeedingResidualComment).toHaveBeenCalledWith(5);
});
