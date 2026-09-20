jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  mergeIntentContext: jest.fn(), listEvaluableMergeIntents: jest.fn(), listMergeIntentIdsForPullRequest: jest.fn(),
  mergeIntentIdForAction: jest.fn(), transitionMergeIntent: jest.fn(), recordMergeEvaluation: jest.fn(),
  blockingFindingsForAction: jest.fn(), recordVerificationCheck: jest.fn(),
  listActionsNeedingVerificationCheck: jest.fn(), actionCheckContext: jest.fn(),
  appliedReportForAction: jest.fn(async () => ({ applied: [], unsupported: [] })),
}));
jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn(() => ({})) }));

const remediationDb = require('../src/db/remediation');
const mergeController = require('../src/services/mergeController');

const INTENT_ID = '11111111-1111-4111-8111-111111111111';
const ACTION_ID = '22222222-2222-4222-8222-222222222222';
const APPLIED = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const MERGE_SHA = 'c'.repeat(40);
const DIGEST = 'd'.repeat(64);

const MERGE_ENV = [
  'REMEDIATION_ENABLED', 'REMEDIATION_MERGE_ENABLED', 'GITHUB_SERVICE_URL', 'GITHUB_SERVICE_INTERNAL_SECRET',
  'REMEDIATION_MAX_MERGE_ATTEMPTS', 'REMEDIATION_MERGE_SWEEP_MINUTES',
];

function enableMerge() {
  process.env.REMEDIATION_ENABLED = 'true';
  process.env.REMEDIATION_MERGE_ENABLED = 'true';
  process.env.GITHUB_SERVICE_URL = 'http://github';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'github';
}

function intent(overrides = {}) {
  return {
    id: INTENT_ID, action_id: ACTION_ID, installation_id: 42, repository_id: '33333333-3333-4333-8333-333333333333',
    actor_id: '44444444-4444-4444-8444-444444444444', actor_login: 'actor', state: 'waiting_for_checks',
    state_version: '3', merge_attempts: 0, blockers: [], merge_method: 'squash',
    approved_manifest_digest: DIGEST, approved_head_sha: 'e'.repeat(40), approved_base_sha: BASE,
    applied_sha: APPLIED, expires_at: new Date(Date.now() + 3600000).toISOString(),
    action_state: 'completed', observed_commit_sha: APPLIED, observed_tree_oid: 'f'.repeat(40),
    batch_manifest_digest: DIGEST, idempotency_key: 'idempotency-key', pull_request_id: '55555555-5555-4555-8555-555555555555',
    job_id: '66666666-6666-4666-8666-666666666666', candidate_ids: ['77777777-7777-4777-8777-777777777777'],
    verification_analysis_run_id: '88888888-8888-4888-8888-888888888888', verification_head_sha: APPLIED,
    verification_check_status: 'completed', verification_check_conclusion: 'success', verification_check_head_sha: APPLIED,
    repository_full_name: 'owner/repo', repository_active: true, pr_number: 7, pull_request_state: 'open',
    installation_status: 'active', ...overrides,
  };
}

function githubClient(overrides = {}) {
  return {
    authorize: jest.fn().mockResolvedValue({ state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: true }),
    readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: APPLIED, base_sha: BASE, state: 'open', draft: false, merged: false, fork: false, mergeable_state: 'clean' }),
    readMergeEligibility: jest.fn().mockResolvedValue({ eligible: true, blockers: [], protection_source: 'branch_protection' }),
    merge: jest.fn().mockResolvedValue({ state: 'merged', operation_id: ACTION_ID, commit_sha: MERGE_SHA }),
    cancelScheduledMerge: jest.fn().mockResolvedValue({ state: 'cancelled', operation_id: ACTION_ID, merged: false }),
    createCheckRun: jest.fn().mockResolvedValue({ state: 'published', check_run_id: 99, external_id: ACTION_ID }),
    ...overrides,
  };
}

function transitions() {
  return remediationDb.transitionMergeIntent.mock.calls.map(([, state]) => state);
}

function lastTransition(state) {
  const call = [...remediationDb.transitionMergeIntent.mock.calls].reverse().find(([, next]) => next === state);
  return call ? call[2] || {} : null;
}

describe('merge controller', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    enableMerge();
    // A transition succeeds by default and returns the row the caller would re-read.
    remediationDb.transitionMergeIntent.mockImplementation(async (row, state, fields = {}) => ({
      ...row, state, state_version: String(Number(row.state_version) + 1),
      merge_attempts: Number(row.merge_attempts || 0) + (fields.attempt ? 1 : 0),
      blockers: fields.blockers || row.blockers,
    }));
    remediationDb.recordMergeEvaluation.mockImplementation(async (row, fields = {}) => ({
      ...row, state_version: String(Number(row.state_version) + 1), blockers: fields.blockers || [],
    }));
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 0, commitSha: APPLIED });
    remediationDb.recordVerificationCheck.mockResolvedValue({});
  });
  afterEach(() => { for (const name of MERGE_ENV) delete process.env[name]; });

  test('an eligible intent merges and records the observed merge SHA', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(transitions()).toEqual(['eligible', 'merging', 'merged']);
    expect(result.state).toBe('merged');
    expect(lastTransition('merged').observedMergeSha).toBe(MERGE_SHA);
    // The intent and its operation identity are durable before the write.
    expect(lastTransition('merging').operationId).toBe(ACTION_ID);
    expect(github.merge).toHaveBeenCalledTimes(1);
    expect(github.merge.mock.calls[0][0].expected_head_sha).toBe(APPLIED);
  });

  test('waiting_for_application advances to waiting_for_checks once the action is applied', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(
      intent({ state: 'waiting_for_application', action_state: 'applied' }), { githubClient: github });
    expect(transitions()).toEqual(['waiting_for_checks']);
    expect(result.blockers).toEqual(['application_verification_pending']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('the global kill switch blocks the merge before any GitHub call', async () => {
    delete process.env.REMEDIATION_ENABLED;
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['global_kill_switch_off']);
    expect(github.authorize).not.toHaveBeenCalled();
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('the merge feature flag alone blocks the merge', async () => {
    delete process.env.REMEDIATION_MERGE_ENABLED;
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.blockers).toEqual(['merge_flag_off']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a revoked actor permission blocks the merge', async () => {
    const github = githubClient({
      authorize: jest.fn().mockResolvedValue({ state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: false }),
    });
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['actor_write_permission_missing']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('an inactive installation blocks the merge', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent({ installation_status: 'suspended' }), { githubClient: github });
    expect(result.blockers).toEqual(['installation_or_repository_inactive']);
    expect(github.authorize).not.toHaveBeenCalled();
  });

  test('a moved head supersedes the intent instead of merging a different revision', async () => {
    const github = githubClient({
      readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: '9'.repeat(40), base_sha: BASE, state: 'open', merged: false, fork: false }),
    });
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('superseded');
    expect(lastTransition('superseded').reason).toBe('head_changed');
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a moved base supersedes the intent', async () => {
    const github = githubClient({
      readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: APPLIED, base_sha: '8'.repeat(40), state: 'open', merged: false, fork: false }),
    });
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('superseded');
    expect(lastTransition('superseded').reason).toBe('base_changed');
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a blocking finding on the applied head blocks the merge', async () => {
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 2 });
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['blocking_findings_present']);
    expect(github.readMergeEligibility).not.toHaveBeenCalled();
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('an incomplete verification analysis keeps the intent waiting rather than blocked', async () => {
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'pending', blocking: null });
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('waiting_for_checks');
    expect(result.blockers).toEqual(['verification_analysis_incomplete']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a missing verification check is a blocker, never an assumed pass', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(
      intent({ verification_check_status: null, verification_check_conclusion: null, verification_check_head_sha: null }),
      { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['verification_check_not_published']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a failed verification check blocks the merge', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(
      intent({ verification_check_conclusion: 'failure' }), { githubClient: github });
    expect(result.blockers).toEqual(['verification_check_not_successful']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('eligibility blockers from GitHub are persisted verbatim', async () => {
    const github = githubClient({
      readMergeEligibility: jest.fn().mockResolvedValue({
        eligible: false, blockers: ['verification_check_not_required', 'required_approvals_missing'], protection_source: 'branch_protection',
      }),
    });
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['verification_check_not_required', 'required_approvals_missing']);
    expect(lastTransition('blocked').blockers).toEqual(['verification_check_not_required', 'required_approvals_missing']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('an unreadable eligibility response blocks rather than merging', async () => {
    const github = githubClient({ readMergeEligibility: jest.fn().mockRejectedValue(new Error('gateway')) });
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.blockers).toEqual(['merge_eligibility_unavailable']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('an ambiguous merge response enters reconciling and settles as merged', async () => {
    const ambiguous = githubClient({ merge: jest.fn().mockResolvedValue({ state: 'reconciling', operation_id: ACTION_ID }) });
    const first = await mergeController.evaluateIntent(intent(), { githubClient: ambiguous });
    expect(first.state).toBe('reconciling');
    expect(transitions()).toEqual(['eligible', 'merging', 'reconciling']);

    jest.clearAllMocks();
    remediationDb.transitionMergeIntent.mockImplementation(async (row, state) => ({ ...row, state }));
    const settler = githubClient({
      readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: MERGE_SHA, base_sha: BASE, state: 'closed', merged: true, fork: false }),
    });
    const settled = await mergeController.evaluateIntent(
      intent({ state: 'reconciling', merge_attempts: 1 }), { githubClient: settler });
    expect(settled.state).toBe('merged');
    expect(settler.merge).not.toHaveBeenCalled();
  });

  test('an ambiguous merge that did not happen returns to eligible with the attempt spent', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(
      intent({ state: 'reconciling', merge_attempts: 1 }), { githubClient: github });
    expect(result.state).toBe('eligible');
    expect(transitions()).toEqual(['eligible']);
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('an unresolved merge outcome stays blocked', async () => {
    const github = githubClient({
      readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: '7'.repeat(40), base_sha: BASE, state: 'open', merged: false, fork: false }),
    });
    const result = await mergeController.evaluateIntent(
      intent({ state: 'merging', merge_attempts: 1 }), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['merge_outcome_unresolved']);
  });

  test('exhausted merge attempts block with a machine-readable reason', async () => {
    process.env.REMEDIATION_MAX_MERGE_ATTEMPTS = '3';
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent({ merge_attempts: 3 }), { githubClient: github });
    expect(result.state).toBe('blocked');
    expect(result.blockers).toEqual(['merge_attempts_exhausted']);
    expect(lastTransition('blocked').reason).toBe('merge_attempts_exhausted');
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('exactly one merge attempt is made per eligibility evaluation', async () => {
    const github = githubClient({ merge: jest.fn().mockResolvedValue({ state: 'reconciling', operation_id: ACTION_ID }) });
    await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(github.merge).toHaveBeenCalledTimes(1);
    expect(lastTransition('merging').attempt).toBe(true);
  });

  test('an expired intent expires before any GitHub call', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(
      intent({ expires_at: new Date(Date.now() - 1000).toISOString() }), { githubClient: github });
    expect(result.state).toBe('expired');
    expect(github.authorize).not.toHaveBeenCalled();
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('a terminal intent is never re-evaluated', async () => {
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent({ state: 'merged' }), { githubClient: github });
    expect(result.state).toBe('merged');
    expect(remediationDb.transitionMergeIntent).not.toHaveBeenCalled();
    expect(github.readPullRequestHead).not.toHaveBeenCalled();
  });

  test('a non-application push superseding the head stops the merge', async () => {
    const github = githubClient({
      readPullRequestHead: jest.fn().mockResolvedValue({ head_sha: '6'.repeat(40), base_sha: BASE, state: 'open', merged: false, fork: false }),
    });
    const result = await mergeController.evaluateIntent(intent({ state: 'eligible' }), { githubClient: github });
    expect(result.state).toBe('superseded');
    expect(github.merge).not.toHaveBeenCalled();
  });

  test('cancellation withdraws the GitHub side and reconciles an ambiguous answer', async () => {
    const cancelled = githubClient();
    const first = await mergeController.cancelScheduledMerge(intent({ state: 'cancelled' }), { githubClient: cancelled });
    expect(cancelled.cancelScheduledMerge).toHaveBeenCalledTimes(1);
    expect(cancelled.cancelScheduledMerge.mock.calls[0][0].expected_head_sha).toBe(APPLIED);
    expect(first.state).toBe('cancelled');

    const ambiguous = githubClient({
      cancelScheduledMerge: jest.fn().mockResolvedValue({ state: 'reconciling', operation_id: ACTION_ID }),
    });
    const second = await mergeController.cancelScheduledMerge(intent({ state: 'cancelled' }), { githubClient: ambiguous });
    expect(second.state).toBe('reconciling');
  });

  test('a lost compare-and-swap never publishes a decision', async () => {
    remediationDb.transitionMergeIntent.mockResolvedValue(null);
    const github = githubClient();
    const result = await mergeController.evaluateIntent(intent(), { githubClient: github });
    expect(result.state).toBe('waiting_for_checks');
    expect(github.merge).not.toHaveBeenCalled();
  });
});

describe('remediation verification check publication', () => {
  const action = {
    id: ACTION_ID, installation_id: 42, repository_id: '33333333-3333-4333-8333-333333333333', state: 'completed',
    actor_login: 'actor', repository_full_name: 'owner/repo', pr_number: 7, head_sha: 'e'.repeat(40), base_sha: BASE,
    batch_manifest_digest: DIGEST, idempotency_key: 'idempotency-key', observed_commit_sha: APPLIED,
    observed_tree_oid: 'f'.repeat(40), verification_head_sha: APPLIED,
    candidate_ids: ['77777777-7777-4777-8777-777777777777'], job_id: '66666666-6666-4666-8666-666666666666',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    enableMerge();
    remediationDb.recordVerificationCheck.mockResolvedValue({});
    remediationDb.actionCheckContext.mockResolvedValue({ action, candidates: [{ id: 'x', preview: { verified_tree_oid: 'f'.repeat(40) } }] });
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 0 });
  });
  afterEach(() => { for (const name of MERGE_ENV) delete process.env[name]; });

  test('a clean re-analysis publishes success with the tree OID, digest and candidate count', async () => {
    const github = githubClient();
    const result = await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    expect(result.published).toBe(true);
    const payload = github.createCheckRun.mock.calls[0][0];
    expect(payload.status).toBe('completed');
    expect(payload.conclusion).toBe('success');
    expect(payload.external_id).toBe(ACTION_ID);
    expect(payload.head_sha).toBe(APPLIED);
    expect(payload.summary).toContain('f'.repeat(40));
    expect(payload.summary).toContain(DIGEST);
    expect(payload.summary).toContain('Candidates in batch: 1');
    expect(remediationDb.recordVerificationCheck).toHaveBeenCalled();
  });

  test('an action still checking publishes in_progress', async () => {
    remediationDb.actionCheckContext.mockResolvedValue({ action: { ...action, state: 'checking' }, candidates: [] });
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'pending', blocking: null });
    const github = githubClient();
    await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    const payload = github.createCheckRun.mock.calls[0][0];
    expect(payload.status).toBe('in_progress');
    expect(payload.conclusion).toBeNull();
  });

  test('a blocking finding on the applied head publishes failure', async () => {
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 1 });
    const github = githubClient();
    await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    expect(github.createCheckRun.mock.calls[0][0].conclusion).toBe('failure');
  });

  test('an open medium finding fails the check and is listed in the residual report, while informational test-code findings do not', async () => {
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 1, open: [
      { id: 'f1', title: 'Command injection', file_path: 'services/orders.js', line_start: 20, severity: 'medium', informational: false },
      { id: 'f2', title: 'Hardcoded secret', file_path: 'tests/orders.test.js', line_start: 3, severity: 'info', informational: true },
    ] });
    remediationDb.appliedReportForAction.mockResolvedValue({
      applied: [{ finding_id: 'f0', title: 'SQL injection', file_path: 'services/customers.js', line_start: 12, severity: 'high' }],
      unsupported: [{ finding_id: 'f3', title: 'Path traversal', file_path: 'services/orders.js', line_start: 40, reason: 'not_repaired' }],
    });
    const github = githubClient();
    await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    const payload = github.createCheckRun.mock.calls[0][0];
    expect(payload.conclusion).toBe('failure');
    expect(payload.title).toBe('Remediation verification did not pass: findings remain open');
    expect(payload.summary).toContain('Open findings on the applied head (any severity, excluding informational test-code findings): 1');
    expect(payload.summary).toContain('- SQL injection in services/customers.js:12');
    expect(payload.summary).toContain('  - medium: Command injection (line 20)');
    expect(payload.summary).toContain('Hardcoded secret in tests/orders.test.js:3');
    expect(payload.summary).toContain('Path traversal in services/orders.js:40: not_repaired');
    expect(payload.summary).toContain('Merging stays a human action on GitHub.');

    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'completed', blocking: 0, open: [
      { id: 'f2', title: 'Hardcoded secret', file_path: 'tests/orders.test.js', line_start: 3, severity: 'info', informational: true },
    ] });
    const clean = githubClient();
    await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: clean });
    expect(clean.createCheckRun.mock.calls[0][0].conclusion).toBe('success');
    expect(clean.createCheckRun.mock.calls[0][0].title).toBe('1 verified fix applied; no open findings remain');
  });

  test('a failed verification analysis publishes failure rather than staying silent', async () => {
    remediationDb.actionCheckContext.mockResolvedValue({ action: { ...action, state: 'checking' }, candidates: [] });
    remediationDb.blockingFindingsForAction.mockResolvedValue({ analysisState: 'failed', blocking: null });
    const github = githubClient();
    await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    expect(github.createCheckRun.mock.calls[0][0].conclusion).toBe('failure');
  });

  test('a publication failure is reported and never recorded as published', async () => {
    const github = githubClient({ createCheckRun: jest.fn().mockRejectedValue(new Error('gateway')) });
    const result = await mergeController.publishVerificationCheck(ACTION_ID, { githubClient: github });
    expect(result.published).toBe(false);
    expect(remediationDb.recordVerificationCheck).not.toHaveBeenCalled();
  });
});
