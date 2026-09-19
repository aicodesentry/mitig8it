const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  getLatestForPullRequest: jest.fn(), createJob: jest.fn(), getJobForUser: jest.fn(), getPreview: jest.fn(),
  createAction: jest.fn(), cancelJob: jest.fn(), getActionForUser: jest.fn(), cancelMerge: jest.fn(),
  budgetSnapshot: jest.fn(), recordApplyDenial: jest.fn(),
  getCandidateForFeedback: jest.fn(), recordRepairMemoryObservation: jest.fn(),
  mergeIntentContext: jest.fn(), transitionMergeIntent: jest.fn(), recordMergeEvaluation: jest.fn(),
}));
jest.mock('../src/services/githubUserAuth', () => ({ getGithubAccessTokenForUser: jest.fn() }));
jest.mock('../src/services/githubRemediationClient', () => {
  const authorize = jest.fn();
  const cancelScheduledMerge = jest.fn();
  return {
    GitHubRemediationClient: jest.fn(() => ({ authorize, cancelScheduledMerge })),
    __authorize: authorize, __cancelScheduledMerge: cancelScheduledMerge,
  };
});

const remediationDb = require('../src/db/remediation');
const { getGithubAccessTokenForUser } = require('../src/services/githubUserAuth');
const { __authorize: authorize, __cancelScheduledMerge: cancelScheduledMerge } = require('../src/services/githubRemediationClient');
const { createApp } = require('../src/app');

const id = '11111111-1111-4111-8111-111111111111';
const candidate = '22222222-2222-4222-8222-222222222222';
const action = '33333333-3333-4333-8333-333333333333';
const sha = 'a'.repeat(40);
const baseSha = 'b'.repeat(40);
const digest = 'd'.repeat(64);
const job = {
  id, state: 'ready', stage: 'ready', head_sha: sha, base_sha: baseSha, attempt_count: 1, revision_count: 0,
  created_at: '2026-01-01', updated_at: '2026-01-01',
  installation_id: 42, repository_id: '44444444-4444-4444-8444-444444444444', repository_full_name: 'owner/repo',
  repository_active: true, installation_status: 'active', pr_number: 7, policy_manifest: { max_spend_usd: 2 },
};

// The nine settings repair_service_configured actually requires. Setting only some of
// them made the route fail closed, which is correct behaviour, not a route defect.
function enableRemediation() {
  process.env.REMEDIATION_ENABLED = 'true';
  process.env.REMEDIATION_GENERATE_ENABLED = 'true';
  process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
  process.env.REMEDIATION_APPLY_ENABLED = 'true';
  process.env.REMEDIATION_MERGE_ENABLED = 'true';
  process.env.REMEDIATION_SERVICE_URL = 'http://repair';
  process.env.REMEDIATION_SERVICE_INTERNAL_SECRET = 'repair';
  process.env.GITHUB_SERVICE_URL = 'http://github';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'github';
  process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = 'sha256:aaaa';
  process.env.REMEDIATION_VERIFICATION_CHECKS_JSON = '["unit","scan"]';
  process.env.REMEDIATION_ALLOWED_RULE_FAMILIES_JSON = '["injection"]';
  process.env.REMEDIATION_INPUT_USD_PER_MILLION_TOKENS = '3';
  process.env.REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS = '15';
}

const REMEDIATION_ENV = [
  'REMEDIATION_ENABLED', 'REMEDIATION_GENERATE_ENABLED', 'REMEDIATION_PUBLISH_ENABLED', 'REMEDIATION_APPLY_ENABLED',
  'REMEDIATION_MERGE_ENABLED', 'REMEDIATION_SERVICE_URL', 'REMEDIATION_SERVICE_INTERNAL_SECRET',
  'REMEDIATION_SANDBOX_IMAGE_DIGEST', 'REMEDIATION_VERIFICATION_CHECKS_JSON', 'REMEDIATION_ALLOWED_RULE_FAMILIES_JSON',
  'REMEDIATION_INPUT_USD_PER_MILLION_TOKENS', 'REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS',
  'REMEDIATION_PROTECTED_BRANCH_PATTERNS_JSON',
];

function applyBody(overrides = {}) {
  return { head_sha: sha, base_sha: baseSha, manifest_digest: digest, candidate_ids: [candidate],
    merge_when_ready: false, idempotency_key: 'idempotency-key', ...overrides };
}

function token() { return jwt.sign({ user_id: id, github_username: 'owner' }, process.env.JWT_SECRET); }

describe('remediation API', () => {
  beforeEach(() => {
    jest.clearAllMocks(); process.env.JWT_SECRET = 'remediation-test';
    enableRemediation();
    remediationDb.budgetSnapshot.mockResolvedValue({ reserved: 0, ceiling: 2, available: 2 });
    remediationDb.recordApplyDenial.mockResolvedValue(undefined);
    getGithubAccessTokenForUser.mockResolvedValue({ githubUsername: 'owner' });
    authorize.mockResolvedValue({ state: 'authorized', installation_active: true, repository_granted: true,
      actor_write_permission: true, head_sha: sha, base_sha: baseSha, head_branch: 'feature', base_branch: 'main' });
  });
  afterEach(() => { for (const name of REMEDIATION_ENV) delete process.env[name]; });

  test('feature defaults fail closed for generation', async () => {
    process.env.REMEDIATION_ENABLED = 'false';
    const res = await request(createApp()).post(`/api/pull-requests/${id}/remediations`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(422); expect(remediationDb.createJob).not.toHaveBeenCalled();
  });

  test('generation is refused when the repair dependency configuration is missing', async () => {
    delete process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST;
    const res = await request(createApp()).post(`/api/pull-requests/${id}/remediations`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(422); expect(remediationDb.createJob).not.toHaveBeenCalled();
  });

  test('a disabled merge flag does not enable itself through the apply flag', async () => {
    process.env.REMEDIATION_MERGE_ENABLED = 'false';
    remediationDb.getJobForUser.mockResolvedValue(job);
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ merge_when_ready: true }));
    expect(res.status).toBe(422); expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('returns a durable generation acceptance', async () => {
    remediationDb.createJob.mockResolvedValue({ kind: 'ok', job, created: true });
    const res = await request(createApp()).post(`/api/pull-requests/${id}/remediations`).set('Authorization', `Bearer ${token()}`).send({ finding_ids: [candidate] });
    expect(res.status).toBe(202); expect(res.body.job.id).toBe(id);
    expect(remediationDb.createJob).toHaveBeenCalledWith(expect.objectContaining({ pullRequestId: id, userId: id, findingIds: [candidate] }));
  });

  test('requires exact immutable apply fields and never accepts patch text', async () => {
    const invalid = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send({ patch: 'evil' });
    expect(invalid.status).toBe(400); expect(remediationDb.createAction).not.toHaveBeenCalled();
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.createAction.mockResolvedValue({ kind: 'ok', action: { id: action, state: 'requested' } });
    const valid = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(valid.status).toBe(202); expect(valid.body.action.id).toBe(action);
    expect(authorize).toHaveBeenCalledWith(expect.objectContaining({ actor_login: 'owner', repository_full_name: 'owner/repo' }));
  });

  test('development verification never applies unless an operator opts in', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.getPreview.mockResolvedValue({ job, manifestDigest: digest, candidates: [{ id: candidate, verification_level: 'development_unverified' }], verification: { outcome: 'passed' } });
    const denied = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(denied.status).toBe(422); expect(denied.body.code).toBe('verification_level_not_permitted');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
    process.env.REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION = 'true';
    remediationDb.createAction.mockResolvedValue({ kind: 'ok', action: { id: action, state: 'requested' } });
    const allowed = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(allowed.status).toBe(202);
    delete process.env.REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION;
  });

  test('preview only renders a ready immutable batch', async () => {
    remediationDb.getPreview.mockResolvedValue({ job, manifestDigest: digest, candidates: [{ id: candidate, finding_snapshot_ids: [candidate], artifact_digest: 'x', context_manifest_digest: 'y', file_manifest: {}, preview: { changes: [] }, verification_level: 'independent_sandbox' }], verification: { outcome: 'passed' } });
    const res = await request(createApp()).get(`/api/remediations/${id}/preview`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200); expect(res.body.manifest_digest).toBe(digest);
    expect(res.body.capabilities.apply).toEqual({ enabled: true, reason: null });
  });

  test('status reports why an unavailable capability is unavailable', async () => {
    process.env.REMEDIATION_MERGE_ENABLED = 'false';
    remediationDb.getJobForUser.mockResolvedValue(job);
    const res = await request(createApp()).get(`/api/remediations/${id}`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.capabilities.merge).toEqual({ enabled: false, reason: 'feature_flag_off' });
  });

  test('an unauthorized pull request never reaches the apply path', async () => {
    remediationDb.getJobForUser.mockResolvedValue(null);
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(404);
    expect(authorize).not.toHaveBeenCalled();
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('an actor without live write permission is denied and audited', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    authorize.mockRejectedValue(Object.assign(new Error('denied'), { response: { status: 403 } }));
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('actor_write_permission_missing');
    expect(remediationDb.recordApplyDenial).toHaveBeenCalledWith(id, job, 'actor_write_permission_missing', expect.any(Object));
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('a suspended installation is denied before any GitHub call', async () => {
    remediationDb.getJobForUser.mockResolvedValue({ ...job, installation_status: 'suspended' });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('installation_or_repository_inactive');
    expect(authorize).not.toHaveBeenCalled();
  });

  test('a protected branch pattern blocks apply while the default list allows it', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    process.env.REMEDIATION_PROTECTED_BRANCH_PATTERNS_JSON = '["main","release/*"]';
    const blocked = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(blocked.status).toBe(422);
    expect(blocked.body.code).toBe('branch_not_allowed');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('an exhausted budget returns 429 without creating an action', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.budgetSnapshot.mockResolvedValue({ reserved: 2, ceiling: 2, available: 0 });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(429);
    expect(res.body.code).toBe('budget_exhausted');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('a replayed idempotency key with a different payload is a conflict', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.createAction.mockResolvedValue({ kind: 'conflict' });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [candidate, action] }));
    expect(res.status).toBe(409);
    expect(res.body.error).toMatch(/Idempotency key/);
  });

  test('a stale head at apply time is a conflict, never a rebase', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    authorize.mockResolvedValue({ state: 'authorized', installation_active: true, repository_granted: true,
      actor_write_permission: true, head_sha: 'c'.repeat(40), base_sha: baseSha, head_branch: 'feature', base_branch: 'main' });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('revision_changed');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('a second concurrent apply for one pull request is refused', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.createAction.mockResolvedValue({ kind: 'writer_busy' });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(409);
    expect(res.body.code).toBe('writer_lease_held');
  });

  test('apply is refused when the GitHub write dependency is not configured', async () => {
    delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    remediationDb.getJobForUser.mockResolvedValue(job);
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(res.status).toBe(422);
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });
});

const actorId = id;
const otherActor = '55555555-5555-4555-8555-555555555555';

function intentRow(overrides = {}) {
  return {
    id: '66666666-6666-4666-8666-666666666666', action_id: action, actor_id: actorId, state: 'waiting_for_checks',
    blockers: ['verification_analysis_incomplete'], expires_at: '2026-01-02T00:00:00.000Z', merge_attempts: 1,
    observed_merge_sha: null, applied_sha: sha, last_evaluated_at: '2026-01-01T00:00:00.000Z',
    merge_method: 'squash', cancellation_reason: null, latest_policy_checks: {}, state_version: '2',
    installation_id: 42, repository_id: job.repository_id, approved_head_sha: sha, approved_base_sha: baseSha,
    approved_manifest_digest: digest, ...overrides,
  };
}

function actionRow(overrides = {}) {
  return {
    id: action, installation_id: 42, repository_id: job.repository_id, repository_full_name: 'owner/repo',
    pr_number: 7, actor_login: 'owner', idempotency_key: 'idempotency-key', state: 'completed', ...overrides,
  };
}

describe('merge intent exposure and cancellation', () => {
  beforeEach(() => {
    jest.clearAllMocks(); process.env.JWT_SECRET = 'remediation-test';
    enableRemediation();
    getGithubAccessTokenForUser.mockResolvedValue({ githubUsername: 'owner' });
    cancelScheduledMerge.mockResolvedValue({ state: 'cancelled', operation_id: action, merged: false });
    remediationDb.recordMergeEvaluation.mockResolvedValue({});
  });
  afterEach(() => { for (const name of REMEDIATION_ENV) delete process.env[name]; });

  test('the action endpoint reports the merge intent state, blockers and attempts', async () => {
    remediationDb.getActionForUser.mockResolvedValue({ action: actionRow(), mergeIntent: intentRow() });
    const res = await request(createApp()).get(`/api/remediation-actions/${action}`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.merge_intent.state).toBe('waiting_for_checks');
    expect(res.body.merge_intent.blockers).toEqual(['verification_analysis_incomplete']);
    expect(res.body.merge_intent.merge_attempts).toBe(1);
    expect(res.body.merge_intent.expires_at).toBe('2026-01-02T00:00:00.000Z');
    expect(res.body.merge_intent.last_evaluated_at).toBe('2026-01-01T00:00:00.000Z');
    expect(res.body.merge_intent.observed_merge_sha).toBeNull();
    expect(res.body.capabilities.merge.enabled).toBe(true);
  });

  test('the panel endpoint reports the same merge intent', async () => {
    remediationDb.getLatestForPullRequest.mockResolvedValue({
      pr: { id }, job, action: actionRow({ observed_commit_sha: sha, merge_state: 'merged' }),
      mergeIntent: intentRow({ state: 'merged', observed_merge_sha: 'c'.repeat(40), blockers: [] }),
    });
    const res = await request(createApp()).get(`/api/pull-requests/${id}/remediations`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.merge_intent.state).toBe('merged');
    expect(res.body.merge_intent.observed_merge_sha).toBe('c'.repeat(40));
  });

  test('cancelling a merge withdraws the GitHub side and returns the resulting state', async () => {
    remediationDb.getActionForUser
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow() })
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow({ state: 'cancelled' }) });
    remediationDb.cancelMerge.mockResolvedValue(intentRow({ state: 'cancelled' }));
    remediationDb.mergeIntentContext.mockResolvedValue(intentRow({ state: 'cancelled' }));

    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(202);
    expect(res.body.merge_intent.state).toBe('cancelled');
    expect(res.body.state).toBe('cancelled');
    expect(cancelScheduledMerge).toHaveBeenCalledTimes(1);
  });

  test('an ambiguous GitHub cancellation leaves the intent reconciling', async () => {
    cancelScheduledMerge.mockResolvedValue({ state: 'reconciling', operation_id: action });
    remediationDb.getActionForUser
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow() })
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow({ state: 'reconciling' }) });
    remediationDb.cancelMerge.mockResolvedValue(intentRow({ state: 'cancelled' }));
    remediationDb.mergeIntentContext.mockResolvedValue(intentRow({ state: 'cancelled' }));
    remediationDb.transitionMergeIntent.mockResolvedValue(intentRow({ state: 'reconciling' }));

    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(202);
    expect(res.body.state).toBe('reconciling');
  });

  test('a non-creator without live write permission cannot cancel the merge', async () => {
    remediationDb.getActionForUser.mockResolvedValue({ action: actionRow(), mergeIntent: intentRow({ actor_id: otherActor }) });
    authorize.mockRejectedValue(Object.assign(new Error('forbidden'), { response: { status: 403 } }));
    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(403);
    expect(remediationDb.cancelMerge).not.toHaveBeenCalled();
    expect(cancelScheduledMerge).not.toHaveBeenCalled();
  });

  test('a non-creator with live write permission may cancel the merge', async () => {
    remediationDb.getActionForUser
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow({ actor_id: otherActor }) })
      .mockResolvedValueOnce({ action: actionRow(), mergeIntent: intentRow({ state: 'cancelled' }) });
    authorize.mockResolvedValue({ state: 'authorized', installation_active: true, repository_granted: true, actor_write_permission: true });
    remediationDb.cancelMerge.mockResolvedValue(intentRow({ state: 'cancelled' }));
    remediationDb.mergeIntentContext.mockResolvedValue(intentRow({ state: 'cancelled' }));
    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(202);
  });

  test('an action with no merge intent cannot be cancelled', async () => {
    remediationDb.getActionForUser.mockResolvedValue({ action: actionRow(), mergeIntent: null });
    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`).set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(409);
  });
});

describe('remediation feedback', () => {
  const candidateRow = { id: candidate, artifact_digest: 'a'.repeat(64), context_manifest_digest: 'c'.repeat(64),
    verification_level: 'independent_sandbox', finding_snapshot_ids: ['77777777-7777-4777-8777-777777777777'] };
  const jobRow = { id, installation_id: 42, repository_id: job.repository_id, pull_request_id: id, head_sha: sha };

  beforeEach(() => {
    jest.clearAllMocks(); process.env.JWT_SECRET = 'remediation-test';
    enableRemediation();
    remediationDb.recordRepairMemoryObservation.mockResolvedValue({ id: 'memory-1' });
  });
  afterEach(() => { for (const name of REMEDIATION_ENV) delete process.env[name]; });

  test('feedback is recorded as an observation with its provenance and expiry', async () => {
    remediationDb.getCandidateForFeedback.mockResolvedValue({ job: jobRow, candidate: candidateRow });
    const res = await request(createApp()).post(`/api/remediations/${id}/feedback`).set('Authorization', `Bearer ${token()}`)
      .send({ candidate_id: candidate, outcome: 'edited', reason: 'renamed the helper' });
    expect(res.status).toBe(204);
    const call = remediationDb.recordRepairMemoryObservation.mock.calls[0][0];
    expect(call.outcome).toBe('edited');
    expect(call.reason).toBe('renamed the helper');
    expect(call.userId).toBe(id);
    expect(call.expiryDays).toBe(90);
  });

  test('an unsupported outcome is rejected', async () => {
    const res = await request(createApp()).post(`/api/remediations/${id}/feedback`).set('Authorization', `Bearer ${token()}`)
      .send({ candidate_id: candidate, outcome: 'approved' });
    expect(res.status).toBe(400);
    expect(remediationDb.recordRepairMemoryObservation).not.toHaveBeenCalled();
  });

  test('a candidate from another job is not accepted', async () => {
    remediationDb.getCandidateForFeedback.mockResolvedValue({ job: jobRow, candidate: null });
    const res = await request(createApp()).post(`/api/remediations/${id}/feedback`).set('Authorization', `Bearer ${token()}`)
      .send({ candidate_id: candidate, outcome: 'accepted' });
    expect(res.status).toBe(404);
    expect(remediationDb.recordRepairMemoryObservation).not.toHaveBeenCalled();
  });

  test('a remediation the actor cannot reach returns 404', async () => {
    remediationDb.getCandidateForFeedback.mockResolvedValue(null);
    const res = await request(createApp()).post(`/api/remediations/${id}/feedback`).set('Authorization', `Bearer ${token()}`)
      .send({ candidate_id: candidate, outcome: 'rejected' });
    expect(res.status).toBe(404);
  });
});
