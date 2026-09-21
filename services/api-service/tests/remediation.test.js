const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => {
  const actual = jest.requireActual('../src/db/remediation');
  return {
    getLatestForPullRequest: jest.fn(), createJob: jest.fn(), getJobForUser: jest.fn(), getPreview: jest.fn(),
    getEvidenceForUser: jest.fn(),
    createAction: jest.fn(), cancelJob: jest.fn(), getActionForUser: jest.fn(), cancelMerge: jest.fn(),
    budgetSnapshot: jest.fn(), recordApplyDenial: jest.fn(),
    getCandidateForFeedback: jest.fn(), recordRepairMemoryObservation: jest.fn(),
    mergeIntentContext: jest.fn(), transitionMergeIntent: jest.fn(), recordMergeEvaluation: jest.fn(),
    // Consent digests and subset selection are pure; the route is tested against the real ones.
    manifestDigestFor: actual.manifestDigestFor, selectCandidates: actual.selectCandidates, hash: actual.hash,
  };
});
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

// Two verified candidates in one job, one per file. Consent digests are computed by the
// real helper over exactly the subset a request names.
const secondCandidate = '77777777-7777-4777-8777-777777777777';
const candidateRows = [
  { id: candidate, finding_snapshot_ids: [candidate], artifact_digest: 'x'.repeat(64), context_manifest_digest: 'y', verification_level: 'independent_sandbox', rejection_reason: null,
    file_manifest: { files: [{ path: 'src/app.js' }], verified_tree_oid: 'e'.repeat(40) }, preview: { changes: [{ path: 'src/app.js' }] } },
  { id: secondCandidate, finding_snapshot_ids: [secondCandidate], artifact_digest: 'z'.repeat(64), context_manifest_digest: 'y', verification_level: 'independent_sandbox', rejection_reason: null,
    file_manifest: { files: [{ path: 'src/other.js' }], verified_tree_oid: 'f'.repeat(40) }, preview: { changes: [{ path: 'src/other.js' }] } },
];
const digestFor = (ids) => remediationDb.manifestDigestFor(job, candidateRows.filter((c) => ids.includes(c.id)));
const previewRow = (candidates = candidateRows) => ({ job, manifestDigest: remediationDb.manifestDigestFor(job, candidates), candidates,
  verification: { outcome: 'passed', candidate_tree_sha: 'a'.repeat(40) }, findings: [{ id: candidate, title: 'SQL injection', file_path: 'src/app.js', line_start: 4, severity: 'high' }] });

function applyBody(overrides = {}) {
  return { head_sha: sha, base_sha: baseSha, manifest_digest: digestFor([candidate]), candidate_ids: [candidate],
    merge_when_ready: false, idempotency_key: 'idempotency-key', ...overrides };
}

function token() { return jwt.sign({ user_id: id, github_username: 'owner' }, process.env.JWT_SECRET); }

describe('remediation API', () => {
  beforeEach(() => {
    jest.clearAllMocks(); process.env.JWT_SECRET = 'remediation-test';
    enableRemediation();
    remediationDb.budgetSnapshot.mockResolvedValue({ reserved: 0, ceiling: 2, available: 2 });
    remediationDb.recordApplyDenial.mockResolvedValue(undefined);
    remediationDb.getPreview.mockResolvedValue(previewRow());
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

  test('merge_when_ready is refused with 400 unless the operator-only merge flag is on', async () => {
    process.env.REMEDIATION_MERGE_ENABLED = 'false';
    remediationDb.getJobForUser.mockResolvedValue(job);
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ merge_when_ready: true }));
    expect(res.status).toBe(400); expect(res.body.code).toBe('merge_not_available');
    expect(res.body.error).toMatch(/human action on GitHub/);
    expect(remediationDb.createAction).not.toHaveBeenCalled();
    expect(authorize).not.toHaveBeenCalled();
  });

  test('the operator-only merge flag still fails closed when its GitHub dependency is missing', async () => {
    delete process.env.GITHUB_SERVICE_URL;
    process.env.REMEDIATION_MERGE_ENABLED = 'true';
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
    remediationDb.getPreview.mockResolvedValue(previewRow([{ ...candidateRows[0], verification_level: 'development_unverified' }, candidateRows[1]]));
    const denied = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(denied.status).toBe(422); expect(denied.body.code).toBe('verification_level_not_permitted');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
    process.env.REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION = 'true';
    remediationDb.createAction.mockResolvedValue({ kind: 'ok', action: { id: action, state: 'requested' } });
    const allowed = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
    expect(allowed.status).toBe(202);
    delete process.env.REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION;
  });

  test('preview renders each candidate with its own consent digest, its file group and its findings', async () => {
    const res = await request(createApp()).get(`/api/remediations/${id}/preview`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200); expect(res.body.manifest_digest).toBe(digestFor([candidate, secondCandidate]));
    expect(res.body.applicable).toBe(true);
    expect(res.body.candidates.map((c) => c.manifest_digest)).toEqual([digestFor([candidate]), digestFor([secondCandidate])]);
    expect(res.body.candidates.map((c) => c.status)).toEqual(['applicable', 'applicable']);
    expect(res.body.files).toEqual([
      { path: 'src/app.js', candidate_ids: [candidate], verified_together: true, manifest_digest: digestFor([candidate]) },
      { path: 'src/other.js', candidate_ids: [secondCandidate], verified_together: true, manifest_digest: digestFor([secondCandidate]) },
    ]);
    expect(res.body.findings[0]).toEqual(expect.objectContaining({ id: candidate, title: 'SQL injection', file_path: 'src/app.js', line_start: 4 }));
    expect(res.body.capabilities.apply).toEqual({ enabled: true, reason: null });
  });

  test('preview stays readable after an apply superseded the job, with stale and applied candidates marked', async () => {
    const applied = { ...candidateRows[0], rejection_reason: { code: 'applied', action_id: action, commit_sha: 'c'.repeat(40) } };
    const stale = { ...candidateRows[1], rejection_reason: { code: 'head_changed' } };
    remediationDb.getPreview.mockResolvedValue(previewRow([applied, stale]));
    remediationDb.getPreview.mockResolvedValue({ ...previewRow([applied, stale]), job: { ...job, state: 'superseded' } });
    const res = await request(createApp()).get(`/api/remediations/${id}/preview`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.applicable).toBe(false); expect(res.body.manifest_digest).toBeNull();
    expect(res.body.candidates[0]).toEqual(expect.objectContaining({ status: 'applied', applied_commit_sha: 'c'.repeat(40) }));
    expect(res.body.candidates[1]).toEqual(expect.objectContaining({ status: 'stale', stale_reason: 'head_changed' }));
    const failed = await request(createApp()).get(`/api/remediations/${id}/preview`).set('Authorization', `Bearer ${token()}`);
    expect(failed.status).toBe(200);
    remediationDb.getPreview.mockResolvedValue({ ...previewRow(), job: { ...job, state: 'failed' } });
    expect((await request(createApp()).get(`/api/remediations/${id}/preview`).set('Authorization', `Bearer ${token()}`)).status).toBe(409);
  });

  test('evidence renders the trace, usage, settlements, groups and check outcomes for the job', async () => {
    remediationDb.getEvidenceForUser.mockResolvedValue({
      job: { ...job, state: 'ready', attempt_count: 1 },
      records: [
        { attempt: 1, kind: 'agent_trace', created_at: '2026-01-01', payload: { total: 1, truncated: false, items: [{ sequence: 1, tool: 'read_file', outcome: 'ok', reason: null, result_bytes: 12 }] } },
        { attempt: 1, kind: 'budget_reservation', created_at: '2026-01-01', payload: { settled_calls: 2, overage_calls: 0, settlements: { total: 2, truncated: false, items: [] } } },
        { attempt: 1, kind: 'candidate_evidence', created_at: '2026-01-01', payload: { total: 1, truncated: false, items: [{ artifact_digest: 'x'.repeat(64), finding_ids: [candidate], evidence: { verification_level: 'independent_sandbox' } }] } },
        { attempt: 1, kind: 'groups', created_at: '2026-01-01', payload: { groups: { total: 1, truncated: false, items: [{ group_index: 0, state: 'ready' }] }, skipped: { total: 0, truncated: false, items: [] } } },
        { attempt: 1, kind: 'usage', created_at: '2026-01-01', payload: { input_tokens: 10, output_tokens: 2, cost_usd: 0.001, provider_request_ids: [] } },
        { attempt: 1, kind: 'verification', created_at: '2026-01-01', payload: { outcome: 'passed', checks: { total: 1, truncated: false, items: [{ check_id: 'generated_regression', candidate: { status: 'passed', output_tail: null } }] } } },
      ],
    });
    const res = await request(createApp()).get(`/api/remediations/${id}/evidence`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(remediationDb.getEvidenceForUser).toHaveBeenCalledWith(id, id);
    expect(res.body.job_id).toBe(id);
    expect(res.body.job_state).toBe('ready');
    expect(res.body.agent_trace.items[0].tool).toBe('read_file');
    expect(res.body.usage).toEqual({ input_tokens: 10, output_tokens: 2, cost_usd: 0.001, provider_request_ids: [] });
    expect(res.body.budget_reservation.settled_calls).toBe(2);
    expect(res.body.groups.groups.items[0].state).toBe('ready');
    expect(res.body.verification.checks.items[0].check_id).toBe('generated_regression');
    expect(res.body.candidates.items[0].evidence.verification_level).toBe('independent_sandbox');
    expect(res.body.records.map((r) => r.kind).sort()).toEqual(['agent_trace', 'budget_reservation', 'candidate_evidence', 'groups', 'usage', 'verification']);
  });

  test('evidence is readable for a job that repaired nothing, where the preview is not', async () => {
    remediationDb.getEvidenceForUser.mockResolvedValue({
      job: { ...job, state: 'inconclusive', stage: 'inconclusive', attempt_count: 3, failure_reason: { code: 'regression_test_not_reproducing' } },
      records: [{ attempt: 3, kind: 'groups', created_at: '2026-01-01', payload: { groups: { total: 1, truncated: false, items: [{ group_index: 0, state: 'inconclusive' }] }, skipped: { total: 1, truncated: false, items: [{ finding_id: candidate, code: 'not_repaired' }] } } }],
    });
    const res = await request(createApp()).get(`/api/remediations/${id}/evidence`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.job_state).toBe('inconclusive');
    expect(res.body.reason).toBe('regression_test_not_reproducing');
    expect(res.body.attempts).toBe(3);
    expect(res.body.groups.skipped.items[0].code).toBe('not_repaired');
    expect(res.body.agent_trace).toBeNull();
    expect(res.body.verification).toBeNull();
  });

  test('evidence requires authentication, a well formed id, and an authorized job', async () => {
    expect((await request(createApp()).get(`/api/remediations/${id}/evidence`)).status).toBe(401);
    expect((await request(createApp()).get('/api/remediations/not-a-uuid/evidence').set('Authorization', `Bearer ${token()}`)).status).toBe(400);
    remediationDb.getEvidenceForUser.mockResolvedValue(null);
    expect((await request(createApp()).get(`/api/remediations/${id}/evidence`).set('Authorization', `Bearer ${token()}`)).status).toBe(404);
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
      .send(applyBody());
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

  test('one candidate of a two-candidate batch is applied on its own consent digest', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.createAction.mockResolvedValue({ kind: 'ok', action: { id: action, state: 'requested' } });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [secondCandidate], manifest_digest: digestFor([secondCandidate]) }));
    expect(res.status).toBe(202);
    expect(authorize).toHaveBeenCalledWith(expect.objectContaining({ manifest_digest: digestFor([secondCandidate]) }));
    expect(remediationDb.createAction).toHaveBeenCalledWith(job, id, expect.objectContaining({ candidate_ids: [secondCandidate], merge_when_ready: false }), 'owner');
  });

  test('a digest computed over a different subset is rejected as manifest_mismatch before any GitHub call', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    for (const wrong of [digestFor([secondCandidate]), digestFor([candidate, secondCandidate]), digest]) {
      const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
        .send(applyBody({ candidate_ids: [candidate], manifest_digest: wrong }));
      expect(res.status).toBe(409); expect(res.body.code).toBe('manifest_mismatch');
    }
    expect(authorize).not.toHaveBeenCalled();
    expect(remediationDb.createAction).not.toHaveBeenCalled();
    expect(remediationDb.recordApplyDenial).toHaveBeenCalledWith(id, job, 'manifest_mismatch', expect.any(Object));
  });

  test('the full batch is applied with the digest computed over the whole ordered batch', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.createAction.mockResolvedValue({ kind: 'ok', action: { id: action, state: 'requested' } });
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [secondCandidate, candidate], manifest_digest: digestFor([candidate, secondCandidate]) }));
    expect(res.status).toBe(202);
  });

  test('a multi-candidate subset that is not the verified batch is refused with 422 subset_not_verified', async () => {
    const third = { ...candidateRows[1], id: '88888888-8888-4888-8888-888888888888', artifact_digest: 'w'.repeat(64) };
    const rows = [...candidateRows, third];
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.getPreview.mockResolvedValue(previewRow(rows));
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [candidate, secondCandidate], manifest_digest: remediationDb.manifestDigestFor(job, rows.slice(0, 2)) }));
    expect(res.status).toBe(422); expect(res.body.code).toBe('subset_not_verified');
    expect(res.body.error).toMatch(/one fix at a time, or apply all/);
    expect(authorize).not.toHaveBeenCalled();
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('a stale candidate is never applied, and an unknown candidate is invalid', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    remediationDb.getPreview.mockResolvedValue(previewRow([candidateRows[0], { ...candidateRows[1], rejection_reason: { code: 'head_changed' } }]));
    const stale = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [secondCandidate], manifest_digest: digestFor([secondCandidate]) }));
    expect(stale.status).toBe(409); expect(stale.body.code).toBe('candidate_stale');
    const unknown = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send(applyBody({ candidate_ids: [action], manifest_digest: digest }));
    expect(unknown.status).toBe(422); expect(unknown.body.code).toBe('invalid_candidates');
    expect(remediationDb.createAction).not.toHaveBeenCalled();
  });

  test('the database re-check under lock reports the same subset errors', async () => {
    remediationDb.getJobForUser.mockResolvedValue(job);
    for (const [kind, status, code] of [['manifest_mismatch', 409, 'manifest_mismatch'], ['candidate_stale', 409, 'candidate_stale'], ['subset_not_verified', 422, 'subset_not_verified']]) {
      remediationDb.createAction.mockResolvedValue({ kind });
      const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`).send(applyBody());
      expect(res.status).toBe(status); expect(res.body.code).toBe(code);
    }
  });
});

describe('subset consent selection', () => {
  test('selectCandidates binds one candidate, the full batch, and nothing in between', () => {
    const one = remediationDb.selectCandidates(job, candidateRows, [candidate]);
    expect(one.kind).toBe('ok'); expect(one.fullBatch).toBe(false); expect(one.manifestDigest).toBe(digestFor([candidate]));
    const all = remediationDb.selectCandidates(job, candidateRows, [secondCandidate, candidate]);
    expect(all.kind).toBe('ok'); expect(all.fullBatch).toBe(true);
    expect(all.candidates.map((c) => c.id)).toEqual([candidate, secondCandidate]);
    expect(all.manifestDigest).toBe(digestFor([candidate, secondCandidate]));
    expect(digestFor([candidate])).not.toBe(digestFor([secondCandidate]));
    const third = { ...candidateRows[1], id: '88888888-8888-4888-8888-888888888888', artifact_digest: 'w'.repeat(64) };
    expect(remediationDb.selectCandidates(job, [...candidateRows, third], [candidate, secondCandidate]).kind).toBe('subset_not_verified');
    expect(remediationDb.selectCandidates(job, candidateRows, []).kind).toBe('invalid_candidates');
    expect(remediationDb.selectCandidates(job, [candidateRows[0], { ...candidateRows[1], rejection_reason: { code: 'head_changed' } }], [candidate, secondCandidate]).kind).toBe('candidate_stale');
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
