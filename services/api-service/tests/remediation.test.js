const request = require('supertest');
const jwt = require('jsonwebtoken');

jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/db/remediation', () => {
  const actual = jest.requireActual('../src/db/remediation');
  return {
    getLatestForPullRequest: jest.fn(), createJob: jest.fn(), getJobForUser: jest.fn(), getPreview: jest.fn(),
    getEvidenceForUser: jest.fn(),
    cancelJob: jest.fn(), getActionForUser: jest.fn(), budgetSnapshot: jest.fn(),
    getCandidateForFeedback: jest.fn(), recordRepairMemoryObservation: jest.fn(),
    // Consent digests and subset selection are pure; the route is tested against the real ones.
    manifestDigestFor: actual.manifestDigestFor, selectCandidates: actual.selectCandidates, hash: actual.hash,
  };
});
jest.mock('../src/services/githubUserAuth', () => ({ getGithubAccessTokenForUser: jest.fn() }));

const remediationDb = require('../src/db/remediation');
const { getGithubAccessTokenForUser } = require('../src/services/githubUserAuth');
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

// The settings repair_service_configured actually requires. Setting only some of
// them made the route fail closed, which is correct behaviour, not a route defect.
function enableRemediation() {
  process.env.REMEDIATION_ENABLED = 'true';
  process.env.REMEDIATION_GENERATE_ENABLED = 'true';
  process.env.REMEDIATION_PUBLISH_ENABLED = 'true';
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
  'REMEDIATION_ENABLED', 'REMEDIATION_GENERATE_ENABLED', 'REMEDIATION_PUBLISH_ENABLED',
  'REMEDIATION_SERVICE_URL', 'REMEDIATION_SERVICE_INTERNAL_SECRET',
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

function token() { return jwt.sign({ user_id: id, github_username: 'owner' }, process.env.JWT_SECRET); }

describe('remediation API', () => {
  beforeEach(() => {
    jest.clearAllMocks(); process.env.JWT_SECRET = 'remediation-test';
    enableRemediation();
    remediationDb.budgetSnapshot.mockResolvedValue({ reserved: 0, ceiling: 2, available: 2 });
    remediationDb.getPreview.mockResolvedValue(previewRow());
    getGithubAccessTokenForUser.mockResolvedValue({ githubUsername: 'owner' });
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

  test('returns a durable generation acceptance', async () => {
    remediationDb.createJob.mockResolvedValue({ kind: 'ok', job, created: true });
    const res = await request(createApp()).post(`/api/pull-requests/${id}/remediations`).set('Authorization', `Bearer ${token()}`).send({ finding_ids: [candidate] });
    expect(res.status).toBe(202); expect(res.body.job.id).toBe(id);
    expect(remediationDb.createJob).toHaveBeenCalledWith(expect.objectContaining({ pullRequestId: id, userId: id, findingIds: [candidate] }));
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
    // There is no apply capability: the App cannot write to repository contents.
    expect(res.body.capabilities.apply).toBeUndefined();
    expect(res.body.capabilities.merge).toBeUndefined();
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
    process.env.REMEDIATION_PUBLISH_ENABLED = 'false';
    remediationDb.getJobForUser.mockResolvedValue(job);
    const res = await request(createApp()).get(`/api/remediations/${id}`).set('Authorization', `Bearer ${token()}`);
    expect(res.status).toBe(200);
    expect(res.body.capabilities.publish).toEqual({ enabled: false, reason: 'feature_flag_off' });
    // Apply and merge are not capabilities any more; they are not reported at all.
    expect(Object.keys(res.body.capabilities)).not.toContain('apply');
    expect(Object.keys(res.body.capabilities)).not.toContain('merge');
  });

  // The App holds no write access to repository contents, so it cannot commit a fix.
  // The route stays only to tell an old client where the fix now gets applied.
  test('the apply route is gone and points at GitHub\'s Commit suggestion button', async () => {
    const res = await request(createApp()).post(`/api/remediations/${id}/apply`).set('Authorization', `Bearer ${token()}`)
      .send({ head_sha: sha, base_sha: baseSha, manifest_digest: digestFor([candidate]), candidate_ids: [candidate],
        idempotency_key: 'idempotency-key' });
    expect(res.status).toBe(410);
    expect(res.body.code).toBe('apply_removed');
    expect(res.body.error).toMatch(/Commit suggestion/);
    expect(res.body.error).toMatch(/no write access/);
  });

  test('the merge cancellation route no longer exists', async () => {
    const res = await request(createApp()).post(`/api/remediation-actions/${action}/cancel-merge`)
      .set('Authorization', `Bearer ${token()}`).send({});
    expect(res.status).toBe(404);
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
