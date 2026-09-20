jest.mock('../src/db/remediation', () => ({
  actionMaterial: jest.fn(), updateAction: jest.fn(async () => ({})), enterChecking: jest.fn(async () => ({})),
  markCandidatesAfterApply: jest.fn(async () => ({ jobs: [], candidates: [], mergeIntents: [] })),
}));
jest.mock('../src/services/githubRemediationClient', () => {
  const prepare = jest.fn();
  const commit = jest.fn();
  const reconcile = jest.fn();
  return { GitHubRemediationClient: jest.fn(() => ({ prepare, commit, reconcile })), __prepare: prepare, __commit: commit };
});
jest.mock('../src/services/remediationPolicy', () => ({
  verificationLevelPermitted: jest.fn(() => true), assertApplyEnabled: jest.fn(), assertMergeEnabled: jest.fn(),
}));
jest.mock('../src/services/remediationMetrics', () => ({ actionTransitions: { labels: jest.fn(() => ({ inc: jest.fn() })) } }));
jest.mock('../src/services/mergeController', () => ({ publishVerificationCheck: jest.fn(async () => {}) }));
jest.mock('../src/services/prAnalysisOrchestrator', () => ({ notifyAnalysisQueued: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ warn: jest.fn(), error: jest.fn(), info: jest.fn() }));
jest.mock('../src/utils/telemetry', () => ({ withSpan: jest.fn((name, attrs, fn) => fn()) }));

const remediationDb = require('../src/db/remediation');
const { __prepare: prepare, __commit: commit } = require('../src/services/githubRemediationClient');
const { executeAction, persistedChanges, verifiedTreeOid } = require('../src/services/remediationActionWorker');

const tree = 'f'.repeat(40);
const repaired = "const { execFile } = require('node:child_process');\nexecFile('ls', [name]);\n";
const contents = Buffer.from(repaired, 'utf8').toString('base64');

// A candidate built from line-range hunks: the repair service still carries the whole final
// file for every changed path, alongside the verified tree the sandbox attested.
function hunkCandidate(overrides = {}) {
  return {
    id: '22222222-2222-4222-8222-222222222222',
    artifact_digest: 'a'.repeat(64),
    verification_level: 'independent_sandbox',
    preview: { verified_tree_oid: tree, changes: [{ path: 'services/accounts.js', unified_diff: '@@ -1 +1,2 @@' }] },
    file_manifest: {
      verified_tree_oid: tree,
      files: [{ path: 'services/accounts.js', base_sha256: 'sha256:' + '1'.repeat(64), new_sha256: 'sha256:' + '2'.repeat(64),
        contents_base64: contents, blob_oid: 'b'.repeat(40), bytes: repaired.length, kind: 'application' }],
    },
    ...overrides,
  };
}

const job = { id: '11111111-1111-4111-8111-111111111111', state: 'ready', head_sha: 'a'.repeat(40), base_sha: 'b'.repeat(40),
  installation_id: 42, repository_full_name: 'owner/repo', pr_number: 7 };
const action = { id: '33333333-3333-4333-8333-333333333333', state: 'claimed', action_type: 'apply', actor_login: 'user',
  head_sha: job.head_sha, base_sha: job.base_sha, batch_manifest_digest: 'd'.repeat(64), idempotency_key: 'k',
  candidate_ids: ['22222222-2222-4222-8222-222222222222'] };

beforeEach(() => {
  jest.clearAllMocks();
});

describe('persistedChanges', () => {
  test('a hunk candidate yields the whole final file for every changed path', () => {
    const changes = persistedChanges([hunkCandidate()]);
    expect(changes).toEqual([expect.objectContaining({ path: 'services/accounts.js', contents_base64: contents })]);
    expect(Buffer.from(changes[0].contents_base64, 'base64').toString('utf8')).toBe(repaired);
    expect(verifiedTreeOid([hunkCandidate()])).toBe(tree);
  });

  test('the verified tree is read from the manifest when the preview lacks it', () => {
    expect(verifiedTreeOid([hunkCandidate({ preview: { changes: [] } })])).toBe(tree);
  });

  test('a manifest stored as a bare file list is still committable', () => {
    const candidate = hunkCandidate({ file_manifest: hunkCandidate().file_manifest.files });
    expect(persistedChanges([candidate])).toHaveLength(1);
  });

  test('hunks without full contents are not committable changes', () => {
    const hunksOnly = hunkCandidate({ file_manifest: { verified_tree_oid: tree, files: [{ path: 'services/accounts.js', unified_diff: '@@' }] } });
    expect(persistedChanges([hunksOnly])).toEqual([]);
    expect(persistedChanges([hunkCandidate({ file_manifest: {} })])).toEqual([]);
  });
});

describe('executeAction', () => {
  test('commits the manifest files against the verified tree', async () => {
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunkCandidate()], manifestDigest: action.batch_manifest_digest,
      orderedCandidateIds: action.candidate_ids });
    prepare.mockResolvedValue({ state: 'ready', operation_id: 'op', branch: 'feature', expected_head_oid: job.head_sha });
    commit.mockResolvedValue({ state: 'applied', operation_id: 'op', commit_sha: 'c'.repeat(40), tree_oid: tree });

    await executeAction(action);

    expect(commit).toHaveBeenCalledWith(expect.objectContaining({
      verified_tree_oid: tree, expected_head_oid: job.head_sha, branch: 'feature',
      changes: [expect.objectContaining({ path: 'services/accounts.js', contents_base64: contents })],
    }));
    expect(remediationDb.updateAction).toHaveBeenCalledWith(action, 'applied', expect.objectContaining({ commitSha: 'c'.repeat(40), treeOid: tree }));
    expect(remediationDb.enterChecking).toHaveBeenCalled();
  });

  test('blocks with verified_full_file_manifest_unavailable when only hunks were stored', async () => {
    const hunksOnly = hunkCandidate({ file_manifest: { verified_tree_oid: tree, files: [{ path: 'services/accounts.js', unified_diff: '@@' }] } });
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunksOnly], manifestDigest: action.batch_manifest_digest,
      orderedCandidateIds: action.candidate_ids });

    await executeAction(action);

    expect(prepare).not.toHaveBeenCalled();
    expect(commit).not.toHaveBeenCalled();
    expect(remediationDb.updateAction).toHaveBeenCalledWith(action, 'blocked', { reason: { code: 'verified_full_file_manifest_unavailable' } });
  });

  test('a committed apply marks the applied candidate and every remaining candidate of the pull request stale', async () => {
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunkCandidate()], manifestDigest: action.batch_manifest_digest,
      orderedCandidateIds: action.candidate_ids, fullBatch: false, combinedTreeOid: '9'.repeat(40) });
    prepare.mockResolvedValue({ state: 'ready', operation_id: 'op', branch: 'feature', expected_head_oid: job.head_sha });
    commit.mockResolvedValue({ state: 'applied', operation_id: 'op', commit_sha: 'c'.repeat(40), tree_oid: tree });

    await executeAction(action);

    // One candidate commits against its own verified tree, not the batch tree.
    expect(commit).toHaveBeenCalledWith(expect.objectContaining({ verified_tree_oid: tree }));
    expect(remediationDb.markCandidatesAfterApply).toHaveBeenCalledWith(action, 'c'.repeat(40));
    expect(remediationDb.enterChecking).toHaveBeenCalled();
  });

  test('a multi-candidate subset that is not the verified batch is rejected before any GitHub call', async () => {
    const second = hunkCandidate({ id: '44444444-4444-4444-8444-444444444444', artifact_digest: 'b'.repeat(64) });
    const subset = { ...action, candidate_ids: [action.candidate_ids[0], second.id] };
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunkCandidate(), second], manifestDigest: subset.batch_manifest_digest,
      orderedCandidateIds: subset.candidate_ids, fullBatch: false, combinedTreeOid: '9'.repeat(40) });

    await executeAction(subset);

    expect(prepare).not.toHaveBeenCalled();
    expect(commit).not.toHaveBeenCalled();
    expect(remediationDb.updateAction).toHaveBeenCalledWith(subset, 'rejected', { reason: { code: 'subset_not_verified' } });
  });

  test('the full batch commits against the combined tree the repair service verified', async () => {
    const second = hunkCandidate({ id: '44444444-4444-4444-8444-444444444444', artifact_digest: 'b'.repeat(64) });
    const batch = { ...action, candidate_ids: [action.candidate_ids[0], second.id] };
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunkCandidate(), second], manifestDigest: batch.batch_manifest_digest,
      orderedCandidateIds: batch.candidate_ids, fullBatch: true, combinedTreeOid: '9'.repeat(40) });
    prepare.mockResolvedValue({ state: 'ready', operation_id: 'op', branch: 'feature', expected_head_oid: job.head_sha });
    commit.mockResolvedValue({ state: 'applied', operation_id: 'op', commit_sha: 'c'.repeat(40), tree_oid: '9'.repeat(40) });

    await executeAction(batch);

    expect(commit).toHaveBeenCalledWith(expect.objectContaining({ verified_tree_oid: '9'.repeat(40) }));
    expect(verifiedTreeOid([hunkCandidate(), second], '9'.repeat(40))).toBe('9'.repeat(40));
    expect(verifiedTreeOid([hunkCandidate(), second], null)).toBeNull();
  });

  test('a stale candidate is rejected rather than rebased', async () => {
    remediationDb.actionMaterial.mockResolvedValue({ job, candidates: [hunkCandidate({ rejection_reason: { code: 'head_changed' } })],
      manifestDigest: action.batch_manifest_digest, orderedCandidateIds: action.candidate_ids, fullBatch: false, combinedTreeOid: null });

    await executeAction(action);

    expect(prepare).not.toHaveBeenCalled();
    expect(remediationDb.updateAction).toHaveBeenCalledWith(action, 'rejected', { reason: { code: 'candidate_stale' } });
  });
});
