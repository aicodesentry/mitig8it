// W10 requires the remediation operations to behave identically over the internal HTTP
// routes and over gRPC. Both transports are driven here against the same mocked
// operations module, so a divergence in payload shape or result mapping fails the build.
const OPERATION_NAMES = [
  'authorizeRemediationActor',
  'cancelScheduledMerge',
  'commitRemediationAction',
  'createCheckRun',
  'createRemediationCheckRun',
  'fetchFileContents',
  'fetchPullRequestFiles',
  'fetchRemediationSnapshot',
  'mergeRemediationAction',
  'postInlineComment',
  'prepareRemediationAction',
  'readMergeEligibility',
  'readPullRequestHead',
  'reconcileRemediationAction',
  'submitPullRequestReview',
];

jest.mock('../services/githubInternalOperations', () => {
  const operations = {};
  for (const name of [
    'cancelScheduledMerge', 'commitRemediationAction', 'createCheckRun', 'createRemediationCheckRun',
    'fetchFileContents', 'fetchPullRequestFiles', 'fetchRemediationSnapshot', 'mergeRemediationAction',
    'postInlineComment', 'prepareRemediationAction', 'readMergeEligibility', 'readPullRequestHead',
    'reconcileRemediationAction', 'submitPullRequestReview', 'authorizeRemediationActor',
  ]) {
    operations[name] = jest.fn();
  }
  operations.githubRequest = jest.fn();
  operations.remediationMarker = jest.fn();
  operations.remediationVerificationCheckName = jest.fn();
  operations.OperationError = class OperationError extends Error {
    constructor(message, statusCode = 500, detail = null) {
      super(message);
      this.statusCode = statusCode;
      this.detail = detail;
    }
  };
  return operations;
});

const operations = require('../services/githubInternalOperations');
const githubPb = require('../grpc/generated/github_pb');
const internalRouter = require('../routes/internal');
const { githubService } = require('../github_grpc_server');

const head = 'a'.repeat(40);
const base = 'b'.repeat(40);
const tree = 'c'.repeat(40);
const digest = 'd'.repeat(64);
const actionId = 'action-identity-0001';

const envelopeBody = {
  repository_full_name: 'owner/repo',
  actor_login: 'developer',
  installation_id: 41,
  pr_number: 9,
  head_sha: head,
  base_sha: base,
  action_id: actionId,
  idempotency_key: 'idempotency-key-0001',
  manifest_digest: digest,
};

function buildEnvelope() {
  const envelope = new githubPb.RemediationEnvelope();
  envelope.setRepositoryFullName(envelopeBody.repository_full_name);
  envelope.setActorLogin(envelopeBody.actor_login);
  envelope.setInstallationId(envelopeBody.installation_id);
  envelope.setPrNumber(envelopeBody.pr_number);
  envelope.setHeadSha(envelopeBody.head_sha);
  envelope.setBaseSha(envelopeBody.base_sha);
  envelope.setActionId(envelopeBody.action_id);
  envelope.setIdempotencyKey(envelopeBody.idempotency_key);
  envelope.setManifestDigest(envelopeBody.manifest_digest);
  return envelope;
}

function findRouteHandler(path) {
  const layer = internalRouter.stack.find(
    (entry) => entry.route && entry.route.path === path && entry.route.methods.post
  );
  return layer.route.stack[layer.route.stack.length - 1].handle;
}

function createRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(payload) {
      this.body = payload;
      return this;
    },
  };
}

const cases = [
  {
    name: 'prepare',
    path: '/github/remediation/prepare',
    rpc: 'prepareRemediation',
    operation: 'prepareRemediationAction',
    body: { ...envelopeBody },
    request: () => {
      const request = new githubPb.RemediationPrepareRequest();
      request.setEnvelope(buildEnvelope());
      return request;
    },
    result: { state: 'ready', operation_id: actionId, branch: 'repair-branch', expected_head_oid: head, marker: '<!-- marker -->' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      branch: response.getBranch(),
      expected_head_oid: response.getExpectedHeadOid(),
      marker: response.getMarker(),
    }),
  },
  {
    name: 'snapshot',
    path: '/github/remediation/snapshot',
    rpc: 'snapshotRemediation',
    operation: 'fetchRemediationSnapshot',
    body: { ...envelopeBody, finding_paths: ['src/app.js'] },
    request: () => {
      const request = new githubPb.RemediationSnapshotRequest();
      request.setEnvelope(buildEnvelope());
      request.setFindingPathsList(['src/app.js']);
      return request;
    },
    result: {
      files: [{ path: 'src/app.js', content: 'const safe = true;\n', sha: 'e'.repeat(40) }],
      tree_entries: [{ path: 'src/app.js', mode: '100644', type: 'blob', sha: 'e'.repeat(40) }],
      head_tree_oid: tree,
      head_sha: head,
      base_sha: base,
      omitted_source_paths: ['src/other.js'],
    },
    read: (response) => ({
      files: response.getFilesList().map((file) => ({ path: file.getPath(), content: file.getContent(), sha: file.getSha() })),
      tree_entries: response.getTreeEntriesList().map((entry) => ({
        path: entry.getPath(), mode: entry.getMode(), type: entry.getType(), sha: entry.getSha(),
      })),
      head_tree_oid: response.getHeadTreeOid(),
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      omitted_source_paths: response.getOmittedSourcePathsList(),
    }),
  },
  {
    name: 'commit',
    path: '/github/remediation/commit',
    rpc: 'commitRemediation',
    operation: 'commitRemediationAction',
    body: {
      ...envelopeBody,
      branch: 'repair-branch',
      expected_head_oid: head,
      verified_tree_oid: tree,
      commit_message: 'Apply verified remediation',
      changes: [{ path: 'src/app.js', contents_base64: 'Y29uc3Qgc2FmZSA9IHRydWU7Cg==' }],
    },
    request: () => {
      const request = new githubPb.RemediationCommitRequest();
      request.setEnvelope(buildEnvelope());
      request.setBranch('repair-branch');
      request.setExpectedHeadOid(head);
      request.setVerifiedTreeOid(tree);
      request.setCommitMessage('Apply verified remediation');
      const change = new githubPb.RemediationFileChange();
      change.setPath('src/app.js');
      change.setContentsBase64('Y29uc3Qgc2FmZSA9IHRydWU7Cg==');
      request.setChangesList([change]);
      return request;
    },
    result: { state: 'applied', operation_id: actionId, commit_sha: 'e'.repeat(40), tree_oid: tree, reason: '' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      commit_sha: response.getCommitSha(),
      tree_oid: response.getTreeOid(),
      reason: response.getReason(),
    }),
  },
  {
    name: 'reconcile',
    path: '/github/remediation/reconcile',
    rpc: 'reconcileRemediation',
    operation: 'reconcileRemediationAction',
    body: { ...envelopeBody, verified_tree_oid: tree },
    request: () => {
      const request = new githubPb.RemediationReconcileRequest();
      request.setEnvelope(buildEnvelope());
      request.setVerifiedTreeOid(tree);
      return request;
    },
    result: { state: 'unresolved', operation_id: actionId, commit_sha: '', tree_oid: '', reason: 'head_changed_without_matching_marker' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      commit_sha: response.getCommitSha(),
      tree_oid: response.getTreeOid(),
      reason: response.getReason(),
    }),
  },
  {
    name: 'merge',
    path: '/github/remediation/merge',
    rpc: 'mergeRemediation',
    operation: 'mergeRemediationAction',
    body: {
      ...envelopeBody,
      expected_head_sha: head,
      expected_base_sha: base,
      merge_method: 'squash',
      verification_check_name: 'Mitig8it Remediation Verification',
    },
    request: () => {
      const request = new githubPb.RemediationMergeRequest();
      request.setEnvelope(buildEnvelope());
      request.setExpectedHeadSha(head);
      request.setExpectedBaseSha(base);
      request.setMergeMethod('squash');
      request.setVerificationCheckName('Mitig8it Remediation Verification');
      return request;
    },
    result: { state: 'reconciling', operation_id: actionId, commit_sha: '', reason: 'github_merge_outcome_ambiguous' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      commit_sha: response.getCommitSha(),
      reason: response.getReason(),
    }),
  },
  {
    name: 'cancel-merge',
    path: '/github/remediation/cancel-merge',
    rpc: 'cancelScheduledMerge',
    operation: 'cancelScheduledMerge',
    body: { ...envelopeBody, pull_number: 9, expected_head_sha: head },
    request: () => {
      const request = new githubPb.CancelScheduledMergeRequest();
      request.setEnvelope(buildEnvelope());
      request.setPullNumber(9);
      request.setExpectedHeadSha(head);
      return request;
    },
    result: { state: 'cancelled', operation_id: actionId, head_sha: head, merged: false, reason: '' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      head_sha: response.getHeadSha(),
      merged: response.getMerged(),
      reason: response.getReason(),
    }),
  },
  {
    name: 'merge-eligibility',
    path: '/github/remediation/merge-eligibility',
    rpc: 'readMergeEligibility',
    operation: 'readMergeEligibility',
    body: {
      ...envelopeBody,
      pull_number: 9,
      expected_head_sha: head,
      verification_check_name: 'Mitig8it Remediation Verification',
    },
    request: () => {
      const request = new githubPb.MergeEligibilityRequest();
      request.setEnvelope(buildEnvelope());
      request.setPullNumber(9);
      request.setExpectedHeadSha(head);
      request.setVerificationCheckName('Mitig8it Remediation Verification');
      return request;
    },
    result: {
      eligible: false,
      blockers: ['verification_check_not_successful'],
      required_checks: [{ context: 'Mitig8it Remediation Verification', app_id: 123 }],
      check_runs: [{ id: 3, name: 'Mitig8it Remediation Verification', app_id: 999, status: 'completed', conclusion: 'success' }],
      reviews: { required: 1, approvals: 1, changes_requested: false },
      protection_source: 'branch_protection',
      mergeable_state: 'clean',
      head_sha: head,
      base_sha: base,
      verification_check_name: 'Mitig8it Remediation Verification',
    },
    read: (response) => ({
      eligible: response.getEligible(),
      blockers: response.getBlockersList(),
      required_checks: response.getRequiredChecksList().map((check) => ({ context: check.getContext(), app_id: check.getAppId() })),
      check_runs: response.getCheckRunsList().map((check) => ({
        id: check.getId(), name: check.getName(), app_id: check.getAppId(),
        status: check.getStatus(), conclusion: check.getConclusion(),
      })),
      reviews: {
        required: response.getReviews().getRequired(),
        approvals: response.getReviews().getApprovals(),
        changes_requested: response.getReviews().getChangesRequested(),
      },
      protection_source: response.getProtectionSource(),
      mergeable_state: response.getMergeableState(),
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      verification_check_name: response.getVerificationCheckName(),
    }),
  },
  {
    name: 'pull-head',
    path: '/github/remediation/pull-head',
    rpc: 'readPullRequestHead',
    operation: 'readPullRequestHead',
    body: { ...envelopeBody, pull_number: 9 },
    request: () => {
      const request = new githubPb.PullRequestHeadRequest();
      request.setEnvelope(buildEnvelope());
      request.setPullNumber(9);
      return request;
    },
    result: { head_sha: head, base_sha: base, state: 'open', draft: false, merged: false, mergeable_state: 'clean', fork: false },
    read: (response) => ({
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      state: response.getState(),
      draft: response.getDraft(),
      merged: response.getMerged(),
      mergeable_state: response.getMergeableState(),
      fork: response.getFork(),
    }),
  },
  {
    name: 'check-run',
    path: '/github/remediation/check-run',
    rpc: 'createRemediationCheckRun',
    operation: 'createRemediationCheckRun',
    body: {
      ...envelopeBody,
      head_sha: head,
      name: 'Mitig8it Remediation Verification',
      status: 'completed',
      conclusion: 'success',
      title: 'Remediation verified',
      summary: 'Independent verification succeeded.',
      external_id: 'verification-0001',
    },
    request: () => {
      const request = new githubPb.RemediationCheckRunRequest();
      request.setEnvelope(buildEnvelope());
      request.setHeadSha(head);
      request.setName('Mitig8it Remediation Verification');
      request.setStatus('completed');
      request.setConclusion('success');
      request.setTitle('Remediation verified');
      request.setSummary('Independent verification succeeded.');
      request.setExternalId('verification-0001');
      return request;
    },
    result: {
      state: 'published',
      operation_id: actionId,
      check_run_id: 55,
      name: 'Mitig8it Remediation Verification',
      external_id: 'verification-0001',
      updated: true,
      reason: '',
    },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      check_run_id: response.getCheckRunId(),
      name: response.getName(),
      external_id: response.getExternalId(),
      updated: response.getUpdated(),
      reason: response.getReason(),
    }),
  },
  {
    name: 'authorize',
    path: '/github/remediation/authorize',
    rpc: 'authorizeRemediation',
    operation: 'authorizeRemediationActor',
    body: { ...envelopeBody },
    request: () => {
      const request = new githubPb.RemediationAuthorizeRequest();
      request.setEnvelope(buildEnvelope());
      return request;
    },
    result: {
      state: 'authorized',
      installation_active: true,
      repository_granted: true,
      actor_write_permission: true,
      head_sha: head,
      base_sha: base,
      head_branch: 'feature-branch',
      base_branch: 'main',
    },
    read: (response) => ({
      state: response.getState(),
      installation_active: response.getInstallationActive(),
      repository_granted: response.getRepositoryGranted(),
      actor_write_permission: response.getActorWritePermission(),
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      head_branch: response.getHeadBranch(),
      base_branch: response.getBaseBranch(),
    }),
  },
  {
    // A ruleset-governed branch reports a different protection source and ruleset-derived
    // blockers, so both transports must carry those values unchanged.
    name: 'merge-eligibility-rulesets',
    path: '/github/remediation/merge-eligibility',
    rpc: 'readMergeEligibility',
    operation: 'readMergeEligibility',
    body: {
      ...envelopeBody,
      pull_number: 9,
      expected_head_sha: head,
      verification_check_name: 'Mitig8it Remediation Verification',
    },
    request: () => {
      const request = new githubPb.MergeEligibilityRequest();
      request.setEnvelope(buildEnvelope());
      request.setPullNumber(9);
      request.setExpectedHeadSha(head);
      request.setVerificationCheckName('Mitig8it Remediation Verification');
      return request;
    },
    result: {
      eligible: false,
      blockers: ['merge_queue_unsupported', 'ruleset_rule_unsupported_required_deployments'],
      required_checks: [{ context: 'Mitig8it Remediation Verification', app_id: 123 }],
      check_runs: [{ id: 3, name: 'Mitig8it Remediation Verification', app_id: 123, status: 'completed', conclusion: 'success' }],
      reviews: { required: 0, approvals: 0, changes_requested: false },
      protection_source: 'rulesets',
      mergeable_state: 'clean',
      head_sha: head,
      base_sha: base,
      verification_check_name: 'Mitig8it Remediation Verification',
    },
    read: (response) => ({
      eligible: response.getEligible(),
      blockers: response.getBlockersList(),
      required_checks: response.getRequiredChecksList().map((check) => ({ context: check.getContext(), app_id: check.getAppId() })),
      check_runs: response.getCheckRunsList().map((check) => ({
        id: check.getId(), name: check.getName(), app_id: check.getAppId(),
        status: check.getStatus(), conclusion: check.getConclusion(),
      })),
      reviews: {
        required: response.getReviews().getRequired(),
        approvals: response.getReviews().getApprovals(),
        changes_requested: response.getReviews().getChangesRequested(),
      },
      protection_source: response.getProtectionSource(),
      mergeable_state: response.getMergeableState(),
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      verification_check_name: response.getVerificationCheckName(),
    }),
  },
];

function callGrpc(rpc, request) {
  return new Promise((resolve, reject) => {
    githubService[rpc]({ request }, (error, response) => (error ? reject(error) : resolve(response)));
  });
}

beforeEach(() => {
  jest.clearAllMocks();
});

test('the operations module exposes every function both transports dispatch to', () => {
  for (const name of OPERATION_NAMES) {
    expect(typeof require('../services/githubInternalOperations')[name]).toBe('function');
  }
  expect(cases).toHaveLength(11);
});

test.each(cases)('$name reaches the same operation with the same payload over HTTP and gRPC', async (testCase) => {
  operations[testCase.operation].mockResolvedValue(testCase.result);

  const res = createRes();
  await findRouteHandler(testCase.path)({ body: testCase.body }, res);
  const grpcResponse = await callGrpc(testCase.rpc, testCase.request());

  expect(operations[testCase.operation]).toHaveBeenCalledTimes(2);
  const [httpPayload, grpcPayload] = operations[testCase.operation].mock.calls.map(([payload]) => payload);
  expect(grpcPayload).toEqual(httpPayload);
  expect(res.statusCode).toBe(200);
  expect(res.body).toEqual(testCase.result);
  expect(testCase.read(grpcResponse)).toEqual(res.body);
});

test.each(cases)('$name maps an operation refusal to a transport-specific failure on both paths', async (testCase) => {
  const { OperationError } = require('../services/githubInternalOperations');
  operations[testCase.operation].mockRejectedValue(new OperationError('Remediation action is superseded', 409));

  const res = createRes();
  await findRouteHandler(testCase.path)({ body: testCase.body }, res);
  expect(res.statusCode).toBe(409);
  expect(res.body.error).toBe('Remediation action is superseded');

  await expect(callGrpc(testCase.rpc, testCase.request())).rejects.toMatchObject({
    code: 9,
    message: 'Remediation action is superseded',
  });
});
