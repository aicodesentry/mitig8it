// W10 requires the remediation operations to behave identically over the internal HTTP
// routes and over gRPC. Both transports are driven here against the same mocked
// operations module, so a divergence in payload shape or result mapping fails the build.
const OPERATION_NAMES = [
  'createCheckRun',
  'createRemediationCheckRun',
  'fetchFileContents',
  'fetchPullRequestFiles',
  'fetchRemediationSnapshot',
  'postInlineComment',
  'publishFindingFixSections',
  'publishRemediationComment',
  'retireInlineComments',
  'submitPullRequestReview',
];

// The operations that used to write to a repository. The App holds no contents write
// permission any more, so neither transport may expose them.
const REMOVED_OPERATION_NAMES = [
  'authorizeRemediationActor',
  'cancelScheduledMerge',
  'commitRemediationAction',
  'mergeRemediationAction',
  'prepareRemediationAction',
  'readMergeEligibility',
  'readPullRequestHead',
  'reconcileRemediationAction',
];

jest.mock('../services/githubInternalOperations', () => {
  const operations = {};
  for (const name of [
    'createCheckRun', 'createRemediationCheckRun',
    'fetchFileContents', 'fetchPullRequestFiles', 'fetchRemediationSnapshot',
    'postInlineComment', 'retireInlineComments', 'submitPullRequestReview',
    'publishRemediationComment', 'publishFindingFixSections',
  ]) {
    operations[name] = jest.fn();
  }
  operations.githubRequest = jest.fn();
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
    name: 'comment',
    path: '/github/remediation/comment',
    rpc: 'publishRemediationComment',
    operation: 'publishRemediationComment',
    body: { ...envelopeBody, external_id: 'report-0001', body: 'Applied 1 fix. Remaining open findings: 0.' },
    request: () => {
      const request = new githubPb.RemediationCommentRequest();
      request.setEnvelope(buildEnvelope());
      request.setExternalId('report-0001');
      request.setBody('Applied 1 fix. Remaining open findings: 0.');
      return request;
    },
    result: { state: 'published', operation_id: actionId, comment_id: 91, external_id: 'report-0001', updated: false, reason: '' },
    read: (response) => ({
      state: response.getState(),
      operation_id: response.getOperationId(),
      comment_id: response.getCommentId(),
      external_id: response.getExternalId(),
      updated: response.getUpdated(),
      reason: response.getReason(),
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
      // A finding source the immutable tree does not carry is reported per path rather
      // than raised as an error, so both transports must carry the skip list.
      skipped: [{ path: 'TestVuln.cs', code: 'affected_source_missing',
        message: 'The finding source is unsupported or missing from the immutable tree.' }],
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
      skipped: response.getSkippedList().map((item) => ({
        path: item.getPath(), code: item.getCode(), message: item.getMessage(),
      })),
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
    name: 'finding-fixes',
    path: '/github/remediation/finding-fixes',
    rpc: 'publishFindingFixSections',
    operation: 'publishFindingFixSections',
    body: {
      ...envelopeBody,
      preview_url: 'https://app.example.test/dashboard/pull-requests/pr-1/findings',
      sections: [
        {
          candidate_id: 'candidate-0001', finding_fingerprint: 'fp-1', path: 'src/app.js', finding_line: 12,
          hunk: { start_line: 12, end_line: 12, original_lines: ['old'], replacement_lines: ['new', 'more'] },
          extra_hunks: [{ start_line: 1, end_line: 1, original_lines: ['const a = 1;'], replacement_lines: ['const a = 1;', "const { execFile } = require('child_process');"] }],
          unified_diff: '@@ -12 +12,2 @@\n-old\n+new\n+more', not_suggestable_reason: '', stated_intent: 'Same result.',
          evidence: ['test failed on original, passed on fix'], limitations: ['no build'], skipped_reason: '', verification_level: 'independent_sandbox',
          finding_body: '**HIGH** — SQL injection\n\n> raw query', finding_ids: ['f-1', 'f-3'], covered_by: '',
          proof: 'regression test t.js asserts that the SQL injection is no longer reproducible; it failed on the original code and passed on the fix.',
        },
        {
          candidate_id: '', finding_fingerprint: 'fp-2', path: 'src/app.js', finding_line: 30, hunk: null, extra_hunks: [],
          unified_diff: '', not_suggestable_reason: '', stated_intent: '', evidence: [], limitations: [],
          skipped_reason: 'outside the enabled repair families', verification_level: '',
          finding_body: '', finding_ids: [], covered_by: '', proof: '',
        },
        {
          candidate_id: 'candidate-0001', finding_fingerprint: 'fp-3', path: 'src/app.js', finding_line: 12, hunk: null, extra_hunks: [],
          unified_diff: '', not_suggestable_reason: '', stated_intent: '', evidence: [], limitations: [],
          skipped_reason: '', verification_level: '', finding_body: '', finding_ids: ['f-1', 'f-3'], covered_by: 'js/path-traversal', proof: '',
        },
      ],
    },
    request: () => {
      const request = new githubPb.FindingFixSectionsRequest();
      request.setEnvelope(buildEnvelope());
      request.setPreviewUrl('https://app.example.test/dashboard/pull-requests/pr-1/findings');
      const first = new githubPb.FindingFixSection();
      first.setCandidateId('candidate-0001'); first.setFindingFingerprint('fp-1'); first.setPath('src/app.js'); first.setFindingLine(12);
      const hunk = new githubPb.FindingFixHunk();
      hunk.setStartLine(12); hunk.setEndLine(12); hunk.setOriginalLinesList(['old']); hunk.setReplacementLinesList(['new', 'more']);
      first.setHunk(hunk);
      const extra = new githubPb.FindingFixHunk();
      extra.setStartLine(1); extra.setEndLine(1); extra.setOriginalLinesList(['const a = 1;']); extra.setReplacementLinesList(['const a = 1;', "const { execFile } = require('child_process');"]);
      first.setExtraHunksList([extra]);
      first.setUnifiedDiff('@@ -12 +12,2 @@\n-old\n+new\n+more'); first.setStatedIntent('Same result.');
      first.setEvidenceList(['test failed on original, passed on fix']); first.setLimitationsList(['no build']); first.setVerificationLevel('independent_sandbox');
      first.setFindingBody('**HIGH** — SQL injection\n\n> raw query'); first.setFindingIdsList(['f-1', 'f-3']);
      first.setProof('regression test t.js asserts that the SQL injection is no longer reproducible; it failed on the original code and passed on the fix.');
      const second = new githubPb.FindingFixSection();
      second.setFindingFingerprint('fp-2'); second.setPath('src/app.js'); second.setFindingLine(30);
      second.setSkippedReason('outside the enabled repair families');
      const third = new githubPb.FindingFixSection();
      third.setCandidateId('candidate-0001'); third.setFindingFingerprint('fp-3'); third.setPath('src/app.js'); third.setFindingLine(12);
      third.setFindingIdsList(['f-1', 'f-3']); third.setCoveredBy('js/path-traversal');
      request.setSectionsList([first, second, third]);
      return request;
    },
    result: {
      state: 'published', operation_id: actionId,
      results: [
        { finding_fingerprint: 'fp-1', candidate_id: 'candidate-0001', comment_id: 77, mode: 'suggestion', updated: true, reason: '', created: true, placement: 'inline' },
        { finding_fingerprint: 'fp-2', candidate_id: '', comment_id: 78, mode: 'skipped', updated: true, reason: 'outside the enabled repair families', created: false, placement: 'inline' },
        { finding_fingerprint: 'fp-3', candidate_id: 'candidate-0001', comment_id: 79, mode: 'covered', updated: true, reason: 'fixed together with js/path-traversal', created: true, placement: 'pull_request' },
      ],
      reason: '',
    },
    read: (response) => ({
      state: response.getState(), operation_id: response.getOperationId(),
      results: response.getResultsList().map((item) => ({
        finding_fingerprint: item.getFindingFingerprint(), candidate_id: item.getCandidateId(), comment_id: item.getCommentId(),
        mode: item.getMode(), updated: item.getUpdated(), reason: item.getReason(), created: item.getCreated(), placement: item.getPlacement(),
      })),
      reason: response.getReason(),
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
  expect(cases).toHaveLength(4);
});

// A regression guard for the least-privilege change: neither the gRPC service nor the
// operations module may grow a code-writing operation back.
test('no transport exposes an operation that writes to a repository', () => {
  const { githubService: service } = require('../github_grpc_server');
  for (const rpc of ['commitRemediation', 'mergeRemediation', 'prepareRemediation', 'reconcileRemediation',
    'cancelScheduledMerge', 'readMergeEligibility', 'readPullRequestHead', 'authorizeRemediation']) {
    expect(service[rpc]).toBeUndefined();
  }
  const real = jest.requireActual('../services/githubInternalOperations');
  for (const name of REMOVED_OPERATION_NAMES) {
    expect(real[name]).toBeUndefined();
  }
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

// Retiring an inline comment is an analysis operation, not a remediation one, so it carries
// no consent envelope and has no place in the cases above. It is driven over both transports
// for the same reason they are: production speaks gRPC, and an operation that worked only
// over HTTP would be an operation that never ran.
test('retiring inline comments reaches the same operation with the same payload over HTTP and gRPC', async () => {
  operations.retireInlineComments.mockResolvedValue({ retired: 2, kept: 1 });
  const body = { owner: 'owner', repo: 'repo', pr_number: 9, installation_id: 41, fingerprints: ['fp-one', 'fp-two'] };

  const res = createRes();
  await findRouteHandler('/github/comments/retire')({ body }, res);

  const request = new githubPb.RetireInlineCommentsRequest();
  request.setOwner('owner');
  request.setRepo('repo');
  request.setPrNumber(9);
  request.setInstallationId(41);
  request.setFingerprintsList(['fp-one', 'fp-two']);
  const grpcResponse = await callGrpc('retireInlineComments', request);

  const [httpPayload, grpcPayload] = operations.retireInlineComments.mock.calls.map(([payload]) => payload);
  expect(grpcPayload).toEqual(httpPayload);
  expect(res.body).toEqual({ retired: 2, kept: 1 });
  expect({ retired: grpcResponse.getRetired(), kept: grpcResponse.getKept() }).toEqual(res.body);
});
