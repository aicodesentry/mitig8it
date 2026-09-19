// The deployed GitHub adapter serves only gRPC, so the remediation client has to reach
// it over gRPC and still hand callers the objects the REST path returned. These tests
// drive both transports and compare their output.
const grpc = require('@grpc/grpc-js');
const githubPb = require('../src/grpc/generated/github_pb');

jest.mock('axios', () => ({ create: jest.fn() }));
jest.mock('../src/clients/grpcConnection', () => ({
  ...jest.requireActual('../src/clients/grpcConnection'),
  getIdentityToken: jest.fn(async () => 'id-token'),
}));

const axios = require('axios');
const { GitHubGrpcClient } = require('../src/clients/githubGrpcClient');
const { GitHubRemediationClient } = require('../src/services/githubRemediationClient');

const head = 'a'.repeat(40);
const base = 'b'.repeat(40);
const tree = 'c'.repeat(40);
const digest = 'd'.repeat(64);
const commit = 'e'.repeat(40);

const envelopeBody = {
  repository_full_name: 'owner/repo',
  actor_login: 'nebullii',
  installation_id: 41,
  pr_number: 9,
  head_sha: head,
  base_sha: base,
  action_id: 'action-identity-0001',
  idempotency_key: 'idempotency-key-0001',
  manifest_digest: digest,
};

// A stand-in for the generated stub: it records the proto request and replies with the
// prepared response, so request building and response reading are both exercised.
function stubGrpcClient(method, response, error = null) {
  const calls = [];
  const client = new GitHubGrpcClient('localhost:50051');
  client.client = {
    [method]: (request, options, callback) => {
      calls.push({ request, options });
      callback(error, response);
    },
  };
  return { client, calls };
}

function grpcError(code, { status, details = 'Remediation action is superseded' } = {}) {
  const error = Object.assign(new Error(details), { code, details });
  if (status) {
    error.metadata = new grpc.Metadata();
    error.metadata.set('x-operation-status', String(status));
  }
  return error;
}

let restInstance;

beforeEach(() => {
  jest.clearAllMocks();
  restInstance = { post: jest.fn(async () => ({ data: { ok: true } })) };
  axios.create.mockReturnValue(restInstance);
  process.env.GITHUB_SERVICE_URL = 'http://github:8081';
  process.env.GITHUB_SERVICE_INTERNAL_SECRET = 'internal-secret';
  process.env.GITHUB_GRPC_URL = 'localhost:50051';
  delete process.env.INTERNAL_SERVICE_TRANSPORT;
});

afterEach(() => {
  delete process.env.GITHUB_SERVICE_URL;
  delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
  delete process.env.GITHUB_GRPC_URL;
  delete process.env.INTERNAL_SERVICE_TRANSPORT;
});

describe('transport selection', () => {
  test('INTERNAL_SERVICE_TRANSPORT=grpc delegates every remediation method to the gRPC client', async () => {
    process.env.INTERNAL_SERVICE_TRANSPORT = 'grpc';
    const grpcClient = {};
    const methods = [
      ['authorize', 'authorizeRemediation'],
      ['prepare', 'prepareRemediation'],
      ['snapshot', 'snapshotRemediation'],
      ['commit', 'commitRemediation'],
      ['reconcile', 'reconcileRemediation'],
      ['merge', 'mergeRemediation'],
      ['createCheckRun', 'createRemediationCheckRun'],
      ['cancelScheduledMerge', 'cancelScheduledMerge'],
      ['readMergeEligibility', 'readMergeEligibility'],
      ['readPullRequestHead', 'readPullRequestHead'],
    ];
    for (const [, rpc] of methods) grpcClient[rpc] = jest.fn(async () => ({ rpc }));

    const client = new GitHubRemediationClient({ grpcClient });
    for (const [method, rpc] of methods) {
      await expect(client[method](envelopeBody)).resolves.toEqual({ rpc });
      expect(grpcClient[rpc]).toHaveBeenCalledWith(envelopeBody);
    }
    expect(axios.create).not.toHaveBeenCalled();
  });

  test('gRPC transport needs no REST base URL or internal secret', () => {
    process.env.INTERNAL_SERVICE_TRANSPORT = 'grpc';
    delete process.env.GITHUB_SERVICE_URL;
    delete process.env.GITHUB_SERVICE_INTERNAL_SECRET;
    expect(() => new GitHubRemediationClient({ grpcClient: {} })).not.toThrow();
  });

  test('any other transport value keeps the REST path', async () => {
    process.env.INTERNAL_SERVICE_TRANSPORT = 'http';
    await new GitHubRemediationClient().snapshot({ pull_number: 1 });
    expect(restInstance.post).toHaveBeenCalledWith(
      '/internal/github/remediation/snapshot',
      { pull_number: 1 },
      { headers: {} }
    );
  });
});

describe('gRPC request and response mapping', () => {
  test('snapshot sends the envelope and finding paths and returns the REST snapshot shape', async () => {
    const response = new githubPb.RemediationSnapshotResponse();
    const file = new githubPb.RemediationSourceFile();
    file.setPath('services/accounts.js');
    file.setContent('const safe = true;\n');
    file.setSha(commit);
    response.setFilesList([file]);
    const entry = new githubPb.RemediationTreeEntry();
    entry.setPath('services/accounts.js');
    entry.setMode('100644');
    entry.setType('blob');
    entry.setSha(commit);
    response.setTreeEntriesList([entry]);
    response.setHeadTreeOid(tree);
    response.setHeadSha(head);
    response.setBaseSha(base);
    response.setOmittedSourcePathsList(['src/other.js']);

    const { client, calls } = stubGrpcClient('snapshotRemediation', response);
    const result = await client.snapshotRemediation({ ...envelopeBody, finding_paths: ['services/accounts.js'] });

    const envelope = calls[0].request.getEnvelope();
    expect(envelope.getRepositoryFullName()).toBe('owner/repo');
    expect(envelope.getActorLogin()).toBe('nebullii');
    expect(envelope.getInstallationId()).toBe(41);
    expect(envelope.getPrNumber()).toBe(9);
    expect(envelope.getHeadSha()).toBe(head);
    expect(envelope.getBaseSha()).toBe(base);
    expect(envelope.getManifestDigest()).toBe(digest);
    expect(calls[0].request.getFindingPathsList()).toEqual(['services/accounts.js']);

    expect(result).toEqual({
      files: [{ path: 'services/accounts.js', content: 'const safe = true;\n', sha: commit }],
      tree_entries: [{ path: 'services/accounts.js', mode: '100644', type: 'blob', sha: commit }],
      head_tree_oid: tree,
      head_sha: head,
      base_sha: base,
      omitted_source_paths: ['src/other.js'],
    });
  });

  test('commit sends the branch, tree and base64 changes and returns the REST commit shape', async () => {
    const response = new githubPb.RemediationCommitResponse();
    response.setState('applied');
    response.setOperationId(envelopeBody.action_id);
    response.setCommitSha(commit);
    response.setTreeOid(tree);

    const { client, calls } = stubGrpcClient('commitRemediation', response);
    const result = await client.commitRemediation({
      ...envelopeBody,
      branch: 'repair-branch',
      expected_head_oid: head,
      verified_tree_oid: tree,
      commit_message: 'Apply verified remediation',
      changes: [{ path: 'services/accounts.js', contents_base64: 'Y29uc3Qgc2FmZSA9IHRydWU7Cg==' }],
    });

    const request = calls[0].request;
    expect(request.getBranch()).toBe('repair-branch');
    expect(request.getExpectedHeadOid()).toBe(head);
    expect(request.getVerifiedTreeOid()).toBe(tree);
    expect(request.getCommitMessage()).toBe('Apply verified remediation');
    expect(request.getChangesList().map((change) => [change.getPath(), change.getContentsBase64()]))
      .toEqual([['services/accounts.js', 'Y29uc3Qgc2FmZSA9IHRydWU7Cg==']]);
    expect(result).toEqual({
      state: 'applied', operation_id: envelopeBody.action_id, commit_sha: commit, tree_oid: tree, reason: '',
    });
  });

  test('merge sends the expected revisions and returns the REST merge shape', async () => {
    const response = new githubPb.RemediationMergeResponse();
    response.setState('reconciling');
    response.setOperationId(envelopeBody.action_id);
    response.setReason('github_merge_outcome_ambiguous');

    const { client, calls } = stubGrpcClient('mergeRemediation', response);
    const result = await client.mergeRemediation({
      ...envelopeBody,
      expected_head_sha: head,
      expected_base_sha: base,
      merge_method: 'squash',
      verification_check_name: 'Mitig8it Remediation Verification',
    });

    const request = calls[0].request;
    expect(request.getExpectedHeadSha()).toBe(head);
    expect(request.getExpectedBaseSha()).toBe(base);
    expect(request.getMergeMethod()).toBe('squash');
    expect(request.getVerificationCheckName()).toBe('Mitig8it Remediation Verification');
    expect(result).toEqual({
      state: 'reconciling', operation_id: envelopeBody.action_id, commit_sha: '', reason: 'github_merge_outcome_ambiguous',
    });
  });

  test('authorize returns the booleans and branches the apply pre-flight reads', async () => {
    const response = new githubPb.RemediationAuthorizeResponse();
    response.setState('authorized');
    response.setInstallationActive(true);
    response.setRepositoryGranted(true);
    response.setActorWritePermission(true);
    response.setHeadSha(head);
    response.setBaseSha(base);
    response.setHeadBranch('feature-branch');
    response.setBaseBranch('main');

    const { client } = stubGrpcClient('authorizeRemediation', response);
    await expect(client.authorizeRemediation(envelopeBody)).resolves.toEqual({
      state: 'authorized',
      installation_active: true,
      repository_granted: true,
      actor_write_permission: true,
      head_sha: head,
      base_sha: base,
      head_branch: 'feature-branch',
      base_branch: 'main',
    });
  });
});

describe('gRPC failures keep the REST error shape', () => {
  test.each([
    ['PERMISSION_DENIED', grpc.status.PERMISSION_DENIED, 403, 403],
    ['NOT_FOUND', grpc.status.NOT_FOUND, 404, 404],
    ['FAILED_PRECONDITION carrying 409', grpc.status.FAILED_PRECONDITION, 409, 409],
    ['FAILED_PRECONDITION carrying 422', grpc.status.FAILED_PRECONDITION, 422, 422],
    ['INVALID_ARGUMENT', grpc.status.INVALID_ARGUMENT, 400, 400],
  ])('%s becomes error.response.status %s', async (_name, code, status, expected) => {
    const { client } = stubGrpcClient('prepareRemediation', null, grpcError(code, { status }));
    await expect(client.prepareRemediation(envelopeBody)).rejects.toMatchObject({
      response: { status: expected },
      message: 'Remediation action is superseded',
    });
  });

  test('a FAILED_PRECONDITION without metadata still reads as 409', async () => {
    const { client } = stubGrpcClient('prepareRemediation', null, grpcError(grpc.status.FAILED_PRECONDITION));
    await expect(client.prepareRemediation(envelopeBody)).rejects.toMatchObject({ response: { status: 409 } });
  });

  test('transport faults stay retryable for remediationWorkflow', async () => {
    const unavailable = stubGrpcClient('snapshotRemediation', null, grpcError(grpc.status.UNAVAILABLE, { details: 'no connection' }));
    await expect(unavailable.client.snapshotRemediation(envelopeBody)).rejects.toMatchObject({
      code: 'ECONNREFUSED', response: { status: 502 },
    });
    const deadline = stubGrpcClient('snapshotRemediation', null, grpcError(grpc.status.DEADLINE_EXCEEDED, { details: 'deadline' }));
    await expect(deadline.client.snapshotRemediation(envelopeBody)).rejects.toMatchObject({
      code: 'ECONNABORTED', response: { status: 504 },
    });
  });
});

test('both transports return an identical snapshot object for the same reply', async () => {
  const restBody = {
    files: [{ path: 'services/accounts.js', content: 'const safe = true;\n', sha: commit }],
    tree_entries: [{ path: 'services/accounts.js', mode: '100644', type: 'blob', sha: commit }],
    head_tree_oid: tree,
    head_sha: head,
    base_sha: base,
    omitted_source_paths: [],
  };
  restInstance.post.mockResolvedValue({ data: restBody });
  const restResult = await new GitHubRemediationClient().snapshot({ ...envelopeBody, finding_paths: ['services/accounts.js'] });

  const response = new githubPb.RemediationSnapshotResponse();
  const file = new githubPb.RemediationSourceFile();
  file.setPath('services/accounts.js');
  file.setContent('const safe = true;\n');
  file.setSha(commit);
  response.setFilesList([file]);
  const entry = new githubPb.RemediationTreeEntry();
  entry.setPath('services/accounts.js');
  entry.setMode('100644');
  entry.setType('blob');
  entry.setSha(commit);
  response.setTreeEntriesList([entry]);
  response.setHeadTreeOid(tree);
  response.setHeadSha(head);
  response.setBaseSha(base);

  process.env.INTERNAL_SERVICE_TRANSPORT = 'grpc';
  const { client: grpcClient } = stubGrpcClient('snapshotRemediation', response);
  const grpcResult = await new GitHubRemediationClient({ grpcClient })
    .snapshot({ ...envelopeBody, finding_paths: ['services/accounts.js'] });

  expect(grpcResult).toEqual(restResult);
});
