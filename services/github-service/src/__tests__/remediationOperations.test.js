jest.mock('axios', () => jest.fn());
jest.mock('../services/githubAppAuth', () => ({ getInstallationToken: jest.fn(), getAppBotLogin: jest.fn() }));

const axios = require('axios');
const githubAppAuth = require('../services/githubAppAuth');
const {
  cancelScheduledMerge,
  commitRemediationAction,
  createRemediationCheckRun,
  mergeRemediationAction,
  prepareRemediationAction,
  readMergeEligibility,
  readPullRequestHead,
  reconcileRemediationAction,
  remediationMarker,
  fetchRemediationSnapshot,
} = require('../services/githubInternalOperations');

const head = 'a'.repeat(40);
const base = 'b'.repeat(40);
const tree = 'c'.repeat(40);
const actionId = 'action-identity-0001';
const digest = 'd'.repeat(64);

function payload(overrides = {}) {
  return {
    installation_id: 41,
    repository_full_name: 'owner/repo',
    actor_login: 'developer',
    pr_number: 9,
    head_sha: head,
    base_sha: base,
    manifest_digest: digest,
    action_id: actionId,
    idempotency_key: 'idempotency-key-0001',
    ...overrides,
  };
}

function repositoryResponse(request) {
  if (request.url.endsWith('/repos/owner/repo')) return { data: { full_name: 'owner/repo' } };
  if (request.url.includes('/installation/repositories')) return { data: { repositories: [{ full_name: 'owner/repo' }] } };
  if (request.url.includes('/collaborators/developer/permission')) return { data: { permission: 'write' } };
  if (request.url.includes('/pulls/9')) return {
    data: {
      state: 'open', draft: false, merged: false,
      head: { sha: head, ref: 'repair-branch', repo: { full_name: 'owner/repo' } },
      base: { sha: base, ref: 'main', repo: { full_name: 'owner/repo' } },
      mergeable: true,
      mergeable_state: 'clean',
    },
  };
  throw new Error(`Unexpected request ${request.method} ${request.url}`);
}

beforeEach(() => {
  jest.clearAllMocks();
  githubAppAuth.getInstallationToken.mockResolvedValue('installation-token');
  githubAppAuth.getAppBotLogin.mockResolvedValue('mitig8it[bot]');
});

test.each([{ state: 'closed' }, { draft: true }, { merged: true }])('prepare rejects non-actionable pull state %j', async override => {
  axios.mockImplementation(async request => {
    const result = repositoryResponse(request);
    if (request.url.endsWith('/pulls/9')) Object.assign(result.data, override);
    return result;
  });
  await expect(prepareRemediationAction(payload())).rejects.toMatchObject({ statusCode: 409 });
});

test('snapshot verifies blob bytes and carries all tree metadata', async () => {
  const content = 'module.exports = 1;\n';
  const sha = require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest('hex');
  const entries = [{ path: 'app.js', type: 'blob', mode: '100644', sha, size: Buffer.byteLength(content) },
    { path: 'logo.png', type: 'blob', mode: '100644', sha: 'f'.repeat(40), size: 100 }];
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: entries } };
    if (request.url.includes('/git/blobs/')) return { data: { encoding: 'base64', content: Buffer.from(content).toString('base64') } };
    return repositoryResponse(request);
  });
  const result = await fetchRemediationSnapshot(payload());
  expect(result.files).toEqual([{ path: 'app.js', content, sha }]);
  expect(result.tree_entries).toHaveLength(2);
  expect(result.head_tree_oid).toBe(tree);
});

test('snapshot rejects truncated repository trees rather than guessing missing source', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: true, tree: [] } };
    return repositoryResponse(request);
  });
  await expect(fetchRemediationSnapshot(payload())).rejects.toMatchObject({ statusCode: 422 });
});

function successfulMergeResponse(request) {
  if (request.url.includes('/rules/branches/')) return { data: [] };
  if (request.url.includes('/branches/main/protection')) return { data: {
    required_status_checks: { checks: [{ context: 'Mitig8it Remediation Verification', app_id: 123 }] },
    required_pull_request_reviews: { required_approving_review_count: 1 },
  } };
  if (request.url.includes('/pulls/9/reviews')) return { data: [{ user: { login: 'reviewer' }, state: 'APPROVED' }] };
  if (request.url.includes('/check-runs')) return { data: { total_count: 1, check_runs: [{ id: 1, name: 'Mitig8it Remediation Verification', app: { id: 123 }, status: 'completed', conclusion: 'success' }] } };
  if (request.method === 'put' && request.url.endsWith('/merge')) return { data: { merged: true, sha: 'e'.repeat(40) } };
  return repositoryResponse(request);
}

test('guarded merge checks permissions, app-owned required verification and approvals before exact SHA mutation', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => successfulMergeResponse(request));
  const result = await mergeRemediationAction(payload({ expected_head_sha: head, expected_base_sha: base,
    merge_method: 'squash', verification_check_name: 'Mitig8it Remediation Verification' }));
  expect(result.state).toBe('merged');
  expect(axios.mock.calls.filter(([request]) => request.method === 'put')).toHaveLength(1);
  expect(axios.mock.calls.find(([request]) => request.method === 'put')[0].data.sha).toBe(head);
});

test('a newer failed verification run blocks merge even if an older run was successful', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    const result = successfulMergeResponse(request);
    if (request.url.includes('/check-runs')) {
      result.data.check_runs.push({ ...result.data.check_runs[0], id: 2, conclusion: 'failure' });
      result.data.total_count = 2;
    }
    return result;
  });
  await expect(mergeRemediationAction(payload({ expected_head_sha: head, expected_base_sha: base,
    merge_method: 'squash', verification_check_name: 'Mitig8it Remediation Verification' }))).rejects.toMatchObject({ statusCode: 409 });
  expect(axios.mock.calls.some(([request]) => request.method === 'put')).toBe(false);
});

test('prepare denies an actor without live write permission before a write is possible', async () => {
  axios.mockImplementation(async (request) => {
    if (request.url.includes('/collaborators/developer/permission')) return { data: { permission: 'read' } };
    return repositoryResponse(request);
  });

  await expect(prepareRemediationAction(payload())).rejects.toMatchObject({ statusCode: 403 });
  expect(axios.mock.calls.some(([request]) => request.url.endsWith('/graphql'))).toBe(false);
});

test('commit uses one exact-head GraphQL mutation and returns reconciling on a lost response without retrying', async () => {
  axios.mockImplementation(async (request) => {
    if (request.url.endsWith('/graphql')) {
      const error = new Error('socket hang up');
      throw error;
    }
    return repositoryResponse(request);
  });
  const result = await commitRemediationAction(payload({
    branch: 'repair-branch',
    expected_head_oid: head,
    verified_tree_oid: tree,
    commit_message: 'Apply verified remediation',
    changes: [{ path: 'src/app.js', contents_base64: Buffer.from('const safe = true;\n').toString('base64') }],
  }));

  expect(result).toEqual(expect.objectContaining({ state: 'reconciling', operation_id: actionId }));
  const writes = axios.mock.calls.filter(([request]) => request.url.endsWith('/graphql'));
  expect(writes).toHaveLength(1);
  expect(writes[0][0].data.variables.input.expectedHeadOid).toBe(head);
  expect(writes[0][0].data.variables.input.message.body).toBe(remediationMarker(actionId, digest));
});

test('reconciliation recognizes only the action marker with the consented parent and verified tree', async () => {
  axios.mockImplementation(async (request) => {
    if (request.url.includes('/commits?sha=')) return {
      data: [{
        sha: 'e'.repeat(40),
        parents: [{ sha: head }],
        commit: { message: `Apply\n\n${remediationMarker(actionId, digest)}` },
      }],
    };
    if (request.url.includes(`/git/commits/${'e'.repeat(40)}`)) return { data: { tree: { sha: tree } } };
    return repositoryResponse(request);
  });

  await expect(reconcileRemediationAction(payload({ verified_tree_oid: tree }))).resolves.toEqual({
    state: 'applied', operation_id: actionId, commit_sha: 'e'.repeat(40), tree_oid: tree,
  });
});

test('merge fails closed when branch rules cannot be evaluated and never calls GitHub merge', async () => {
  axios.mockImplementation(async (request) => {
    if (request.url.includes('/rules/branches/')) {
      const error = new Error('not found');
      error.response = { status: 404, data: { message: 'Not Found' } };
      throw error;
    }
    return repositoryResponse(request);
  });
  await expect(mergeRemediationAction(payload({
    expected_head_sha: head,
    expected_base_sha: base,
    merge_method: 'squash',
    verification_check_name: 'Mitig8it Remediation Verification',
  }))).rejects.toMatchObject({ statusCode: 422 });
  expect(axios.mock.calls.some(([request]) => request.method === 'put' && request.url.endsWith('/merge'))).toBe(false);
});

test('merge requires the named verification check to be protected by this app, not just any check with that name', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async (request) => {
    if (request.url.includes('/rules/branches/')) return { data: [] };
    if (request.url.includes('/branches/main/protection')) return {
      data: {
        required_status_checks: { checks: [{ context: 'Mitig8it Remediation Verification', app_id: 999 }] },
        required_pull_request_reviews: { required_approving_review_count: 1 },
      },
    };
    return repositoryResponse(request);
  });
  await expect(mergeRemediationAction(payload({
    expected_head_sha: head,
    expected_base_sha: base,
    merge_method: 'squash',
    verification_check_name: 'Mitig8it Remediation Verification',
  }))).rejects.toMatchObject({ statusCode: 422 });
  expect(axios.mock.calls.some(([request]) => request.method === 'put' && request.url.endsWith('/merge'))).toBe(false);
});

function checkRunPayload(overrides = {}) {
  return payload({
    external_id: 'verification-0001',
    conclusion: 'success',
    title: 'Remediation verified',
    summary: 'Independent verification succeeded on the applied tree.',
    ...overrides,
  });
}

test('remediation check run updates this app own run for the same external id instead of creating a duplicate', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/check-runs?check_name=')) return { data: { check_runs: [{
      id: 55, head_sha: head, name: 'Mitig8it Remediation Verification',
      app: { id: 123 }, external_id: 'verification-0001',
    }] } };
    if (request.url.endsWith('/check-runs/55')) return { data: { id: 55 } };
    return repositoryResponse(request);
  });
  const result = await createRemediationCheckRun(checkRunPayload());
  expect(result).toMatchObject({ state: 'published', check_run_id: 55, updated: true, name: 'Mitig8it Remediation Verification' });
  const writes = axios.mock.calls.filter(([request]) => ['post', 'patch'].includes(request.method));
  expect(writes).toHaveLength(1);
  expect(writes[0][0].method).toBe('patch');
  expect(writes[0][0].data.external_id).toBe('verification-0001');
});

test('remediation check run ignores a same-named run owned by another app and publishes its own', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/check-runs?check_name=')) return { data: { check_runs: [{
      id: 77, head_sha: head, name: 'Mitig8it Remediation Verification',
      app: { id: 999 }, external_id: 'verification-0001',
    }] } };
    if (request.method === 'post') return { data: { id: 88 } };
    return repositoryResponse(request);
  });
  const result = await createRemediationCheckRun(checkRunPayload());
  expect(result).toMatchObject({ state: 'published', check_run_id: 88, updated: false });
  const writes = axios.mock.calls.filter(([request]) => ['post', 'patch'].includes(request.method));
  expect(writes).toHaveLength(1);
  expect(writes[0][0].url).toMatch(/\/check-runs$/);
});

test('remediation check run uses the configured verification name that branch protection must require', async () => {
  process.env.GITHUB_APP_ID = '123';
  process.env.REMEDIATION_VERIFICATION_CHECK_NAME = 'Custom Remediation Gate';
  axios.mockImplementation(async request => {
    if (request.url.includes('/check-runs?check_name=')) return { data: { check_runs: [] } };
    if (request.method === 'post') return { data: { id: 91 } };
    return repositoryResponse(request);
  });
  try {
    const result = await createRemediationCheckRun(checkRunPayload());
    expect(result.name).toBe('Custom Remediation Gate');
    const lookup = axios.mock.calls.find(([request]) => request.url.includes('/check-runs?check_name='));
    expect(lookup[0].url).toContain(encodeURIComponent('Custom Remediation Gate'));
  } finally {
    delete process.env.REMEDIATION_VERIFICATION_CHECK_NAME;
  }
});

test('remediation check run reports reconciling on a lost write response without a second attempt', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/check-runs?check_name=')) return { data: { check_runs: [] } };
    if (request.method === 'post') throw new Error('socket hang up');
    return repositoryResponse(request);
  });
  const result = await createRemediationCheckRun(checkRunPayload());
  expect(result).toEqual({ state: 'reconciling', operation_id: actionId, reason: 'github_check_run_outcome_ambiguous' });
  expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(1);
});

function autoMergeLookup(autoMergeRequest, overrides = {}) {
  return { data: { data: { repository: { pullRequest: {
    id: 'PR_kwABC', state: 'OPEN', merged: false, headRefOid: head, autoMergeRequest, ...overrides,
  } } } } };
}

test('cancel scheduled merge reports not_scheduled when GitHub auto-merge was never enabled', async () => {
  axios.mockImplementation(async request => {
    if (request.url.endsWith('/graphql')) return autoMergeLookup(null);
    return repositoryResponse(request);
  });
  const result = await cancelScheduledMerge(payload({ pull_number: 9, expected_head_sha: head }));
  expect(result).toMatchObject({ state: 'not_scheduled', merged: false, head_sha: head, reason: 'auto_merge_not_enabled' });
  expect(axios.mock.calls.filter(([request]) => request.url.endsWith('/graphql'))).toHaveLength(1);
});

test('cancel scheduled merge disables this app auto-merge and never merges', async () => {
  axios.mockImplementation(async request => {
    if (request.url.endsWith('/graphql') && request.data.query.includes('disablePullRequestAutoMerge')) {
      return { data: { data: { disablePullRequestAutoMerge: { pullRequest: { id: 'PR_kwABC', autoMergeRequest: null } } } } };
    }
    if (request.url.endsWith('/graphql')) return autoMergeLookup({ enabledBy: { login: 'mitig8it[bot]' } });
    return repositoryResponse(request);
  });
  const result = await cancelScheduledMerge(payload({ pull_number: 9, expected_head_sha: head }));
  expect(result).toMatchObject({ state: 'cancelled', merged: false, head_sha: head });
  const mutations = axios.mock.calls.filter(([request]) => request.url.endsWith('/graphql') && request.data.query.includes('mutation'));
  expect(mutations).toHaveLength(1);
  expect(mutations[0][0].data.variables.input).toEqual({ pullRequestId: 'PR_kwABC' });
  expect(axios.mock.calls.some(([request]) => request.method === 'put' || /\/merge$/.test(request.url))).toBe(false);
});

test('cancel scheduled merge reports already_merged and issues no mutation', async () => {
  axios.mockImplementation(async request => {
    if (request.url.endsWith('/graphql')) {
      return autoMergeLookup({ enabledBy: { login: 'mitig8it[bot]' } }, { merged: true, state: 'MERGED' });
    }
    return repositoryResponse(request);
  });
  const result = await cancelScheduledMerge(payload({ pull_number: 9, expected_head_sha: head }));
  expect(result).toMatchObject({ state: 'already_merged', merged: true, head_sha: head });
  expect(axios.mock.calls.filter(([request]) => request.url.endsWith('/graphql'))).toHaveLength(1);
});

test('cancel scheduled merge does not claim to cancel an auto-merge another account scheduled', async () => {
  axios.mockImplementation(async request => {
    if (request.url.endsWith('/graphql')) return autoMergeLookup({ enabledBy: { login: 'release-manager' } });
    return repositoryResponse(request);
  });
  const result = await cancelScheduledMerge(payload({ pull_number: 9, expected_head_sha: head }));
  expect(result).toMatchObject({ state: 'not_scheduled', reason: 'auto_merge_enabled_by_another_actor' });
  expect(axios.mock.calls.some(([request]) => request.url.endsWith('/graphql') && request.data.query.includes('mutation'))).toBe(false);
});

test('cancel scheduled merge reports reconciling when the cancellation outcome is ambiguous', async () => {
  axios.mockImplementation(async request => {
    if (request.url.endsWith('/graphql') && request.data.query.includes('disablePullRequestAutoMerge')) {
      throw new Error('socket hang up');
    }
    if (request.url.endsWith('/graphql')) return autoMergeLookup({ enabledBy: { login: 'mitig8it[bot]' } });
    return repositoryResponse(request);
  });
  const result = await cancelScheduledMerge(payload({ pull_number: 9, expected_head_sha: head }));
  expect(result).toEqual({ state: 'reconciling', operation_id: actionId, reason: 'github_cancel_outcome_ambiguous' });
});

test('cancel scheduled merge rejects a pull_number that is not the consented pull request', async () => {
  axios.mockImplementation(async request => repositoryResponse(request));
  await expect(cancelScheduledMerge(payload({ pull_number: 10, expected_head_sha: head })))
    .rejects.toMatchObject({ statusCode: 409 });
  expect(axios).not.toHaveBeenCalled();
});

function eligibilityPayload(overrides = {}) {
  return payload({ pull_number: 9, expected_head_sha: head, verification_check_name: 'Mitig8it Remediation Verification', ...overrides });
}

test('merge eligibility reports an eligible pull request and never mutates GitHub', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => successfulMergeResponse(request));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(true);
  expect(result.blockers).toEqual([]);
  expect(result.protection_source).toBe('branch_protection');
  expect(result.reviews).toEqual({ required: 1, approvals: 1, changes_requested: false });
  expect(result.required_checks).toEqual([{ context: 'Mitig8it Remediation Verification', app_id: 123 }]);
  expect(result.mergeable_state).toBe('clean');
  expect(axios.mock.calls.every(([request]) => request.method === 'get')).toBe(true);
});

test('merge eligibility blocks when the verification check is not required by this app', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/branches/main/protection')) return { data: {
      required_status_checks: { checks: [{ context: 'Mitig8it Remediation Verification', app_id: 999 }] },
      required_pull_request_reviews: { required_approving_review_count: 1 },
    } };
    return successfulMergeResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('verification_check_not_required');
});

test('merge eligibility blocks when required approvals are missing', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/pulls/9/reviews')) return { data: [] };
    return successfulMergeResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('required_approvals_missing');
  expect(result.reviews).toEqual({ required: 1, approvals: 0, changes_requested: false });
});

test('merge eligibility reports an unknown protection source as a blocker rather than assuming none', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/rules/branches/')) {
      const error = new Error('not found');
      error.response = { status: 404, data: { message: 'Not Found' } };
      throw error;
    }
    return successfulMergeResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.protection_source).toBe('unknown');
  expect(result.blockers).toEqual(expect.arrayContaining(['ruleset_capability_unavailable', 'protection_source_unknown']));
});

test('merge eligibility ignores a verification check run published by a foreign app', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/check-runs')) return { data: { total_count: 1, check_runs: [{
      id: 3, name: 'Mitig8it Remediation Verification', app: { id: 999 }, status: 'completed', conclusion: 'success',
    }] } };
    return successfulMergeResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('verification_check_not_successful');
  expect(result.check_runs).toEqual([{ id: 3, name: 'Mitig8it Remediation Verification', app_id: 999, status: 'completed', conclusion: 'success' }]);
});

test('merge eligibility reports a changed head as a blocker instead of throwing', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    const result = successfulMergeResponse(request);
    if (request.url.endsWith('/pulls/9')) result.data.head = { ...result.data.head, sha: 'f'.repeat(40) };
    return result;
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('pull_request_head_changed');
  expect(result.head_sha).toBe('f'.repeat(40));
});

// --- Ruleset-governed branches ------------------------------------------------------
// A branch governed only by a ruleset has no classic protection to read; the ruleset is
// the protection source and its rules carry the required checks and reviews.
const verificationContext = 'Mitig8it Remediation Verification';

function rulesetRules(extra = []) {
  return [
    { type: 'deletion' },
    { type: 'non_fast_forward' },
    { type: 'required_status_checks', parameters: { required_status_checks: [
      { context: 'build', integration_id: null },
      { context: verificationContext, integration_id: 123 },
    ] } },
    ...extra,
  ];
}

function rulesetResponse(request, { rules = rulesetRules(), reviews = [] } = {}) {
  if (request.url.includes('/rules/branches/')) return { data: rules };
  if (request.url.includes('/branches/main/protection')) {
    const error = new Error('Branch not protected');
    error.response = { status: 404, data: { message: 'Branch not protected' } };
    throw error;
  }
  if (request.url.includes('/pulls/9/reviews')) return { data: reviews };
  if (request.url.includes('/check-runs')) return { data: { total_count: 1, check_runs: [
    { id: 1, name: verificationContext, app: { id: 123 }, status: 'completed', conclusion: 'success' },
  ] } };
  if (request.method === 'put' && request.url.endsWith('/merge')) return { data: { merged: true, sha: 'e'.repeat(40) } };
  return repositoryResponse(request);
}

test('merge eligibility accepts a ruleset-only branch that requires this app verification check and no review', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => rulesetResponse(request));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.blockers).toEqual([]);
  expect(result.eligible).toBe(true);
  expect(result.protection_source).toBe('rulesets');
  expect(result.reviews).toEqual({ required: 0, approvals: 0, changes_requested: false });
  expect(result.required_checks).toEqual([
    { context: 'build', app_id: 0 },
    { context: verificationContext, app_id: 123 },
  ]);
});

test('guarded merge proceeds on a ruleset-only branch and still mutates only the consented head', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => rulesetResponse(request));
  const result = await mergeRemediationAction(payload({ expected_head_sha: head, expected_base_sha: base,
    merge_method: 'squash', verification_check_name: verificationContext }));
  expect(result.state).toBe('merged');
  const mutations = axios.mock.calls.filter(([request]) => request.method === 'put');
  expect(mutations).toHaveLength(1);
  expect(mutations[0][0].data.sha).toBe(head);
});

test('merge eligibility blocks when a ruleset context binds the verification check to another app', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = [{ type: 'required_status_checks', parameters: { required_status_checks: [
    { context: verificationContext, integration_id: 999 },
  ] } }];
  axios.mockImplementation(async request => rulesetResponse(request, { rules }));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('verification_check_not_required');
});

test('merge eligibility blocks when a ruleset requires an approval the pull request does not have', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = rulesetRules([{ type: 'pull_request', parameters: {
    required_approving_review_count: 1, dismiss_stale_reviews_on_push: true, require_code_owner_review: false,
  } }]);
  axios.mockImplementation(async request => rulesetResponse(request, { rules }));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('required_approvals_missing');
  expect(result.reviews).toEqual({ required: 1, approvals: 0, changes_requested: false });
});

test('merge eligibility blocks a merge queue ruleset because queue integration is out of scope', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = rulesetRules([{ type: 'merge_queue', parameters: { merge_method: 'SQUASH' } }]);
  axios.mockImplementation(async request => rulesetResponse(request, { rules }));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('merge_queue_unsupported');
});

test('merge eligibility fails closed on a ruleset rule this release does not model', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = rulesetRules([{ type: 'required_deployments', parameters: { required_deployment_environments: ['staging'] } }]);
  axios.mockImplementation(async request => rulesetResponse(request, { rules }));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('ruleset_rule_unsupported_required_deployments');
});

test('merge eligibility blocks when this app is a ruleset bypass actor', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = rulesetRules().map(rule => (rule.type === 'required_status_checks'
    ? { ...rule, bypass_actors: [{ actor_id: 123, actor_type: 'Integration', bypass_mode: 'always' }] } : rule));
  axios.mockImplementation(async request => rulesetResponse(request, { rules }));
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('app_bypass_forbidden');
});

test('merge eligibility accepts a ruleset-only branch when the legacy protection endpoint is forbidden to the installation', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/branches/main/protection')) {
      const error = new Error('Resource not accessible by integration');
      error.response = { status: 403, data: { message: 'Resource not accessible by integration' } };
      throw error;
    }
    return rulesetResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.blockers).toEqual([]);
  expect(result.eligible).toBe(true);
  expect(result.protection_source).toBe('rulesets');
});

test('merge eligibility still blocks when the legacy protection endpoint is unreadable and no ruleset governs the branch', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/rules/branches/')) return { data: [] };
    if (request.url.includes('/branches/main/protection')) {
      const error = new Error('Resource not accessible by integration');
      error.response = { status: 403, data: { message: 'Resource not accessible by integration' } };
      throw error;
    }
    return successfulMergeResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toEqual(expect.arrayContaining(['branch_protection_unavailable', 'protection_source_unknown']));
});

test('merge eligibility blocks a ruleset branch when the legacy protection endpoint fails for an unclear reason', async () => {
  process.env.GITHUB_APP_ID = '123';
  axios.mockImplementation(async request => {
    if (request.url.includes('/branches/main/protection')) {
      const error = new Error('bad credentials');
      error.response = { status: 401, data: { message: 'Bad credentials' } };
      throw error;
    }
    return rulesetResponse(request);
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.blockers).toContain('branch_protection_unavailable');
});

test('merge eligibility combines a ruleset with classic protection and enforces the stricter requirement', async () => {
  process.env.GITHUB_APP_ID = '123';
  const rules = rulesetRules([{ type: 'pull_request', parameters: { required_approving_review_count: 0 } }]);
  axios.mockImplementation(async request => {
    if (request.url.includes('/rules/branches/')) return { data: rules };
    if (request.url.includes('/branches/main/protection')) return { data: {
      required_status_checks: { checks: [{ context: 'legacy-ci', app_id: 456 }] },
      required_pull_request_reviews: { required_approving_review_count: 2 },
    } };
    return rulesetResponse(request, { rules, reviews: [{ user: { login: 'reviewer' }, state: 'APPROVED' }] });
  });
  const result = await readMergeEligibility(eligibilityPayload());
  expect(result.eligible).toBe(false);
  expect(result.protection_source).toBe('rulesets+branch_protection');
  expect(result.reviews).toEqual({ required: 2, approvals: 1, changes_requested: false });
  expect(result.blockers).toEqual(['required_approvals_missing']);
  expect(result.required_checks).toEqual([
    { context: 'build', app_id: 0 },
    { context: verificationContext, app_id: 123 },
    { context: 'legacy-ci', app_id: 456 },
  ]);
});

test('pull head read returns the current revision, state and fork flag without mutating', async () => {
  axios.mockImplementation(async request => repositoryResponse(request));
  const result = await readPullRequestHead(payload({ pull_number: 9 }));
  expect(result).toEqual({
    head_sha: head, base_sha: base, state: 'open', draft: false, merged: false, mergeable_state: 'clean', fork: false,
  });
  expect(axios.mock.calls.every(([request]) => request.method === 'get' || request.method === undefined)).toBe(true);
});

test('pull head read treats an unreadable head repository as a fork', async () => {
  axios.mockImplementation(async request => {
    const result = repositoryResponse(request);
    if (request.url.endsWith('/pulls/9')) result.data.head = { sha: head, ref: 'repair-branch' };
    return result;
  });
  const result = await readPullRequestHead(payload({ pull_number: 9 }));
  expect(result.fork).toBe(true);
});
