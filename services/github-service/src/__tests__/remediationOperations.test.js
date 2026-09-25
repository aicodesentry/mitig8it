// The operations call axios(request); the summary comment publisher calls the method
// helpers. Both shapes are routed to the same mock so one scripted GitHub answers all.
jest.mock('axios', () => {
  const fn = jest.fn();
  fn.get = (url, config = {}) => fn({ method: 'get', url, ...config });
  fn.post = (url, data, config = {}) => fn({ method: 'post', url, data, ...config });
  fn.patch = (url, data, config = {}) => fn({ method: 'patch', url, data, ...config });
  return fn;
});
jest.mock('../services/githubAppAuth', () => ({ getInstallationToken: jest.fn(), getAppBotLogin: jest.fn() }));

const axios = require('axios');
const githubAppAuth = require('../services/githubAppAuth');
const operations = require('../services/githubInternalOperations');
const {
  createRemediationCheckRun,
  publishFindingFixSections,
  publishRemediationComment,
  fetchRemediationSnapshot,
} = operations;

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

// The App holds no write access to repository contents. The operations module must not
// expose anything that could commit to a branch or merge a pull request, and nothing it
// still exposes may reach GitHub's commit, ref, contents-write or merge endpoints.
test('the operations module exposes nothing that can write to a repository', () => {
  for (const name of ['commitRemediationAction', 'mergeRemediationAction', 'prepareRemediationAction',
    'reconcileRemediationAction', 'cancelScheduledMerge', 'readMergeEligibility', 'readPullRequestHead',
    'authorizeRemediationActor', 'remediationMarker']) {
    expect(operations[name]).toBeUndefined();
  }
});

test('the snapshot read never issues a mutating request', async () => {
  const content = 'module.exports = 1;\n';
  const sha = require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest('hex');
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: [{ path: 'app.js', type: 'blob', mode: '100644', sha, size: Buffer.byteLength(content) }] } };
    if (request.url.includes('/git/blobs/')) return { data: { encoding: 'base64', content: Buffer.from(content).toString('base64') } };
    return repositoryResponse(request);
  });
  await fetchRemediationSnapshot(payload());
  for (const [request] of axios.mock.calls) {
    expect(['get', undefined]).toContain(request.method);
    expect(request.url).not.toMatch(/\/merge$/);
  }
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

test('snapshot includes Python sources and dependency manifests so Python findings can be repaired', async () => {
  const py = 'API_KEY = "x"\n';
  const req = 'flask==3.0.0\n';
  const blob = (text) => require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(text)}\0`).update(text).digest('hex');
  const entries = [{ path: 'text.py', type: 'blob', mode: '100644', sha: blob(py), size: Buffer.byteLength(py) },
    { path: 'requirements.txt', type: 'blob', mode: '100644', sha: blob(req), size: Buffer.byteLength(req) },
    { path: 'README.md', type: 'blob', mode: '100644', sha: 'e'.repeat(40), size: 10 }];
  const contents = { [blob(py)]: py, [blob(req)]: req };
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: entries } };
    if (request.url.includes('/git/blobs/')) { const sha = request.url.split('/git/blobs/')[1]; return { data: { encoding: 'base64', content: Buffer.from(contents[sha]).toString('base64') } }; }
    return repositoryResponse(request);
  });
  const result = await fetchRemediationSnapshot({ ...payload(), finding_paths: ['text.py'] });
  expect(result.files.map(file => file.path).sort()).toEqual(['requirements.txt', 'text.py']);
  expect(result.files.find(file => file.path === 'text.py').content).toBe(py);
});

test('snapshot caps unrelated files and fetches blobs concurrently so large repositories stay within the deadline', async () => {
  const text = 'x = 1\n';
  const sha = require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(text)}\0`).update(text).digest('hex');
  const entries = [{ path: 'app/text.py', type: 'blob', mode: '100644', sha, size: Buffer.byteLength(text) }];
  for (let i = 0; i < 40; i += 1) entries.push({ path: `app/sibling${i}.py`, type: 'blob', mode: '100644', sha, size: Buffer.byteLength(text) });
  for (let i = 0; i < 200; i += 1) entries.push({ path: `elsewhere/other${i}.js`, type: 'blob', mode: '100644', sha, size: Buffer.byteLength(text) });
  let inFlight = 0; let maxInFlight = 0;
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: entries } };
    if (request.url.includes('/git/blobs/')) {
      inFlight += 1; maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise(resolve => setTimeout(resolve, 5));
      inFlight -= 1;
      return { data: { encoding: 'base64', content: Buffer.from(text).toString('base64') } };
    }
    return repositoryResponse(request);
  });
  const result = await fetchRemediationSnapshot({ ...payload(), finding_paths: ['app/text.py'] });
  const paths = result.files.map(file => file.path);
  expect(paths).toContain('app/text.py');
  expect(paths.filter(path => path.startsWith('app/sibling')).length).toBe(30);
  expect(paths.filter(path => path.startsWith('elsewhere/')).length).toBe(10);
  expect(result.files.length).toBe(41);
  expect(maxInFlight).toBeGreaterThan(1);
  expect(result.omitted_source_paths.length).toBe(entries.length - 41);
});

// Pull request 135 of nebullii/test-only mixed C#, Java, JavaScript and Python findings in
// one automatic job. The snapshot refused the whole request because the C# and Java sources
// are not in the tree it selects, so the nine JavaScript and Python findings on the same
// pull request got no fix either. One unsupported source is now one finding's skip.
test('snapshot drops a finding source the tree does not carry and repairs the rest', async () => {
  const js = 'const q = "select";\n';
  const py = 'API_KEY = "x"\n';
  const blob = (text) => require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(text)}\0`).update(text).digest('hex');
  const entries = [{ path: 'services/orders.js', type: 'blob', mode: '100644', sha: blob(js), size: Buffer.byteLength(js) },
    { path: 'main.py', type: 'blob', mode: '100644', sha: blob(py), size: Buffer.byteLength(py) }];
  const contents = { [blob(js)]: js, [blob(py)]: py };
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: entries } };
    if (request.url.includes('/git/blobs/')) { const sha = request.url.split('/git/blobs/')[1]; return { data: { encoding: 'base64', content: Buffer.from(contents[sha]).toString('base64') } }; }
    return repositoryResponse(request);
  });
  const result = await fetchRemediationSnapshot({ ...payload(), finding_paths: ['services/orders.js', 'TestVuln.cs', 'TestVuln.java', 'main.py'] });
  expect(result.files.map(file => file.path).sort()).toEqual(['main.py', 'services/orders.js']);
  expect(result.skipped).toEqual([
    { path: 'TestVuln.cs', code: 'affected_source_missing', message: 'The finding source is unsupported or missing from the immutable tree.' },
    { path: 'TestVuln.java', code: 'affected_source_missing', message: 'The finding source is unsupported or missing from the immutable tree.' },
  ]);
});

test('snapshot reports no skip when every finding source is in the tree', async () => {
  const js = 'const q = "select";\n';
  const sha = require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(js)}\0`).update(js).digest('hex');
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: [{ path: 'services/orders.js', type: 'blob', mode: '100644', sha, size: Buffer.byteLength(js) }] } };
    if (request.url.includes('/git/blobs/')) return { data: { encoding: 'base64', content: Buffer.from(js).toString('base64') } };
    return repositoryResponse(request);
  });
  const result = await fetchRemediationSnapshot({ ...payload(), finding_paths: ['services/orders.js'] });
  expect(result.skipped).toEqual([]);
});

// The 422 is the last resort, not the first: it stands only when the snapshot would carry
// no requested source at all, so the caller learns nothing could be repaired.
test('snapshot still refuses when no requested finding source can be materialised', async () => {
  const js = 'const q = "select";\n';
  const sha = require('crypto').createHash('sha1').update(`blob ${Buffer.byteLength(js)}\0`).update(js).digest('hex');
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: false, tree: [{ path: 'services/orders.js', type: 'blob', mode: '100644', sha, size: Buffer.byteLength(js) }] } };
    if (request.url.includes('/git/blobs/')) return { data: { encoding: 'base64', content: Buffer.from(js).toString('base64') } };
    return repositoryResponse(request);
  });
  await expect(fetchRemediationSnapshot({ ...payload(), finding_paths: ['TestVuln.cs', 'TestVuln.java'] }))
    .rejects.toMatchObject({ statusCode: 422, message: 'Finding source is unsupported or missing from the immutable tree' });
  const tooMany = Array.from({ length: 201 }, (_, index) => `src/file${index}.js`);
  await expect(fetchRemediationSnapshot({ ...payload(), finding_paths: tooMany })).rejects.toMatchObject({ statusCode: 422 });
});

test('snapshot rejects truncated repository trees rather than guessing missing source', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/git/commits/')) return { data: { tree: { sha: tree } } };
    if (request.url.includes('/git/trees/')) return { data: { truncated: true, tree: [] } };
    return repositoryResponse(request);
  });
  await expect(fetchRemediationSnapshot(payload())).rejects.toMatchObject({ statusCode: 422 });
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
function commentPayload(overrides = {}) {
  return payload({ external_id: 'report-0001', body: 'Applied 1 fix. Remaining open findings: 0.', ...overrides });
}

test('remediation report comment is created once and updated in place for the same external id', async () => {
  const marker = '<!-- mitig8it-remediation-report:report-0001 -->';
  const comments = [];
  axios.mockImplementation(async request => {
    if (request.url.includes('/issues/9/comments') && request.method === 'get') return { data: comments };
    if (request.url.endsWith('/issues/9/comments') && request.method === 'post') {
      comments.push({ id: 501, body: request.data.body, user: { login: 'mitig8it[bot]' } });
      return { data: { id: 501 } };
    }
    if (request.url.endsWith('/issues/comments/501') && request.method === 'patch') {
      comments[0].body = request.data.body;
      return { data: { id: 501 } };
    }
    return repositoryResponse(request);
  });
  const first = await publishRemediationComment(commentPayload());
  expect(first).toMatchObject({ state: 'published', comment_id: 501, updated: false, external_id: 'report-0001' });
  expect(comments[0].body.startsWith(marker)).toBe(true);
  const second = await publishRemediationComment(commentPayload({ body: 'Applied 1 fix. Remaining open findings: 1.' }));
  expect(second).toMatchObject({ state: 'published', comment_id: 501, updated: true });
  expect(comments).toHaveLength(1);
  expect(comments[0].body).toContain('Remaining open findings: 1.');
  const writes = axios.mock.calls.filter(([request]) => ['post', 'patch'].includes(request.method));
  expect(writes.map(([request]) => request.method)).toEqual(['post', 'patch']);
});

test('remediation report comment never edits a marker comment written by another author', async () => {
  const marker = '<!-- mitig8it-remediation-report:report-0001 -->';
  axios.mockImplementation(async request => {
    if (request.url.includes('/issues/9/comments') && request.method === 'get') {
      return { data: [{ id: 7, body: `${marker}\nforged`, user: { login: 'someone-else' } }] };
    }
    if (request.method === 'post') return { data: { id: 8 } };
    return repositoryResponse(request);
  });
  const result = await publishRemediationComment(commentPayload());
  expect(result).toMatchObject({ state: 'published', comment_id: 8, updated: false });
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(0);
});

test('remediation report comment reports reconciling on a lost write response without a second attempt', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/issues/9/comments') && request.method === 'get') return { data: [] };
    if (request.method === 'post') throw new Error('socket hang up');
    return repositoryResponse(request);
  });
  const result = await publishRemediationComment(commentPayload());
  expect(result).toEqual({ state: 'reconciling', operation_id: actionId, reason: 'github_comment_outcome_ambiguous' });
  expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(1);
});

// --- Verified fix sections under inline finding comments -------------------------

const FINDING_MARKER = '<!-- mitig8it-finding:fp-sql-1 -->';
const CANDIDATE = 'c1d2e3f4-0000-4000-8000-000000000001';

function fixSection(overrides = {}) {
  return {
    candidate_id: CANDIDATE, finding_fingerprint: 'fp-sql-1', path: 'services/orders.js', finding_line: 12,
    hunk: { start_line: 12, end_line: 12, original_lines: ['  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);'],
      replacement_lines: ['  const rows = await db.query(\'SELECT * FROM orders WHERE id = $1\', [id]);'] },
    unified_diff: '--- a/services/orders.js\n+++ b/services/orders.js\n@@ -12,1 +12,1 @@\n-  old\n+  new',
    not_suggestable_reason: '', stated_intent: 'The order lookup returns the same row for the same id.',
    proof: 'regression test tests/orders.regression.test.js asserts that the SQL injection at services/orders.js:12 is no longer reproducible; it failed on the original code and passed on the fix.',
    evidence: ['Regression test tests/orders.regression.test.js: failed on the original code, passed on the fix.', 'Syntax check: passed on the fixed file.'],
    limitations: ['verification ran in the development local sandbox without network, kernel, or filesystem isolation'],
    verification_level: 'development_unverified', skipped_reason: '', finding_body: '', finding_ids: ['f-sql-1'], covered_by: '',
    extra_hunks: [],
    ...overrides,
  };
}

const VERIFIED_LINE = 'Verified: regression test failed on the original code and passed with this change (development sandbox).';

const FINDING_BODY = '🔴 **HIGH** — SQL injection\n\n> Template literal in db.query\n\n**Confidence:** 85%\n\n**Fix:** Use a parameterized query.';
const PLACED = { created: false, placement: 'inline' };

function fixPayload(sections, overrides = {}) {
  return payload({ preview_url: 'https://app.example.test/dashboard/pull-requests/pr-1/findings', sections, ...overrides });
}

// A scripted pull request with one bot finding comment. Writes are recorded in place.
function findingCommentGitHub(comment, extra = {}) {
  const comments = [comment];
  axios.mockImplementation(async request => {
    if (request.url.includes('/pulls/9/comments') && request.method === 'get') return { data: comments };
    if (request.url.includes('/pulls/comments/') && request.method === 'patch') {
      const id = Number(request.url.split('/').pop());
      const target = comments.find(item => item.id === id);
      target.body = request.data.body;
      return { data: { id } };
    }
    if (extra.handle) { const handled = extra.handle(request); if (handled) return handled; }
    return repositoryResponse(request);
  });
  return comments;
}

test('a verified fix is appended to the existing finding comment as a suggestion and updated in place on a retry', async () => {
  const comments = findingCommentGitHub({ id: 77, body: `${FINDING_MARKER}\n**SQL injection**\nUse parameters.`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const first = await publishFindingFixSections(fixPayload([fixSection()]));
  expect(first.state).toBe('published');
  expect(first.results).toEqual([{ finding_fingerprint: 'fp-sql-1', candidate_id: CANDIDATE, comment_id: 77, mode: 'suggestion', updated: true, reason: '', ...PLACED }]);
  const body = comments[0].body;
  expect(body.startsWith(`${FINDING_MARKER}\n**SQL injection**\nUse parameters.`)).toBe(true);
  // The suggestion block comes first, with no prose above it, then the one verified line,
  // then the collapsed details.
  expect(body).toContain(`<!-- mitig8it-fix:${CANDIDATE} -->\n\`\`\`suggestion\n  const rows = await db.query('SELECT * FROM orders WHERE id = $1', [id]);\n\`\`\`\n${VERIFIED_LINE}\n\n<details>\n<summary>Details</summary>\n\n`);
  expect(body).not.toContain('Recommended fix');
  // The model's claim and the sandbox proof are labelled apart, and neither is called "behavior preserved".
  expect(body).toContain("**Model's stated intent:** The order lookup returns the same row for the same id.\n\n**Proof:** regression test tests/orders.regression.test.js asserts that the SQL injection at services/orders.js:12 is no longer reproducible; it failed on the original code and passed on the fix.\n\n**Evidence:** ");
  expect(body).not.toContain('Behavior preserved');
  expect(body).not.toContain('**Findings covered:**');
  expect(body).toContain('**Evidence:** Regression test tests/orders.regression.test.js: failed on the original code, passed on the fix. Syntax check: passed on the fixed file.');
  expect(body).toContain('**Limitations:** verification ran in the development local sandbox');
  expect(body).toContain('Nothing is applied or merged automatically. Apply this suggestion on GitHub or use Apply this fix in [Mitig8it](https://app.example.test/dashboard/pull-requests/pr-1/findings)');
  expect(body).toContain('\n</details>\n<!-- /mitig8it-fix:' + CANDIDATE + ' -->');
  expect(body.trim().endsWith(`<!-- /mitig8it-fix:${CANDIDATE} -->`)).toBe(true);

  // The same input again: the body is unchanged, so nothing is written.
  const second = await publishFindingFixSections(fixPayload([fixSection()]));
  expect(second.results[0]).toMatchObject({ mode: 'suggestion', updated: false });
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(1);

  // A regenerated candidate replaces the earlier block instead of stacking under it.
  const regenerated = 'c1d2e3f4-0000-4000-8000-000000000002';
  const third = await publishFindingFixSections(fixPayload([fixSection({ candidate_id: regenerated })]));
  expect(third.results[0]).toMatchObject({ candidate_id: regenerated, mode: 'suggestion', updated: true });
  expect(comments[0].body).not.toContain(`<!-- mitig8it-fix:${CANDIDATE} -->`);
  expect(comments[0].body.match(/<!-- mitig8it-fix:/g)).toHaveLength(1);
  expect(comments[0].body.startsWith(`${FINDING_MARKER}\n**SQL injection**\nUse parameters.`)).toBe(true);
});

// The verified line names the sandbox the check pair actually ran in. `isolated_job` is the
// Cloud Run job sandbox: separate containers and a network the job's own probes measured as
// unreachable, so it is named as an isolated sandbox and never given the development wording.
// A level this service does not recognize is named the most cautious way, not the most
// flattering one, because an unknown sandbox is not evidence of a strong one.
test.each([
  ['independent_sandbox', 'isolated sandbox'],
  ['isolated_job', 'isolated sandbox (Cloud Run job, network denied)'],
  ['development_unverified', 'development sandbox'],
  ['', 'development sandbox'],
  ['some_level_from_the_future', 'development sandbox'],
])('the verified line names the sandbox for verification level "%s"', async (level, where) => {
  const comments = findingCommentGitHub({ id: 77, body: `${FINDING_MARKER}\n**SQL injection**\nUse parameters.`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const result = await publishFindingFixSections(fixPayload([fixSection({ verification_level: level })]));
  expect(result.state).toBe('published');
  expect(comments[0].body).toContain(`Verified: regression test failed on the original code and passed with this change (${where}).`);
});

test('the Cloud Run job sandbox is never described to a reviewer as a development sandbox', async () => {
  const comments = findingCommentGitHub({ id: 77, body: `${FINDING_MARKER}\n**SQL injection**\nUse parameters.`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  await publishFindingFixSections(fixPayload([fixSection({
    verification_level: 'isolated_job',
    limitations: ['verification ran in an isolated Cloud Run job container without a read-only root filesystem or a gVisor runtime class'],
  })]));
  const body = comments[0].body;
  expect(body).toContain('(isolated sandbox (Cloud Run job, network denied))');
  expect(body).not.toContain('development sandbox');
  expect(body).toContain('**Limitations:** verification ran in an isolated Cloud Run job container without a read-only root filesystem or a gVisor runtime class');
});

test('a multi-line hunk inside a ranged finding comment becomes a suggestion for the whole comment range', async () => {
  const file = ['const path = require(\'path\');', 'function read(base, name) {', '  const target = path.join(base, name);', '  return fs.readFileSync(target);', '}', 'module.exports = { read };'].join('\n');
  const comments = findingCommentGitHub(
    { id: 78, body: `${FINDING_MARKER}\n**Path traversal**`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', start_line: 2, line: 5, side: 'RIGHT' },
    { handle: (request) => (request.url.includes('/contents/services/orders.js') ? { data: { content: Buffer.from(file).toString('base64') } } : null) }
  );
  const section = fixSection({ hunk: { start_line: 3, end_line: 4,
    original_lines: ['  const target = path.join(base, name);', '  return fs.readFileSync(target);'],
    replacement_lines: ['  const target = path.resolve(base, name);', '  if (!target.startsWith(base + path.sep)) throw new Error(\'outside base\');', '  return fs.readFileSync(target);'] } });
  const result = await publishFindingFixSections(fixPayload([section]));
  expect(result.results[0]).toMatchObject({ mode: 'suggestion', updated: true });
  expect(comments[0].body).toContain([
    '```suggestion', 'function read(base, name) {', '  const target = path.resolve(base, name);',
    '  if (!target.startsWith(base + path.sep)) throw new Error(\'outside base\');', '  return fs.readFileSync(target);', '}', '```',
  ].join('\n'));
});

test('a hunk the comment cannot carry and the diff does not show falls back to the unified diff with one line saying why', async () => {
  const comments = findingCommentGitHub({ id: 79, body: `${FINDING_MARKER}\n**Command injection**`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' },
    { handle: (request) => (request.url.includes('/pulls/9/files') ? { data: [{ filename: 'services/orders.js', patch: '@@ -12,1 +12,1 @@\n+  new' }] } : null) });
  const outside = await publishFindingFixSections(fixPayload([fixSection({ hunk: { start_line: 10, end_line: 14, original_lines: [], replacement_lines: ['x'] } })]));
  expect(outside.results[0]).toMatchObject({ mode: 'diff', updated: true, reason: 'the fix changes lines 10-14, and this comment can only carry a suggestion for line 12' });
  expect(comments[0].body).toContain(`<!-- mitig8it-fix:${CANDIDATE} -->\n\`\`\`diff\n--- a/services/orders.js\n+++ b/services/orders.js\n@@ -12,1 +12,1 @@\n-  old\n+  new\n\`\`\`\nShown as a diff: the fix changes lines 10-14, and this comment can only carry a suggestion for line 12.\n${VERIFIED_LINE}\n\n<details>`);
  expect(comments[0].body).not.toContain('```suggestion');

  const regions = await publishFindingFixSections(fixPayload([fixSection({ hunk: null, not_suggestable_reason: 'multiple_files' })]));
  expect(regions.results[0]).toMatchObject({ mode: 'diff', reason: 'the verified fix changes more than one file' });
  expect(comments[0].body).toContain('Shown as a diff: the verified fix changes more than one file.');
});

// A candidate whose change has two regions: the one on the finding's line is the suggestion
// in the finding comment; an added import on its own line in the diff gets a second inline
// comment on that line carrying the same candidate marker, kept in place on a retry and
// removed when a regeneration no longer needs it.
test('an added import in the diff becomes a second suggestion comment on its line, idempotently', async () => {
  const github = emptyPullRequestGitHub({ patch: '@@ -1,3 +1,5 @@\n context\n+const cp = require(\'child_process\');\n context\n@@ -10,3 +12,5 @@\n context\n+  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);\n+  more\n context\n context' });
  const importHunk = { start_line: 2, end_line: 2, original_lines: ["const cp = require('child_process');"], replacement_lines: ["const cp = require('child_process');", "const { execFile } = require('child_process');"] };
  const first = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY, extra_hunks: [importHunk] })]));
  expect(first.results[0]).toMatchObject({ comment_id: 500, mode: 'suggestion', updated: true, created: true, placement: 'inline' });
  expect(github.created.inline.map((item) => [item.path, item.start_line, item.line])).toEqual([['services/orders.js', undefined, 12], ['services/orders.js', undefined, 2]]);
  const [finding, extra] = github.reviewComments;
  expect(finding.body).toContain(`\`\`\`suggestion\n  const rows = await db.query('SELECT * FROM orders WHERE id = $1', [id]);\n\`\`\`\n${VERIFIED_LINE}\n\n<details>`);
  expect(finding.body).not.toContain('Also add');
  expect(extra.body).toBe([
    '<!-- mitig8it-fix-extra:fp-sql-1:0 -->', `<!-- mitig8it-fix:${CANDIDATE} -->`,
    '```suggestion', "const cp = require('child_process');", "const { execFile } = require('child_process');", '```',
    'Part of the verified fix for `services/orders.js` line 12; the finding comment there has the details.',
    `<!-- /mitig8it-fix:${CANDIDATE} -->`,
  ].join('\n'));

  // The same input again writes nothing; a regeneration without the import removes the extra comment.
  const second = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY, extra_hunks: [importHunk] })]));
  expect(second.results[0]).toMatchObject({ mode: 'suggestion', updated: false });
  expect(github.created.inline).toHaveLength(2);
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch' || request.method === 'delete')).toHaveLength(0);
  const regenerated = 'c1d2e3f4-0000-4000-8000-000000000004';
  await publishFindingFixSections(fixPayload([fixSection({ candidate_id: regenerated, finding_body: FINDING_BODY })]));
  expect(axios.mock.calls.filter(([request]) => request.method === 'delete').map(([request]) => request.url)).toEqual([expect.stringMatching(/\/pulls\/comments\/501$/)]);
  expect(github.reviewComments[0].body).toContain(`<!-- mitig8it-fix:${regenerated} -->`);
});

// The same two regions when the import line is not in the diff: GitHub cannot take a comment
// there, so the import is folded into a short note under the suggestion. A region that is
// neither an import nor in the diff means the fix cannot be a suggestion at all.
test('an added import outside the diff is folded into a note; any other region outside the diff makes the fix a diff', async () => {
  const github = emptyPullRequestGitHub();
  const importHunk = { start_line: 2, end_line: 2, original_lines: ['import os'], replacement_lines: ['import os', 'import ast'] };
  const first = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY, extra_hunks: [importHunk] })]));
  expect(first.results[0]).toMatchObject({ mode: 'suggestion', created: true });
  expect(github.created.inline).toHaveLength(1);
  expect(github.reviewComments[0].body).toContain(`\`\`\`\n${VERIFIED_LINE}\nAlso add \`import ast\` at line 2, which is outside the pull request diff.\n\n<details>`);

  const other = { start_line: 40, end_line: 41, original_lines: ['a', 'b'], replacement_lines: ['c'] };
  const second = await publishFindingFixSections(fixPayload([fixSection({ candidate_id: 'c1d2e3f4-0000-4000-8000-000000000005', finding_body: FINDING_BODY, extra_hunks: [other] })]));
  expect(second.results[0]).toMatchObject({ mode: 'diff', reason: 'the fix also changes lines 40-41, outside the pull request diff' });
  expect(github.reviewComments[0].body).toContain('Shown as a diff: the fix also changes lines 40-41, outside the pull request diff.');
  expect(github.reviewComments[0].body).not.toContain('```suggestion');
});

// The region on the finding's line may lie outside the single-line comment's range (the
// fix rewrites the line above the sink) while still being in the diff: it is suggested in
// a separate comment on its own lines, and the finding comment says so under the verified line.
test('a primary region the finding comment cannot carry is suggested in a separate comment on its lines', async () => {
  const github = emptyPullRequestGitHub();
  const hunk = { start_line: 10, end_line: 11, original_lines: ['  const target = path.join(REPORT_DIR, req.query.name);', '  fs.readFile(target, (error, data) => {'],
    replacement_lines: ['  const baseDir = path.resolve(REPORT_DIR);', '  const target = path.resolve(baseDir, String(req.query.name));', '  fs.readFile(target, (error, data) => {'] };
  const result = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY, hunk })]));
  expect(result.results[0]).toMatchObject({ mode: 'suggestion', created: true, placement: 'inline' });
  expect(github.created.inline.map((item) => [item.start_line, item.line])).toEqual([[undefined, 12], [10, 11]]);
  expect(github.reviewComments[0].body).toContain(`<!-- mitig8it-fix:${CANDIDATE} -->\n${VERIFIED_LINE}\nThe change is suggested in a separate comment on lines 10-11.\n\n<details>`);
  expect(github.reviewComments[1].body).toContain('```suggestion\n  const baseDir = path.resolve(REPORT_DIR);\n  const target = path.resolve(baseDir, String(req.query.name));\n  fs.readFile(target, (error, data) => {\n```');
});

test('a skipped finding receives one "No automatic fix" line and an unknown marker is reported, never created', async () => {
  const comments = findingCommentGitHub({ id: 80, body: `${FINDING_MARKER}\n**Open redirect**`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const result = await publishFindingFixSections(fixPayload([
    fixSection({ candidate_id: '', hunk: null, skipped_reason: 'This finding is outside the enabled repair families.' }),
    fixSection({ finding_fingerprint: 'fp-unknown' }),
  ]));
  expect(result.results).toEqual([
    { finding_fingerprint: 'fp-sql-1', candidate_id: '', comment_id: 80, mode: 'skipped', updated: true, reason: 'This finding is outside the enabled repair families.', ...PLACED },
    { finding_fingerprint: 'fp-unknown', candidate_id: CANDIDATE, comment_id: 0, mode: 'comment_not_found', updated: false, reason: 'no finding comment carries this marker', created: false, placement: '' },
  ]);
  expect(comments[0].body).toContain('<!-- mitig8it-fix:none -->\nNo automatic fix: This finding is outside the enabled repair families.\n<!-- /mitig8it-fix:none -->');
  expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(0);
});

test('fix sections never edit a marker comment by another author and are not written after the head moved', async () => {
  findingCommentGitHub({ id: 81, body: `${FINDING_MARKER}\nforged`, user: { login: 'someone-else' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const result = await publishFindingFixSections(fixPayload([fixSection()]));
  expect(result.results[0]).toMatchObject({ mode: 'comment_not_found', updated: false });
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(0);

  jest.clearAllMocks();
  githubAppAuth.getInstallationToken.mockResolvedValue('installation-token');
  githubAppAuth.getAppBotLogin.mockResolvedValue('mitig8it[bot]');
  axios.mockImplementation(async request => {
    const response = repositoryResponse(request);
    if (request.url.endsWith('/pulls/9')) response.data.head.sha = 'f'.repeat(40);
    return response;
  });
  const stale = await publishFindingFixSections(fixPayload([fixSection()]));
  expect(stale).toEqual({ state: 'stale', operation_id: actionId, results: [], reason: 'head_moved' });
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(0);
});

// A scripted pull request without a finding comment: the diff shows services/orders.js
// lines 10 to 14 (one hunk), inline and pull request comment creation are recorded.
function emptyPullRequestGitHub({ patch = '@@ -10,3 +10,5 @@\n context\n+  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);\n+  more\n context\n context', issueComments = [] } = {}) {
  const reviewComments = [];
  const created = { inline: [], issue: [] };
  axios.mockImplementation(async request => {
    if (request.url.includes('/pulls/9/comments') && request.method === 'get') return { data: reviewComments };
    if (request.url.includes('/pulls/9/comments') && request.method === 'post') {
      const comment = { id: 500 + reviewComments.length, body: request.data.body, path: request.data.path, line: request.data.line, side: request.data.side, user: { login: 'mitig8it[bot]' } };
      reviewComments.push(comment); created.inline.push(request.data);
      return { data: { id: comment.id } };
    }
    if (request.url.includes('/pulls/9/files')) return { data: [{ filename: 'services/orders.js', patch }] };
    if (request.url.includes('/issues/9/comments') && request.method === 'get') return { data: issueComments };
    if (request.url.includes('/issues/9/comments') && request.method === 'post') {
      const comment = { id: 700 + issueComments.length, body: request.data.body, user: { login: 'mitig8it[bot]' } };
      issueComments.push(comment); created.issue.push(request.data);
      return { data: { id: comment.id } };
    }
    if (request.url.includes('/issues/comments/') && request.method === 'patch') {
      const id = Number(request.url.split('/').pop());
      issueComments.find(item => item.id === id).body = request.data.body;
      return { data: { id } };
    }
    if (request.url.includes('/pulls/comments/') && request.method === 'patch') {
      const id = Number(request.url.split('/').pop());
      reviewComments.find(item => item.id === id).body = request.data.body;
      return { data: { id } };
    }
    return repositoryResponse(request);
  });
  return { reviewComments, issueComments, created };
}

// A finding the analysis kept summary only has no comment. When the section carries the
// finding text and the line is in the diff, the comment is created on that line with the
// analysis marker and body, then the fix section; a retry finds it and writes nothing.
test('a section with the finding text creates the finding comment on the line when the diff shows it, once', async () => {
  const github = emptyPullRequestGitHub();
  const first = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY })]));
  expect(first.state).toBe('published');
  expect(first.results).toEqual([{ finding_fingerprint: 'fp-sql-1', candidate_id: CANDIDATE, comment_id: 500, mode: 'suggestion', updated: true, reason: '', created: true, placement: 'inline' }]);
  expect(github.created.inline).toEqual([expect.objectContaining({ path: 'services/orders.js', line: 12, side: 'RIGHT', commit_id: head })]);
  const body = github.reviewComments[0].body;
  expect(body.startsWith(`${FINDING_MARKER}\n${FINDING_BODY}\n\n<!-- mitig8it-fix:${CANDIDATE} -->`)).toBe(true);
  expect(body).toContain('```suggestion\n  const rows = await db.query(\'SELECT * FROM orders WHERE id = $1\', [id]);\n```');
  expect(body).toContain('**Proof:** regression test tests/orders.regression.test.js asserts');
  expect(github.created.issue).toHaveLength(0);

  const second = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY })]));
  expect(second.results[0]).toMatchObject({ comment_id: 500, mode: 'suggestion', updated: false, created: false, placement: 'inline' });
  expect(github.created.inline).toHaveLength(1);
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(0);
});

// A finding body that arrives with stale fix blocks cannot smuggle a section past the
// candidate markers: the blocks are dropped before the comment is created.
test('fix blocks inside the finding text are stripped before the comment is created', async () => {
  const github = emptyPullRequestGitHub();
  await publishFindingFixSections(fixPayload([fixSection({ finding_body: `${FINDING_BODY}\n\n<!-- mitig8it-fix:stale -->\nold\n<!-- /mitig8it-fix:stale -->` })]));
  expect(github.reviewComments[0].body).not.toContain('mitig8it-fix:stale');
  expect(github.reviewComments[0].body.match(/<!-- mitig8it-fix:/g)).toHaveLength(1);
});

// GitHub refuses an inline comment on a line the diff does not show. The fix then goes
// to a pull request comment carrying the same marker, the file and line, the reason,
// and the change as a diff, and a retry updates that comment instead of adding one.
test('a finding line outside the diff falls back to a pull request comment that says why and carries the diff', async () => {
  const github = emptyPullRequestGitHub();
  const section = fixSection({ finding_body: FINDING_BODY, finding_line: 35, hunk: { start_line: 35, end_line: 35, original_lines: ['old'], replacement_lines: ['new'] } });
  const first = await publishFindingFixSections(fixPayload([section]));
  expect(first.results).toEqual([{ finding_fingerprint: 'fp-sql-1', candidate_id: CANDIDATE, comment_id: 700, mode: 'diff', updated: true,
    reason: "this finding's line is not part of the pull request diff, so GitHub allows neither an inline comment nor a suggestion there", created: true, placement: 'pull_request' }]);
  expect(github.created.inline).toHaveLength(0);
  const body = github.issueComments[0].body;
  expect(body.startsWith(`${FINDING_MARKER}\n**Verified fix for \`services/orders.js\` line 35.** This line is not part of the pull request diff, so GitHub does not accept an inline comment on it; the finding and its verified fix are reported here instead.\n\n${FINDING_BODY}`)).toBe(true);
  expect(body).toContain("Shown as a diff: this finding's line is not part of the pull request diff, so GitHub allows neither an inline comment nor a suggestion there.");
  expect(body).toContain('```diff\n--- a/services/orders.js');
  expect(body).not.toContain('```suggestion');

  const regenerated = 'c1d2e3f4-0000-4000-8000-000000000003';
  const second = await publishFindingFixSections(fixPayload([{ ...section, candidate_id: regenerated }]));
  expect(second.results[0]).toMatchObject({ comment_id: 700, mode: 'diff', updated: true, created: false, placement: 'pull_request' });
  expect(github.issueComments).toHaveLength(1);
  expect(github.issueComments[0].body).toContain(`<!-- mitig8it-fix:${regenerated} -->`);
  expect(github.issueComments[0].body).not.toContain(`<!-- mitig8it-fix:${CANDIDATE} -->`);
});

// Two findings on the same line: the candidate that proves one covers the other. The
// covered finding's comment says so and names the proven rule; both sections carry both
// finding ids; the covered comment never says there is no automatic fix.
test('a covered finding is published as fixed together with the proven finding, under its own comment', async () => {
  const covered = '<!-- mitig8it-finding:fp-traversal-2 -->';
  const comments = findingCommentGitHub({ id: 90, body: `${FINDING_MARKER}\n**Path traversal**`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  comments.push({ id: 91, body: `${covered}\n**Uncontrolled path**`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const result = await publishFindingFixSections(fixPayload([
    fixSection({ finding_ids: ['f-1', 'f-2'] }),
    fixSection({ finding_fingerprint: 'fp-traversal-2', hunk: null, unified_diff: '', evidence: [], finding_ids: ['f-1', 'f-2'], covered_by: 'js/path-traversal' }),
  ]));
  expect(result.results).toEqual([
    { finding_fingerprint: 'fp-sql-1', candidate_id: CANDIDATE, comment_id: 90, mode: 'suggestion', updated: true, reason: '', ...PLACED },
    { finding_fingerprint: 'fp-traversal-2', candidate_id: CANDIDATE, comment_id: 91, mode: 'covered', updated: true, reason: 'fixed together with js/path-traversal', ...PLACED },
  ]);
  expect(comments[0].body).toContain('**Findings covered:** `f-1`, `f-2`');
  expect(comments[1].body).toContain(`<!-- mitig8it-fix:${CANDIDATE} -->\nFixed together with js/path-traversal: the verified fix published under that finding on the same lines resolves this finding as well (findings \`f-1\`, \`f-2\`).\n<!-- /mitig8it-fix:${CANDIDATE} -->`);
  expect(comments[1].body).not.toContain('No automatic fix');
  expect(comments[1].body).not.toContain('```suggestion');
});

test("a marker comment by another author is never edited; with the finding text the app creates its own comment instead", async () => {
  const github = emptyPullRequestGitHub();
  github.reviewComments.push({ id: 1, body: `${FINDING_MARKER}\nforged`, user: { login: 'someone-else' }, path: 'services/orders.js', line: 12, side: 'RIGHT' });
  const result = await publishFindingFixSections(fixPayload([fixSection({ finding_body: FINDING_BODY })]));
  expect(result.results[0]).toMatchObject({ comment_id: 501, mode: 'suggestion', created: true, placement: 'inline' });
  expect(github.reviewComments[0].body).toBe(`${FINDING_MARKER}\nforged`);
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(0);
});

test('fix sections report reconciling on a lost write response without a second attempt', async () => {
  axios.mockImplementation(async request => {
    if (request.url.includes('/pulls/9/comments') && request.method === 'get') {
      return { data: [{ id: 82, body: `${FINDING_MARKER}\nbody`, user: { login: 'mitig8it[bot]' }, path: 'services/orders.js', line: 12, side: 'RIGHT' }] };
    }
    if (request.method === 'patch') throw new Error('socket hang up');
    return repositoryResponse(request);
  });
  const result = await publishFindingFixSections(fixPayload([fixSection()]));
  expect(result).toEqual({ state: 'reconciling', operation_id: actionId, results: [], reason: 'github_comment_outcome_ambiguous' });
  expect(axios.mock.calls.filter(([request]) => request.method === 'patch')).toHaveLength(1);
});
