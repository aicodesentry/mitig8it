const axios = require('axios');
const githubAppAuth = require('./githubAppAuth');

class OperationError extends Error {
  constructor(message, statusCode = 500, detail = null) {
    super(message);
    this.statusCode = statusCode;
    this.detail = detail;
  }
}

function badRequest(message) {
  return new OperationError(message, 400);
}

function externalError(message, error) {
  return new OperationError(message, 502, error.response?.data || error.message);
}

function validateRepositoryFullName(repositoryFullName) {
  if (!repositoryFullName || !repositoryFullName.includes('/') || repositoryFullName.split('/').length !== 2) {
    throw badRequest('Invalid repository_full_name format');
  }
  return repositoryFullName.split('/');
}

function validateOwnerRepo(owner, repo) {
  if (!/^[a-zA-Z0-9_.-]+$/.test(owner || '') || !/^[a-zA-Z0-9_.-]+$/.test(repo || '')) {
    throw badRequest('Invalid owner or repo format');
  }
}

async function githubRequest(method, url, token, data) {
  const maxAttempts = 4;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await axios({
        method,
        url,
        data,
        timeout: 25000,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      });
    } catch (error) {
      const status = error.response?.status;
      const retryable = [429, 500, 502, 503, 504].includes(status);
      if (!retryable || attempt === maxAttempts) throw error;
      const delayMs = 1000 * Math.pow(2, attempt - 1);
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }
}

async function fetchPullRequestFiles({ repository_full_name, pull_request_number, installation_id, commit_sha }) {
  if (!repository_full_name || !pull_request_number || !installation_id) {
    throw badRequest('repository_full_name, pull_request_number and installation_id are required');
  }

  const [owner, repo] = validateRepositoryFullName(repository_full_name);

  try {
    const token = await githubAppAuth.getInstallationToken(installation_id);
    if (!commit_sha) throw badRequest('commit_sha is required for immutable analysis');
    const assertHead = async () => {
      const pull = await githubRequest('get', `https://api.github.com/repos/${owner}/${repo}/pulls/${pull_request_number}`, token);
      if (pull.data.head?.sha !== commit_sha) throw new OperationError('Analysis run superseded by another PR head', 409);
    };
    await assertHead();
    const files = [];
    let page = 1;

    for (;;) {
      const response = await githubRequest(
        'get',
        `https://api.github.com/repos/${owner}/${repo}/pulls/${pull_request_number}/files?per_page=100&page=${page}`,
        token
      );
      files.push(...response.data);
      if (response.data.length < 100) break;
      page += 1;
    }

    await assertHead();
    const scoped = files
        .filter((f) => ['added', 'modified', 'renamed'].includes(f.status))
        .filter((f) => !f.filename.startsWith('dist/') && !f.filename.includes('node_modules'));
    if (scoped.length > 200) throw new OperationError('PR exceeds the 200-file analysis limit; split the change before retrying', 422);
    return {
      files: scoped.map((f) => ({
          path: f.filename,
          patch: f.patch || '',
          additions: f.additions,
          deletions: f.deletions,
          status: f.status,
          raw_url: f.raw_url,
        })),
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to fetch pull request files from GitHub', error);
  }
}

async function fetchFileContents({ repository_full_name, installation_id, ref, paths }) {
  if (!repository_full_name || !installation_id || !ref || !Array.isArray(paths)) {
    throw badRequest('repository_full_name, installation_id, ref and paths are required');
  }

  const [owner, repo] = validateRepositoryFullName(repository_full_name);

  try {
    const token = await githubAppAuth.getInstallationToken(installation_id);
    const files = [];

    for (const path of paths.slice(0, 200)) {
      if (!path || typeof path !== 'string') continue;
      const encodedPath = path.split('/').map(encodeURIComponent).join('/');
      const response = await githubRequest(
        'get',
        `https://api.github.com/repos/${owner}/${repo}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`,
        token
      );
      const content = typeof response.data === 'string'
        ? response.data
        : Buffer.from(response.data.content || '', 'base64').toString('utf8');

      if (Buffer.byteLength(content || '', 'utf8') > 500000) continue;
      files.push({ path, content });
    }

    return { files };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to fetch file contents from GitHub', error);
  }
}

async function submitPullRequestReview({ owner, repo, pr_number, installation_id, commit_sha, body, event, comments }) {
  if (!owner || !repo || !pr_number || !installation_id || !commit_sha || !body || !event) {
    throw badRequest('owner, repo, pr_number, installation_id, commit_sha, body, event are required');
  }
  validateOwnerRepo(owner, repo);

  try {
    const token = await githubAppAuth.getInstallationToken(installation_id);
    const pull = await githubRequest('get', `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}`, token);
    if (pull.data.head?.sha !== commit_sha) throw new OperationError('Analysis run superseded by another PR head', 409);
    const reviews = [];
    for (let page = 1; ; page += 1) {
      const response = await githubRequest('get',
        `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/reviews?per_page=100&page=${page}`, token);
      reviews.push(...response.data);
      if (response.data.length < 100) break;
    }
    const botLogin = await githubAppAuth.getAppBotLogin();
    const owned = reviews.filter(review => review.user?.login === botLogin && review.body?.includes('<!-- mitig8it-review -->'));
    const expectedState = event === 'REQUEST_CHANGES' ? 'CHANGES_REQUESTED' : 'COMMENTED';
    const existing = owned.find(review => review.commit_id === commit_sha && review.body === body && review.state === expectedState);
    for (const review of owned) {
      if (review.id !== existing?.id && review.state === 'CHANGES_REQUESTED') {
        await githubRequest('put',
          `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/reviews/${review.id}/dismissals`,
          token, { message: 'Superseded by new analysis run.' });
      }
    }
    if (existing) return { review_id: existing.id, comments_posted: 0 };

    const reviewPayload = {
      commit_id: commit_sha,
      body,
      event,
      comments: (comments || []).map((c) => ({
        path: c.path,
        line: c.line || 1,
        side: 'RIGHT',
        body: c.body,
      })),
    };

    const response = await githubRequest(
      'post',
      `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/reviews`,
      token,
      reviewPayload
    );

    return {
      review_id: response.data.id,
      comments_posted: (comments || []).length,
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to submit review', error);
  }
}

async function postInlineComment({ owner, repo, pr_number, installation_id, commit_sha, path, line, body }) {
  if (!owner || !repo || !pr_number || !installation_id || !commit_sha || !path || !line || !body) {
    throw badRequest('owner, repo, pr_number, installation_id, commit_sha, path, line and body are required');
  }
  validateOwnerRepo(owner, repo);

  try {
    const token = await githubAppAuth.getInstallationToken(installation_id);
    // Stable finding markers make retries and later tiers reconcile the same thread.
    const marker = body.match(/<!-- mitig8it-finding:[^>]+ -->/)?.[0];
    if (marker) {
      const pull = await githubRequest('get', `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}`, token);
      if (pull.data.head?.sha !== commit_sha) throw new OperationError('Analysis run superseded by another PR head', 409);
      const botLogin = await githubAppAuth.getAppBotLogin();
      for (let page = 1; ; page += 1) {
        const existing = await githubRequest('get',
          `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/comments?per_page=100&page=${page}`, token);
        const comment = existing.data.find(c => c.user?.login === botLogin && c.path === path && c.body?.includes(marker));
        if (comment) {
          // A re-analysis of the same head re-renders the finding text. The verified fix
          // sections under it were published for this same finding and this same head, so
          // they are carried over verbatim instead of being overwritten away. The marker
          // match is the fingerprint check, and the head check above is the head check:
          // a different fingerprint finds a different comment, and a moved head has
          // already refused this publication.
          const nextBody = withPreservedFixBlocks(body, comment.body);
          if (comment.body !== nextBody) await githubRequest('patch',
            `https://api.github.com/repos/${owner}/${repo}/pulls/comments/${comment.id}`, token, { body: nextBody });
          return { comment_id: comment.id, url: comment.html_url, success: true };
        }
        if (existing.data.length < 100) break;
      }
    }
    const response = await githubRequest(
      'post',
      `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/comments`,
      token,
      {
        body,
        commit_id: commit_sha,
        path,
        line,
        side: 'RIGHT',
      }
    );

    return {
      comment_id: response.data.id,
      url: response.data.html_url,
      success: true,
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to post inline comment', error);
  }
}

async function createCheckRun({ owner, repo, installation_id, head_sha, conclusion, title, summary }) {
  if (!owner || !repo || !installation_id || !head_sha || !conclusion || !title || !summary) {
    throw badRequest('owner, repo, installation_id, head_sha, conclusion, title and summary are required');
  }

  try {
    const token = await githubAppAuth.getInstallationToken(installation_id);
    let existing = null;
    for (let page = 1; ; page += 1) {
      const response = await githubRequest('get',
        `https://api.github.com/repos/${owner}/${repo}/commits/${encodeURIComponent(head_sha)}/check-runs?check_name=Mitig8it%20Security%20Review&per_page=100&page=${page}`, token);
      const checks = response.data.check_runs;
      if (!Array.isArray(checks)) throw new OperationError('Invalid check run response', 502);
      existing = checks.find(check => check.head_sha === head_sha && check.name === 'Mitig8it Security Review'
        && String(check.app?.id) === String(process.env.GITHUB_APP_ID));
      if (existing || checks.length < 100) break;
    }
    const response = await githubRequest(
      existing ? 'patch' : 'post',
      `https://api.github.com/repos/${owner}/${repo}/check-runs${existing ? `/${existing.id}` : ''}`,
      token,
      {
        name: 'Mitig8it Security Review',
        head_sha,
        status: 'completed',
        conclusion,
        output: { title, summary },
      }
    );
    return { check_run_id: response.data.id };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to create check run', error);
  }
}

// Remediation writes are deliberately kept separate from githubRequest. That helper
// retries transient REST failures, which is appropriate for reads but unsafe for a
// mutation whose response may have been lost after GitHub accepted it.
function isAmbiguousWriteError(error) {
  const status = error.response?.status;
  return !status || [429, 500, 502, 503, 504].includes(status);
}

async function githubGraphqlMutation(token, query, variables) {
  return axios({
    method: 'post',
    url: 'https://api.github.com/graphql',
    data: { query, variables },
    timeout: 25000,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
}

function requireString(value, name, maxLength = 255) {
  if (typeof value !== 'string' || !value || value.length > maxLength) throw badRequest(`${name} is required`);
  return value;
}

function validateSha(value, name) {
  const sha = requireString(value, name, 64);
  if (!/^[0-9a-f]{7,64}$/i.test(sha)) throw badRequest(`${name} must be a Git object ID`);
  return sha;
}

function validateActionEnvelope(payload) {
  const repositoryFullName = requireString(payload.repository_full_name, 'repository_full_name');
  const [owner, repo] = validateRepositoryFullName(repositoryFullName);
  const actorLogin = requireString(payload.actor_login, 'actor_login');
  if (!/^[a-zA-Z0-9-]+$/.test(actorLogin)) throw badRequest('Invalid actor_login');
  if (!Number.isInteger(Number(payload.installation_id)) || Number(payload.installation_id) <= 0) {
    throw badRequest('installation_id must be a positive integer');
  }
  if (!Number.isInteger(Number(payload.pr_number)) || Number(payload.pr_number) <= 0) {
    throw badRequest('pr_number must be a positive integer');
  }
  const actionId = requireString(payload.action_id, 'action_id', 128);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{7,127}$/.test(actionId)) throw badRequest('Invalid action_id');
  const idempotencyKey = requireString(payload.idempotency_key, 'idempotency_key', 255);
  const manifestDigest = requireString(payload.manifest_digest, 'manifest_digest', 64);
  if (!/^[0-9a-f]{64}$/i.test(manifestDigest)) throw badRequest('manifest_digest must be a SHA-256 digest');
  return {
    owner,
    repo,
    repository_full_name: repositoryFullName,
    actor_login: actorLogin,
    installation_id: Number(payload.installation_id),
    pr_number: Number(payload.pr_number),
    head_sha: validateSha(payload.head_sha, 'head_sha'),
    base_sha: validateSha(payload.base_sha, 'base_sha'),
    action_id: actionId,
    idempotency_key: idempotencyKey,
    manifest_digest: manifestDigest.toLowerCase(),
  };
}

function remediationMarker(actionId, manifestDigest) {
  return `<!-- mitig8it-remediation:${actionId}:${manifestDigest} -->`;
}

function isAllowedRemediationPath(filePath) {
  if (typeof filePath !== 'string' || !filePath || filePath.length > 1024
    || filePath.startsWith('/') || filePath.includes('\\') || /[\x00-\x1f]/.test(filePath)
    || filePath.split('/').some(part => !part || part === '.' || part === '..')) return false;
  const blocked = ['.github/', 'dist/', 'node_modules/'];
  const blockedNames = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];
  return !blocked.some((prefix) => filePath.startsWith(prefix)) && !blockedNames.includes(filePath);
}

function validateFileChanges(changes) {
  if (!Array.isArray(changes) || changes.length < 1 || changes.length > 5) {
    throw new OperationError('A remediation batch must contain one to five file additions', 422);
  }
  const paths = new Set();
  const additions = changes.map((change) => {
    if (!change || !isAllowedRemediationPath(change.path) || paths.has(change.path)) {
      throw new OperationError('Remediation contains an unsupported or duplicate path', 422);
    }
    paths.add(change.path);
    if (typeof change.contents_base64 !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(change.contents_base64)) {
      throw new OperationError('Remediation contents must be canonical base64', 422);
    }
    const decoded = Buffer.from(change.contents_base64, 'base64');
    if (decoded.toString('base64') !== change.contents_base64 || decoded.length > 500000) {
      throw new OperationError('Remediation contents are invalid or too large', 422);
    }
    if (decoded.includes(0) || !Buffer.from(decoded.toString('utf8')).equals(decoded)) {
      throw new OperationError('Remediation requires UTF-8 source files', 422);
    }
    return { path: change.path, contents: change.contents_base64 };
  });
  // Changed-line limits are checked against source in the trusted verifier.
  // Counting whole replacement files here would reject a one-line fix in a large file.
  return additions;
}

async function assertInstallationRepositoryAndActor(envelope, requireActorWritePermission = true) {
  const token = await githubAppAuth.getInstallationToken(envelope.installation_id);
  const repository = await githubRequest('get', `https://api.github.com/repos/${envelope.owner}/${envelope.repo}`, token);
  if (repository.data?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()) {
    throw new OperationError('Repository is not accessible through this installation', 403);
  }
  // The installation token is scoped to the claimed installation. Enumerating its
  // accessible repositories protects against a caller mixing repository IDs across
  // installations, including selected-repository installations.
  let repositoryFound = false;
  for (let page = 1; page <= 10; page += 1) {
    const response = await githubRequest('get',
      `https://api.github.com/installation/repositories?per_page=100&page=${page}`, token);
    const repositories = response.data?.repositories;
    if (!Array.isArray(repositories)) throw new OperationError('Invalid installation repository response', 502);
    repositoryFound = repositories.some((candidate) => candidate.full_name?.toLowerCase() === envelope.repository_full_name.toLowerCase());
    if (repositoryFound || repositories.length < 100) break;
  }
  if (!repositoryFound) throw new OperationError('Repository is not enabled for this installation', 403);

  if (requireActorWritePermission) {
    const permission = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/collaborators/${encodeURIComponent(envelope.actor_login)}/permission`, token);
    if (!['write', 'admin'].includes(permission.data?.permission)) {
      throw new OperationError('Actor does not currently have write permission for this repository', 403);
    }
  }
  return token;
}

async function loadExactSameRepositoryPull(envelope, token) {
  const response = await githubRequest('get',
    `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
  const pull = response.data;
  if (pull?.state !== 'open' || pull.draft || pull.merged) {
    throw new OperationError('Remediation requires an open, non-draft pull request', 409);
  }
  if (pull?.head?.sha !== envelope.head_sha || pull?.base?.sha !== envelope.base_sha) {
    throw new OperationError('Remediation action is superseded by a changed pull request revision', 409);
  }
  if (!pull.head?.ref || !pull.base?.ref || pull.head?.repo?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()
    || pull.base?.repo?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()) {
    throw new OperationError('Fork pull requests are unsupported for automated remediation', 422);
  }
  return pull;
}

async function prepareRemediationAction(payload) {
  const envelope = validateActionEnvelope(payload);
  try {
    const token = await assertInstallationRepositoryAndActor(envelope);
    const pull = await loadExactSameRepositoryPull(envelope, token);
    return {
      state: 'ready',
      operation_id: envelope.action_id,
      branch: pull.head.ref,
      expected_head_oid: envelope.head_sha,
      marker: remediationMarker(envelope.action_id, envelope.manifest_digest),
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to prepare remediation action', error);
  }
}

async function fetchRemediationSnapshot(payload) {
  const envelope = validateActionEnvelope(payload);
  const token = await assertInstallationRepositoryAndActor(envelope);
  await loadExactSameRepositoryPull(envelope, token);
  const commit = await githubRequest('get',
    `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/git/commits/${envelope.head_sha}`, token);
  const treeOid = validateSha(commit.data?.tree?.sha, 'head_tree_oid');
  const tree = await githubRequest('get',
    `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/git/trees/${treeOid}?recursive=1`, token);
  if (tree.data?.truncated !== false || !Array.isArray(tree.data?.tree) || tree.data.tree.length > 20000) {
    throw new OperationError('Repository tree exceeds supported snapshot limits', 422);
  }
  const entries = tree.data.tree.map(({ path, mode, type, sha }) => ({ path, mode, type, sha }));
  const sources = tree.data.tree.filter(entry => entry.type === 'blob' && ['100644', '100755'].includes(entry.mode)
    && !/(^|\/)(node_modules|dist|vendor|\.git|coverage)\//.test(entry.path)
    && (/\.(js|jsx|ts|tsx|json|py|pyi|toml|txt|cfg|ini)$/.test(entry.path))
    && !/(^|\/)(\.env|credentials|secrets)(\.|\/|$)/i.test(entry.path));
  const requiredPaths = new Set(Array.isArray(payload.finding_paths) ? payload.finding_paths : []);
  if (requiredPaths.size > 200 || [...requiredPaths].some(path => typeof path !== 'string' || !sources.some(source => source.path === path))) {
    throw new OperationError('Finding source is unsupported or missing from the immutable tree', 422);
  }
  const directories = [...requiredPaths].map(path => path.slice(0, path.lastIndexOf('/') + 1));
  const rank = entry => requiredPaths.has(entry.path) ? 0
    : /(^|\/)(package\.json|tsconfig[^/]*\.json|requirements[^/]*\.txt|pyproject\.toml|setup\.cfg|Pipfile)$/.test(entry.path) ? 1
      : directories.some(directory => entry.path.startsWith(directory)) ? 2 : 3;
  const ranked = [...sources].sort((left, right) => rank(left) - rank(right) || left.path.localeCompare(right.path));
  // The snapshot is context for the repair agent, not a repository mirror. Finding files
  // and manifests always ship; sibling files and unrelated files are capped so a large
  // repository does not push the fetch past the caller's deadline.
  const RANK_LIMITS = { 2: 30, 3: 10 };
  const rankCounts = { 2: 0, 3: 0 };
  const selected = [];
  let sourceBytes = 0;
  for (const entry of ranked) {
    const size = Number(entry.size);
    const entryRank = rank(entry);
    const rankFull = entryRank >= 2 && rankCounts[entryRank] >= RANK_LIMITS[entryRank];
    if (!Number.isSafeInteger(size) || size < 0 || size > 500000 || sourceBytes + size > 500000 || selected.length >= 60 || rankFull) {
      if (requiredPaths.has(entry.path)) throw new OperationError('Finding source exceeds the repair snapshot budget', 422);
      continue;
    }
    selected.push(entry);
    if (entryRank >= 2) rankCounts[entryRank] += 1;
    sourceBytes += size;
  }
  const fetchBlob = async (entry) => {
    const blob = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/git/blobs/${entry.sha}`, token);
    if (blob.data?.encoding !== 'base64' || typeof blob.data.content !== 'string') {
      throw new OperationError('GitHub did not return the requested source blob', 502);
    }
    return blob;
  };
  const BLOB_CONCURRENCY = 8;
  const blobs = [];
  for (let start = 0; start < selected.length; start += BLOB_CONCURRENCY) {
    const batch = selected.slice(start, start + BLOB_CONCURRENCY);
    blobs.push(...(await Promise.all(batch.map(fetchBlob))));
  }
  const files = [];
  for (const [index, entry] of selected.entries()) {
    const blob = blobs[index];
    const bytes = Buffer.from(blob.data.content, 'base64');
    if (bytes.length > 500000 || bytes.includes(0) || !Buffer.from(bytes.toString('utf8')).equals(bytes)) {
      throw new OperationError('Repair snapshot contains unsupported binary or oversized source', 422);
    }
    const actual = require('crypto').createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
    if (actual !== entry.sha) throw new OperationError('GitHub source blob hash mismatch', 502);
    files.push({ path: entry.path, content: bytes.toString('utf8'), sha: entry.sha });
  }
  await loadExactSameRepositoryPull(envelope, token);
  const selectedPaths = new Set(selected.map(entry => entry.path));
  return { files, tree_entries: entries, head_tree_oid: treeOid, head_sha: envelope.head_sha, base_sha: envelope.base_sha,
    omitted_source_paths: sources.filter(entry => !selectedPaths.has(entry.path)).map(entry => entry.path) };
}

async function commitRemediationAction(payload) {
  const envelope = validateActionEnvelope(payload);
  const additions = validateFileChanges(payload.changes);
  const branch = requireString(payload.branch, 'branch');
  const expectedHeadOid = validateSha(payload.expected_head_oid, 'expected_head_oid');
  const verifiedTreeOid = validateSha(payload.verified_tree_oid, 'verified_tree_oid');
  if (expectedHeadOid !== envelope.head_sha) throw new OperationError('expected_head_oid must match the consented head_sha', 409);
  const headline = requireString(payload.commit_message, 'commit_message', 200);
  if (headline.includes('<!-- mitig8it-remediation:')) throw badRequest('commit_message must not include a remediation marker');

  try {
    const token = await assertInstallationRepositoryAndActor(envelope);
    const pull = await loadExactSameRepositoryPull(envelope, token);
    if (pull.head.ref !== branch) throw new OperationError('Branch changed after preparation', 409);
    const response = await githubGraphqlMutation(token, `mutation CreateRemediationCommit($input: CreateCommitOnBranchInput!) {
      createCommitOnBranch(input: $input) { commit { oid tree { oid } } }
    }`, {
      input: {
        branch: { repositoryNameWithOwner: envelope.repository_full_name, branchName: branch },
        expectedHeadOid,
        message: { headline, body: remediationMarker(envelope.action_id, envelope.manifest_digest) },
        fileChanges: { additions },
      },
    });
    if (response.data?.errors?.length || !response.data?.data?.createCommitOnBranch?.commit?.oid) {
      throw new OperationError('GitHub rejected the atomic remediation commit', 409, response.data?.errors || null);
    }
    const commit = response.data.data.createCommitOnBranch.commit;
    if (commit.tree?.oid !== verifiedTreeOid) {
      throw new OperationError('GitHub commit tree does not match the verified tree', 502, { commit_sha: commit.oid });
    }
    return { state: 'applied', operation_id: envelope.action_id, commit_sha: commit.oid, tree_oid: commit.tree.oid };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) {
      // Do not retry and do not inspect-and-write here. The durable control plane
      // must persist this state and invoke reconciliation with the same identity.
      return { state: 'reconciling', operation_id: envelope.action_id, reason: 'github_write_outcome_ambiguous' };
    }
    throw externalError('Failed to create atomic remediation commit', error);
  }
}

async function reconcileRemediationAction(payload) {
  const envelope = validateActionEnvelope(payload);
  const expectedTree = validateSha(payload.verified_tree_oid, 'verified_tree_oid');
  try {
    // Reconciliation is read-only. It remains available after a user loses write
    // access so the control plane can truthfully settle an in-flight action.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    const pull = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
    if (pull.data?.base?.sha !== envelope.base_sha || pull.data?.base?.ref === undefined || pull.data?.head?.repo?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()) {
      throw new OperationError('Pull request no longer matches the remediation scope', 409);
    }
    const commits = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/commits?sha=${encodeURIComponent(pull.data.head.ref)}&per_page=100`, token);
    if (!Array.isArray(commits.data)) throw new OperationError('Invalid commit reconciliation response', 502);
    const marker = remediationMarker(envelope.action_id, envelope.manifest_digest);
    const found = commits.data.find((commit) => commit.commit?.message?.includes(marker)
      && commit.parents?.[0]?.sha === envelope.head_sha);
    if (found) {
      const detail = await githubRequest('get',
        `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/git/commits/${encodeURIComponent(found.sha)}`, token);
      if (detail.data?.tree?.sha !== expectedTree) {
        throw new OperationError('Found remediation marker with a non-verified tree', 409, { commit_sha: found.sha });
      }
      return { state: 'applied', operation_id: envelope.action_id, commit_sha: found.sha, tree_oid: expectedTree };
    }
    if (pull.data?.head?.sha === envelope.head_sha) return { state: 'not_applied', operation_id: envelope.action_id };
    return { state: 'unresolved', operation_id: envelope.action_id, reason: 'head_changed_without_matching_marker' };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to reconcile remediation action', error);
  }
}

// Merge capability is evaluated once and reported two ways. `assertMergeCapability`
// stops at the first blocker so a guarded merge never issues avoidable GitHub reads,
// while `readMergeEligibility` gathers every blocker for a pre-flight report.
const MERGE_BLOCKERS = {
  ruleset_capability_unavailable: { status: 422, message: 'Repository ruleset capability is unavailable; automatic merge is disabled' },
  ruleset_response_unknown: { status: 422, message: 'Repository ruleset response is unknown; automatic merge is disabled' },
  merge_queue_unsupported: { status: 422, message: 'Merge queue repositories are unsupported for automatic merge in this release' },
  ruleset_rule_unsupported: { status: 422, message: 'The branch ruleset contains a rule this release does not model; automatic merge is disabled' },
  app_bypass_forbidden: { status: 422, message: 'The remediation app must not be a ruleset bypass actor' },
  branch_protection_unavailable: { status: 422, message: 'Branch protection capability is unavailable; automatic merge is disabled' },
  app_bypasses_required_reviews: { status: 422, message: 'The remediation app must not bypass required reviews' },
  verification_check_not_required: { status: 422, message: 'The app-specific remediation verification check is not required by branch protection or a ruleset' },
  policy_requires_review: { status: 422, message: 'Remediation policy requires at least one approving review; the branch configures none' },
  review_response_invalid: { status: 502, message: 'Invalid pull request review response' },
  review_pagination_exceeded: { status: 422, message: 'Review pagination exceeds supported limit' },
  required_approvals_missing: { status: 409, message: 'Required pull request approvals are not currently satisfied' },
  changes_requested: { status: 409, message: 'Outstanding review requests changes' },
  check_state_incomplete: { status: 409, message: 'Required check state is incomplete' },
  check_state_unavailable: { status: 409, message: 'Required check state could not be read; automatic merge is disabled' },
  review_state_unavailable: { status: 409, message: 'Pull request reviews could not be read; automatic merge is disabled' },
  verification_check_not_successful: { status: 409, message: 'Current remediation verification check is missing or not successful' },
  protection_source_unknown: { status: 422, message: 'Branch protection source is unknown; automatic merge is disabled' },
  base_branch_unknown: { status: 409, message: 'Pull request base branch is unknown' },
  pull_request_not_open: { status: 409, message: 'Pull request is not open' },
  pull_request_draft: { status: 409, message: 'Pull request is a draft' },
  pull_request_already_merged: { status: 409, message: 'Pull request is already merged' },
  pull_request_head_changed: { status: 409, message: 'Pull request head does not match the consented revision' },
  pull_request_base_changed: { status: 409, message: 'Pull request base does not match the consented revision' },
  fork_pull_request_unsupported: { status: 422, message: 'Fork pull requests are unsupported for automated remediation' },
  pull_request_not_mergeable: { status: 409, message: 'Pull request is not currently mergeable' },
};

class BlockerSignal extends Error {
  constructor(report) {
    super('Merge capability blocked');
    this.report = report;
  }
}

function createMergeReport(mergeableState) {
  return {
    eligible: false,
    blockers: [],
    required_checks: [],
    check_runs: [],
    reviews: { required: null, approvals: 0, changes_requested: false },
    protection_source: 'unknown',
    mergeable_state: mergeableState || 'unknown',
    failure: null,
  };
}

// An unmodelled ruleset rule blocks under a code that names the rule, so the report says
// which rule stopped the merge while still resolving to a stable message.
function mergeBlockerEntry(code) {
  if (MERGE_BLOCKERS[code]) return MERGE_BLOCKERS[code];
  if (code.startsWith('ruleset_rule_unsupported_')) return MERGE_BLOCKERS.ruleset_rule_unsupported;
  return { status: 422, message: code };
}

function addMergeBlocker(report, code, stopOnFirstBlocker, detail) {
  const entry = mergeBlockerEntry(code);
  if (!report.blockers.includes(code)) report.blockers.push(code);
  if (!report.failure) report.failure = new OperationError(entry.message, entry.status, detail === undefined ? null : detail);
  if (stopOnFirstBlocker) throw new BlockerSignal(report);
}

// Rules that cannot change who may merge a pull request or on what evidence.
const MERGE_IRRELEVANT_RULE_TYPES = new Set(['deletion', 'non_fast_forward', 'creation', 'update']);

// Derive merge requirements from the rules GitHub says apply to the base branch.
// Anything this release does not model blocks, so a new rule type never merges by silence.
function deriveRulesetRequirements(ruleList, appId, verificationCheckName) {
  const result = {
    blockers: [], detail: {}, required_checks: [], required_reviews: null,
    requires_verification_check: false, require_code_owner_review: false, dismiss_stale_reviews: false,
  };
  const addBlocker = (code, detail) => {
    if (!result.blockers.includes(code)) result.blockers.push(code);
    if (detail !== undefined && result.detail[code] === undefined) result.detail[code] = detail;
  };
  for (const rule of ruleList) {
    const type = typeof rule?.type === 'string' ? rule.type : '';
    // Bypass actors are only present on detailed rule payloads. Where GitHub does report
    // them, an app-level bypass for this app defeats the gate and must block.
    const bypassActors = Array.isArray(rule?.bypass_actors) ? rule.bypass_actors : [];
    if (Number.isInteger(appId) && bypassActors.some((actor) => String(actor?.actor_type) === 'Integration'
      && Number(actor?.actor_id) === appId)) {
      addBlocker('app_bypass_forbidden', { rule_type: type });
    }
    if (MERGE_IRRELEVANT_RULE_TYPES.has(type)) continue;
    if (type === 'merge_queue') {
      addBlocker('merge_queue_unsupported', { rule_type: type });
      continue;
    }
    if (type === 'required_status_checks') {
      const required = Array.isArray(rule?.parameters?.required_status_checks) ? rule.parameters.required_status_checks : [];
      for (const check of required) {
        const context = String(check?.context || '');
        const integrationId = check?.integration_id === null || check?.integration_id === undefined
          ? null : Number(check.integration_id);
        result.required_checks.push({ context, app_id: Number.isInteger(integrationId) ? integrationId : 0 });
        // An unbound context is satisfied by any app, including this one, so it still counts.
        if (context === verificationCheckName && (integrationId === null || (Number.isInteger(appId) && integrationId === appId))) {
          result.requires_verification_check = true;
        }
      }
      continue;
    }
    if (type === 'pull_request') {
      const count = Number(rule?.parameters?.required_approving_review_count);
      result.required_reviews = Math.max(result.required_reviews ?? 0, Number.isFinite(count) ? count : 0);
      // Stale dismissal is enforced by GitHub before merge; approvals are read live here.
      if (rule?.parameters?.dismiss_stale_reviews_on_push === true) result.dismiss_stale_reviews = true;
      if (rule?.parameters?.require_code_owner_review === true) result.require_code_owner_review = true;
      continue;
    }
    addBlocker(`ruleset_rule_unsupported_${type || 'unknown'}`, { rule_type: type });
  }
  return result;
}

// Whether remediation policy insists on a human approval even where the branch does not.
function mergeRequiresHumanReview() {
  return process.env.REMEDIATION_REQUIRE_HUMAN_REVIEW === 'true';
}

async function evaluateMergeCapability(envelope, pull, token, verificationCheckName, stopOnFirstBlocker) {
  const report = createMergeReport(pull?.mergeable_state);
  const block = (code, detail) => addMergeBlocker(report, code, stopOnFirstBlocker, detail);
  const baseRef = pull?.base?.ref;
  if (!baseRef) {
    block('base_branch_unknown');
    return report;
  }

  const appId = Number(process.env.GITHUB_APP_ID);

  let rules = null;
  try {
    rules = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/rules/branches/${encodeURIComponent(baseRef)}`, token);
  } catch (error) {
    block('ruleset_capability_unavailable', error.response?.data || error.message);
  }
  if (rules && !Array.isArray(rules.data)) block('ruleset_response_unknown');
  const ruleList = Array.isArray(rules?.data) ? rules.data : [];
  const ruleset = ruleList.length > 0 ? deriveRulesetRequirements(ruleList, appId, verificationCheckName) : null;
  if (ruleset) {
    report.protection_source = 'rulesets';
    for (const code of ruleset.blockers) block(code, ruleset.detail[code]);
    report.required_checks = ruleset.required_checks;
  }

  let protection = null;
  let protectionAbsent = false;
  try {
    protection = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/branches/${encodeURIComponent(baseRef)}/protection`, token);
  } catch (error) {
    // A ruleset-governed branch commonly has no classic protection at all (404), and an
    // installation without repository administration cannot read the legacy endpoint at
    // all (403). Neither is an outage, and the ruleset already states the requirements in
    // full, so they only block when no ruleset governs the branch either.
    const status = Number(error.response?.status);
    protectionAbsent = status === 404 || status === 403;
    if (!ruleset || !protectionAbsent) block('branch_protection_unavailable', error.response?.data || error.message);
  }
  const checks = protection?.data?.required_status_checks?.checks;
  const bypassApps = protection?.data?.required_pull_request_reviews?.bypass_pull_request_allowances?.apps || [];
  if (Array.isArray(checks)) {
    const classicChecks = checks.map((check) => ({ context: String(check.context || ''), app_id: Number(check.app_id || 0) }));
    // Both sources are reported, and where both exist the branch really does require both.
    const seen = new Set(report.required_checks.map((check) => `${check.context}:${check.app_id}`));
    report.required_checks = [...report.required_checks,
      ...classicChecks.filter((check) => !seen.has(`${check.context}:${check.app_id}`))];
  }
  // Classic protection only names the source when the ruleset read itself succeeded;
  // an unreadable ruleset endpoint leaves the true configuration unknown.
  if (Array.isArray(rules?.data) && protection) {
    report.protection_source = ruleset ? 'rulesets+branch_protection' : 'branch_protection';
  }
  if (report.protection_source === 'unknown') block('protection_source_unknown');
  if (bypassApps.some(app => Number(app.id) === appId)) block('app_bypasses_required_reviews');
  const classicRequiresVerification = Number.isInteger(appId) && Array.isArray(checks)
    && checks.some((check) => check.context === verificationCheckName && Number(check.app_id) === appId);
  if (!classicRequiresVerification && !(ruleset?.requires_verification_check)) block('verification_check_not_required');

  // The stricter of the two sources wins: GitHub enforces every source that applies.
  const classicReviewCount = protection?.data?.required_pull_request_reviews?.required_approving_review_count;
  const configuredCounts = [];
  if (Number.isInteger(classicReviewCount)) configuredCounts.push(classicReviewCount);
  if (ruleset && Number.isInteger(ruleset.required_reviews)) configuredCounts.push(ruleset.required_reviews);
  const reviewsConfigured = configuredCounts.length > 0;
  let reviewCount = reviewsConfigured ? Math.max(...configuredCounts) : 0;
  // A code-owner requirement forces at least one approval even where the count is zero.
  if (ruleset?.require_code_owner_review || protection?.data?.required_pull_request_reviews?.require_code_owner_reviews) {
    reviewCount = Math.max(reviewCount, 1);
  }
  // Remediation policy, not this evaluator, decides whether a human review is mandatory.
  // The plan requires this app's verification check, not a human approval, so a branch that
  // requires no review is eligible unless the deployment opts into requiring one.
  if (!reviewsConfigured && reviewCount < 1 && mergeRequiresHumanReview()) {
    reviewCount = 1;
    block('policy_requires_review');
  }
  report.reviews.required = reviewCount;

  const latestReviewByActor = new Map();
  let reviewsComplete = true;
  for (let page = 1; page <= 10; page += 1) {
    let reviews;
    try {
      reviews = await githubRequest('get',
        `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}/reviews?per_page=100&page=${page}`, token);
    } catch (error) {
      if (stopOnFirstBlocker) throw error;
      reviewsComplete = false;
      block('review_state_unavailable', error.response?.data || error.message);
      break;
    }
    if (!Array.isArray(reviews.data)) {
      reviewsComplete = false;
      block('review_response_invalid');
      break;
    }
    for (const review of reviews.data) {
      // A later COMMENTED review does not dismiss an earlier approval/request.
      if (review.user?.login && ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(review.state)) {
        latestReviewByActor.set(review.user.login, review.state);
      }
    }
    if (page === 10 && reviews.data.length === 100) {
      reviewsComplete = false;
      block('review_pagination_exceeded');
      break;
    }
    if (reviews.data.length < 100) break;
  }
  if (reviewsComplete) {
    const appBotLogin = await githubAppAuth.getAppBotLogin();
    const approvals = [...latestReviewByActor.entries()]
      .filter(([login, state]) => login !== appBotLogin && state === 'APPROVED').length;
    report.reviews.approvals = approvals;
    report.reviews.changes_requested = [...latestReviewByActor.values()].includes('CHANGES_REQUESTED');
    if (reviewCount > 0 && approvals < reviewCount) block('required_approvals_missing');
    if (report.reviews.changes_requested) block('changes_requested');
  }

  let checkRuns = null;
  try {
    checkRuns = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/commits/${encodeURIComponent(envelope.head_sha)}/check-runs?per_page=100`, token);
  } catch (error) {
    if (stopOnFirstBlocker) throw error;
    block('check_state_unavailable', error.response?.data || error.message);
  }
  if (checkRuns) {
    if (!Array.isArray(checkRuns.data?.check_runs) || checkRuns.data.total_count > 100) {
      block('check_state_incomplete');
    } else {
      report.check_runs = checkRuns.data.check_runs.slice(0, 100).map((check) => ({
        id: Number(check.id || 0),
        name: String(check.name || ''),
        app_id: Number(check.app?.id || 0),
        status: String(check.status || ''),
        conclusion: String(check.conclusion || ''),
      }));
      // Only a run published by this app under the protected name counts as verification;
      // a same-named run from another app proves nothing about this remediation.
      const matching = checkRuns.data.check_runs.filter(check => check.name === verificationCheckName && Number(check.app?.id) === appId)
        .sort((a, b) => Number(b.id) - Number(a.id));
      const verified = matching[0]?.status === 'completed' && matching[0]?.conclusion === 'success';
      if (!verified) block('verification_check_not_successful');
    }
  }
  report.eligible = report.blockers.length === 0;
  return report;
}

async function assertMergeCapability(envelope, pull, token, verificationCheckName) {
  let report;
  try {
    report = await evaluateMergeCapability(envelope, pull, token, verificationCheckName, true);
  } catch (error) {
    if (error instanceof BlockerSignal) throw error.report.failure;
    throw error;
  }
  if (report.failure) throw report.failure;
}

async function mergeRemediationAction(payload) {
  const envelope = validateActionEnvelope(payload);
  const expectedHead = validateSha(payload.expected_head_sha, 'expected_head_sha');
  const expectedBase = validateSha(payload.expected_base_sha, 'expected_base_sha');
  const mergeMethod = requireString(payload.merge_method, 'merge_method', 16);
  const verificationCheckName = remediationVerificationCheckName(payload.verification_check_name);
  if (!['merge', 'squash', 'rebase'].includes(mergeMethod)) throw badRequest('Unsupported merge_method');
  if (expectedHead !== envelope.head_sha || expectedBase !== envelope.base_sha) throw new OperationError('Merge revisions do not match the consented action', 409);
  try {
    const token = await assertInstallationRepositoryAndActor(envelope);
    const pull = await loadExactSameRepositoryPull(envelope, token);
    if (pull.mergeable !== true || pull.mergeable_state !== 'clean') {
      throw new OperationError('Pull request is not currently mergeable', 409);
    }
    await assertMergeCapability(envelope, pull, token, verificationCheckName);
    const response = await axios({
      method: 'put',
      url: `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}/merge`,
      data: { sha: expectedHead, merge_method: mergeMethod },
      timeout: 25000,
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
    });
    if (!response.data?.merged || !response.data?.sha) throw new OperationError('GitHub did not merge the expected pull request head', 409, response.data);
    return { state: 'merged', operation_id: envelope.action_id, commit_sha: response.data.sha };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) return { state: 'reconciling', operation_id: envelope.action_id, reason: 'github_merge_outcome_ambiguous' };
    throw externalError('Failed to merge remediation action', error);
  }
}

const DEFAULT_REMEDIATION_CHECK_NAME = 'Mitig8it Remediation Verification';
const CHECK_RUN_STATUSES = ['queued', 'in_progress', 'completed'];
const CHECK_RUN_CONCLUSIONS = ['success', 'failure', 'neutral', 'cancelled', 'timed_out', 'action_required', 'skipped'];

// One source for the remediation verification check name. The publisher and the merge
// gate must agree, otherwise a merge could pass on a check nobody publishes.
function remediationVerificationCheckName(explicit) {
  const name = typeof explicit === 'string' && explicit
    ? explicit
    : (process.env.REMEDIATION_VERIFICATION_CHECK_NAME || DEFAULT_REMEDIATION_CHECK_NAME);
  if (typeof name !== 'string' || !name.trim() || name.length > 100) {
    throw badRequest('verification_check_name is invalid');
  }
  return name;
}

// gRPC leaves an unset int32 at 0, so an absent pull_number is not a mismatch.
function assertPullNumberMatches(payload, envelope) {
  if (!payload.pull_number) return;
  if (Number(payload.pull_number) !== envelope.pr_number) {
    throw new OperationError('pull_number does not match the consented pr_number', 409);
  }
}

// A remediation REST write is issued exactly once. githubRequest retries transient
// failures, which is unsafe when GitHub may already have accepted the mutation.
async function githubRestMutation(method, url, token, data) {
  return axios({
    method,
    url,
    data,
    timeout: 25000,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
}

async function createRemediationCheckRun(payload) {
  const envelope = validateActionEnvelope(payload);
  const name = remediationVerificationCheckName(payload.name);
  const headSha = validateSha(payload.head_sha || envelope.head_sha, 'head_sha');
  if (headSha !== envelope.head_sha) {
    throw new OperationError('Check run head_sha must match the consented head_sha', 409);
  }
  const externalId = requireString(payload.external_id, 'external_id', 255);
  const status = payload.status ? requireString(payload.status, 'status', 32) : 'completed';
  if (!CHECK_RUN_STATUSES.includes(status)) throw badRequest('Unsupported check run status');
  const conclusion = status === 'completed' ? requireString(payload.conclusion, 'conclusion', 32) : null;
  if (conclusion && !CHECK_RUN_CONCLUSIONS.includes(conclusion)) throw badRequest('Unsupported check run conclusion');
  const title = requireString(payload.title, 'title', 255);
  const summary = requireString(payload.summary, 'summary', 65000);

  try {
    // Publishing the verification result is system initiated. It runs after verification
    // completes, when no human actor is present, so actor write permission is not
    // required for this operation; it writes only this app's own check run.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    let existing = null;
    for (let page = 1; page <= 10; page += 1) {
      const response = await githubRequest('get',
        `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/commits/${encodeURIComponent(headSha)}`
        + `/check-runs?check_name=${encodeURIComponent(name)}&per_page=100&page=${page}`, token);
      const checks = response.data?.check_runs;
      if (!Array.isArray(checks)) throw new OperationError('Invalid check run response', 502);
      // Only this app's own run for this external id may be updated; a same-named run
      // owned by another app belongs to that app.
      existing = checks.find(check => check.head_sha === headSha && check.name === name
        && String(check.app?.id) === String(process.env.GITHUB_APP_ID)
        && check.external_id === externalId) || null;
      if (existing || checks.length < 100) break;
    }
    const body = { name, head_sha: headSha, status, external_id: externalId, output: { title, summary } };
    if (conclusion) body.conclusion = conclusion;
    const response = await githubRestMutation(
      existing ? 'patch' : 'post',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/check-runs${existing ? `/${existing.id}` : ''}`,
      token,
      body
    );
    if (!response.data?.id) throw new OperationError('GitHub did not return the published check run', 502);
    return {
      state: 'published',
      operation_id: envelope.action_id,
      check_run_id: Number(response.data.id),
      name,
      external_id: externalId,
      updated: Boolean(existing),
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) {
      return { state: 'reconciling', operation_id: envelope.action_id, reason: 'github_check_run_outcome_ambiguous' };
    }
    throw externalError('Failed to publish the remediation verification check run', error);
  }
}

function residualReportMarker(externalId) {
  return `<!-- mitig8it-remediation-report:${externalId} -->`;
}

// One residual report comment per action. The marker identifies this app's own comment
// for the external id, which is updated in place; another author's comment carrying
// the same text is never edited. It reuses the summary comment publisher.
async function publishRemediationComment(payload) {
  const envelope = validateActionEnvelope(payload);
  const externalId = requireString(payload.external_id, 'external_id', 255);
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,254}$/.test(externalId)) throw badRequest('Invalid external_id');
  const text = requireString(payload.body, 'body', 65000);
  const marker = residualReportMarker(externalId);
  const body = `${marker}\n${text}`;
  const commentService = require('./githubCommentService');

  try {
    // Publishing the report is system initiated, after verification completes, so actor
    // write permission is not required; the app writes only its own comment.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    const botLogin = await githubAppAuth.getAppBotLogin();
    let existing = null;
    for (let page = 1; page <= 10; page += 1) {
      const comments = await commentService.listSummaryComments(envelope.owner, envelope.repo, envelope.pr_number, token, page);
      existing = comments.find((comment) => typeof comment?.body === 'string' && comment.body.startsWith(marker)
        && (!botLogin || comment.user?.login === botLogin)) || null;
      if (existing || comments.length < 100) break;
    }
    const response = existing
      ? await commentService.updateSummaryComment(envelope.owner, envelope.repo, existing.id, body, token)
      : await commentService.postSummaryComment(envelope.owner, envelope.repo, envelope.pr_number, body, token);
    if (!response?.id) throw new OperationError('GitHub did not return the published comment', 502);
    return {
      state: 'published',
      operation_id: envelope.action_id,
      comment_id: Number(response.id),
      external_id: externalId,
      updated: Boolean(existing),
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) {
      return { state: 'reconciling', operation_id: envelope.action_id, reason: 'github_comment_outcome_ambiguous' };
    }
    throw externalError('Failed to publish the remediation report comment', error);
  }
}

// --- Verified fix sections under inline finding comments -------------------------

const FIX_SECTION_LIMIT = 200;
const FIX_LINE_LIMIT = 400;

function findingMarker(fingerprint) { return `<!-- mitig8it-finding:${fingerprint} -->`; }
function fixMarker(candidateId) { return `<!-- mitig8it-fix:${candidateId} -->`; }
function fixEndMarker(candidateId) { return `<!-- /mitig8it-fix:${candidateId} -->`; }
const FIX_BLOCK_PATTERN = /\n*<!-- mitig8it-fix:[^>]+ -->[\s\S]*?<!-- \/mitig8it-fix:[^>]+ -->/g;

function stripFixBlocks(body) { return String(body || '').replace(FIX_BLOCK_PATTERN, '').replace(/\s+$/, ''); }

// The fix blocks of an existing comment, trimmed of the blank lines the pattern eats
// around them, in the order they appear.
function extractFixBlocks(body) {
  const matches = String(body || '').match(FIX_BLOCK_PATTERN) || [];
  return matches.map((block) => block.replace(/^\n+/, '')).filter(Boolean);
}

// A freshly rendered finding comment plus the fix sections the old comment already
// carried. Used when an analysis re-publishes a finding comment it published before:
// the finding text is replaced, the verified fixes underneath are kept as they were.
function withPreservedFixBlocks(nextBody, existingBody) {
  const preserved = extractFixBlocks(existingBody);
  if (!preserved.length) return nextBody;
  return `${stripFixBlocks(nextBody)}\n\n${preserved.join('\n\n')}`;
}

function safeMarkerText(value, name, maxLength) {
  const text = requireString(value, name, maxLength);
  if (/[<>]|--/.test(text)) throw badRequest(`${name} contains characters that are not allowed`);
  return text;
}

function validateFixSection(raw, index) {
  if (!raw || typeof raw !== 'object') throw badRequest(`sections[${index}] must be an object`);
  const skipped = typeof raw.skipped_reason === 'string' && raw.skipped_reason ? raw.skipped_reason.slice(0, 500) : '';
  const section = {
    finding_fingerprint: safeMarkerText(raw.finding_fingerprint, `sections[${index}].finding_fingerprint`, 255),
    candidate_id: skipped && !raw.candidate_id ? '' : safeMarkerText(raw.candidate_id, `sections[${index}].candidate_id`, 128),
    path: typeof raw.path === 'string' ? raw.path.slice(0, 1024) : '',
    finding_line: Number.isInteger(Number(raw.finding_line)) ? Number(raw.finding_line) : 0,
    hunk: null,
    unified_diff: typeof raw.unified_diff === 'string' ? raw.unified_diff.slice(0, 20000) : '',
    not_suggestable_reason: typeof raw.not_suggestable_reason === 'string' ? raw.not_suggestable_reason : '',
    behavior_preserved: typeof raw.behavior_preserved === 'string' ? raw.behavior_preserved.slice(0, 2000) : '',
    evidence: Array.isArray(raw.evidence) ? raw.evidence.filter((item) => typeof item === 'string').slice(0, 20) : [],
    limitations: Array.isArray(raw.limitations) ? raw.limitations.filter((item) => typeof item === 'string').slice(0, 40) : [],
    verification_level: typeof raw.verification_level === 'string' ? raw.verification_level : '',
    skipped_reason: skipped,
  };
  const hunk = raw.hunk;
  if (hunk && typeof hunk === 'object' && Number.isInteger(Number(hunk.start_line)) && Number(hunk.start_line) > 0
    && Number.isInteger(Number(hunk.end_line)) && Number(hunk.end_line) >= Number(hunk.start_line)
    && Array.isArray(hunk.replacement_lines) && hunk.replacement_lines.length <= FIX_LINE_LIMIT
    && hunk.replacement_lines.every((line) => typeof line === 'string')) {
    section.hunk = {
      start_line: Number(hunk.start_line), end_line: Number(hunk.end_line),
      original_lines: Array.isArray(hunk.original_lines) ? hunk.original_lines.filter((line) => typeof line === 'string') : [],
      replacement_lines: hunk.replacement_lines,
    };
  }
  return section;
}

const NOT_SUGGESTABLE_TEXT = {
  multiple_regions: 'the fix changes several separate regions of the file',
  multiple_files: 'the verified fix changes more than one file',
  changes_other_file: 'the verified fix changes a different file than this finding',
  no_line_change: 'the fix cannot be expressed as a line replacement',
  comment_outdated: "this comment's line is no longer part of the pull request diff",
  contains_code_fence: 'the fixed lines contain a code fence, which a suggestion cannot carry',
  file_unavailable: 'the file could not be read at the pull request head',
};

// A suggestion replaces exactly the lines the comment is anchored to. The hunk must lie
// inside that range; when it is smaller, the surrounding lines come from the file at
// the pull request head, so the suggestion reproduces the verified content.
async function suggestionFor(section, comment, readFileLines) {
  const hunk = section.hunk;
  if (!hunk) return { ok: false, reason: NOT_SUGGESTABLE_TEXT[section.not_suggestable_reason] || NOT_SUGGESTABLE_TEXT.no_line_change };
  const commentEnd = Number(comment.line);
  if (!Number.isInteger(commentEnd) || commentEnd < 1 || (comment.side && comment.side !== 'RIGHT')) {
    return { ok: false, reason: NOT_SUGGESTABLE_TEXT.comment_outdated };
  }
  const commentStart = Number.isInteger(Number(comment.start_line)) && Number(comment.start_line) > 0 ? Number(comment.start_line) : commentEnd;
  if (hunk.start_line < commentStart || hunk.end_line > commentEnd) {
    const range = commentStart === commentEnd ? `line ${commentEnd}` : `lines ${commentStart}-${commentEnd}`;
    return { ok: false, reason: `the fix changes lines ${hunk.start_line}-${hunk.end_line}, and this comment can only carry a suggestion for ${range}` };
  }
  let lines = hunk.replacement_lines;
  if (hunk.start_line !== commentStart || hunk.end_line !== commentEnd) {
    const fileLines = await readFileLines(section.path);
    if (!fileLines || fileLines.length < commentEnd) return { ok: false, reason: NOT_SUGGESTABLE_TEXT.file_unavailable };
    lines = [...fileLines.slice(commentStart - 1, hunk.start_line - 1), ...hunk.replacement_lines, ...fileLines.slice(hunk.end_line, commentEnd)];
  }
  if (lines.some((line) => line.includes('```'))) return { ok: false, reason: NOT_SUGGESTABLE_TEXT.contains_code_fence };
  return { ok: true, lines };
}

function fixHeading(section) {
  const level = section.verification_level || '';
  const wording = level === 'independent_sandbox' ? 'verified in an isolated sandbox' : 'verified in a development sandbox';
  return `**Recommended fix (${wording})**`;
}

function diffFence(diff) {
  const fence = diff.includes('```') ? '~~~' : '```';
  return `${fence}diff\n${diff.replace(/\s+$/, '')}\n${fence}`;
}

function buildFixSection(section, suggestion, previewUrl) {
  const lines = [fixMarker(section.candidate_id), '---', fixHeading(section), ''];
  if (suggestion.ok) {
    lines.push('```suggestion', ...suggestion.lines, '```');
  } else {
    lines.push(`This fix cannot be offered as a GitHub suggestion because ${suggestion.reason}. The verified change is:`, '');
    lines.push(section.unified_diff ? diffFence(section.unified_diff) : '_(no diff available)_');
  }
  lines.push('');
  if (section.behavior_preserved) lines.push(`**Behavior preserved:** ${section.behavior_preserved}`);
  lines.push(`**Evidence:** ${section.evidence.length ? section.evidence.join(' ') : 'verification passed in the sandbox.'}`);
  lines.push(`**Coverage limitations:** ${section.limitations.length ? section.limitations.join('; ') : 'none reported.'}`);
  lines.push('');
  const preview = previewUrl ? ` or use Apply this fix in [Mitig8it](${previewUrl})` : '';
  lines.push(`Nothing is applied or merged automatically. Apply this suggestion on GitHub${preview}; either way the change is a normal human push that Mitig8it re-analyses, and merging stays a human action.`);
  lines.push(fixEndMarker(section.candidate_id));
  return lines.join('\n');
}

function buildSkippedSection(section) {
  return [fixMarker('none'), `No automatic fix: ${section.skipped_reason}`, fixEndMarker('none')].join('\n');
}

// Verified fix sections under this app's own inline finding comments. Each finding
// comment is identified by its finding marker; every earlier fix block is replaced by
// the sections of this publication, so a regeneration updates in place and a retry
// with the same input writes nothing. Comments by another author are never edited.
async function publishFindingFixSections(payload) {
  const envelope = validateActionEnvelope(payload);
  if (!Array.isArray(payload.sections) || !payload.sections.length || payload.sections.length > FIX_SECTION_LIMIT) {
    throw badRequest(`sections must contain 1 to ${FIX_SECTION_LIMIT} entries`);
  }
  const sections = payload.sections.map(validateFixSection);
  const previewUrl = typeof payload.preview_url === 'string' && /^https?:\/\//.test(payload.preview_url) && !/[\s()]/.test(payload.preview_url)
    ? payload.preview_url.slice(0, 500) : '';
  try {
    // System initiated after verification: actor write permission is not required
    // because the app edits only its own comments.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    const pull = await githubRequest('get', `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
    if ((pull.data?.head?.sha || '').toLowerCase() !== envelope.head_sha.toLowerCase()) {
      return { state: 'stale', operation_id: envelope.action_id, results: [], reason: 'head_moved' };
    }
    const botLogin = await githubAppAuth.getAppBotLogin();
    const comments = [];
    for (let page = 1; page <= 10; page += 1) {
      const response = await githubRequest('get',
        `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}/comments?per_page=100&page=${page}`, token);
      const batch = Array.isArray(response.data) ? response.data : [];
      comments.push(...batch);
      if (batch.length < 100) break;
    }
    const fileCache = new Map();
    const readFileLines = async (path) => {
      if (!path) return null;
      if (!fileCache.has(path)) {
        try {
          const encodedPath = path.split('/').map(encodeURIComponent).join('/');
          const response = await githubRequest('get',
            `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/contents/${encodedPath}?ref=${encodeURIComponent(envelope.head_sha)}`, token);
          const content = typeof response.data === 'string' ? response.data : Buffer.from(response.data?.content || '', 'base64').toString('utf8');
          fileCache.set(path, content.replace(/\r\n/g, '\n').split('\n'));
        } catch (_) {
          fileCache.set(path, null);
        }
      }
      return fileCache.get(path);
    };
    // Group by finding so one comment receives all of its sections in one write.
    const byFingerprint = new Map();
    for (const section of sections) {
      if (!byFingerprint.has(section.finding_fingerprint)) byFingerprint.set(section.finding_fingerprint, []);
      byFingerprint.get(section.finding_fingerprint).push(section);
    }
    const results = [];
    for (const [fingerprint, group] of byFingerprint) {
      const marker = findingMarker(fingerprint);
      const comment = comments.find((item) => typeof item?.body === 'string' && item.body.includes(marker)
        && (!botLogin || item.user?.login === botLogin)) || null;
      if (!comment) {
        for (const section of group) results.push({ finding_fingerprint: fingerprint, candidate_id: section.candidate_id, comment_id: 0, mode: 'comment_not_found', updated: false, reason: 'no finding comment carries this marker' });
        continue;
      }
      const blocks = [];
      for (const section of group) {
        if (section.skipped_reason) {
          blocks.push(buildSkippedSection(section));
          results.push({ finding_fingerprint: fingerprint, candidate_id: '', comment_id: Number(comment.id), mode: 'skipped', updated: false, reason: section.skipped_reason });
          continue;
        }
        const suggestion = await suggestionFor(section, comment, readFileLines);
        blocks.push(buildFixSection(section, suggestion, previewUrl));
        results.push({ finding_fingerprint: fingerprint, candidate_id: section.candidate_id, comment_id: Number(comment.id), mode: suggestion.ok ? 'suggestion' : 'diff', updated: false, reason: suggestion.ok ? '' : suggestion.reason });
      }
      const body = `${stripFixBlocks(comment.body)}\n\n${blocks.join('\n\n')}`;
      if (body.length > 65000) throw new OperationError('Finding comment would exceed the GitHub comment size limit', 422);
      if (body === comment.body) continue;
      const response = await githubRestMutation('patch',
        `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/comments/${comment.id}`, token, { body });
      if (!response?.data?.id) throw new OperationError('GitHub did not return the updated finding comment', 502);
      for (const result of results) if (result.comment_id === Number(comment.id)) result.updated = true;
    }
    return { state: 'published', operation_id: envelope.action_id, results, reason: '' };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) {
      return { state: 'reconciling', operation_id: envelope.action_id, results: [], reason: 'github_comment_outcome_ambiguous' };
    }
    throw externalError('Failed to publish the verified fix sections', error);
  }
}

async function cancelScheduledMerge(payload) {
  const envelope = validateActionEnvelope(payload);
  assertPullNumberMatches(payload, envelope);
  const expectedHead = validateSha(payload.expected_head_sha || envelope.head_sha, 'expected_head_sha');
  if (expectedHead !== envelope.head_sha) {
    throw new OperationError('expected_head_sha must match the consented head_sha', 409);
  }
  try {
    // Cancelling merge intent stays available after the actor loses write access so a
    // scheduled merge can always be withdrawn. This operation never merges.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    const lookup = await githubGraphqlMutation(token, `query RemediationAutoMerge($owner: String!, $name: String!, $number: Int!) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) { id state merged headRefOid autoMergeRequest { enabledBy { login } } }
      }
    }`, { owner: envelope.owner, name: envelope.repo, number: envelope.pr_number });
    if (lookup.data?.errors?.length) {
      throw new OperationError('GitHub rejected the scheduled merge lookup', 502, lookup.data.errors);
    }
    const pull = lookup.data?.data?.repository?.pullRequest;
    if (!pull?.id) throw new OperationError('Pull request is not accessible for merge cancellation', 404);
    const observedHead = typeof pull.headRefOid === 'string' ? pull.headRefOid : '';
    if (pull.merged) {
      return { state: 'already_merged', operation_id: envelope.action_id, head_sha: observedHead, merged: true };
    }
    if (!pull.autoMergeRequest) {
      return { state: 'not_scheduled', operation_id: envelope.action_id, head_sha: observedHead, merged: false,
        reason: 'auto_merge_not_enabled' };
    }
    const appBotLogin = await githubAppAuth.getAppBotLogin();
    if (pull.autoMergeRequest.enabledBy?.login !== appBotLogin) {
      // Another account scheduled this merge. Disabling it is not this app's decision and
      // reporting it as cancelled would be untrue.
      return { state: 'not_scheduled', operation_id: envelope.action_id, head_sha: observedHead, merged: false,
        reason: 'auto_merge_enabled_by_another_actor' };
    }
    const disabled = await githubGraphqlMutation(token, `mutation DisableRemediationAutoMerge($input: DisablePullRequestAutoMergeInput!) {
      disablePullRequestAutoMerge(input: $input) { pullRequest { id autoMergeRequest { enabledBy { login } } } }
    }`, { input: { pullRequestId: pull.id } });
    if (disabled.data?.errors?.length || !disabled.data?.data?.disablePullRequestAutoMerge?.pullRequest?.id) {
      throw new OperationError('GitHub rejected the scheduled merge cancellation', 409, disabled.data?.errors || null);
    }
    const after = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
    const merged = Boolean(after.data?.merged);
    return {
      state: merged ? 'already_merged' : 'cancelled',
      operation_id: envelope.action_id,
      head_sha: after.data?.head?.sha || observedHead,
      merged,
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    if (isAmbiguousWriteError(error)) {
      return { state: 'reconciling', operation_id: envelope.action_id, reason: 'github_cancel_outcome_ambiguous' };
    }
    throw externalError('Failed to cancel the scheduled merge', error);
  }
}

async function readMergeEligibility(payload) {
  const envelope = validateActionEnvelope(payload);
  assertPullNumberMatches(payload, envelope);
  const expectedHead = validateSha(payload.expected_head_sha || envelope.head_sha, 'expected_head_sha');
  const verificationCheckName = remediationVerificationCheckName(payload.verification_check_name);
  try {
    // Pre-flight eligibility is read only. It reports blockers and never merges, but it
    // still requires the same live actor permission the guarded merge requires so that a
    // caller without write access cannot enumerate protection configuration.
    const token = await assertInstallationRepositoryAndActor(envelope);
    const response = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
    const pull = response.data || {};
    const report = await evaluateMergeCapability(envelope, pull, token, verificationCheckName, false);
    const pullBlockers = [];
    if (pull.state !== 'open') pullBlockers.push('pull_request_not_open');
    if (pull.draft) pullBlockers.push('pull_request_draft');
    if (pull.merged) pullBlockers.push('pull_request_already_merged');
    if (pull.head?.sha !== expectedHead) pullBlockers.push('pull_request_head_changed');
    if (pull.base?.sha !== envelope.base_sha) pullBlockers.push('pull_request_base_changed');
    if (pull.head?.repo?.full_name?.toLowerCase() !== envelope.repository_full_name.toLowerCase()) {
      pullBlockers.push('fork_pull_request_unsupported');
    }
    if (pull.mergeable !== true || pull.mergeable_state !== 'clean') pullBlockers.push('pull_request_not_mergeable');
    const blockers = [...new Set([...pullBlockers, ...report.blockers])];
    return {
      eligible: blockers.length === 0,
      blockers,
      required_checks: report.required_checks,
      check_runs: report.check_runs,
      reviews: report.reviews,
      protection_source: report.protection_source,
      mergeable_state: typeof pull.mergeable_state === 'string' ? pull.mergeable_state : 'unknown',
      head_sha: pull.head?.sha || '',
      base_sha: pull.base?.sha || '',
      verification_check_name: verificationCheckName,
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to read merge eligibility', error);
  }
}

async function readPullRequestHead(payload) {
  const envelope = validateActionEnvelope(payload);
  assertPullNumberMatches(payload, envelope);
  try {
    // Reading current pull request state is used for polling and reconciliation, which
    // must keep working after an actor loses write permission. It never mutates.
    const token = await assertInstallationRepositoryAndActor(envelope, false);
    const response = await githubRequest('get',
      `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}`, token);
    const pull = response.data || {};
    const headRepo = pull.head?.repo?.full_name;
    return {
      head_sha: pull.head?.sha || '',
      base_sha: pull.base?.sha || '',
      state: typeof pull.state === 'string' ? pull.state : 'unknown',
      draft: Boolean(pull.draft),
      merged: Boolean(pull.merged),
      mergeable_state: typeof pull.mergeable_state === 'string' ? pull.mergeable_state : 'unknown',
      // An unreadable head repository is treated as a fork, never as same repository.
      fork: typeof headRepo !== 'string' || headRepo.toLowerCase() !== envelope.repository_full_name.toLowerCase(),
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to read pull request head', error);
  }
}

// Live authorization pre-flight for the control plane's apply route. It proves the
// installation is active, the repository is still granted to it, and the actor holds
// write permission right now. It never mutates anything.
async function authorizeRemediationActor(payload) {
  const envelope = validateActionEnvelope(payload);
  try {
    const token = await assertInstallationRepositoryAndActor(envelope, true);
    const pull = await loadExactSameRepositoryPull(envelope, token);
    return {
      state: 'authorized',
      installation_active: true,
      repository_granted: true,
      actor_write_permission: true,
      head_sha: pull.head.sha,
      base_sha: pull.base.sha,
      head_branch: pull.head.ref,
      base_branch: pull.base.ref,
    };
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw externalError('Failed to authorize remediation actor', error);
  }
}

module.exports = {
  OperationError,
  authorizeRemediationActor,
  cancelScheduledMerge,
  createCheckRun,
  createRemediationCheckRun,
  publishRemediationComment,
  publishFindingFixSections,
  fetchFileContents,
  fetchPullRequestFiles,
  fetchRemediationSnapshot,
  githubRequest,
  commitRemediationAction,
  mergeRemediationAction,
  postInlineComment,
  prepareRemediationAction,
  readMergeEligibility,
  readPullRequestHead,
  reconcileRemediationAction,
  remediationMarker,
  remediationVerificationCheckName,
  submitPullRequestReview,
  withPreservedFixBlocks,
};
