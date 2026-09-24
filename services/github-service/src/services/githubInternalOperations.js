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

const GITHUB_TIMEOUT_MS = 25000;
const READ_METHODS = new Set(['get', 'head']);
const RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504]);

function githubHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

// GitHub sends Retry-After either as a delay in seconds or as an HTTP date.
function retryAfterMs(value, now) {
  if (value === undefined || value === null || value === '') return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds)) return Math.max(0, seconds * 1000);
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, at - now);
}

// A read can be repeated freely, so the reader retries a transient failure with
// jittered backoff and honours Retry-After. It refuses mutating methods: a retry of a
// POST after a 502 that GitHub had already applied created duplicate comments.
class GitHubReader {
  constructor({ maxAttempts = 4, baseDelayMs = 1000, maxDelayMs = 60000, sleep, now, random } = {}) {
    this.maxAttempts = maxAttempts;
    this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs;
    this.sleep = sleep || ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.now = now || Date.now;
    this.random = random || Math.random;
  }

  async request(method, url, token, data) {
    const verb = String(method).toLowerCase();
    if (!READ_METHODS.has(verb)) throw new Error(`GitHubReader refuses ${verb.toUpperCase()}; mutations go through GitHubWriter`);
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await axios({ method: verb, url, data, timeout: GITHUB_TIMEOUT_MS, headers: githubHeaders(token) });
      } catch (error) {
        const status = error.response?.status;
        if (!RETRYABLE_STATUSES.has(status) || attempt === this.maxAttempts) throw error;
        await this.sleep(this.delayMs(attempt, error.response?.headers?.['retry-after']));
      }
    }
  }

  delayMs(attempt, retryAfter) {
    const requested = retryAfterMs(retryAfter, this.now());
    if (requested !== null) return Math.min(requested, this.maxDelayMs);
    // Full jitter keeps a burst of readers that failed together from retrying together.
    const ceiling = Math.min(this.baseDelayMs * 2 ** (attempt - 1), this.maxDelayMs);
    return Math.round(ceiling * (0.5 + this.random() * 0.5));
  }
}

// A write is sent exactly once. When the response is lost (timeout, connection error,
// 5xx) GitHub may or may not have applied it, so the writer reports that as an
// ambiguous outcome rather than retrying or failing. The caller decides how to
// reconcile: the remediation writes return `reconciling` to the control plane, and
// the analysis writes report the ambiguity because their next run reads GitHub
// (comment by marker, review by body and commit, check run by name) before writing.
class GitHubWriter {
  async request(method, url, token, data) {
    const verb = String(method).toLowerCase();
    if (READ_METHODS.has(verb)) throw new Error(`GitHubWriter refuses ${verb.toUpperCase()}; reads go through GitHubReader`);
    try {
      const response = await axios({ method: verb, url, data, timeout: GITHUB_TIMEOUT_MS, headers: githubHeaders(token) });
      return { outcome: 'completed', response };
    } catch (error) {
      if (!isAmbiguousWriteError(error)) throw error;
      const status = error.response?.status;
      return { outcome: 'ambiguous', reason: status ? `github_status_${status}` : (error.code || 'no_response'), error };
    }
  }
}

// A response was never received, or GitHub answered after it may already have applied
// the mutation. A 429 is included: GitHub's secondary rate limit can reject a request
// it has partially processed.
function isAmbiguousWriteError(error) {
  const status = error.response?.status;
  return !status || RETRYABLE_STATUSES.has(status);
}

class AmbiguousWriteError extends OperationError {
  constructor(result) {
    super('GitHub write outcome is unknown; reconcile by reading before retrying', 502, {
      code: 'github_write_outcome_ambiguous',
      reason: result.reason,
    });
    this.ambiguous = true;
  }
}

const githubReader = new GitHubReader();
const githubWriter = new GitHubWriter();

// Retained name: every read in this module calls it.
function githubRequest(method, url, token, data) {
  return githubReader.request(method, url, token, data);
}

// The analysis writes. An ambiguous outcome surfaces as an error the route reports,
// never as a retry: the next analysis of the same head reads first, and that read is
// the reconciliation.
async function githubAnalysisWrite(method, url, token, data) {
  const result = await githubWriter.request(method, url, token, data);
  if (result.outcome === 'ambiguous') throw new AmbiguousWriteError(result);
  return result.response;
}

// The analysable files of one pull request that a single run may review. Over the cap
// the run reviews the first FILE_CAP in path order and reports a `file_cap` limitation;
// it never refuses the pull request.
const FILE_CAP = 200;

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
    // A pull request over the cap is reviewed as far as the cap allows rather than
    // refused: a partial review of a large change is worth more than no review at all,
    // and refusing was the one case where a developer got nothing. The selection is
    // sorted by path first so the same pull request always yields the same 200 files,
    // whatever order GitHub's pagination returned them in, and the limitation says
    // plainly how many of how many were reviewed.
    const ordered = [...scoped].sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0));
    const selected = ordered.slice(0, FILE_CAP);
    const limitation = ordered.length > FILE_CAP
      ? { kind: 'file_cap', message: `Reviewed ${FILE_CAP} of ${ordered.length} changed files` }
      : null;
    return {
      files: selected.map((f) => ({
          path: f.filename,
          patch: f.patch || '',
          additions: f.additions,
          deletions: f.deletions,
          status: f.status,
          raw_url: f.raw_url,
        })),
      ...(limitation ? { limitation } : {}),
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
        await githubAnalysisWrite('put',
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

    const response = await githubAnalysisWrite(
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
          if (comment.body !== nextBody) await githubAnalysisWrite('patch',
            `https://api.github.com/repos/${owner}/${repo}/pulls/comments/${comment.id}`, token, { body: nextBody });
          return { comment_id: comment.id, url: comment.html_url, success: true };
        }
        if (existing.data.length < 100) break;
      }
    }
    const response = await createInlineComment({ owner, repo, pr_number, token, commit_sha, path, line, body });

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

// The one write that creates an inline review comment on the head commit. The analysis
// and the verified fix publisher both post through it, so a finding comment created for
// a verified fix has the same shape as one the analysis created. The publisher passes the
// remediation mutation so an ambiguous outcome reaches its own `reconciling` path.
function createInlineComment({ owner, repo, pr_number, token, commit_sha, path, line, start_line, body, request = githubAnalysisWrite }) {
  const range = Number.isInteger(Number(start_line)) && Number(start_line) > 0 && Number(start_line) < Number(line)
    ? { start_line: Number(start_line), start_side: 'RIGHT' } : {};
  return request(
    'post',
    `https://api.github.com/repos/${owner}/${repo}/pulls/${pr_number}/comments`,
    token,
    { body, commit_id: commit_sha, path, line, side: 'RIGHT', ...range }
  );
}

// The new-side line numbers a pull request diff shows for one file: every added and
// context line of every hunk. GitHub accepts an inline comment only on those lines.
function diffLinesOfPatch(patch) {
  const lines = new Set();
  let newLine = 0;
  for (const raw of String(patch || '').split('\n')) {
    if (raw.startsWith('@@')) {
      const match = raw.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      newLine = match ? Number(match[1]) : 0;
      continue;
    }
    if (!newLine || raw.startsWith('-') || raw.startsWith('\\')) continue;
    lines.add(newLine);
    newLine += 1;
  }
  return lines;
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
    const response = await githubAnalysisWrite(
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

const DEFAULT_REMEDIATION_CHECK_NAME = 'Mitig8it Remediation Verification';
const CHECK_RUN_STATUSES = ['queued', 'in_progress', 'completed'];
const CHECK_RUN_CONCLUSIONS = ['success', 'failure', 'neutral', 'cancelled', 'timed_out', 'action_required', 'skipped'];

// One source for the remediation verification check name, so the residual report and
// the check run a repository's branch protection may require agree on one name.
function remediationVerificationCheckName(explicit) {
  const name = typeof explicit === 'string' && explicit
    ? explicit
    : (process.env.REMEDIATION_VERIFICATION_CHECK_NAME || DEFAULT_REMEDIATION_CHECK_NAME);
  if (typeof name !== 'string' || !name.trim() || name.length > 100) {
    throw badRequest('verification_check_name is invalid');
  }
  return name;
}

// The remediation REST writes. The writer sends once; an ambiguous outcome is rethrown
// as the transport error so each operation's catch maps it to `reconciling` for the
// control plane, which owns the durable action identity that reconciliation needs.
async function githubRestMutation(method, url, token, data) {
  const result = await githubWriter.request(method, url, token, data);
  if (result.outcome === 'ambiguous') throw result.error;
  return result.response;
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
// A second inline comment carrying one more region of a finding's fix (an added import, or
// a change away from the finding's line), keyed by the finding and the region's position.
function extraMarker(fingerprint, index) { return `<!-- mitig8it-fix-extra:${fingerprint}:${index} -->`; }
const EXTRA_HUNK_LIMIT = 10;
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

const FINDING_BODY_LIMIT = 30000;

function validateFixSection(raw, index) {
  if (!raw || typeof raw !== 'object') throw badRequest(`sections[${index}] must be an object`);
  const skipped = typeof raw.skipped_reason === 'string' && raw.skipped_reason ? raw.skipped_reason.slice(0, 500) : '';
  const findingIds = Array.isArray(raw.finding_ids)
    ? raw.finding_ids.filter((item) => typeof item === 'string' && item && !/[<>`]|--/.test(item)).map((item) => item.slice(0, 128)).slice(0, 50)
    : [];
  const section = {
    finding_fingerprint: safeMarkerText(raw.finding_fingerprint, `sections[${index}].finding_fingerprint`, 255),
    candidate_id: skipped && !raw.candidate_id ? '' : safeMarkerText(raw.candidate_id, `sections[${index}].candidate_id`, 128),
    path: typeof raw.path === 'string' ? raw.path.slice(0, 1024) : '',
    finding_line: Number.isInteger(Number(raw.finding_line)) ? Number(raw.finding_line) : 0,
    hunk: null,
    unified_diff: typeof raw.unified_diff === 'string' ? raw.unified_diff.slice(0, 20000) : '',
    not_suggestable_reason: typeof raw.not_suggestable_reason === 'string' ? raw.not_suggestable_reason : '',
    stated_intent: typeof raw.stated_intent === 'string' ? raw.stated_intent.slice(0, 2000) : '',
    proof: typeof raw.proof === 'string' ? raw.proof.slice(0, 2000) : '',
    evidence: Array.isArray(raw.evidence) ? raw.evidence.filter((item) => typeof item === 'string').slice(0, 20) : [],
    limitations: Array.isArray(raw.limitations) ? raw.limitations.filter((item) => typeof item === 'string').slice(0, 40) : [],
    verification_level: typeof raw.verification_level === 'string' ? raw.verification_level : '',
    skipped_reason: skipped,
    // The finding comment to create when none carries the marker. It is trimmed of any
    // fix blocks so a stale copy can never smuggle a section past the candidate markers.
    finding_body: typeof raw.finding_body === 'string' ? stripFixBlocks(raw.finding_body.slice(0, FINDING_BODY_LIMIT)) : '',
    finding_ids: findingIds,
    covered_by: typeof raw.covered_by === 'string' ? raw.covered_by.replace(/[<>`]/g, '').slice(0, 300) : '',
  };
  section.hunk = parseHunk(raw.hunk);
  section.extra_hunks = (Array.isArray(raw.extra_hunks) ? raw.extra_hunks : []).map(parseHunk).filter(Boolean).slice(0, EXTRA_HUNK_LIMIT);
  return section;
}

function parseHunk(hunk) {
  if (hunk && typeof hunk === 'object' && Number.isInteger(Number(hunk.start_line)) && Number(hunk.start_line) > 0
    && Number.isInteger(Number(hunk.end_line)) && Number(hunk.end_line) >= Number(hunk.start_line)
    && Array.isArray(hunk.replacement_lines) && hunk.replacement_lines.length <= FIX_LINE_LIMIT
    && hunk.replacement_lines.every((line) => typeof line === 'string')) {
    return {
      start_line: Number(hunk.start_line), end_line: Number(hunk.end_line),
      original_lines: Array.isArray(hunk.original_lines) ? hunk.original_lines.filter((line) => typeof line === 'string') : [],
      replacement_lines: hunk.replacement_lines,
    };
  }
  return null;
}

const NOT_SUGGESTABLE_TEXT = {
  multiple_regions: 'the fix changes several separate regions of the file',
  multiple_files: 'the verified fix changes more than one file',
  changes_other_file: 'the verified fix changes a different file than this finding',
  no_line_change: 'the fix cannot be expressed as a line replacement',
  comment_outdated: "this comment's line is no longer part of the pull request diff",
  contains_code_fence: 'the fixed lines contain a code fence, which a suggestion cannot carry',
  file_unavailable: 'the file could not be read at the pull request head',
  line_outside_diff: "this finding's line is not part of the pull request diff, so GitHub allows neither an inline comment nor a suggestion there",
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

// How each verification level is named to a reader of the pull request. The text says what the
// sandbox actually was, so a reader never has to know the level's internal name, and the
// development level keeps saying it is a development sandbox. An unrecognized level is named
// the most cautious way rather than the most flattering one.
const VERIFICATION_LEVEL_TEXT = {
  independent_sandbox: 'isolated sandbox',
  isolated_job: 'isolated sandbox (Cloud Run job, network denied)',
  development_unverified: 'development sandbox',
};

function verifiedLine(section) {
  const where = VERIFICATION_LEVEL_TEXT[section.verification_level] || VERIFICATION_LEVEL_TEXT.development_unverified;
  return `Verified: regression test failed on the original code and passed with this change (${where}).`;
}

function diffFence(diff) {
  const fence = diff.includes('```') ? '~~~' : '```';
  return `${fence}diff\n${diff.replace(/\s+$/, '')}\n${fence}`;
}

function lineRange(hunk) {
  return hunk.start_line === hunk.end_line ? `line ${hunk.start_line}` : `lines ${hunk.start_line}-${hunk.end_line}`;
}

const IMPORT_LINE = /^\s*(?:import\s+\S|from\s+\S+\s+import\s+\S|(?:const|let|var)\s+.+?=\s*require\()/;

function addedLines(hunk) {
  return hunk.replacement_lines.filter((line) => !hunk.original_lines.includes(line));
}

// A hunk that adds or rewrites nothing but import lines.
function isImportHunk(hunk) {
  const added = addedLines(hunk);
  const removed = hunk.original_lines.filter((line) => !hunk.replacement_lines.includes(line));
  return added.length > 0 && [...added, ...removed].every((line) => !line.trim() || IMPORT_LINE.test(line));
}

// The collapsed details under the suggestion: the model's own claim, then what the sandbox
// run established, labelled apart so neither reads as the other, then the human-in-the-loop
// sentence. Blank lines keep the Markdown rendering inside the HTML block.
function detailsBlock(section, previewUrl) {
  const lines = ['<details>', '<summary>Details</summary>', ''];
  if (section.stated_intent) lines.push(`**Model's stated intent:** ${section.stated_intent}`, '');
  lines.push(`**Proof:** ${section.proof || 'the generated regression test failed on the original code and passed on the fix.'}`, '');
  lines.push(`**Evidence:** ${section.evidence.length ? section.evidence.join(' ') : 'verification passed in the sandbox.'}`, '');
  lines.push(`**Limitations:** ${section.limitations.length ? section.limitations.join('; ') : 'none reported.'}`, '');
  if (section.finding_ids.length > 1) lines.push(`**Findings covered:** ${findingIdList(section)}`, '');
  const preview = previewUrl ? ` or use Apply this fix in [Mitig8it](${previewUrl})` : '';
  lines.push(`Nothing is applied or merged automatically. Apply this suggestion on GitHub${preview}; either way the change is a normal human push that Mitig8it re-analyses, and merging stays a human action.`);
  lines.push('</details>');
  return lines;
}

// The fix section under a finding comment: the suggestion block first (or the diff and one
// line saying why it is not a suggestion), the verified line, any short notes about regions
// suggested elsewhere or folded in, then the collapsed details. No prose above the block.
function buildFixSection(section, plan, previewUrl) {
  const lines = [fixMarker(section.candidate_id)];
  if (plan.suggestion) {
    lines.push('```suggestion', ...plan.suggestion, '```');
  } else if (!plan.extras.length) {
    lines.push(section.unified_diff ? diffFence(section.unified_diff) : '_(no diff available)_');
    lines.push(`Shown as a diff: ${plan.reason}.`);
  }
  lines.push(verifiedLine(section));
  lines.push(...plan.notes);
  lines.push('', ...detailsBlock(section, previewUrl));
  lines.push(fixEndMarker(section.candidate_id));
  return lines.join('\n');
}

// A second inline comment on the lines of one more region of the fix.
function buildExtraComment(section, hunk, index) {
  return [
    extraMarker(section.finding_fingerprint, index),
    fixMarker(section.candidate_id),
    '```suggestion', ...hunk.replacement_lines, '```',
    `Part of the verified fix for \`${section.path}\` line ${section.finding_line}; the finding comment there has the details.`,
    fixEndMarker(section.candidate_id),
  ].join('\n');
}

// Where each region of a section's fix goes: the region on the finding's line is the
// suggestion in the finding comment when the comment can carry it; every other region in
// the diff gets its own comment; an added import outside the diff is folded into a note;
// any other region outside the diff means the fix cannot be a suggestion at all, and the
// finding comment shows the diff with that reason.
async function planSection(section, anchor, placement, readFileLines, diffLinesFor) {
  const plan = { suggestion: null, reason: '', notes: [], extras: [] };
  if (placement !== 'inline') {
    plan.reason = NOT_SUGGESTABLE_TEXT.line_outside_diff;
    return plan;
  }
  const primary = await suggestionFor(section, anchor, readFileLines);
  const diffLines = await diffLinesFor(section.path);
  const inDiff = (hunk) => {
    for (let line = hunk.start_line; line <= hunk.end_line; line += 1) if (!diffLines.has(line)) return false;
    return !hunk.replacement_lines.some((line) => line.includes('```'));
  };
  if (primary.ok) {
    plan.suggestion = primary.lines;
  } else if (section.hunk && inDiff(section.hunk)) {
    plan.extras.push(section.hunk);
    plan.notes.push(`The change is suggested in a separate comment on ${lineRange(section.hunk)}.`);
  } else {
    plan.reason = primary.reason;
    return plan;
  }
  for (const hunk of section.extra_hunks) {
    if (inDiff(hunk)) {
      plan.extras.push(hunk);
    } else if (isImportHunk(hunk)) {
      const added = addedLines(hunk).map((line) => `\`${line.trim()}\``).join(' and ');
      plan.notes.push(`Also add ${added} at ${lineRange(hunk)}, which is outside the pull request diff.`);
    } else {
      return { suggestion: null, reason: `the fix also changes ${lineRange(hunk)}, outside the pull request diff`, notes: [], extras: [] };
    }
  }
  return plan;
}

function findingIdList(section) {
  return section.finding_ids.map((id) => `\`${id}\``).join(', ');
}

function buildSkippedSection(section) {
  return [fixMarker('none'), `No automatic fix: ${section.skipped_reason}`, fixEndMarker('none')].join('\n');
}

// A finding that another finding's verified candidate covers on the same lines: the fix
// is published once, under that finding, and this comment says so instead of claiming
// there is no fix. The candidate marker keeps a regeneration idempotent here too.
function buildCoveredSection(section) {
  const ids = section.finding_ids.length ? ` (findings ${findingIdList(section)})` : '';
  return [
    fixMarker(section.candidate_id),
    `Fixed together with ${section.covered_by}: the verified fix published under that finding on the same lines resolves this finding as well${ids}.`,
    fixEndMarker(section.candidate_id),
  ].join('\n');
}

// The finding comment created when no comment carries the finding's marker: the same
// marker the analysis writes, then the finding text the analysis renders. In a pull
// request comment the header says why the comment is not on the line.
function createdFindingBody(section, placement) {
  const marker = findingMarker(section.finding_fingerprint);
  if (placement === 'inline') return `${marker}\n${section.finding_body}`;
  const location = `\`${section.path}\`${section.finding_line ? ` line ${section.finding_line}` : ''}`;
  return [
    marker,
    `**Verified fix for ${location}.** This line is not part of the pull request diff, so GitHub does not accept an inline comment on it; the finding and its verified fix are reported here instead.`,
    '',
    section.finding_body,
  ].join('\n');
}

// Verified fix sections under this app's own inline finding comments. Each finding
// comment is identified by its finding marker; every earlier fix block is replaced by
// the sections of this publication, so a regeneration updates in place and a retry
// with the same input writes nothing. A finding with no comment of its own gets one
// from the section's finding body: on its line when the diff shows that line, else as
// a pull request comment that says why. Comments by another author are never edited.
async function publishFindingFixSections(payload) {
  const envelope = validateActionEnvelope(payload);
  if (!Array.isArray(payload.sections) || !payload.sections.length || payload.sections.length > FIX_SECTION_LIMIT) {
    throw badRequest(`sections must contain 1 to ${FIX_SECTION_LIMIT} entries`);
  }
  const sections = payload.sections.map(validateFixSection);
  const previewUrl = typeof payload.preview_url === 'string' && /^https?:\/\//.test(payload.preview_url) && !/[\s()]/.test(payload.preview_url)
    ? payload.preview_url.slice(0, 500) : '';
  const commentService = require('./githubCommentService');
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
    // The pull request diff, read once and only when a finding has no comment yet: an
    // inline comment can be created only on a line the diff shows.
    let diffLinesByPath = null;
    const diffLinesFor = async (path) => {
      if (!diffLinesByPath) {
        diffLinesByPath = new Map();
        for (let page = 1; page <= 30; page += 1) {
          const response = await githubRequest('get',
            `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/${envelope.pr_number}/files?per_page=100&page=${page}`, token);
          const batch = Array.isArray(response.data) ? response.data : [];
          for (const file of batch) if (file?.filename) diffLinesByPath.set(file.filename, diffLinesOfPatch(file.patch));
          if (batch.length < 100) break;
        }
      }
      return diffLinesByPath.get(path) || new Set();
    };
    // Pull request comments, read once and only when a finding's line is outside the diff.
    let pullRequestComments = null;
    const pullRequestCommentWith = async (marker) => {
      if (!pullRequestComments) {
        pullRequestComments = [];
        for (let page = 1; page <= 10; page += 1) {
          const batch = await commentService.listSummaryComments(envelope.owner, envelope.repo, envelope.pr_number, token, page);
          pullRequestComments.push(...batch);
          if (batch.length < 100) break;
        }
      }
      return pullRequestComments.find((item) => typeof item?.body === 'string' && item.body.includes(marker)
        && (!botLogin || item.user?.login === botLogin)) || null;
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
      // Where the sections go: the app's own inline comment carrying the marker; else a
      // comment created on the finding's line when the diff shows it; else the app's own
      // pull request comment carrying the marker, created when there is none. Without a
      // finding body nothing can be created, and the sections are reported as unplaced.
      let comment = comments.find((item) => typeof item?.body === 'string' && item.body.includes(marker)
        && (!botLogin || item.user?.login === botLogin)) || null;
      let placement = 'inline';
      const withBody = group.find((section) => section.finding_body) || null;
      if (!comment && withBody) {
        const onDiff = withBody.finding_line > 0 && (await diffLinesFor(withBody.path)).has(withBody.finding_line);
        if (!onDiff) {
          placement = 'pull_request';
          comment = await pullRequestCommentWith(marker);
        }
      }
      if (!comment && !withBody) {
        for (const section of group) results.push({ finding_fingerprint: fingerprint, candidate_id: section.candidate_id, comment_id: 0, mode: 'comment_not_found', updated: false, reason: 'no finding comment carries this marker', created: false, placement: '' });
        continue;
      }
      const anchor = comment || { line: withBody.finding_line, side: 'RIGHT' };
      const blocks = [];
      const groupResults = [];
      const extraPlans = [];
      for (const section of group) {
        const result = { finding_fingerprint: fingerprint, candidate_id: section.candidate_id, comment_id: Number(comment?.id || 0), mode: '', updated: false, reason: '', created: false, placement };
        if (section.skipped_reason) {
          blocks.push(buildSkippedSection(section));
          Object.assign(result, { candidate_id: '', mode: 'skipped', reason: section.skipped_reason });
        } else if (section.covered_by) {
          blocks.push(buildCoveredSection(section));
          Object.assign(result, { mode: 'covered', reason: `fixed together with ${section.covered_by}` });
        } else {
          const plan = await planSection(section, anchor, placement, readFileLines, diffLinesFor);
          blocks.push(buildFixSection(section, plan, previewUrl));
          const suggested = Boolean(plan.suggestion) || plan.extras.length > 0;
          Object.assign(result, { mode: suggested ? 'suggestion' : 'diff', reason: suggested ? '' : plan.reason });
          extraPlans.push({ section, extras: plan.extras });
        }
        groupResults.push(result);
        results.push(result);
      }
      const base = comment ? stripFixBlocks(comment.body) : createdFindingBody(withBody, placement);
      const body = `${base}\n\n${blocks.join('\n\n')}`;
      if (body.length > 65000) throw new OperationError('Finding comment would exceed the GitHub comment size limit', 422);
      if (comment && body === comment.body) continue;
      let response;
      if (!comment && placement === 'inline') {
        response = await createInlineComment({ owner: envelope.owner, repo: envelope.repo, pr_number: envelope.pr_number, token,
          commit_sha: envelope.head_sha, path: withBody.path, line: withBody.finding_line, body, request: githubRestMutation });
      } else if (!comment) {
        response = { data: await commentService.postSummaryComment(envelope.owner, envelope.repo, envelope.pr_number, body, token) };
      } else if (placement === 'inline') {
        response = await githubRestMutation('patch',
          `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/comments/${comment.id}`, token, { body });
      } else {
        response = { data: await commentService.updateSummaryComment(envelope.owner, envelope.repo, comment.id, body, token) };
      }
      if (!response?.data?.id) throw new OperationError(comment ? 'GitHub did not return the updated finding comment' : 'GitHub did not return the created finding comment', 502);
      for (const result of groupResults) {
        result.comment_id = Number(response.data.id);
        result.updated = true;
        result.created = !comment;
      }
      await publishExtraComments(envelope, token, fingerprint, comments, botLogin, extraPlans);
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

// The second inline comments of a finding's fix, one per region placed outside the finding
// comment, each identified by the finding and the region's position: an existing one with
// the same body is left alone, a changed one is updated, a missing one is created on its
// lines, and one a regeneration no longer needs is removed. Comments by another author are
// never touched.
async function publishExtraComments(envelope, token, fingerprint, comments, botLogin, extraPlans) {
  const own = (item) => typeof item?.body === 'string' && (!botLogin || item.user?.login === botLogin);
  const existing = comments.filter((item) => own(item) && item.body.includes(`<!-- mitig8it-fix-extra:${fingerprint}:`));
  let index = 0;
  for (const { section, extras } of extraPlans) {
    for (const hunk of extras) {
      const marker = extraMarker(fingerprint, index);
      const body = buildExtraComment(section, hunk, index);
      index += 1;
      const current = existing.find((item) => item.body.includes(marker));
      if (current && current.body === body) continue;
      if (current) {
        await githubRestMutation('patch', `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/comments/${current.id}`, token, { body });
        continue;
      }
      await createInlineComment({ owner: envelope.owner, repo: envelope.repo, pr_number: envelope.pr_number, token,
        commit_sha: envelope.head_sha, path: section.path, line: hunk.end_line, start_line: hunk.start_line, body, request: githubRestMutation });
    }
  }
  for (const item of existing) {
    const match = item.body.match(/<!-- mitig8it-fix-extra:[^:>]+:(\d+) -->/);
    if (match && Number(match[1]) >= index) {
      await githubRestMutation('delete', `https://api.github.com/repos/${envelope.owner}/${envelope.repo}/pulls/comments/${item.id}`, token);
    }
  }
}

module.exports = {
  AmbiguousWriteError,
  GitHubReader,
  GitHubWriter,
  OperationError,
  createCheckRun,
  createRemediationCheckRun,
  publishRemediationComment,
  publishFindingFixSections,
  fetchFileContents,
  fetchPullRequestFiles,
  fetchRemediationSnapshot,
  githubReader,
  githubRequest,
  githubRestMutation,
  githubWriter,
  postInlineComment,
  remediationVerificationCheckName,
  submitPullRequestReview,
  withPreservedFixBlocks,
};
