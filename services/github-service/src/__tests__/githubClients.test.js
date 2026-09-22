// Reads may be repeated; writes may not. A retried POST after a 502 that GitHub had
// already applied created duplicate review comments, so the reader and the writer
// are separate collaborators with different failure contracts.
jest.mock('axios', () => jest.fn());
jest.mock('../services/githubAppAuth', () => ({
  getInstallationToken: jest.fn().mockResolvedValue('installation-token'),
  getAppBotLogin: jest.fn().mockResolvedValue('fixture[bot]'),
}));

const axios = require('axios');
const operations = require('../services/githubInternalOperations');

const { GitHubReader, GitHubWriter, githubWriter, postInlineComment, submitPullRequestReview, createCheckRun } = operations;
const URL = 'https://api.github.com/repos/owner/repo/pulls/1/comments';

function httpError(status, headers = {}) {
  const error = new Error(`Request failed with status code ${status}`);
  error.response = { status, headers, data: { message: 'x' } };
  return error;
}

function transportError(code) {
  const error = new Error(code);
  error.code = code;
  return error;
}

beforeEach(() => {
  jest.clearAllMocks();
  axios.mockReset();
});

describe('GitHubWriter', () => {
  test('a POST that receives 502 is sent once and yields an ambiguous outcome', async () => {
    axios.mockRejectedValueOnce(httpError(502));
    const result = await githubWriter.request('post', URL, 'token', { body: 'x' });
    expect(result).toMatchObject({ outcome: 'ambiguous', reason: 'github_status_502' });
    expect(axios).toHaveBeenCalledTimes(1);
  });

  test.each(['ECONNABORTED', 'ECONNRESET'])('a write whose response is lost (%s) is ambiguous, not retried', async (code) => {
    axios.mockRejectedValueOnce(transportError(code));
    const result = await githubWriter.request('patch', URL, 'token', { body: 'x' });
    expect(result).toMatchObject({ outcome: 'ambiguous', reason: code });
    expect(axios).toHaveBeenCalledTimes(1);
  });

  test('a write GitHub definitely rejected throws the response error', async () => {
    axios.mockRejectedValueOnce(httpError(422));
    await expect(githubWriter.request('post', URL, 'token', {})).rejects.toMatchObject({ response: { status: 422 } });
    expect(axios).toHaveBeenCalledTimes(1);
  });

  test('a completed write returns the response', async () => {
    axios.mockResolvedValueOnce({ data: { id: 7 } });
    const result = await githubWriter.request('delete', URL, 'token');
    expect(result).toEqual({ outcome: 'completed', response: { data: { id: 7 } } });
    expect(axios.mock.calls[0][0]).toMatchObject({ method: 'delete', url: URL, headers: { Authorization: 'Bearer token' } });
  });

  test('the writer refuses a read and the reader refuses a write', async () => {
    await expect(new GitHubWriter().request('get', URL, 'token')).rejects.toThrow(/refuses GET/);
    await expect(new GitHubReader().request('post', URL, 'token', {})).rejects.toThrow(/refuses POST/);
    expect(axios).not.toHaveBeenCalled();
  });
});

describe('GitHubReader', () => {
  test('a GET honours Retry-After given in seconds', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    const reader = new GitHubReader({ sleep });
    axios.mockRejectedValueOnce(httpError(429, { 'retry-after': '3' })).mockResolvedValueOnce({ data: 'ok' });
    await expect(reader.request('get', URL, 'token')).resolves.toEqual({ data: 'ok' });
    expect(sleep).toHaveBeenCalledWith(3000);
    expect(axios).toHaveBeenCalledTimes(2);
  });

  test('a GET honours Retry-After given as an HTTP date', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    const now = () => Date.parse('Tue, 22 Sep 2026 10:00:00 GMT');
    const reader = new GitHubReader({ sleep, now });
    axios.mockRejectedValueOnce(httpError(503, { 'retry-after': 'Tue, 22 Sep 2026 10:00:05 GMT' })).mockResolvedValueOnce({ data: 'ok' });
    await reader.request('get', URL, 'token');
    expect(sleep).toHaveBeenCalledWith(5000);
  });

  test('a Retry-After longer than the ceiling waits only the ceiling', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    const reader = new GitHubReader({ sleep, maxDelayMs: 60000 });
    axios.mockRejectedValueOnce(httpError(429, { 'retry-after': '3600' })).mockResolvedValueOnce({ data: 'ok' });
    await reader.request('get', URL, 'token');
    expect(sleep).toHaveBeenCalledWith(60000);
  });

  test('a GET without Retry-After backs off exponentially with jitter', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    const reader = new GitHubReader({ sleep, random: () => 0 });
    axios.mockRejectedValueOnce(httpError(502)).mockRejectedValueOnce(httpError(500)).mockResolvedValueOnce({ data: 'ok' });
    await reader.request('get', URL, 'token');
    // random() of 0 lands on the bottom of each window: half the ceiling, doubling per attempt.
    expect(sleep.mock.calls.map(([ms]) => ms)).toEqual([500, 1000]);
    const upper = new GitHubReader({ sleep: jest.fn(), random: () => 1 });
    expect(upper.delayMs(1)).toBe(1000);
    expect(upper.delayMs(3)).toBe(4000);
  });

  test('a GET gives up after the last attempt and surfaces the final error', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    const reader = new GitHubReader({ sleep, maxAttempts: 4 });
    axios.mockRejectedValue(httpError(503));
    await expect(reader.request('get', URL, 'token')).rejects.toMatchObject({ response: { status: 503 } });
    expect(axios).toHaveBeenCalledTimes(4);
    expect(sleep).toHaveBeenCalledTimes(3);
  });

  test('a GET does not retry a definite client error', async () => {
    const sleep = jest.fn();
    const reader = new GitHubReader({ sleep });
    axios.mockRejectedValueOnce(httpError(404));
    await expect(reader.request('get', URL, 'token')).rejects.toMatchObject({ response: { status: 404 } });
    expect(axios).toHaveBeenCalledTimes(1);
    expect(sleep).not.toHaveBeenCalled();
  });
});

describe('analysis writes through the writer', () => {
  const base = { owner: 'owner', repo: 'repo', pr_number: 1, installation_id: 5, commit_sha: 'head-a' };

  test('postInlineComment sends a 502 POST once and reports the ambiguous outcome', async () => {
    axios.mockImplementation(async (request) => {
      if (request.method === 'post') throw httpError(502);
      return { data: { head: { sha: 'head-a' } } };
    });
    await expect(postInlineComment({ ...base, path: 'a.py', line: 3, body: 'finding text' })).rejects.toMatchObject({
      statusCode: 502,
      ambiguous: true,
      detail: { code: 'github_write_outcome_ambiguous', reason: 'github_status_502' },
    });
    expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(1);
  });

  test('submitPullRequestReview sends a timed out review POST once and reports it', async () => {
    axios.mockImplementation(async (request) => {
      if (request.method === 'post') throw transportError('ECONNABORTED');
      if (request.url.includes('/reviews')) return { data: [] };
      return { data: { head: { sha: 'head-a' } } };
    });
    await expect(submitPullRequestReview({ ...base, body: '<!-- mitig8it-review --> run', event: 'COMMENT', comments: [] }))
      .rejects.toMatchObject({ statusCode: 502, detail: { code: 'github_write_outcome_ambiguous', reason: 'ECONNABORTED' } });
    expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(1);
  });

  test('createCheckRun still retries its read and never its write', async () => {
    const sleep = jest.fn().mockResolvedValue(undefined);
    operations.githubReader.sleep = sleep;
    let reads = 0;
    axios.mockImplementation(async (request) => {
      if (request.method === 'get') {
        reads += 1;
        if (reads === 1) throw httpError(502);
        return { data: { check_runs: [] } };
      }
      throw httpError(503);
    });
    await expect(createCheckRun({ owner: 'owner', repo: 'repo', installation_id: 5, head_sha: 'head-a', conclusion: 'success', title: 't', summary: 's' }))
      .rejects.toMatchObject({ statusCode: 502, detail: { code: 'github_write_outcome_ambiguous' } });
    expect(reads).toBe(2);
    expect(axios.mock.calls.filter(([request]) => request.method === 'post')).toHaveLength(1);
  });
});
