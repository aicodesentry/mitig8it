const { EventEmitter } = require('events');

jest.mock('http', () => ({ request: jest.fn() }));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const http = require('http');
const logger = require('../src/utils/logger');
const { __private } = require('../src/clients/grpcConnection');

const AUDIENCE = 'https://analysis-service.example.run.app';

// A metadata request double: `plan` entries are played in call order.
function programMetadata(plan) {
  http.request.mockImplementation((options, onResponse) => {
    const request = new EventEmitter();
    request.end = () => {
      const step = plan.shift();
      setImmediate(() => {
        if (step.status) {
          const response = new EventEmitter();
          response.statusCode = step.status;
          response.setEncoding = () => {};
          onResponse(response);
          if (step.body) response.emit('data', step.body);
          response.emit('end');
          return;
        }
        if (step.timeout) {
          request.emit('timeout');
          request.emit('error', new Error('Metadata token request timed out'));
          return;
        }
        request.emit('error', Object.assign(new Error(step.message || 'socket error'), { code: step.code }));
      });
    };
    request.destroy = () => {};
    return request;
  });
}

// Token exp is read from the payload; keep fixtures decodable.
function tokenWithExpiry(secondsFromNow) {
  const payload = Buffer.from(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + secondsFromNow }))
    .toString('base64url');
  return `header.${payload}.signature`;
}

let originalBase;
let originalMaxDelay;

beforeAll(() => {
  originalBase = __private.retryPolicy.baseDelayMs;
  originalMaxDelay = __private.retryPolicy.maxDelayMs;
});

afterAll(() => {
  __private.retryPolicy.baseDelayMs = originalBase;
  __private.retryPolicy.maxDelayMs = originalMaxDelay;
});

beforeEach(() => {
  jest.clearAllMocks();
  __private.resetTokenCache();
  // Keep the real backoff shape but compress the wall clock for tests.
  __private.retryPolicy.baseDelayMs = 2;
  __private.retryPolicy.maxDelayMs = 8;
});

describe('metadata identity token retrieval', () => {
  test('retries a timed-out metadata request and then succeeds', async () => {
    const token = tokenWithExpiry(3600);
    programMetadata([{ timeout: true }, { code: 'ECONNRESET' }, { status: 200, body: token }]);

    await expect(__private.getIdentityToken(AUDIENCE)).resolves.toBe(token);
    expect(http.request).toHaveBeenCalledTimes(3);
    expect(http.request.mock.calls[0][0].timeout).toBe(5000);
    expect(logger.warn).toHaveBeenCalledWith(
      'Metadata identity token attempt failed; retrying',
      expect.objectContaining({ attempt: 1 })
    );
  });

  test('stops after the attempt budget and surfaces the last transport failure', async () => {
    programMetadata([{ timeout: true }, { timeout: true }, { timeout: true }, { timeout: true }]);

    await expect(__private.getIdentityToken(AUDIENCE)).rejects.toThrow('Metadata token request timed out');
    expect(http.request).toHaveBeenCalledTimes(4);
  });

  test('does not retry a 4xx metadata rejection', async () => {
    programMetadata([{ status: 403, body: 'forbidden' }]);

    await expect(__private.getIdentityToken(AUDIENCE)).rejects.toThrow('Metadata token request failed with 403');
    expect(http.request).toHaveBeenCalledTimes(1);
  });

  test('retries a 5xx metadata rejection', async () => {
    const token = tokenWithExpiry(3600);
    programMetadata([{ status: 503, body: 'unavailable' }, { status: 200, body: token }]);

    await expect(__private.getIdentityToken(AUDIENCE)).resolves.toBe(token);
    expect(http.request).toHaveBeenCalledTimes(2);
  });

  test('serves a recently expired cached token once when the refresh fails', async () => {
    const cachedToken = tokenWithExpiry(-30);
    __private.seedTokenCache(AUDIENCE, { token: cachedToken, expiresAt: Date.now() - 30_000 });
    programMetadata([{ timeout: true }, { timeout: true }, { timeout: true }, { timeout: true }]);

    await expect(__private.getIdentityToken(AUDIENCE)).resolves.toBe(cachedToken);
    expect(logger.warn).toHaveBeenCalledWith(
      'Metadata identity token refresh failed; using cached token once',
      expect.objectContaining({ audience: AUDIENCE })
    );

    // The fallback is spent: a second failing refresh must not reuse the token.
    programMetadata([{ timeout: true }, { timeout: true }, { timeout: true }, { timeout: true }]);
    await expect(__private.getIdentityToken(AUDIENCE)).rejects.toThrow('Metadata token request timed out');
  });

  test('does not serve a cached token expired beyond the stale grace window', async () => {
    __private.seedTokenCache(AUDIENCE, {
      token: tokenWithExpiry(-600),
      expiresAt: Date.now() - 6 * 60 * 1000,
    });
    programMetadata([{ status: 500 }, { status: 500 }, { status: 500 }, { status: 500 }]);

    await expect(__private.getIdentityToken(AUDIENCE)).rejects.toThrow('Metadata token request failed with 500');
  });

  test('uses a cached token inside the early-refresh margin without contacting the metadata server', async () => {
    const cachedToken = tokenWithExpiry(3600);
    __private.seedTokenCache(AUDIENCE, { token: cachedToken, expiresAt: Date.now() + 3600_000 });

    await expect(__private.getIdentityToken(AUDIENCE)).resolves.toBe(cachedToken);
    expect(http.request).not.toHaveBeenCalled();
  });

  test('shares one in-flight fetch across concurrent calls for the same audience', async () => {
    const token = tokenWithExpiry(3600);
    programMetadata([{ status: 200, body: token }]);

    const results = await Promise.all([
      __private.getIdentityToken(AUDIENCE),
      __private.getIdentityToken(AUDIENCE),
      __private.getIdentityToken(AUDIENCE),
    ]);

    expect(results).toEqual([token, token, token]);
    expect(http.request).toHaveBeenCalledTimes(1);
  });

  test('single flight does not merge distinct audiences', async () => {
    const first = tokenWithExpiry(3600);
    const second = tokenWithExpiry(3600).replace('signature', 'signature2');
    programMetadata([{ status: 200, body: first }, { status: 200, body: second }]);

    const [a, b] = await Promise.all([
      __private.getIdentityToken(AUDIENCE),
      __private.getIdentityToken('https://github-service.example.run.app'),
    ]);

    expect(a).toBe(first);
    expect(b).toBe(second);
    expect(http.request).toHaveBeenCalledTimes(2);
  });

  test('a failed shared fetch is not cached as the in-flight result', async () => {
    programMetadata([{ status: 401 }, { status: 200, body: tokenWithExpiry(3600) }]);

    await expect(__private.getIdentityToken(AUDIENCE)).rejects.toThrow('Metadata token request failed with 401');
    await expect(__private.getIdentityToken(AUDIENCE)).resolves.toMatch(/^header\./);
    expect(http.request).toHaveBeenCalledTimes(2);
  });
});
