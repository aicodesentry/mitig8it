const grpc = require('@grpc/grpc-js');
const http = require('http');
const logger = require('../utils/logger');

const tokenCache = new Map();

function normalizeGrpcTarget(rawTarget, fallbackTarget) {
  const value = rawTarget || fallbackTarget;
  if (!value) {
    return '';
  }

  if (value.startsWith('http://') || value.startsWith('https://')) {
    const url = new URL(value);
    return url.port ? url.host : `${url.hostname}:443`;
  }

  if (process.env.GRPC_TRANSPORT_TLS === 'true' && !value.includes(':')) {
    return `${value}:443`;
  }

  return value;
}

function normalizeAudience(rawAudience, rawTarget) {
  if (rawAudience) {
    return rawAudience.replace(/\/+$/, '');
  }
  if (rawTarget && rawTarget.startsWith('https://')) {
    return rawTarget.replace(/\/+$/, '');
  }
  return '';
}

function shouldUseTls(rawTarget, target) {
  return (
    process.env.GRPC_TRANSPORT_TLS === 'true' ||
    (rawTarget || '').startsWith('https://') ||
    target.endsWith(':443')
  );
}

function decodeJwtExpiry(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return Number(payload.exp || 0) * 1000;
  } catch (_error) {
    return Date.now() + 45 * 60 * 1000;
  }
}

// Metadata server hiccups are common on Cloud Run cold paths. A single short
// attempt turned one slow metadata response into a terminally failed analysis.
const retryPolicy = {
  maxAttempts: 4,
  baseDelayMs: 250,
  maxDelayMs: 2000,
  requestTimeoutMs: 5000,
  // Cloud Run accepts an identity token until its exp, so a token only marginally
  // past the early-refresh margin is still worth one last use.
  staleGraceMs: 5 * 60 * 1000,
  refreshMarginMs: 60_000,
};

const inFlightFetches = new Map();

function isRetryableMetadataError(error) {
  if (!error) return false;
  if (Number.isInteger(error.statusCode)) {
    // A 4xx means the request itself is wrong; repeating it cannot help.
    return error.statusCode >= 500;
  }
  // Timeouts, ECONNRESET and other transport faults are worth another attempt.
  return true;
}

function backoffDelayMs(attempt) {
  const exponential = Math.min(
    retryPolicy.maxDelayMs,
    retryPolicy.baseDelayMs * 2 ** (attempt - 1)
  );
  // Full jitter keeps concurrent instances from retrying in lockstep.
  return Math.round(exponential * (0.5 + Math.random() * 0.5));
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function requestMetadataIdentityToken(audience) {
  const path = `/computeMetadata/v1/instance/service-accounts/default/identity?audience=${encodeURIComponent(audience)}`;

  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        hostname: 'metadata.google.internal',
        path,
        headers: { 'Metadata-Flavor': 'Google' },
        timeout: retryPolicy.requestTimeoutMs,
      },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          body += chunk;
        });
        response.on('end', () => {
          if (response.statusCode >= 200 && response.statusCode < 300) {
            resolve(body);
            return;
          }
          const error = new Error(`Metadata token request failed with ${response.statusCode}`);
          error.statusCode = response.statusCode;
          reject(error);
        });
      }
    );

    request.on('timeout', () => {
      request.destroy(new Error('Metadata token request timed out'));
    });
    request.on('error', reject);
    request.end();
  });
}

async function fetchMetadataIdentityToken(audience) {
  let lastError = null;

  for (let attempt = 1; attempt <= retryPolicy.maxAttempts; attempt += 1) {
    try {
      return await requestMetadataIdentityToken(audience);
    } catch (error) {
      lastError = error;
      if (!isRetryableMetadataError(error) || attempt === retryPolicy.maxAttempts) {
        break;
      }
      logger.warn('Metadata identity token attempt failed; retrying', {
        audience,
        attempt,
        maxAttempts: retryPolicy.maxAttempts,
        error: error.message,
      });
      await sleep(backoffDelayMs(attempt));
    }
  }

  throw lastError;
}

// Concurrent calls for one audience share a single fetch: a metadata server under
// pressure should not be asked the same question by every in-flight RPC.
function fetchIdentityTokenOnce(audience) {
  const existing = inFlightFetches.get(audience);
  if (existing) {
    return existing;
  }

  const pending = fetchMetadataIdentityToken(audience).finally(() => {
    inFlightFetches.delete(audience);
  });
  inFlightFetches.set(audience, pending);
  return pending;
}

async function getIdentityToken(audience) {
  const cached = tokenCache.get(audience);
  if (cached && cached.expiresAt - retryPolicy.refreshMarginMs > Date.now()) {
    return cached.token;
  }

  let token;
  try {
    token = await fetchIdentityTokenOnce(audience);
  } catch (error) {
    // A token barely past the refresh margin still authenticates. Serving it once
    // keeps a metadata blip from failing an analysis that is otherwise healthy.
    if (cached && !cached.staleServed && Date.now() - cached.expiresAt < retryPolicy.staleGraceMs) {
      cached.staleServed = true;
      tokenCache.delete(audience);
      logger.warn('Metadata identity token refresh failed; using cached token once', {
        audience,
        expiredForMs: Math.max(0, Date.now() - cached.expiresAt),
        error: error.message,
      });
      return cached.token;
    }
    throw error;
  }

  tokenCache.set(audience, {
    token,
    expiresAt: decodeJwtExpiry(token),
    staleServed: false,
  });
  return token;
}

function createCloudRunCallCredentials(audience) {
  return grpc.credentials.createFromMetadataGenerator(async (_params, callback) => {
    try {
      const token = await getIdentityToken(audience);
      const metadata = new grpc.Metadata();
      metadata.set('x-serverless-authorization', `Bearer ${token}`);
      callback(null, metadata);
    } catch (error) {
      callback(error);
    }
  });
}

function createChannelCredentials({ rawTarget, target, audience }) {
  if (!shouldUseTls(rawTarget, target)) {
    return grpc.credentials.createInsecure();
  }

  const sslCredentials = grpc.credentials.createSsl();
  if (!audience) {
    return sslCredentials;
  }

  return grpc.credentials.combineChannelCredentials(
    sslCredentials,
    createCloudRunCallCredentials(audience)
  );
}

function createGrpcClientConfig({ target, fallbackTarget, audience }) {
  const normalizedTarget = normalizeGrpcTarget(target, fallbackTarget);
  const normalizedAudience = normalizeAudience(audience, target);
  return {
    target: normalizedTarget,
    credentials: createChannelCredentials({
      rawTarget: target,
      target: normalizedTarget,
      audience: normalizedAudience,
    }),
  };
}

module.exports = {
  createGrpcClientConfig,
  getIdentityToken,
  normalizeAudience,
  normalizeGrpcTarget,
  __private: {
    fetchMetadataIdentityToken,
    getIdentityToken,
    isRetryableMetadataError,
    resetTokenCache: () => {
      tokenCache.clear();
      inFlightFetches.clear();
    },
    retryPolicy,
    seedTokenCache: (audience, entry) => tokenCache.set(audience, { staleServed: false, ...entry }),
  },
};
