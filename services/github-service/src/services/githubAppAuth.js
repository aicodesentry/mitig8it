const axios = require('axios');
const crypto = require('crypto');

// Normalize private key to PEM (handles \n escaped strings and optional base64)
function normalizePrivateKey(rawKey) {
  if (!rawKey) return null;
  let key = rawKey;
  if (!key.includes('BEGIN')) {
    try {
      key = Buffer.from(rawKey, 'base64').toString('utf8');
    } catch (_err) {
      // fall through and use rawKey
      key = rawKey;
    }
  }
  return key.replace(/\\n/g, '\n');
}

function buildAppJWT(appId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iat: now - 60, // backdate to allow minor clock skew
    exp: now + 9 * 60, // GitHub allows up to 10 minutes
    iss: appId,
  };

  const header = { alg: 'RS256', typ: 'JWT' };

  const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const signingInput = `${encode(header)}.${encode(payload)}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  const signature = signer.sign(privateKey, 'base64url');

  return `${signingInput}.${signature}`;
}

async function getInstallationToken(installationIdOverride) {
  const appId = process.env.GITHUB_APP_ID;
  const installationId = installationIdOverride || process.env.GITHUB_APP_INSTALLATION_ID;
  const rawKey = process.env.GITHUB_APP_PRIVATE_KEY;

  const privateKey = normalizePrivateKey(rawKey);

  if (!appId || !installationId || !privateKey) {
    throw new Error('GitHub App values missing (GITHUB_APP_ID, installation_id, or GITHUB_APP_PRIVATE_KEY)');
  }

  const jwt = buildAppJWT(appId, privateKey);

  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;

  const maxAttempts = 3;
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const response = await axios.post(
        url,
        {},
        {
          headers: {
            Authorization: `Bearer ${jwt}`,
            Accept: 'application/vnd.github+json',
          },
          timeout: 15000,
        }
      );

      return response.data.token;
    } catch (err) {
      const status = err.response?.status;
      const retryable = !status || [429, 500, 502, 503, 504].includes(status);
      if (!retryable || attempt === maxAttempts) {
        const body = err.response?.data;
        const detail = body ? JSON.stringify(body) : err.message;
        throw new Error(`GitHub App token request failed (status ${status || 'unknown'}): ${detail}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 1000 * attempt));
    }
  }
}

function isConfigured() {
  return Boolean(
    process.env.GITHUB_APP_ID &&
    process.env.GITHUB_APP_PRIVATE_KEY
  );
}

async function healthCheck() {
  if (!isConfigured()) {
    return { ok: false, error: 'Missing GITHUB_APP_ID or GITHUB_APP_PRIVATE_KEY' };
  }

  return { ok: true };
}

// Resolve the authenticated app's bot identity; never trust a marker from another bot.
let appIdentity = null;
async function getAppBotLogin() {
  const appId = process.env.GITHUB_APP_ID;
  if (appIdentity?.appId === appId) return appIdentity.login;
  const privateKey = normalizePrivateKey(process.env.GITHUB_APP_PRIVATE_KEY);
  if (!appId || !privateKey) throw new Error('GitHub App identity is not configured');
  const response = await axios.get('https://api.github.com/app', {
    timeout: 15000,
    headers: { Authorization: `Bearer ${buildAppJWT(appId, privateKey)}`, Accept: 'application/vnd.github+json' },
  });
  if (!response.data.slug || String(response.data.id) !== String(appId)) throw new Error('GitHub App identity mismatch');
  appIdentity = { appId, login: `${response.data.slug}[bot]` };
  return appIdentity.login;
}

module.exports = {
  getInstallationToken,
  getAppBotLogin,
  isConfigured,
  healthCheck,
};
