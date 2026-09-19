const axios = require('axios');
const { getIdentityToken, normalizeAudience } = require('../clients/grpcConnection');

// Cloud Run rejects an unauthenticated request before the container sees it, so the
// Authorization header has to carry the Google-signed identity token. The repair service
// reads the shared internal secret from either the Authorization bearer or
// `x-internal-secret` (see services/remediation-service/src/main.py), so the secret moves
// to `x-internal-secret` whenever the identity token occupies Authorization.
class RemediationServiceClient {
  constructor({
    baseUrl = process.env.REMEDIATION_SERVICE_URL,
    secret = process.env.REMEDIATION_SERVICE_INTERNAL_SECRET,
    audience = process.env.REMEDIATION_SERVICE_AUDIENCE,
  } = {}) {
    if (!baseUrl || !secret) throw new Error('Repair service dependency is not configured');
    this.audience = normalizeAudience(audience, null);
    const headers = { 'x-internal-secret': secret, 'Content-Type': 'application/json' };
    if (!this.audience) headers.Authorization = `Bearer ${secret}`;
    this.client = axios.create({
      baseURL: baseUrl.replace(/\/$/, ''),
      timeout: Number(process.env.REMEDIATION_SERVICE_TIMEOUT_MS || 45000),
      headers,
    });
  }
  async authHeaders() {
    if (!this.audience) return {};
    return { Authorization: `Bearer ${await getIdentityToken(this.audience)}` };
  }
  async repair(payload, traceContext = {}) {
    const headers = { ...traceContext, ...(await this.authHeaders()) };
    const response = await this.client.post('/v1/repair-stages', payload, { headers });
    return response.data;
  }
  async getExecution(executionId, traceContext = {}) {
    const headers = { ...traceContext, ...(await this.authHeaders()) };
    const response = await this.client.get(`/v1/repair/${encodeURIComponent(executionId)}`, { headers });
    return response.data;
  }
}
module.exports = { RemediationServiceClient };
