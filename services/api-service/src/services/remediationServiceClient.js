const axios = require('axios');

class RemediationServiceClient {
  constructor({ baseUrl = process.env.REMEDIATION_SERVICE_URL, secret = process.env.REMEDIATION_SERVICE_INTERNAL_SECRET } = {}) {
    if (!baseUrl || !secret) throw new Error('Repair service dependency is not configured');
    this.client = axios.create({ baseURL: baseUrl.replace(/\/$/, ''), timeout: Number(process.env.REMEDIATION_SERVICE_TIMEOUT_MS || 45000), headers: { Authorization: `Bearer ${secret}`, 'x-internal-secret': secret, 'Content-Type': 'application/json' } });
  }
  async repair(payload, traceContext = {}) {
    const response = await this.client.post('/v1/repair-stages', payload, { headers: traceContext });
    return response.data;
  }
  async getExecution(executionId, traceContext = {}) {
    const response = await this.client.get(`/v1/repair/${encodeURIComponent(executionId)}`, { headers: traceContext });
    return response.data;
  }
}
module.exports = { RemediationServiceClient };
