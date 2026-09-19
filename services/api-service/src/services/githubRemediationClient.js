const axios = require('axios');
const { getIdentityToken, normalizeAudience } = require('../clients/grpcConnection');

// The GitHub adapter is deployed without unauthenticated access, so Cloud Run rejects a
// request at its edge unless Authorization carries a Google-signed identity token. The
// adapter's own auth reads only x-internal-secret, so the shared secret stays in that
// header and the identity token goes in Authorization when an audience is configured.
class GitHubRemediationClient {
  constructor({
    baseUrl = process.env.GITHUB_SERVICE_URL,
    secret = process.env.GITHUB_SERVICE_INTERNAL_SECRET,
    audience = process.env.GITHUB_SERVICE_AUDIENCE || process.env.GITHUB_GRPC_AUDIENCE,
  } = {}) {
    if (!baseUrl || !secret) throw new Error('GitHub remediation dependency is not configured');
    // An https base URL implies Cloud Run and becomes the audience when none is configured;
    // a plain http URL (local development, tests) sends no identity token.
    this.audience = normalizeAudience(audience, baseUrl);
    this.client = axios.create({
      baseURL: baseUrl.replace(/\/$/, ''),
      timeout: Number(process.env.GITHUB_REMEDIATION_TIMEOUT_MS || 30000),
      headers: { 'x-internal-secret': secret, 'Content-Type': 'application/json' },
    });
  }
  async authHeaders() {
    if (!this.audience) return {};
    return { Authorization: `Bearer ${await getIdentityToken(this.audience)}` };
  }
  async post(path, payload) {
    const response = await this.client.post(path, payload, { headers: await this.authHeaders() });
    return response.data;
  }
  async authorize(payload) { return this.post('/internal/github/remediation/authorize', payload); }
  async prepare(payload) { return this.post('/internal/github/remediation/prepare', payload); }
  async snapshot(payload) { return this.post('/internal/github/remediation/snapshot', payload); }
  async commit(payload) { return this.post('/internal/github/remediation/commit', payload); }
  async reconcile(payload) { return this.post('/internal/github/remediation/reconcile', payload); }
  async merge(payload) { return this.post('/internal/github/remediation/merge', payload); }
  async createCheckRun(payload) { return this.post('/internal/github/remediation/check-run', payload); }
  async cancelScheduledMerge(payload) { return this.post('/internal/github/remediation/cancel-merge', payload); }
  // Pre-flight reads. They report blockers and current revisions; they never mutate.
  async readMergeEligibility(payload) { return this.post('/internal/github/remediation/merge-eligibility', payload); }
  async readPullRequestHead(payload) { return this.post('/internal/github/remediation/pull-head', payload); }
}
module.exports = { GitHubRemediationClient };
