const axios = require('axios');

class GitHubRemediationClient {
  constructor({ baseUrl = process.env.GITHUB_SERVICE_URL, secret = process.env.GITHUB_SERVICE_INTERNAL_SECRET } = {}) {
    if (!baseUrl || !secret) throw new Error('GitHub remediation dependency is not configured');
    this.client = axios.create({ baseURL: baseUrl.replace(/\/$/, ''), timeout: Number(process.env.GITHUB_REMEDIATION_TIMEOUT_MS || 30000), headers: { 'x-internal-secret': secret, 'Content-Type': 'application/json' } });
  }
  async authorize(payload) { return (await this.client.post('/internal/github/remediation/authorize', payload)).data; }
  async prepare(payload) { return (await this.client.post('/internal/github/remediation/prepare', payload)).data; }
  async snapshot(payload) { return (await this.client.post('/internal/github/remediation/snapshot', payload)).data; }
  async commit(payload) { return (await this.client.post('/internal/github/remediation/commit', payload)).data; }
  async reconcile(payload) { return (await this.client.post('/internal/github/remediation/reconcile', payload)).data; }
  async merge(payload) { return (await this.client.post('/internal/github/remediation/merge', payload)).data; }
  async createCheckRun(payload) { return (await this.client.post('/internal/github/remediation/check-run', payload)).data; }
  async cancelScheduledMerge(payload) { return (await this.client.post('/internal/github/remediation/cancel-merge', payload)).data; }
  // Pre-flight reads. They report blockers and current revisions; they never mutate.
  async readMergeEligibility(payload) { return (await this.client.post('/internal/github/remediation/merge-eligibility', payload)).data; }
  async readPullRequestHead(payload) { return (await this.client.post('/internal/github/remediation/pull-head', payload)).data; }
}
module.exports = { GitHubRemediationClient };
