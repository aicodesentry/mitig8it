const axios = require('axios');
const { getIdentityToken, normalizeAudience } = require('../clients/grpcConnection');
const { GitHubGrpcClient } = require('../clients/githubGrpcClient');

// The deployed GitHub adapter runs only the gRPC listener, so the control plane picks
// its transport from INTERNAL_SERVICE_TRANSPORT exactly as prAnalysisOrchestrator does.
// Either path takes and returns the same plain objects, so no caller changes.
function useGrpcTransport() {
  return String(process.env.INTERNAL_SERVICE_TRANSPORT || '').toLowerCase() === 'grpc';
}

// The GitHub adapter is deployed without unauthenticated access, so Cloud Run rejects a
// request at its edge unless Authorization carries a Google-signed identity token. The
// adapter's own auth reads only x-internal-secret, so the shared secret stays in that
// header and the identity token goes in Authorization when an audience is configured.
class GitHubRemediationClient {
  constructor({
    baseUrl = process.env.GITHUB_SERVICE_URL,
    secret = process.env.GITHUB_SERVICE_INTERNAL_SECRET,
    audience = process.env.GITHUB_SERVICE_AUDIENCE || process.env.GITHUB_GRPC_AUDIENCE,
    transport = useGrpcTransport() ? 'grpc' : 'rest',
    grpcClient = null,
  } = {}) {
    this.transport = transport;
    if (transport === 'grpc') {
      // gRPC carries its own Cloud Run identity token as a call credential, so the
      // REST base URL and shared secret are not required on this path.
      this.grpc = grpcClient || new GitHubGrpcClient(process.env.GITHUB_GRPC_URL);
      return;
    }
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
  // One dispatcher for both transports: the gRPC method name is the only difference.
  async call(path, rpc, payload) {
    if (this.transport === 'grpc') return this.grpc[rpc](payload);
    return this.post(path, payload);
  }
  async authorize(payload) { return this.call('/internal/github/remediation/authorize', 'authorizeRemediation', payload); }
  async prepare(payload) { return this.call('/internal/github/remediation/prepare', 'prepareRemediation', payload); }
  async snapshot(payload) { return this.call('/internal/github/remediation/snapshot', 'snapshotRemediation', payload); }
  async commit(payload) { return this.call('/internal/github/remediation/commit', 'commitRemediation', payload); }
  async reconcile(payload) { return this.call('/internal/github/remediation/reconcile', 'reconcileRemediation', payload); }
  async merge(payload) { return this.call('/internal/github/remediation/merge', 'mergeRemediation', payload); }
  async createCheckRun(payload) { return this.call('/internal/github/remediation/check-run', 'createRemediationCheckRun', payload); }
  // One residual report comment per action, updated in place when it already exists.
  async publishComment(payload) { return this.call('/internal/github/remediation/comment', 'publishRemediationComment', payload); }
  // Verified fix sections under this app's own inline finding comments, one per
  // candidate and finding, each updated in place by its candidate marker.
  async publishFindingFixSections(payload) { return this.call('/internal/github/remediation/finding-fixes', 'publishFindingFixSections', payload); }
  async cancelScheduledMerge(payload) { return this.call('/internal/github/remediation/cancel-merge', 'cancelScheduledMerge', payload); }
  // Pre-flight reads. They report blockers and current revisions; they never mutate.
  async readMergeEligibility(payload) { return this.call('/internal/github/remediation/merge-eligibility', 'readMergeEligibility', payload); }
  async readPullRequestHead(payload) { return this.call('/internal/github/remediation/pull-head', 'readPullRequestHead', payload); }
}
module.exports = { GitHubRemediationClient, __private: { useGrpcTransport } };
