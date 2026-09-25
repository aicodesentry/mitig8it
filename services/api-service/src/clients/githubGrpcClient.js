const grpc = require('@grpc/grpc-js');
const githubPb = require('../grpc/generated/github_pb');
const githubGrpc = require('../grpc/generated/github_grpc_pb');
const commonPb = require('../grpc/generated/common_pb');
const { createGrpcClientConfig } = require('./grpcConnection');
const { changedFileToPlain } = require('./grpcConverters');
const requestContext = require('../utils/requestContext');

// The GitHub service reports the originating internal HTTP status in this trailing
// metadata entry, because gRPC collapses the 409 and 422 that callers branch on into
// one FAILED_PRECONDITION.
const OPERATION_STATUS_METADATA_KEY = 'x-operation-status';

// Remediation callers were written against the REST client and read error.response.status
// and the axios-style string error.code. Rebuilding that exact shape here keeps
// remediationWorkflow, remediationVerificationCheck and routes/remediation
// classifying failures the same way on either transport.
const GRPC_STATUS_TO_HTTP = new Map([
  [grpc.status.INVALID_ARGUMENT, { status: 400 }],
  [grpc.status.NOT_FOUND, { status: 404 }],
  [grpc.status.PERMISSION_DENIED, { status: 403 }],
  [grpc.status.FAILED_PRECONDITION, { status: 409 }],
  [grpc.status.UNAUTHENTICATED, { status: 401 }],
  [grpc.status.RESOURCE_EXHAUSTED, { status: 429 }],
  [grpc.status.UNIMPLEMENTED, { status: 501 }],
  [grpc.status.UNAVAILABLE, { status: 502, code: 'ECONNREFUSED' }],
  [grpc.status.DEADLINE_EXCEEDED, { status: 504, code: 'ECONNABORTED' }],
]);

function originatingStatus(error) {
  const raw = error?.metadata?.get?.(OPERATION_STATUS_METADATA_KEY);
  const value = Array.isArray(raw) ? raw[0] : raw;
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isInteger(parsed) && parsed >= 100 && parsed < 600 ? parsed : null;
}

function toRemediationTransportError(error) {
  const mapped = GRPC_STATUS_TO_HTTP.get(error?.code) || { status: 500 };
  const status = originatingStatus(error) || mapped.status;
  const message = error?.details || error?.message || 'GitHub remediation call failed';
  const transportError = new Error(message);
  transportError.code = mapped.code || error?.code;
  transportError.grpcCode = error?.code;
  transportError.response = { status, data: { error: message } };
  return transportError;
}

function unary(client, method, request, timeoutMs = 45000) {
  return new Promise((resolve, reject) => {
    const deadline = new Date(Date.now() + timeoutMs);
    // The delivery and run identifiers ride along on every call, so the github
    // service's log lines for this work join the API's without a manual argument.
    const metadata = requestContext.toGrpcMetadata(grpc.Metadata);
    client[method](request, metadata, { deadline }, (error, response) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(response);
    });
  });
}

const REMEDIATION_TIMEOUT_MS = Number(process.env.GITHUB_REMEDIATION_TIMEOUT_MS || 30000);

async function remediationUnary(client, method, request) {
  try {
    return await unary(client, method, request, REMEDIATION_TIMEOUT_MS);
  } catch (error) {
    throw toRemediationTransportError(error);
  }
}

// Every remediation RPC carries the same consent envelope, built from the flat JSON
// payload the control plane already assembles for the REST endpoints.
function buildRemediationEnvelope(payload = {}) {
  const envelope = new githubPb.RemediationEnvelope();
  envelope.setRepositoryFullName(payload.repository_full_name || '');
  envelope.setActorLogin(payload.actor_login || '');
  envelope.setInstallationId(Number(payload.installation_id || 0));
  envelope.setPrNumber(Number(payload.pr_number || 0));
  envelope.setHeadSha(payload.head_sha || '');
  envelope.setBaseSha(payload.base_sha || '');
  envelope.setActionId(payload.action_id || '');
  envelope.setIdempotencyKey(payload.idempotency_key || '');
  envelope.setManifestDigest(payload.manifest_digest || '');
  return envelope;
}

function buildReviewComments(comments = []) {
  return comments.map((comment) => {
    const message = new commonPb.ReviewComment();
    message.setPath(comment.path || '');
    message.setLine(Number(comment.line || 0));
    message.setBody(comment.body || '');
    return message;
  });
}

class GitHubGrpcClient {
  constructor(target = process.env.GITHUB_GRPC_URL || 'github-service:50051') {
    const config = createGrpcClientConfig({
      target,
      fallbackTarget: 'github-service:50051',
      audience: process.env.GITHUB_GRPC_AUDIENCE,
    });
    this.client = new githubGrpc.GitHubServiceClient(
      config.target,
      config.credentials
    );
  }

  async fetchPullRequestFiles(payload) {
    const request = new githubPb.FetchPullRequestFilesRequest();
    request.setRepositoryFullName(payload.repository_full_name || '');
    request.setPullRequestNumber(Number(payload.pull_request_number || 0));
    request.setCommitSha(payload.commit_sha || '');
    request.setInstallationId(Number(payload.installation_id || 0));
    const response = await unary(this.client, 'fetchPullRequestFiles', request);
    const limitation = response.getLimitation();
    return {
      files: response.getFilesList().map(changedFileToPlain),
      // An unset message reads as an empty kind, which is not a limitation.
      ...(limitation && limitation.getKind()
        ? { limitation: { kind: limitation.getKind(), message: limitation.getMessage() } }
        : {}),
    };
  }

  async fetchFileContents(payload) {
    const request = new githubPb.FetchFileContentsRequest();
    request.setRepositoryFullName(payload.repository_full_name || '');
    request.setInstallationId(Number(payload.installation_id || 0));
    request.setRef(payload.ref || '');
    request.setPathsList(payload.paths || []);
    const response = await unary(this.client, 'fetchFileContents', request);
    return {
      files: response.getFilesList().map((file) => ({
        path: file.getPath(),
        content: file.getContent(),
      })),
    };
  }

  async submitPullRequestReview(payload) {
    const request = new githubPb.SubmitPullRequestReviewRequest();
    request.setOwner(payload.owner || '');
    request.setRepo(payload.repo || '');
    request.setPrNumber(Number(payload.pr_number || 0));
    request.setInstallationId(Number(payload.installation_id || 0));
    request.setCommitSha(payload.commit_sha || '');
    request.setBody(payload.body || '');
    request.setEvent(payload.event || '');
    request.setCommentsList(buildReviewComments(payload.comments || []));
    const response = await unary(this.client, 'submitPullRequestReview', request);
    return {
      review_id: response.getReviewId(),
      comments_posted: response.getCommentsPosted(),
    };
  }

  async postInlineComment(payload) {
    const request = new githubPb.PostInlineCommentRequest();
    request.setOwner(payload.owner || '');
    request.setRepo(payload.repo || '');
    request.setPrNumber(Number(payload.pr_number || 0));
    request.setInstallationId(Number(payload.installation_id || 0));
    request.setCommitSha(payload.commit_sha || '');
    request.setPath(payload.path || '');
    request.setLine(Number(payload.line || 0));
    request.setBody(payload.body || '');
    const response = await unary(this.client, 'postInlineComment', request);
    return {
      comment_id: response.getCommentId(),
      url: response.getUrl(),
      success: response.getSuccess(),
    };
  }

  async retireInlineComments(payload) {
    const request = new githubPb.RetireInlineCommentsRequest();
    request.setOwner(payload.owner || '');
    request.setRepo(payload.repo || '');
    request.setPrNumber(Number(payload.pr_number || 0));
    request.setInstallationId(Number(payload.installation_id || 0));
    request.setFingerprintsList(payload.fingerprints || []);
    const response = await unary(this.client, 'retireInlineComments', request);
    return {
      retired: response.getRetired(),
      kept: response.getKept(),
    };
  }

  async snapshotRemediation(payload) {
    const request = new githubPb.RemediationSnapshotRequest();
    request.setEnvelope(buildRemediationEnvelope(payload));
    request.setFindingPathsList(payload.finding_paths || []);
    const response = await remediationUnary(this.client, 'snapshotRemediation', request);
    return {
      files: response.getFilesList().map((file) => ({
        path: file.getPath(),
        content: file.getContent(),
        sha: file.getSha(),
      })),
      tree_entries: response.getTreeEntriesList().map((entry) => ({
        path: entry.getPath(),
        mode: entry.getMode(),
        type: entry.getType(),
        sha: entry.getSha(),
      })),
      head_tree_oid: response.getHeadTreeOid(),
      head_sha: response.getHeadSha(),
      base_sha: response.getBaseSha(),
      omitted_source_paths: response.getOmittedSourcePathsList(),
    };
  }

  async createRemediationCheckRun(payload) {
    const request = new githubPb.RemediationCheckRunRequest();
    request.setEnvelope(buildRemediationEnvelope(payload));
    request.setHeadSha(payload.head_sha || '');
    request.setName(payload.name || '');
    request.setStatus(payload.status || '');
    request.setConclusion(payload.conclusion || '');
    request.setTitle(payload.title || '');
    request.setSummary(payload.summary || '');
    request.setExternalId(payload.external_id || '');
    const response = await remediationUnary(this.client, 'createRemediationCheckRun', request);
    return {
      state: response.getState(),
      operation_id: response.getOperationId(),
      check_run_id: response.getCheckRunId(),
      name: response.getName(),
      external_id: response.getExternalId(),
      updated: response.getUpdated(),
      reason: response.getReason(),
    };
  }

  async publishRemediationComment(payload) {
    const request = new githubPb.RemediationCommentRequest();
    request.setEnvelope(buildRemediationEnvelope(payload));
    request.setExternalId(payload.external_id || '');
    request.setBody(payload.body || '');
    const response = await remediationUnary(this.client, 'publishRemediationComment', request);
    return {
      state: response.getState(),
      operation_id: response.getOperationId(),
      comment_id: response.getCommentId(),
      external_id: response.getExternalId(),
      updated: response.getUpdated(),
      reason: response.getReason(),
    };
  }

  async publishFindingFixSections(payload) {
    const request = new githubPb.FindingFixSectionsRequest();
    request.setEnvelope(buildRemediationEnvelope(payload));
    request.setPreviewUrl(payload.preview_url || '');
    request.setSectionsList((payload.sections || []).map((section) => {
      const message = new githubPb.FindingFixSection();
      message.setCandidateId(section.candidate_id || '');
      message.setFindingFingerprint(section.finding_fingerprint || '');
      message.setPath(section.path || '');
      message.setFindingLine(Number(section.finding_line || 0));
      if (section.hunk) {
        const hunk = new githubPb.FindingFixHunk();
        hunk.setStartLine(Number(section.hunk.start_line || 0));
        hunk.setEndLine(Number(section.hunk.end_line || 0));
        hunk.setOriginalLinesList(section.hunk.original_lines || []);
        hunk.setReplacementLinesList(section.hunk.replacement_lines || []);
        message.setHunk(hunk);
      }
      message.setExtraHunksList((section.extra_hunks || []).map((item) => {
        const extra = new githubPb.FindingFixHunk();
        extra.setStartLine(Number(item.start_line || 0));
        extra.setEndLine(Number(item.end_line || 0));
        extra.setOriginalLinesList(item.original_lines || []);
        extra.setReplacementLinesList(item.replacement_lines || []);
        return extra;
      }));
      message.setUnifiedDiff(section.unified_diff || '');
      message.setNotSuggestableReason(section.not_suggestable_reason || '');
      message.setStatedIntent(section.stated_intent || '');
      message.setEvidenceList(section.evidence || []);
      message.setLimitationsList(section.limitations || []);
      message.setSkippedReason(section.skipped_reason || '');
      message.setVerificationLevel(section.verification_level || '');
      message.setFindingBody(section.finding_body || '');
      message.setFindingIdsList(section.finding_ids || []);
      message.setCoveredBy(section.covered_by || '');
      message.setProof(section.proof || '');
      return message;
    }));
    const response = await remediationUnary(this.client, 'publishFindingFixSections', request);
    return {
      state: response.getState(),
      operation_id: response.getOperationId(),
      results: response.getResultsList().map((item) => ({
        finding_fingerprint: item.getFindingFingerprint(),
        candidate_id: item.getCandidateId(),
        comment_id: item.getCommentId(),
        mode: item.getMode(),
        updated: item.getUpdated(),
        reason: item.getReason(),
        created: item.getCreated(),
        placement: item.getPlacement(),
      })),
      reason: response.getReason(),
    };
  }

  async createCheckRun(payload) {
    const request = new githubPb.CreateCheckRunRequest();
    request.setOwner(payload.owner || '');
    request.setRepo(payload.repo || '');
    request.setInstallationId(Number(payload.installation_id || 0));
    request.setHeadSha(payload.head_sha || '');
    request.setConclusion(payload.conclusion || '');
    request.setTitle(payload.title || '');
    request.setSummary(payload.summary || '');
    const response = await unary(this.client, 'createCheckRun', request);
    return { check_run_id: response.getCheckRunId() };
  }
}

module.exports = {
  GitHubGrpcClient,
  OPERATION_STATUS_METADATA_KEY,
  __private: { toRemediationTransportError },
};
