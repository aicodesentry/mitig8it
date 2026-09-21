const grpc = require('@grpc/grpc-js');
const githubPb = require('./grpc/generated/github_pb');
const githubGrpc = require('./grpc/generated/github_grpc_pb');
const commonPb = require('./grpc/generated/common_pb');
const {
  authorizeRemediationActor,
  cancelScheduledMerge,
  commitRemediationAction,
  createCheckRun,
  createRemediationCheckRun,
  publishRemediationComment,
  publishFindingFixSections,
  fetchFileContents,
  fetchPullRequestFiles,
  fetchRemediationSnapshot,
  mergeRemediationAction,
  postInlineComment,
  prepareRemediationAction,
  readMergeEligibility,
  readPullRequestHead,
  reconcileRemediationAction,
  submitPullRequestReview,
} = require('./services/githubInternalOperations');

const HEALTH_SERVING_STATUS = 1;
const OPERATION_STATUS_METADATA_KEY = 'x-operation-status';

function readVarint(buffer, offset) {
  let result = 0;
  let shift = 0;
  let cursor = offset;
  while (cursor < buffer.length) {
    const byte = buffer[cursor];
    result |= (byte & 0x7f) << shift;
    cursor += 1;
    if ((byte & 0x80) === 0) {
      return { value: result, offset: cursor };
    }
    shift += 7;
  }
  return { value: result, offset: cursor };
}

function decodeHealthCheckRequest(buffer) {
  let offset = 0;
  let service = '';
  while (offset < buffer.length) {
    const tag = buffer[offset];
    offset += 1;
    if (tag === 0x0a) {
      const length = readVarint(buffer, offset);
      offset = length.offset;
      service = buffer.subarray(offset, offset + length.value).toString('utf8');
      offset += length.value;
    } else {
      break;
    }
  }
  return { service };
}

function encodeHealthCheckResponse(response = {}) {
  return Buffer.from([0x08, Number(response.status || HEALTH_SERVING_STATUS)]);
}

const standardHealthService = {
  check: {
    path: '/grpc.health.v1.Health/Check',
    requestStream: false,
    responseStream: false,
    requestSerialize: () => Buffer.alloc(0),
    requestDeserialize: decodeHealthCheckRequest,
    responseSerialize: encodeHealthCheckResponse,
    responseDeserialize: () => ({ status: HEALTH_SERVING_STATUS }),
  },
};

const standardHealthHandlers = {
  check: (call, callback) => {
    callback(null, { status: HEALTH_SERVING_STATUS });
  },
};

// gRPC has one FAILED_PRECONDITION for the 409 and 422 the operations distinguish, and
// callers branch on that difference. The originating status therefore travels in
// trailing metadata so the gRPC client can rebuild the exact error the HTTP path raises.
function operationStatusMetadata(statusCode) {
  if (!Number.isInteger(statusCode)) {
    return undefined;
  }
  const metadata = new grpc.Metadata();
  metadata.set(OPERATION_STATUS_METADATA_KEY, String(statusCode));
  return metadata;
}

function operationErrorToGrpc(error) {
  const metadata = operationStatusMetadata(error.statusCode);
  if (error.statusCode === 400) {
    return { code: grpc.status.INVALID_ARGUMENT, message: error.message, metadata };
  }
  if (error.statusCode === 502) {
    return { code: grpc.status.UNAVAILABLE, message: error.message, metadata };
  }
  // Remediation operations refuse with these statuses; collapsing them into INTERNAL
  // would hide a permission or precondition failure behind a server fault.
  if (error.statusCode === 403) {
    return { code: grpc.status.PERMISSION_DENIED, message: error.message, metadata };
  }
  if (error.statusCode === 404) {
    return { code: grpc.status.NOT_FOUND, message: error.message, metadata };
  }
  if (error.statusCode === 409 || error.statusCode === 422) {
    return { code: grpc.status.FAILED_PRECONDITION, message: error.message, metadata };
  }
  return { code: grpc.status.INTERNAL, message: error.message || 'Internal error', metadata };
}

function toChangedFile(file) {
  const message = new commonPb.ChangedFile();
  message.setPath(file.path || '');
  message.setPatch(file.patch || '');
  message.setContent(file.content || '');
  message.setAdditions(Number(file.additions || 0));
  message.setDeletions(Number(file.deletions || 0));
  message.setStatus(file.status || '');
  message.setRawUrl(file.raw_url || '');
  return message;
}

function toFetchPullRequestFilesPayload(request) {
  return {
    repository_full_name: request.getRepositoryFullName(),
    pull_request_number: request.getPullRequestNumber(),
    installation_id: request.getInstallationId(),
    commit_sha: request.getCommitSha(),
  };
}

function toFetchFileContentsPayload(request) {
  return {
    repository_full_name: request.getRepositoryFullName(),
    installation_id: request.getInstallationId(),
    ref: request.getRef(),
    paths: request.getPathsList(),
  };
}

function toSubmitReviewPayload(request) {
  return {
    owner: request.getOwner(),
    repo: request.getRepo(),
    pr_number: request.getPrNumber(),
    installation_id: request.getInstallationId(),
    commit_sha: request.getCommitSha(),
    body: request.getBody(),
    event: request.getEvent(),
    comments: request.getCommentsList().map((comment) => ({
      path: comment.getPath(),
      line: comment.getLine(),
      body: comment.getBody(),
    })),
  };
}

function toPostInlineCommentPayload(request) {
  return {
    owner: request.getOwner(),
    repo: request.getRepo(),
    pr_number: request.getPrNumber(),
    installation_id: request.getInstallationId(),
    commit_sha: request.getCommitSha(),
    path: request.getPath(),
    line: request.getLine(),
    body: request.getBody(),
  };
}

function toCreateCheckRunPayload(request) {
  return {
    owner: request.getOwner(),
    repo: request.getRepo(),
    installation_id: request.getInstallationId(),
    head_sha: request.getHeadSha(),
    conclusion: request.getConclusion(),
    title: request.getTitle(),
    summary: request.getSummary(),
  };
}

function unary(handler, buildResponse) {
  return async (call, callback) => {
    try {
      const result = await handler(call.request);
      callback(null, buildResponse(result));
    } catch (error) {
      callback(operationErrorToGrpc(error));
    }
  };
}

// Remediation gRPC parity. Every handler converts its typed request into the exact
// payload shape the internal HTTP routes pass, so both transports run one code path.
function fromRemediationEnvelope(envelope) {
  if (!envelope) return {};
  return {
    repository_full_name: envelope.getRepositoryFullName(),
    actor_login: envelope.getActorLogin(),
    installation_id: envelope.getInstallationId(),
    pr_number: envelope.getPrNumber(),
    head_sha: envelope.getHeadSha(),
    base_sha: envelope.getBaseSha(),
    action_id: envelope.getActionId(),
    idempotency_key: envelope.getIdempotencyKey(),
    manifest_digest: envelope.getManifestDigest(),
  };
}

function toRemediationSnapshotPayload(request) {
  return { ...fromRemediationEnvelope(request.getEnvelope()), finding_paths: request.getFindingPathsList() };
}

function toRemediationCommitPayload(request) {
  return {
    ...fromRemediationEnvelope(request.getEnvelope()),
    branch: request.getBranch(),
    expected_head_oid: request.getExpectedHeadOid(),
    verified_tree_oid: request.getVerifiedTreeOid(),
    commit_message: request.getCommitMessage(),
    changes: request.getChangesList().map((change) => ({
      path: change.getPath(),
      contents_base64: change.getContentsBase64(),
    })),
  };
}

function toRemediationMergePayload(request) {
  return {
    ...fromRemediationEnvelope(request.getEnvelope()),
    expected_head_sha: request.getExpectedHeadSha(),
    expected_base_sha: request.getExpectedBaseSha(),
    merge_method: request.getMergeMethod(),
    verification_check_name: request.getVerificationCheckName(),
  };
}

const remediationService = {
  prepareRemediation: unary(
    async (request) => prepareRemediationAction(fromRemediationEnvelope(request.getEnvelope())),
    (result) => {
      const response = new githubPb.RemediationPrepareResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setBranch(result.branch || '');
      response.setExpectedHeadOid(result.expected_head_oid || '');
      response.setMarker(result.marker || '');
      return response;
    }
  ),

  snapshotRemediation: unary(
    async (request) => fetchRemediationSnapshot(toRemediationSnapshotPayload(request)),
    (result) => {
      const response = new githubPb.RemediationSnapshotResponse();
      response.setFilesList((result.files || []).map((file) => {
        const message = new githubPb.RemediationSourceFile();
        message.setPath(file.path || '');
        message.setContent(file.content || '');
        message.setSha(file.sha || '');
        return message;
      }));
      response.setTreeEntriesList((result.tree_entries || []).map((entry) => {
        const message = new githubPb.RemediationTreeEntry();
        message.setPath(entry.path || '');
        message.setMode(entry.mode || '');
        message.setType(entry.type || '');
        message.setSha(entry.sha || '');
        return message;
      }));
      response.setHeadTreeOid(result.head_tree_oid || '');
      response.setHeadSha(result.head_sha || '');
      response.setBaseSha(result.base_sha || '');
      response.setOmittedSourcePathsList(result.omitted_source_paths || []);
      return response;
    }
  ),

  commitRemediation: unary(
    async (request) => commitRemediationAction(toRemediationCommitPayload(request)),
    (result) => {
      const response = new githubPb.RemediationCommitResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setCommitSha(result.commit_sha || '');
      response.setTreeOid(result.tree_oid || '');
      response.setReason(result.reason || '');
      return response;
    }
  ),

  reconcileRemediation: unary(
    async (request) => reconcileRemediationAction({
      ...fromRemediationEnvelope(request.getEnvelope()),
      verified_tree_oid: request.getVerifiedTreeOid(),
    }),
    (result) => {
      const response = new githubPb.RemediationReconcileResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setCommitSha(result.commit_sha || '');
      response.setTreeOid(result.tree_oid || '');
      response.setReason(result.reason || '');
      return response;
    }
  ),

  mergeRemediation: unary(
    async (request) => mergeRemediationAction(toRemediationMergePayload(request)),
    (result) => {
      const response = new githubPb.RemediationMergeResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setCommitSha(result.commit_sha || '');
      response.setReason(result.reason || '');
      return response;
    }
  ),

  cancelScheduledMerge: unary(
    async (request) => cancelScheduledMerge({
      ...fromRemediationEnvelope(request.getEnvelope()),
      pull_number: request.getPullNumber(),
      expected_head_sha: request.getExpectedHeadSha(),
    }),
    (result) => {
      const response = new githubPb.CancelScheduledMergeResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setHeadSha(result.head_sha || '');
      response.setMerged(Boolean(result.merged));
      response.setReason(result.reason || '');
      return response;
    }
  ),

  readMergeEligibility: unary(
    async (request) => readMergeEligibility({
      ...fromRemediationEnvelope(request.getEnvelope()),
      pull_number: request.getPullNumber(),
      expected_head_sha: request.getExpectedHeadSha(),
      verification_check_name: request.getVerificationCheckName(),
    }),
    (result) => {
      const response = new githubPb.MergeEligibilityResponse();
      response.setEligible(Boolean(result.eligible));
      response.setBlockersList(result.blockers || []);
      response.setRequiredChecksList((result.required_checks || []).map((check) => {
        const message = new githubPb.RequiredCheck();
        message.setContext(check.context || '');
        message.setAppId(Number(check.app_id || 0));
        return message;
      }));
      response.setCheckRunsList((result.check_runs || []).map((check) => {
        const message = new githubPb.CheckRunSummary();
        message.setId(Number(check.id || 0));
        message.setName(check.name || '');
        message.setAppId(Number(check.app_id || 0));
        message.setStatus(check.status || '');
        message.setConclusion(check.conclusion || '');
        return message;
      }));
      const reviews = new githubPb.ReviewSummary();
      reviews.setRequired(Number(result.reviews?.required || 0));
      reviews.setApprovals(Number(result.reviews?.approvals || 0));
      reviews.setChangesRequested(Boolean(result.reviews?.changes_requested));
      response.setReviews(reviews);
      response.setProtectionSource(result.protection_source || 'unknown');
      response.setMergeableState(result.mergeable_state || 'unknown');
      response.setHeadSha(result.head_sha || '');
      response.setBaseSha(result.base_sha || '');
      response.setVerificationCheckName(result.verification_check_name || '');
      return response;
    }
  ),

  readPullRequestHead: unary(
    async (request) => readPullRequestHead({
      ...fromRemediationEnvelope(request.getEnvelope()),
      pull_number: request.getPullNumber(),
    }),
    (result) => {
      const response = new githubPb.PullRequestHeadResponse();
      response.setHeadSha(result.head_sha || '');
      response.setBaseSha(result.base_sha || '');
      response.setState(result.state || '');
      response.setDraft(Boolean(result.draft));
      response.setMerged(Boolean(result.merged));
      response.setMergeableState(result.mergeable_state || '');
      response.setFork(Boolean(result.fork));
      return response;
    }
  ),

  authorizeRemediation: unary(
    async (request) => authorizeRemediationActor(fromRemediationEnvelope(request.getEnvelope())),
    (result) => {
      const response = new githubPb.RemediationAuthorizeResponse();
      response.setState(result.state || '');
      response.setInstallationActive(Boolean(result.installation_active));
      response.setRepositoryGranted(Boolean(result.repository_granted));
      response.setActorWritePermission(Boolean(result.actor_write_permission));
      response.setHeadSha(result.head_sha || '');
      response.setBaseSha(result.base_sha || '');
      response.setHeadBranch(result.head_branch || '');
      response.setBaseBranch(result.base_branch || '');
      return response;
    }
  ),

  createRemediationCheckRun: unary(
    async (request) => createRemediationCheckRun({
      ...fromRemediationEnvelope(request.getEnvelope()),
      head_sha: request.getHeadSha() || undefined,
      name: request.getName() || undefined,
      status: request.getStatus() || undefined,
      conclusion: request.getConclusion() || undefined,
      title: request.getTitle(),
      summary: request.getSummary(),
      external_id: request.getExternalId(),
    }),
    (result) => {
      const response = new githubPb.RemediationCheckRunResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setCheckRunId(Number(result.check_run_id || 0));
      response.setName(result.name || '');
      response.setExternalId(result.external_id || '');
      response.setUpdated(Boolean(result.updated));
      response.setReason(result.reason || '');
      return response;
    }
  ),

  publishRemediationComment: unary(
    async (request) => publishRemediationComment({
      ...fromRemediationEnvelope(request.getEnvelope()),
      external_id: request.getExternalId(),
      body: request.getBody(),
    }),
    (result) => {
      const response = new githubPb.RemediationCommentResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setCommentId(Number(result.comment_id || 0));
      response.setExternalId(result.external_id || '');
      response.setUpdated(Boolean(result.updated));
      response.setReason(result.reason || '');
      return response;
    }
  ),

  publishFindingFixSections: unary(
    async (request) => publishFindingFixSections({
      ...fromRemediationEnvelope(request.getEnvelope()),
      preview_url: request.getPreviewUrl(),
      sections: request.getSectionsList().map((section) => {
        const hunk = section.getHunk();
        return {
          candidate_id: section.getCandidateId(),
          finding_fingerprint: section.getFindingFingerprint(),
          path: section.getPath(),
          finding_line: section.getFindingLine(),
          hunk: hunk ? {
            start_line: hunk.getStartLine(), end_line: hunk.getEndLine(),
            original_lines: hunk.getOriginalLinesList(), replacement_lines: hunk.getReplacementLinesList(),
          } : null,
          extra_hunks: section.getExtraHunksList().map((item) => ({
            start_line: item.getStartLine(), end_line: item.getEndLine(),
            original_lines: item.getOriginalLinesList(), replacement_lines: item.getReplacementLinesList(),
          })),
          unified_diff: section.getUnifiedDiff(),
          not_suggestable_reason: section.getNotSuggestableReason(),
          stated_intent: section.getStatedIntent(),
          evidence: section.getEvidenceList(),
          limitations: section.getLimitationsList(),
          skipped_reason: section.getSkippedReason(),
          verification_level: section.getVerificationLevel(),
          finding_body: section.getFindingBody(),
          finding_ids: section.getFindingIdsList(),
          covered_by: section.getCoveredBy(),
          proof: section.getProof(),
        };
      }),
    }),
    (result) => {
      const response = new githubPb.FindingFixSectionsResponse();
      response.setState(result.state || '');
      response.setOperationId(result.operation_id || '');
      response.setResultsList((result.results || []).map((item) => {
        const message = new githubPb.FindingFixSectionResult();
        message.setFindingFingerprint(item.finding_fingerprint || '');
        message.setCandidateId(item.candidate_id || '');
        message.setCommentId(Number(item.comment_id || 0));
        message.setMode(item.mode || '');
        message.setUpdated(Boolean(item.updated));
        message.setReason(item.reason || '');
        message.setCreated(Boolean(item.created));
        message.setPlacement(item.placement || '');
        return message;
      }));
      response.setReason(result.reason || '');
      return response;
    }
  ),
};

const githubService = {
  fetchPullRequestFiles: unary(
    async (request) => fetchPullRequestFiles(toFetchPullRequestFilesPayload(request)),
    (result) => {
      const response = new githubPb.FetchPullRequestFilesResponse();
      response.setFilesList((result.files || []).map(toChangedFile));
      return response;
    }
  ),

  fetchFileContents: unary(
    async (request) => fetchFileContents(toFetchFileContentsPayload(request)),
    (result) => {
      const response = new githubPb.FetchFileContentsResponse();
      response.setFilesList((result.files || []).map((file) => {
        const message = new githubPb.FileContent();
        message.setPath(file.path || '');
        message.setContent(file.content || '');
        return message;
      }));
      return response;
    }
  ),

  submitPullRequestReview: unary(
    async (request) => submitPullRequestReview(toSubmitReviewPayload(request)),
    (result) => {
      const response = new githubPb.SubmitPullRequestReviewResponse();
      response.setReviewId(Number(result.review_id || 0));
      response.setCommentsPosted(Number(result.comments_posted || 0));
      return response;
    }
  ),

  postInlineComment: unary(
    async (request) => postInlineComment(toPostInlineCommentPayload(request)),
    (result) => {
      const response = new githubPb.PostInlineCommentResponse();
      response.setCommentId(Number(result.comment_id || 0));
      response.setUrl(result.url || '');
      response.setSuccess(Boolean(result.success));
      return response;
    }
  ),

  createCheckRun: unary(
    async (request) => createCheckRun(toCreateCheckRunPayload(request)),
    (result) => {
      const response = new githubPb.CreateCheckRunResponse();
      response.setCheckRunId(Number(result.check_run_id || 0));
      return response;
    }
  ),

  ...remediationService,

  healthCheck: (call, callback) => {
    const response = new commonPb.HealthCheckResponse();
    response.setStatus('ok');
    response.setService('github-service');
    response.setVersion('1.0.0');
    callback(null, response);
  },
};

function createServer() {
  const server = new grpc.Server();
  server.addService(githubGrpc.GitHubServiceService, githubService);
  server.addService(standardHealthService, standardHealthHandlers);
  return server;
}

function startServer() {
  const port = Number(process.env.GITHUB_GRPC_PORT || process.env.PORT || 50051);
  const server = createServer();
  server.bindAsync(`0.0.0.0:${port}`, grpc.ServerCredentials.createInsecure(), (error) => {
    if (error) {
      throw error;
    }
    console.log(`GitHub gRPC service listening on ${port}`);
  });
  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  OPERATION_STATUS_METADATA_KEY,
  createServer,
  githubService,
  startServer,
};
