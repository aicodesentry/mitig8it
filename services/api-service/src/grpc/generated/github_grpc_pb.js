// GENERATED CODE -- DO NOT EDIT!

'use strict';
var grpc = require('@grpc/grpc-js');
var github_pb = require('./github_pb.js');
var common_pb = require('./common_pb.js');

function serialize_mitig8it_common_v1_HealthCheckRequest(arg) {
  if (!(arg instanceof common_pb.HealthCheckRequest)) {
    throw new Error('Expected argument of type mitig8it.common.v1.HealthCheckRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_common_v1_HealthCheckRequest(buffer_arg) {
  return common_pb.HealthCheckRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_common_v1_HealthCheckResponse(arg) {
  if (!(arg instanceof common_pb.HealthCheckResponse)) {
    throw new Error('Expected argument of type mitig8it.common.v1.HealthCheckResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_common_v1_HealthCheckResponse(buffer_arg) {
  return common_pb.HealthCheckResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_CancelScheduledMergeRequest(arg) {
  if (!(arg instanceof github_pb.CancelScheduledMergeRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.CancelScheduledMergeRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_CancelScheduledMergeRequest(buffer_arg) {
  return github_pb.CancelScheduledMergeRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_CancelScheduledMergeResponse(arg) {
  if (!(arg instanceof github_pb.CancelScheduledMergeResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.CancelScheduledMergeResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_CancelScheduledMergeResponse(buffer_arg) {
  return github_pb.CancelScheduledMergeResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_CreateCheckRunRequest(arg) {
  if (!(arg instanceof github_pb.CreateCheckRunRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.CreateCheckRunRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_CreateCheckRunRequest(buffer_arg) {
  return github_pb.CreateCheckRunRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_CreateCheckRunResponse(arg) {
  if (!(arg instanceof github_pb.CreateCheckRunResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.CreateCheckRunResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_CreateCheckRunResponse(buffer_arg) {
  return github_pb.CreateCheckRunResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_FetchFileContentsRequest(arg) {
  if (!(arg instanceof github_pb.FetchFileContentsRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FetchFileContentsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FetchFileContentsRequest(buffer_arg) {
  return github_pb.FetchFileContentsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_FetchFileContentsResponse(arg) {
  if (!(arg instanceof github_pb.FetchFileContentsResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FetchFileContentsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FetchFileContentsResponse(buffer_arg) {
  return github_pb.FetchFileContentsResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_FetchPullRequestFilesRequest(arg) {
  if (!(arg instanceof github_pb.FetchPullRequestFilesRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FetchPullRequestFilesRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FetchPullRequestFilesRequest(buffer_arg) {
  return github_pb.FetchPullRequestFilesRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_FetchPullRequestFilesResponse(arg) {
  if (!(arg instanceof github_pb.FetchPullRequestFilesResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FetchPullRequestFilesResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FetchPullRequestFilesResponse(buffer_arg) {
  return github_pb.FetchPullRequestFilesResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_MergeEligibilityRequest(arg) {
  if (!(arg instanceof github_pb.MergeEligibilityRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.MergeEligibilityRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_MergeEligibilityRequest(buffer_arg) {
  return github_pb.MergeEligibilityRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_MergeEligibilityResponse(arg) {
  if (!(arg instanceof github_pb.MergeEligibilityResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.MergeEligibilityResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_MergeEligibilityResponse(buffer_arg) {
  return github_pb.MergeEligibilityResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_PostInlineCommentRequest(arg) {
  if (!(arg instanceof github_pb.PostInlineCommentRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.PostInlineCommentRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_PostInlineCommentRequest(buffer_arg) {
  return github_pb.PostInlineCommentRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_PostInlineCommentResponse(arg) {
  if (!(arg instanceof github_pb.PostInlineCommentResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.PostInlineCommentResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_PostInlineCommentResponse(buffer_arg) {
  return github_pb.PostInlineCommentResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_PullRequestHeadRequest(arg) {
  if (!(arg instanceof github_pb.PullRequestHeadRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.PullRequestHeadRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_PullRequestHeadRequest(buffer_arg) {
  return github_pb.PullRequestHeadRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_PullRequestHeadResponse(arg) {
  if (!(arg instanceof github_pb.PullRequestHeadResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.PullRequestHeadResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_PullRequestHeadResponse(buffer_arg) {
  return github_pb.PullRequestHeadResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationCheckRunRequest(arg) {
  if (!(arg instanceof github_pb.RemediationCheckRunRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCheckRunRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCheckRunRequest(buffer_arg) {
  return github_pb.RemediationCheckRunRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationCheckRunResponse(arg) {
  if (!(arg instanceof github_pb.RemediationCheckRunResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCheckRunResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCheckRunResponse(buffer_arg) {
  return github_pb.RemediationCheckRunResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationCommitRequest(arg) {
  if (!(arg instanceof github_pb.RemediationCommitRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCommitRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCommitRequest(buffer_arg) {
  return github_pb.RemediationCommitRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationCommitResponse(arg) {
  if (!(arg instanceof github_pb.RemediationCommitResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCommitResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCommitResponse(buffer_arg) {
  return github_pb.RemediationCommitResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationMergeRequest(arg) {
  if (!(arg instanceof github_pb.RemediationMergeRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationMergeRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationMergeRequest(buffer_arg) {
  return github_pb.RemediationMergeRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationMergeResponse(arg) {
  if (!(arg instanceof github_pb.RemediationMergeResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationMergeResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationMergeResponse(buffer_arg) {
  return github_pb.RemediationMergeResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationPrepareRequest(arg) {
  if (!(arg instanceof github_pb.RemediationPrepareRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationPrepareRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationPrepareRequest(buffer_arg) {
  return github_pb.RemediationPrepareRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationPrepareResponse(arg) {
  if (!(arg instanceof github_pb.RemediationPrepareResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationPrepareResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationPrepareResponse(buffer_arg) {
  return github_pb.RemediationPrepareResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationReconcileRequest(arg) {
  if (!(arg instanceof github_pb.RemediationReconcileRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationReconcileRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationReconcileRequest(buffer_arg) {
  return github_pb.RemediationReconcileRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationReconcileResponse(arg) {
  if (!(arg instanceof github_pb.RemediationReconcileResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationReconcileResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationReconcileResponse(buffer_arg) {
  return github_pb.RemediationReconcileResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationSnapshotRequest(arg) {
  if (!(arg instanceof github_pb.RemediationSnapshotRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationSnapshotRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationSnapshotRequest(buffer_arg) {
  return github_pb.RemediationSnapshotRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationSnapshotResponse(arg) {
  if (!(arg instanceof github_pb.RemediationSnapshotResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationSnapshotResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationSnapshotResponse(buffer_arg) {
  return github_pb.RemediationSnapshotResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_SubmitPullRequestReviewRequest(arg) {
  if (!(arg instanceof github_pb.SubmitPullRequestReviewRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.SubmitPullRequestReviewRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_SubmitPullRequestReviewRequest(buffer_arg) {
  return github_pb.SubmitPullRequestReviewRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_SubmitPullRequestReviewResponse(arg) {
  if (!(arg instanceof github_pb.SubmitPullRequestReviewResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.SubmitPullRequestReviewResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_SubmitPullRequestReviewResponse(buffer_arg) {
  return github_pb.SubmitPullRequestReviewResponse.deserializeBinary(new Uint8Array(buffer_arg));
}


var GitHubServiceService = exports.GitHubServiceService = {
  fetchPullRequestFiles: {
    path: '/mitig8it.github.v1.GitHubService/FetchPullRequestFiles',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.FetchPullRequestFilesRequest,
    responseType: github_pb.FetchPullRequestFilesResponse,
    requestSerialize: serialize_mitig8it_github_v1_FetchPullRequestFilesRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_FetchPullRequestFilesRequest,
    responseSerialize: serialize_mitig8it_github_v1_FetchPullRequestFilesResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_FetchPullRequestFilesResponse,
  },
  fetchFileContents: {
    path: '/mitig8it.github.v1.GitHubService/FetchFileContents',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.FetchFileContentsRequest,
    responseType: github_pb.FetchFileContentsResponse,
    requestSerialize: serialize_mitig8it_github_v1_FetchFileContentsRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_FetchFileContentsRequest,
    responseSerialize: serialize_mitig8it_github_v1_FetchFileContentsResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_FetchFileContentsResponse,
  },
  submitPullRequestReview: {
    path: '/mitig8it.github.v1.GitHubService/SubmitPullRequestReview',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.SubmitPullRequestReviewRequest,
    responseType: github_pb.SubmitPullRequestReviewResponse,
    requestSerialize: serialize_mitig8it_github_v1_SubmitPullRequestReviewRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_SubmitPullRequestReviewRequest,
    responseSerialize: serialize_mitig8it_github_v1_SubmitPullRequestReviewResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_SubmitPullRequestReviewResponse,
  },
  postInlineComment: {
    path: '/mitig8it.github.v1.GitHubService/PostInlineComment',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.PostInlineCommentRequest,
    responseType: github_pb.PostInlineCommentResponse,
    requestSerialize: serialize_mitig8it_github_v1_PostInlineCommentRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_PostInlineCommentRequest,
    responseSerialize: serialize_mitig8it_github_v1_PostInlineCommentResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_PostInlineCommentResponse,
  },
  createCheckRun: {
    path: '/mitig8it.github.v1.GitHubService/CreateCheckRun',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.CreateCheckRunRequest,
    responseType: github_pb.CreateCheckRunResponse,
    requestSerialize: serialize_mitig8it_github_v1_CreateCheckRunRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_CreateCheckRunRequest,
    responseSerialize: serialize_mitig8it_github_v1_CreateCheckRunResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_CreateCheckRunResponse,
  },
  prepareRemediation: {
    path: '/mitig8it.github.v1.GitHubService/PrepareRemediation',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationPrepareRequest,
    responseType: github_pb.RemediationPrepareResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationPrepareRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationPrepareRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationPrepareResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationPrepareResponse,
  },
  snapshotRemediation: {
    path: '/mitig8it.github.v1.GitHubService/SnapshotRemediation',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationSnapshotRequest,
    responseType: github_pb.RemediationSnapshotResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationSnapshotRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationSnapshotRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationSnapshotResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationSnapshotResponse,
  },
  commitRemediation: {
    path: '/mitig8it.github.v1.GitHubService/CommitRemediation',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationCommitRequest,
    responseType: github_pb.RemediationCommitResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationCommitRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationCommitRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationCommitResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationCommitResponse,
  },
  reconcileRemediation: {
    path: '/mitig8it.github.v1.GitHubService/ReconcileRemediation',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationReconcileRequest,
    responseType: github_pb.RemediationReconcileResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationReconcileRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationReconcileRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationReconcileResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationReconcileResponse,
  },
  mergeRemediation: {
    path: '/mitig8it.github.v1.GitHubService/MergeRemediation',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationMergeRequest,
    responseType: github_pb.RemediationMergeResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationMergeRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationMergeRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationMergeResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationMergeResponse,
  },
  cancelScheduledMerge: {
    path: '/mitig8it.github.v1.GitHubService/CancelScheduledMerge',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.CancelScheduledMergeRequest,
    responseType: github_pb.CancelScheduledMergeResponse,
    requestSerialize: serialize_mitig8it_github_v1_CancelScheduledMergeRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_CancelScheduledMergeRequest,
    responseSerialize: serialize_mitig8it_github_v1_CancelScheduledMergeResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_CancelScheduledMergeResponse,
  },
  readMergeEligibility: {
    path: '/mitig8it.github.v1.GitHubService/ReadMergeEligibility',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.MergeEligibilityRequest,
    responseType: github_pb.MergeEligibilityResponse,
    requestSerialize: serialize_mitig8it_github_v1_MergeEligibilityRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_MergeEligibilityRequest,
    responseSerialize: serialize_mitig8it_github_v1_MergeEligibilityResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_MergeEligibilityResponse,
  },
  readPullRequestHead: {
    path: '/mitig8it.github.v1.GitHubService/ReadPullRequestHead',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.PullRequestHeadRequest,
    responseType: github_pb.PullRequestHeadResponse,
    requestSerialize: serialize_mitig8it_github_v1_PullRequestHeadRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_PullRequestHeadRequest,
    responseSerialize: serialize_mitig8it_github_v1_PullRequestHeadResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_PullRequestHeadResponse,
  },
  createRemediationCheckRun: {
    path: '/mitig8it.github.v1.GitHubService/CreateRemediationCheckRun',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationCheckRunRequest,
    responseType: github_pb.RemediationCheckRunResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationCheckRunRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationCheckRunRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationCheckRunResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationCheckRunResponse,
  },
  healthCheck: {
    path: '/mitig8it.github.v1.GitHubService/HealthCheck',
    requestStream: false,
    responseStream: false,
    requestType: common_pb.HealthCheckRequest,
    responseType: common_pb.HealthCheckResponse,
    requestSerialize: serialize_mitig8it_common_v1_HealthCheckRequest,
    requestDeserialize: deserialize_mitig8it_common_v1_HealthCheckRequest,
    responseSerialize: serialize_mitig8it_common_v1_HealthCheckResponse,
    responseDeserialize: deserialize_mitig8it_common_v1_HealthCheckResponse,
  },
};

exports.GitHubServiceClient = grpc.makeGenericClientConstructor(GitHubServiceService, 'GitHubService');
