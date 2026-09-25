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

function serialize_mitig8it_github_v1_FindingFixSectionsRequest(arg) {
  if (!(arg instanceof github_pb.FindingFixSectionsRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FindingFixSectionsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FindingFixSectionsRequest(buffer_arg) {
  return github_pb.FindingFixSectionsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_FindingFixSectionsResponse(arg) {
  if (!(arg instanceof github_pb.FindingFixSectionsResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.FindingFixSectionsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_FindingFixSectionsResponse(buffer_arg) {
  return github_pb.FindingFixSectionsResponse.deserializeBinary(new Uint8Array(buffer_arg));
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

function serialize_mitig8it_github_v1_RemediationCommentRequest(arg) {
  if (!(arg instanceof github_pb.RemediationCommentRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCommentRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCommentRequest(buffer_arg) {
  return github_pb.RemediationCommentRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RemediationCommentResponse(arg) {
  if (!(arg instanceof github_pb.RemediationCommentResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RemediationCommentResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RemediationCommentResponse(buffer_arg) {
  return github_pb.RemediationCommentResponse.deserializeBinary(new Uint8Array(buffer_arg));
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

function serialize_mitig8it_github_v1_RetireInlineCommentsRequest(arg) {
  if (!(arg instanceof github_pb.RetireInlineCommentsRequest)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RetireInlineCommentsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RetireInlineCommentsRequest(buffer_arg) {
  return github_pb.RetireInlineCommentsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_github_v1_RetireInlineCommentsResponse(arg) {
  if (!(arg instanceof github_pb.RetireInlineCommentsResponse)) {
    throw new Error('Expected argument of type mitig8it.github.v1.RetireInlineCommentsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_github_v1_RetireInlineCommentsResponse(buffer_arg) {
  return github_pb.RetireInlineCommentsResponse.deserializeBinary(new Uint8Array(buffer_arg));
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
  retireInlineComments: {
    path: '/mitig8it.github.v1.GitHubService/RetireInlineComments',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RetireInlineCommentsRequest,
    responseType: github_pb.RetireInlineCommentsResponse,
    requestSerialize: serialize_mitig8it_github_v1_RetireInlineCommentsRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RetireInlineCommentsRequest,
    responseSerialize: serialize_mitig8it_github_v1_RetireInlineCommentsResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RetireInlineCommentsResponse,
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
  publishRemediationComment: {
    path: '/mitig8it.github.v1.GitHubService/PublishRemediationComment',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.RemediationCommentRequest,
    responseType: github_pb.RemediationCommentResponse,
    requestSerialize: serialize_mitig8it_github_v1_RemediationCommentRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_RemediationCommentRequest,
    responseSerialize: serialize_mitig8it_github_v1_RemediationCommentResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_RemediationCommentResponse,
  },
  publishFindingFixSections: {
    path: '/mitig8it.github.v1.GitHubService/PublishFindingFixSections',
    requestStream: false,
    responseStream: false,
    requestType: github_pb.FindingFixSectionsRequest,
    responseType: github_pb.FindingFixSectionsResponse,
    requestSerialize: serialize_mitig8it_github_v1_FindingFixSectionsRequest,
    requestDeserialize: deserialize_mitig8it_github_v1_FindingFixSectionsRequest,
    responseSerialize: serialize_mitig8it_github_v1_FindingFixSectionsResponse,
    responseDeserialize: deserialize_mitig8it_github_v1_FindingFixSectionsResponse,
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
