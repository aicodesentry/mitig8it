// GENERATED CODE -- DO NOT EDIT!

'use strict';
var grpc = require('@grpc/grpc-js');
var analysis_pb = require('./analysis_pb.js');
var common_pb = require('./common_pb.js');
var google_protobuf_struct_pb = require('google-protobuf/google/protobuf/struct_pb.js');

function serialize_mitig8it_analysis_v1_AnalyzePullRequestRequest(arg) {
  if (!(arg instanceof analysis_pb.AnalyzePullRequestRequest)) {
    throw new Error('Expected argument of type mitig8it.analysis.v1.AnalyzePullRequestRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_analysis_v1_AnalyzePullRequestRequest(buffer_arg) {
  return analysis_pb.AnalyzePullRequestRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_analysis_v1_AnalyzePullRequestResponse(arg) {
  if (!(arg instanceof analysis_pb.AnalyzePullRequestResponse)) {
    throw new Error('Expected argument of type mitig8it.analysis.v1.AnalyzePullRequestResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_analysis_v1_AnalyzePullRequestResponse(buffer_arg) {
  return analysis_pb.AnalyzePullRequestResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_analysis_v1_TriageFindingsRequest(arg) {
  if (!(arg instanceof analysis_pb.TriageFindingsRequest)) {
    throw new Error('Expected argument of type mitig8it.analysis.v1.TriageFindingsRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_analysis_v1_TriageFindingsRequest(buffer_arg) {
  return analysis_pb.TriageFindingsRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_mitig8it_analysis_v1_TriageFindingsResponse(arg) {
  if (!(arg instanceof analysis_pb.TriageFindingsResponse)) {
    throw new Error('Expected argument of type mitig8it.analysis.v1.TriageFindingsResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_mitig8it_analysis_v1_TriageFindingsResponse(buffer_arg) {
  return analysis_pb.TriageFindingsResponse.deserializeBinary(new Uint8Array(buffer_arg));
}

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


var AnalysisServiceService = exports.AnalysisServiceService = {
  analyzePullRequest: {
    path: '/mitig8it.analysis.v1.AnalysisService/AnalyzePullRequest',
    requestStream: false,
    responseStream: false,
    requestType: analysis_pb.AnalyzePullRequestRequest,
    responseType: analysis_pb.AnalyzePullRequestResponse,
    requestSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    requestDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    responseSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
    responseDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
  },
  analyzeTier1: {
    path: '/mitig8it.analysis.v1.AnalysisService/AnalyzeTier1',
    requestStream: false,
    responseStream: false,
    requestType: analysis_pb.AnalyzePullRequestRequest,
    responseType: analysis_pb.AnalyzePullRequestResponse,
    requestSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    requestDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    responseSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
    responseDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
  },
  analyzeTier2: {
    path: '/mitig8it.analysis.v1.AnalysisService/AnalyzeTier2',
    requestStream: false,
    responseStream: false,
    requestType: analysis_pb.AnalyzePullRequestRequest,
    responseType: analysis_pb.AnalyzePullRequestResponse,
    requestSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    requestDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestRequest,
    responseSerialize: serialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
    responseDeserialize: deserialize_mitig8it_analysis_v1_AnalyzePullRequestResponse,
  },
  triageFindings: {
    path: '/mitig8it.analysis.v1.AnalysisService/TriageFindings',
    requestStream: false,
    responseStream: false,
    requestType: analysis_pb.TriageFindingsRequest,
    responseType: analysis_pb.TriageFindingsResponse,
    requestSerialize: serialize_mitig8it_analysis_v1_TriageFindingsRequest,
    requestDeserialize: deserialize_mitig8it_analysis_v1_TriageFindingsRequest,
    responseSerialize: serialize_mitig8it_analysis_v1_TriageFindingsResponse,
    responseDeserialize: deserialize_mitig8it_analysis_v1_TriageFindingsResponse,
  },
  healthCheck: {
    path: '/mitig8it.analysis.v1.AnalysisService/HealthCheck',
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

exports.AnalysisServiceClient = grpc.makeGenericClientConstructor(AnalysisServiceService, 'AnalysisService');
