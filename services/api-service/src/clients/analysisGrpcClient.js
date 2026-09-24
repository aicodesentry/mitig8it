const structPb = require('google-protobuf/google/protobuf/struct_pb');
const analysisPb = require('../grpc/generated/analysis_pb');
const analysisGrpc = require('../grpc/generated/analysis_grpc_pb');
const commonPb = require('../grpc/generated/common_pb');
const { createGrpcClientConfig } = require('./grpcConnection');
const {
  changedFileToMessage,
  findingToMessage,
  findingToPlain,
} = require('./grpcConverters');

function unary(client, method, request, timeoutMs) {
  return new Promise((resolve, reject) => {
    const deadline = new Date(Date.now() + timeoutMs);
    client[method](request, { deadline }, (error, response) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(response);
    });
  });
}

function buildAnalyzeRequest(payload = {}) {
  const request = new analysisPb.AnalyzePullRequestRequest();
  request.setRepositoryFullName(payload.repository_full_name || '');
  request.setPullRequestNumber(Number(payload.pull_request_number || 0));
  request.setCommitSha(payload.commit_sha || '');
  request.setFilesList((payload.files || []).map(changedFileToMessage));
  return request;
}

function limitationToPlain(limitation) {
  const line = limitation.getLine();
  return {
    path: limitation.getPath(),
    kind: limitation.getKind(),
    type: limitation.getType(),
    message: limitation.getMessage(),
    line: line > 0 ? line : null,
  };
}

function analyzeResponseToPlain(response) {
  return {
    repository_full_name: response.getRepositoryFullName(),
    pull_request_number: response.getPullRequestNumber(),
    commit_sha: response.getCommitSha(),
    files_analyzed: response.getFilesAnalyzed(),
    tier: response.getTier(),
    findings: response.getFindingsList().map(findingToPlain),
    analysis_limitations: response.getAnalysisLimitationsList().map(limitationToPlain),
  };
}

function buildTriageRequest(payload = {}) {
  const request = new analysisPb.TriageFindingsRequest();
  request.setRepositoryFullName(payload.repository_full_name || '');
  request.setPullRequestNumber(Number(payload.pull_request_number || 0));
  request.setCommitSha(payload.commit_sha || '');
  request.setFindingsList((payload.findings || []).map(findingToMessage));
  request.getFilePatchesMap().clear();
  for (const [path, patch] of Object.entries(payload.file_patches || {})) {
    request.getFilePatchesMap().set(path, patch || '');
  }
  if (payload.repo_profile && typeof payload.repo_profile === 'object') {
    const repoProfile = new commonPb.RepoProfile();
    repoProfile.setData(structPb.Struct.fromJavaScript(payload.repo_profile));
    request.setRepoProfile(repoProfile);
  }
  return request;
}

function triageResponseToPlain(response) {
  return {
    repository_full_name: response.getRepositoryFullName(),
    pull_request_number: response.getPullRequestNumber(),
    commit_sha: response.getCommitSha(),
    tier: response.getTier(),
    findings: response.getFindingsList().map(findingToPlain),
    filtered_count: response.getFilteredCount(),
  };
}

class AnalysisGrpcClient {
  constructor(target = process.env.ANALYSIS_GRPC_URL || 'analysis-service:50052') {
    const config = createGrpcClientConfig({
      target,
      fallbackTarget: 'analysis-service:50052',
      audience: process.env.ANALYSIS_GRPC_AUDIENCE,
    });
    this.client = new analysisGrpc.AnalysisServiceClient(
      config.target,
      config.credentials
    );
  }

  async analyzePullRequest(payload, timeoutMs = 120000) {
    const response = await unary(this.client, 'analyzePullRequest', buildAnalyzeRequest(payload), timeoutMs);
    return analyzeResponseToPlain(response);
  }

  async analyzeTier1(payload, timeoutMs = 30000) {
    const response = await unary(this.client, 'analyzeTier1', buildAnalyzeRequest(payload), timeoutMs);
    return analyzeResponseToPlain(response);
  }

  async analyzeTier2(payload, timeoutMs = 60000) {
    const response = await unary(this.client, 'analyzeTier2', buildAnalyzeRequest(payload), timeoutMs);
    return analyzeResponseToPlain(response);
  }

  async triageFindings(payload, timeoutMs = 120000) {
    const response = await unary(this.client, 'triageFindings', buildTriageRequest(payload), timeoutMs);
    return triageResponseToPlain(response);
  }
}

module.exports = {
  AnalysisGrpcClient,
  buildAnalyzeRequest,
  buildTriageRequest,
  analyzeResponseToPlain,
};
