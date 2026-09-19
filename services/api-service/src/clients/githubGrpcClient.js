const githubPb = require('../grpc/generated/github_pb');
const githubGrpc = require('../grpc/generated/github_grpc_pb');
const commonPb = require('../grpc/generated/common_pb');
const { createGrpcClientConfig } = require('./grpcConnection');
const { changedFileToPlain } = require('./grpcConverters');

function unary(client, method, request, timeoutMs = 45000) {
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
    return { files: response.getFilesList().map(changedFileToPlain) };
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
};
