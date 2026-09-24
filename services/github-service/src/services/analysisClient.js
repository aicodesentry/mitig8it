const axios = require('axios');
const logger = require('../utils/logger');
const requestContext = require('../utils/requestContext');

const ANALYSIS_SERVICE_URL = process.env.ANALYSIS_SERVICE_URL || 'http://analysis-service:8001';

function analysisHeaders() {
  const internalSecret =
    process.env.ANALYSIS_SERVICE_INTERNAL_SECRET || process.env.GITHUB_SERVICE_INTERNAL_SECRET;

  // The correlation headers go out either way: an unauthenticated call is still work
  // an operator will want to find next to the delivery that caused it.
  if (!internalSecret) {
    return { ...requestContext.toHeaders() };
  }

  return { 'x-internal-secret': internalSecret, ...requestContext.toHeaders() };
}

class AnalysisClient {
  /**
   * Call analysis-service and return canonical findings payload.
   */
  async analyzeCode(code, filePath, prNumber, repository, retries = 2) {
    const payload = {
      repository_full_name: repository,
      pull_request_number: Number(prNumber),
      commit_sha: 'unknown',
      files: [
        {
          path: filePath,
          patch: code,
          additions: 0,
          deletions: 0,
          status: 'modified',
        },
      ],
    };

    try {
      logger.info(`[ANALYZE] Analyzing Python file: ${filePath}`);
      const response = await axios.post(`${ANALYSIS_SERVICE_URL}/analyze/pr`, payload, {
        headers: analysisHeaders(),
        timeout: 600000,
      });
      const data = response.data;
      logger.info(`[SUCCESS] Analysis complete: ${(data.findings || []).length} findings found`);
      return data;
    } catch (error) {
      logger.error(`[ERROR] Analysis failed for ${filePath}:`, error.message);

      if (retries > 0 && error.response && [502, 503, 504].includes(error.response.status)) {
        logger.info(`[RETRY] Retrying analysis for ${filePath} (${retries} retries left)...`);
        await new Promise((resolve) => setTimeout(resolve, 5000));
        return this.analyzeCode(code, filePath, prNumber, repository, retries - 1);
      }

      logger.error(`[SKIP] Skipping ${filePath} due to analysis failure`);
      return {
        repository_full_name: repository,
        pull_request_number: Number(prNumber),
        commit_sha: 'unknown',
        files_analyzed: 1,
        findings: [],
        error: error.message,
      };
    }
  }

  async healthCheck() {
    try {
      const response = await axios.get(`${ANALYSIS_SERVICE_URL}/health`, {
        timeout: 5000
      });
      return response.data;
    } catch (error) {
      logger.error('[ERROR] Analysis service health check failed:', error.message);
      return null;
    }
  }
}

module.exports = new AnalysisClient();
