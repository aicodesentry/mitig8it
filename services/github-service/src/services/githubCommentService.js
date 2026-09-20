const axios = require('axios');

class GitHubCommentService {
  /**
   * SCRUM-88: Post review comment on PR
   */
  async postReviewComment(owner, repo, prNumber, commitId, filePath, lineNumber, body, githubToken) {
    try {
      const url = `https://api.github.com/repos/${owner}/${repo}/pulls/${prNumber}/comments`;
      
      const response = await axios.post(url, {
        body: body,
        commit_id: commitId,
        path: filePath,
        line: lineNumber,
      }, {
        headers: {
          'Authorization': `Bearer ${githubToken}`,
          'Accept': 'application/vnd.github+json',
        }
      });

      return response.data;
    } catch (error) {
      console.error(`[ERROR] Failed to post comment on line ${lineNumber}:`, error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * SCRUM-88: Post summary comment on PR
   */
  async postSummaryComment(owner, repo, prNumber, body, githubToken) {
    try {
      const url = `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments`;

      const response = await axios.post(url, {
        body: body
      }, {
        headers: {
          'Authorization': `Bearer ${githubToken}`,
          'Accept': 'application/vnd.github+json',
        }
      });

      return response.data;
    } catch (error) {
      console.error('[ERROR] Failed to post summary comment:', error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Update an existing pull request summary comment in place.
   */
  async updateSummaryComment(owner, repo, commentId, body, githubToken) {
    try {
      const url = `https://api.github.com/repos/${owner}/${repo}/issues/comments/${commentId}`;
      const response = await axios.patch(url, { body }, {
        headers: {
          'Authorization': `Bearer ${githubToken}`,
          'Accept': 'application/vnd.github+json',
        }
      });
      return response.data;
    } catch (error) {
      console.error('[ERROR] Failed to update summary comment:', error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * One page of the pull request's issue comments, oldest first.
   */
  async listSummaryComments(owner, repo, prNumber, githubToken, page = 1) {
    const url = `https://api.github.com/repos/${owner}/${repo}/issues/${prNumber}/comments?per_page=100&page=${page}`;
    const response = await axios.get(url, {
      headers: {
        'Authorization': `Bearer ${githubToken}`,
        'Accept': 'application/vnd.github+json',
      }
    });
    return Array.isArray(response.data) ? response.data : [];
  }
}

module.exports = new GitHubCommentService();