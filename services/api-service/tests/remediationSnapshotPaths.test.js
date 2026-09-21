jest.mock('../src/services/githubRemediationClient', () => ({ GitHubRemediationClient: jest.fn() }));
jest.mock('../src/db/remediation', () => ({ hash: () => 'a'.repeat(64) }));

const { GitHubRemediationClient } = require('../src/services/githubRemediationClient');
const { loadSnapshot } = require('../src/services/remediationWorkflow');

const HEAD = '9'.repeat(40);
const BASE = 'e'.repeat(40);

test('the snapshot request names the finding files so the adapter selects them first', async () => {
  const snapshot = jest.fn(async () => ({ head_sha: HEAD, base_sha: BASE, head_tree_oid: '2'.repeat(40), files: [{ path: 'text.py', content: 'x', sha: 'f'.repeat(64) }], tree_entries: [{ path: 'text.py', mode: '100644', type: 'blob', sha: '1'.repeat(40), size: 1 }] }));
  GitHubRemediationClient.mockImplementation(() => ({ snapshot }));
  const job = { id: 'job-1', installation_id: 42, repository_full_name: 'owner/repo', creator_login: 'owner', pr_number: 52, head_sha: HEAD, base_sha: BASE };
  const result = await loadSnapshot(job, ['text.py', 'text.py', null]);
  expect(snapshot).toHaveBeenCalledWith(expect.objectContaining({ finding_paths: ['text.py'] }));
  expect(result.files.map((file) => file.path)).toEqual(['text.py']);
  expect(result.treeEntries).toEqual([{ path: 'text.py', mode: '100644', type: 'blob', sha: '1'.repeat(40) }]);
});
