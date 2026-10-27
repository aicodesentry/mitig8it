jest.mock('axios', () => jest.fn());
jest.mock('../services/githubAppAuth', () => ({
  getInstallationToken: jest.fn().mockResolvedValue('fixture-token'),
  getAppBotLogin: jest.fn().mockResolvedValue('fixture[bot]'),
}));
const axios = require('axios');
const quality = require('../services/qualityPublication');
const operations = require('../services/githubInternalOperations');

test('the packaged release cannot publish remediation before independent evidence exists', () => {
  expect(quality.remediationPublicationReady()).toBe(false);
  expect(() => quality.assertRemediationPublicationReady()).toThrow(/release evidence/);
});

test('the Action and App fix-publication seam rejects malformed input before any GitHub call', async () => {
  await expect(operations.publishFindingFixSections({ sections: [] }))
    .rejects.toMatchObject({ statusCode: 400 });
  expect(axios).not.toHaveBeenCalled();
});

test.each(['<!-- mitig8it-fix:candidate -->', '**Recommended fix**'])
('generic review/comment transports cannot bypass release admission: %s', async (body) => {
  await expect(operations.postInlineComment({ body })).rejects.toMatchObject({ code: 'REMEDIATION_RELEASE_EVIDENCE_MISSING' });
  await expect(operations.submitPullRequestReview({ body: 'review', comments: [{ body }] }))
    .rejects.toMatchObject({ code: 'REMEDIATION_RELEASE_EVIDENCE_MISSING' });
  await expect(operations.publishRemediationComment({ body }))
    .rejects.toMatchObject({ code: 'REMEDIATION_RELEASE_EVIDENCE_MISSING' });
  expect(axios).not.toHaveBeenCalled();
});

test('an unverified Tier 3 snippet can never become a GitHub commit suggestion', async () => {
  const body = '```suggestion\nsafe();\n```';
  expect(() => quality.assertReviewBodyReady(body)).toThrow(/sandbox-verified/);
  await expect(operations.postInlineComment({ body }))
    .rejects.toMatchObject({ code: 'UNVERIFIED_SUGGESTION_PROHIBITED', statusCode: 422 });
  await expect(operations.submitPullRequestReview({ body: 'review', comments: [{ body }] }))
    .rejects.toMatchObject({ code: 'UNVERIFIED_SUGGESTION_PROHIBITED', statusCode: 422 });
  expect(axios).not.toHaveBeenCalled();
});

test('a spoofed candidate marker cannot open the generic suggestion transport', () => {
  expect(() => quality.assertReviewBodyReady(
    '<!-- mitig8it-fix:candidate -->\n```suggestion\nsafe();\n```'
  )).toThrow(/sandbox-verified/);
});

test('ordinary finding evidence remains reportable without a repair quality claim', () => {
  expect(() => quality.assertReviewBodyReady('SQL injection detected.\n```js\neval(input);\n```')).not.toThrow();
});

test('re-analysis removes stale suggestion sections after release evidence is revoked', async () => {
  const stale = '<!-- mitig8it-finding:fp1 -->\nold\n\n<!-- mitig8it-fix:c1 -->\n'
    + '```suggestion\nsafe();\n```\n<!-- /mitig8it-fix:c1 -->';
  const comment = { id: 7, body: stale, user: { login: 'fixture[bot]' }, path: 'a.py', html_url: 'fixture' };
  axios.mockImplementation(async request => {
    if (request.url.includes('/comments?')) return { data: [comment] };
    if (request.method === 'patch') { comment.body = request.data.body; return { data: { id: 7 } }; }
    return { data: { head: { sha: 'head-a' } } };
  });
  await operations.postInlineComment({
    owner: 'owner', repo: 'repo', pr_number: 1, installation_id: 1, commit_sha: 'head-a',
    path: 'a.py', line: 1, body: '<!-- mitig8it-finding:fp1 -->\nnew',
  });
  expect(comment.body).toBe('<!-- mitig8it-finding:fp1 -->\nnew');
});
