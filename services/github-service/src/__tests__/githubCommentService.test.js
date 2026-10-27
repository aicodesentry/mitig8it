// Every GitHub call needs a deadline. Without one a hung connection held the publication
// that made it (out-of-diff fix placement, the remediation comment) until the gRPC
// deadline on the caller's side expired, and kept the work running after the caller left.
jest.mock('axios', () => ({ post: jest.fn(), patch: jest.fn(), get: jest.fn() }));
jest.mock('../utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const axios = require('axios');
const service = require('../services/githubCommentService');
const { GITHUB_TIMEOUT_MS } = require('../services/githubTimeout');

beforeEach(() => {
  jest.clearAllMocks();
  axios.post.mockResolvedValue({ data: { id: 1 } });
  axios.patch.mockResolvedValue({ data: { id: 1 } });
  axios.get.mockResolvedValue({ data: [] });
});

test('the shared GitHub timeout is 25 seconds', () => {
  expect(GITHUB_TIMEOUT_MS).toBe(25000);
});

test('every comment call carries the GitHub timeout', async () => {
  await service.postReviewComment('o', 'r', 1, 'sha', 'a.py', 3, 'body', 'token');
  await service.postSummaryComment('o', 'r', 1, 'body', 'token');
  await service.updateSummaryComment('o', 'r', 5, 'body', 'token');
  await service.listSummaryComments('o', 'r', 1, 'token');
  const configs = [
    ...axios.post.mock.calls.map((call) => call[2]),
    axios.patch.mock.calls[0][2],
    axios.get.mock.calls[0][1],
  ];
  expect(configs).toHaveLength(4);
  for (const config of configs) expect(config.timeout).toBe(GITHUB_TIMEOUT_MS);
});
