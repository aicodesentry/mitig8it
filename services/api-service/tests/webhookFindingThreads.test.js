const crypto = require('crypto');
const request = require('supertest');

jest.mock('../src/config/database', () => ({ pool: { query: jest.fn() }, transaction: jest.fn() }));
jest.mock('../src/services/prAnalysisOrchestrator', () => ({ notifyAnalysisQueued: jest.fn() }));
jest.mock('../src/db/installations', () => ({ upsertInstallation: jest.fn() }));
jest.mock('../src/db/remediation', () => ({
  supersedeForBranchPush: jest.fn(async () => ({})),
  supersedeForHeadChange: jest.fn(async () => ({ jobs: [], candidates: [], mergeIntents: [] })),
  // The same push scan that records the outcome also records the observed apply
  // action (PR 442); the handler walks the pushed commits once and feeds both.
  recordObservedApply: jest.fn(async () => ([])),
}));
jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn() }));

const { transaction } = require('../src/config/database');
const remediationDb = require('../src/db/remediation');
const { createApp } = require('../src/app');

const SECRET = 'webhook-test-secret';
const FINGERPRINT = 'c'.repeat(64);
const MARKER = `<!-- mitig8it-finding:${FINGERPRINT} -->`;

const FINDING = {
  id: 'finding-1',
  fingerprint: FINGERPRINT,
  rule_id: 'sql.injection.raw_query',
  cwe_id: 'CWE-89',
  severity: 'high',
  confidence: 0.9,
  category: 'SQL injection',
  repository_id: 'repo-1',
  installation_id: 77,
  pull_request_id: 'pr-1',
  file_path: 'services/orders.js',
  line_start: 12,
  status: 'open',
};

// One in-memory stand-in for the database, shared across deliveries in a test so a
// redelivery meets the state the first delivery left behind.
function createDatabase(overrides = {}) {
  const state = {
    deliveries: new Map(),
    outcomeKeys: new Set(),
    outcomes: [],
    statusUpdates: [],
    inlineCommentUpdates: [],
    findings: [{ ...FINDING }],
    publishedFindingIds: ['finding-1'],
    openPullRequests: [{ id: 'pr-1' }],
    ...overrides,
  };

  const client = {
    query: jest.fn(async (sql, params = []) => {
      if (sql.includes('INSERT INTO webhook_deliveries')) {
        const [deliveryId] = params;
        const seen = state.deliveries.get(deliveryId);
        if (seen === 'processed') return { rowCount: 0, rows: [] };
        state.deliveries.set(deliveryId, 'received');
        return { rowCount: 1, rows: [{ delivery_id: deliveryId }] };
      }
      if (sql.includes('UPDATE webhook_deliveries')) {
        state.deliveries.set(params[0], 'processed');
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes('FROM repositories WHERE github_id')) {
        return { rowCount: 1, rows: [{ id: 'repo-1', installation_id: 77 }] };
      }
      if (sql.includes('SELECT installation_id FROM repositories WHERE id')) {
        return { rowCount: 1, rows: [{ installation_id: 77 }] };
      }
      if (sql.includes('FROM pull_requests WHERE repository_id = $1 AND pr_number')) {
        return { rowCount: 1, rows: [{ id: 'pr-1' }] };
      }
      if (sql.includes('FROM pull_requests WHERE repository_id = $1 AND head_branch')) {
        return { rowCount: state.openPullRequests.length, rows: state.openPullRequests };
      }
      if (sql.includes('UPDATE findings SET inline_comment_id')) {
        const [, , fingerprint, commentId] = params;
        const finding = state.findings.find((row) => row.fingerprint === fingerprint);
        if (!finding || finding.inline_comment_id === commentId) return { rowCount: 0, rows: [] };
        finding.inline_comment_id = commentId;
        state.inlineCommentUpdates.push({ fingerprint, commentId });
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes('FROM findings') && sql.includes('AND fingerprint = $3')) {
        const found = state.findings.find((row) => row.fingerprint === params[2]);
        return { rowCount: found ? 1 : 0, rows: found ? [found] : [] };
      }
      if (sql.includes('FROM findings') && sql.includes('AND inline_comment_id = $2')) {
        const found = state.findings.find((row) => row.inline_comment_id === params[1]);
        return { rowCount: found ? 1 : 0, rows: found ? [found] : [] };
      }
      if (sql.includes('FROM findings') && sql.includes('file_path = ANY')) {
        const paths = params[2] || [];
        const found = state.findings.filter((row) => paths.includes(row.file_path));
        return { rowCount: found.length, rows: found };
      }
      if (sql.includes("UPDATE findings SET status = 'dismissed'")) {
        state.statusUpdates.push({ findingId: params[0], reason: params[1] });
        const finding = state.findings.find((row) => row.id === params[0]);
        if (finding) finding.status = 'dismissed';
        return { rowCount: 1, rows: [] };
      }
      if (sql.includes('SELECT DISTINCT finding_id FROM finding_outcomes')) {
        return {
          rowCount: state.publishedFindingIds.length,
          rows: state.publishedFindingIds.map((finding_id) => ({ finding_id })),
        };
      }
      if (sql.includes('INSERT INTO finding_outcomes')) {
        const key = [params[3] || 'none', params[4], params[10], params[11], params[18] || ''].join('|');
        if (state.outcomeKeys.has(key)) return { rowCount: 0, rows: [] };
        state.outcomeKeys.add(key);
        state.outcomes.push({
          installation_id: params[0], repository_id: params[1], pull_request_id: params[2],
          finding_id: params[3], fingerprint: params[4], rule_id: params[5],
          outcome: params[10], source: params[11], reason: params[12], actor_login: params[13],
          commit_sha: params[17], external_id: params[18],
        });
        return { rowCount: 1, rows: [{ id: `outcome-${state.outcomes.length}` }] };
      }
      return { rowCount: 0, rows: [] };
    }),
  };

  transaction.mockImplementation(async (fn) => fn(client));
  return state;
}

async function deliver(event, payload, deliveryId) {
  const body = JSON.stringify(payload);
  const signature = `sha256=${crypto.createHmac('sha256', SECRET).update(body).digest('hex')}`;
  return request(createApp())
    .post('/webhooks/github')
    .set('x-github-event', event)
    .set('x-github-delivery', deliveryId)
    .set('x-hub-signature-256', signature)
    .set('content-type', 'application/json')
    .send(body);
}

const REPOSITORY = { id: 999, full_name: 'acme/service' };
const PULL_REQUEST = { number: 12 };

function threadPayload(action, { rootBody = MARKER + '\nSQL injection', nodeId = 'PRRT_thread1' } = {}) {
  return {
    action,
    thread: {
      node_id: nodeId,
      comments: [
        { id: 501, node_id: 'PRRC_root', in_reply_to_id: null, body: rootBody, path: 'services/orders.js' },
        { id: 502, node_id: 'PRRC_reply', in_reply_to_id: 501, body: 'agreed' },
      ],
    },
    pull_request: PULL_REQUEST,
    repository: REPOSITORY,
    sender: { login: 'reviewer-1' },
    installation: { id: 77 },
  };
}

function commentPayload({ body, inReplyTo = 501, id = 600 }) {
  return {
    action: 'created',
    comment: { id, node_id: `PRRC_${id}`, in_reply_to_id: inReplyTo, body, path: 'services/orders.js', user: { login: 'reviewer-1' } },
    pull_request: PULL_REQUEST,
    repository: REPOSITORY,
    sender: { login: 'reviewer-1' },
    installation: { id: 77 },
  };
}

beforeEach(() => {
  jest.clearAllMocks();
  process.env.GITHUB_WEBHOOK_SECRET = SECRET;
  process.env.GITHUB_APP_SLUG = 'mitig8it';
});

describe('pull_request_review_thread', () => {
  test('records thread_resolved for the finding the root comment marks', async () => {
    const state = createDatabase();
    const res = await deliver('pull_request_review_thread', threadPayload('resolved'), 'thread-resolve-1');

    expect(res.status).toBe(200);
    expect(state.outcomes).toHaveLength(1);
    expect(state.outcomes[0]).toMatchObject({
      finding_id: 'finding-1',
      fingerprint: FINGERPRINT,
      outcome: 'thread_resolved',
      source: 'github_thread',
      actor_login: 'reviewer-1',
      external_id: 'PRRT_thread1',
    });
  });

  test('records thread_unresolved when the thread is reopened', async () => {
    const state = createDatabase();
    await deliver('pull_request_review_thread', threadPayload('unresolved'), 'thread-unresolve-1');
    expect(state.outcomes[0].outcome).toBe('thread_unresolved');
  });

  test('a redelivery of the same thread event records nothing new', async () => {
    const state = createDatabase();
    await deliver('pull_request_review_thread', threadPayload('resolved'), 'thread-resolve-1');
    // A different delivery id carrying the identical event is the realistic replay: the
    // delivery table does not deduplicate it, the outcome key does.
    await deliver('pull_request_review_thread', threadPayload('resolved'), 'thread-resolve-2');
    expect(state.outcomes).toHaveLength(1);
  });

  test('remembers the root comment so a later reply can be resolved', async () => {
    const state = createDatabase();
    await deliver('pull_request_review_thread', threadPayload('resolved'), 'thread-resolve-1');
    expect(state.inlineCommentUpdates).toEqual([{ fingerprint: FINGERPRINT, commentId: '501' }]);
  });

  test('ignores a thread that is not one of ours', async () => {
    const state = createDatabase();
    const res = await deliver(
      'pull_request_review_thread',
      threadPayload('resolved', { rootBody: 'Please rename this variable' }),
      'thread-foreign-1'
    );
    expect(res.status).toBe(200);
    expect(state.outcomes).toHaveLength(0);
  });

  test('survives a payload with no thread comments', async () => {
    const state = createDatabase();
    const payload = threadPayload('resolved');
    delete payload.thread.comments;
    const res = await deliver('pull_request_review_thread', payload, 'thread-empty-1');
    expect(res.status).toBe(200);
    expect(state.outcomes).toHaveLength(0);
  });
});

describe('pull_request_review_comment', () => {
  test('remembers the app\'s own marked comment without recording an outcome', async () => {
    const state = createDatabase();
    const res = await deliver(
      'pull_request_review_comment',
      commentPayload({ body: `${MARKER}\nSQL injection`, inReplyTo: null, id: 501 }),
      'comment-root-1'
    );

    expect(res.status).toBe(200);
    expect(state.inlineCommentUpdates).toEqual([{ fingerprint: FINGERPRINT, commentId: '501' }]);
    expect(state.outcomes).toHaveLength(0);
  });

  test.each([
    ['Not an issue, the input is validated upstream.', 'wrong_rule_match'],
    ['False positive', 'not_exploitable'],
    ['/mitig8it dismiss', 'wrong_rule_match'],
    ['/mitig8it dismiss test_or_sample_code', 'test_or_sample_code'],
  ])('a reply of %p dismisses the finding with reason %p', async (body, reason) => {
    const state = createDatabase({ findings: [{ ...FINDING, inline_comment_id: '501' }] });
    const res = await deliver('pull_request_review_comment', commentPayload({ body }), `comment-${reason}-${body.length}`);

    expect(res.status).toBe(200);
    expect(state.statusUpdates).toEqual([{ findingId: 'finding-1', reason }]);
    expect(state.outcomes).toHaveLength(1);
    expect(state.outcomes[0]).toMatchObject({
      outcome: 'dismissed', source: 'github_thread', reason, external_id: '600',
    });
  });

  test('ignores a reply that is not a command', async () => {
    const state = createDatabase({ findings: [{ ...FINDING, inline_comment_id: '501' }] });
    await deliver('pull_request_review_comment', commentPayload({ body: 'Good catch, fixing now.' }), 'comment-chat-1');
    expect(state.outcomes).toHaveLength(0);
    expect(state.statusUpdates).toHaveLength(0);
  });

  test('ignores a command on a thread the log does not know', async () => {
    const state = createDatabase({ findings: [{ ...FINDING, inline_comment_id: null }] });
    await deliver('pull_request_review_comment', commentPayload({ body: 'false positive' }), 'comment-unknown-1');
    expect(state.outcomes).toHaveLength(0);
    expect(state.statusUpdates).toHaveLength(0);
  });

  test('a redelivered dismissal reply records the dismissal once', async () => {
    const state = createDatabase({ findings: [{ ...FINDING, inline_comment_id: '501' }] });
    await deliver('pull_request_review_comment', commentPayload({ body: 'false positive' }), 'comment-replay-1');
    await deliver('pull_request_review_comment', commentPayload({ body: 'false positive' }), 'comment-replay-2');
    expect(state.outcomes).toHaveLength(1);
  });
});

describe('push carrying a Commit suggestion', () => {
  function pushPayload(message, sha = 'f'.repeat(40)) {
    return {
      ref: 'refs/heads/feature/orders',
      after: sha,
      repository: REPOSITORY,
      sender: { login: 'reviewer-1' },
      installation: { id: 77 },
      commits: [{ id: sha, message, modified: ['services/orders.js'], added: [], removed: [] }],
    };
  }

  test('records applied_on_github for a published fix the reviewer committed', async () => {
    const state = createDatabase();
    remediationDb.recordObservedApply.mockClear();
    const res = await deliver(
      'push',
      pushPayload('Update services/orders.js\n\nCo-authored-by: mitig8it[bot] <1234+mitig8it[bot]@users.noreply.github.com>'),
      'push-suggestion-1'
    );

    expect(res.status).toBe(200);
    expect(state.outcomes).toHaveLength(1);
    expect(state.outcomes[0]).toMatchObject({
      finding_id: 'finding-1',
      outcome: 'applied_on_github',
      source: 'github_push',
      commit_sha: 'f'.repeat(40),
      external_id: 'f'.repeat(40),
    });
    // One scan of the pushed commits, two records: the outcome above and the observed
    // apply action the residual report and the verification check hang off.
    expect(remediationDb.recordObservedApply).toHaveBeenCalledTimes(1);
    expect(remediationDb.recordObservedApply).toHaveBeenCalledWith(expect.objectContaining({
      repositoryGithubId: REPOSITORY.id,
      branch: 'feature/orders',
      commitSha: 'f'.repeat(40),
    }));
  });

  test('uses the configured app slug rather than a literal bot name', async () => {
    process.env.GITHUB_APP_SLUG = 'acme-reviewer';
    const state = createDatabase();
    await deliver(
      'push',
      pushPayload('Update services/orders.js\n\nCo-authored-by: acme-reviewer[bot] <x@users.noreply.github.com>'),
      'push-slug-1'
    );
    expect(state.outcomes).toHaveLength(1);

    const other = createDatabase();
    await deliver(
      'push',
      pushPayload('Update services/orders.js\n\nCo-authored-by: mitig8it[bot] <x@users.noreply.github.com>'),
      'push-slug-2'
    );
    expect(other.outcomes).toHaveLength(0);
  });

  test('ignores an ordinary commit', async () => {
    const state = createDatabase();
    await deliver('push', pushPayload('Fix the order lookup'), 'push-plain-1');
    expect(state.outcomes).toHaveLength(0);
  });

  test('ignores a file with no published fix', async () => {
    const state = createDatabase({ publishedFindingIds: [] });
    await deliver(
      'push',
      pushPayload('Update services/orders.js\n\nCo-authored-by: mitig8it[bot] <x@users.noreply.github.com>'),
      'push-nofix-1'
    );
    expect(state.outcomes).toHaveLength(0);
  });

  test('a redelivered push records the apply once', async () => {
    const state = createDatabase();
    const message = 'Update services/orders.js\n\nCo-authored-by: mitig8it[bot] <x@users.noreply.github.com>';
    await deliver('push', pushPayload(message), 'push-replay-1');
    await deliver('push', pushPayload(message), 'push-replay-2');
    expect(state.outcomes).toHaveLength(1);
  });
});

describe('signature handling is unchanged for the new events', () => {
  test('an unsigned review thread delivery is refused before any work', async () => {
    const state = createDatabase();
    const res = await request(createApp())
      .post('/webhooks/github')
      .set('x-github-event', 'pull_request_review_thread')
      .set('x-github-delivery', 'thread-unsigned-1')
      .set('x-hub-signature-256', 'sha256=deadbeef')
      .send(threadPayload('resolved'));

    expect(res.status).toBe(401);
    expect(state.outcomes).toHaveLength(0);
  });
});
