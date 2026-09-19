// Requires local HTTP + gRPC analysis processes, with LLM_TRIAGE_ENABLED=false.
const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const request = require('supertest');
const jwt = require('jsonwebtoken');
const dbUrl = new URL(process.env.DATABASE_URL || 'http://invalid');
assert.ok(['127.0.0.1', 'localhost'].includes(dbUrl.hostname) && dbUrl.pathname.endsWith('_test'));
assert.match(process.env.ANALYSIS_SERVICE_URL || '', /^http:\/\/(127\.0\.0\.1|localhost):\d+$/);
assert.match(process.env.ANALYSIS_GRPC_URL || '', /^(127\.0\.0\.1|localhost):\d+$/);
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'transport-local-fixture';
process.env.GRPC_TRANSPORT_TLS = 'false';
process.env.INTERNAL_SERVICE_TRANSPORT = 'http';
const { pool } = require('../../src/config/database');
const { callAnalysisTier } = require('../../src/services/prAnalysisOrchestrator');
const { AnalysisGrpcClient } = require('../../src/clients/analysisGrpcClient');
const { createApp } = require('../../src/app');
const grpc = new AnalysisGrpcClient(process.env.ANALYSIS_GRPC_URL);
const source = 'const result = eval(req.body.code); // git add .';
const payload = { repository_full_name: 'fixture/transport', pull_request_number: 1,
  commit_sha: 'a'.repeat(40), files: [{ path: 'handler.js', content: source,
    patch: `@@ -0,0 +1 @@\n+${source}`, additions: 1, status: 'added' }] };
after(async () => { grpc.client.close(); await pool.end(); });

test('real HTTP analysis rejects unauthenticated internal requests', async () => {
  const response = await fetch(`${process.env.ANALYSIS_SERVICE_URL}/analyze/pr/tier1`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
  });
  assert.equal(response.status, 401);
});

test('HTTP and gRPC produce matching deterministic and native AST findings', async () => {
  for (const tier of [1, 2]) {
    const http = await callAnalysisTier(`/analyze/pr/tier${tier}`, payload, 30000);
    const rpc = await grpc[tier === 1 ? 'analyzeTier1' : 'analyzeTier2'](payload, 30000);
    assert.ok(http.findings.some(f => f.rule_id.includes('eval')));
    assert.deepEqual(rpc.findings.map(f => f.rule_id).sort(), http.findings.map(f => f.rule_id).sort());
    assert.equal(rpc.commit_sha, payload.commit_sha);
  }
});

test('authenticated playground uses the real HTTP scanner and persists user history', async () => {
  const user = (await pool.query('INSERT INTO users (github_id, github_username) VALUES ($1,$2) RETURNING id',
    [Date.now(), `transport-${randomUUID()}`])).rows[0].id;
  const token = jwt.sign({ user_id: user }, process.env.JWT_SECRET);
  const response = await request(createApp()).post('/api/analysis/analyze').auth(token, { type: 'bearer' })
    .send({ code: source, language: 'javascript' });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  assert.ok(response.body.total_vulnerabilities > 0);
  const history = await request(createApp()).get('/api/analysis/history').auth(token, { type: 'bearer' });
  assert.equal(history.body.total, 1);
  assert.equal(history.body.analyses[0].analysis_id, response.body.analysis_id);
});

test('synthetic playground identifiers survive the production protobuf transport', async () => {
  const response = await grpc.analyzeTier1({ ...payload, repository_full_name: 'playground/code', pull_request_number: 0 });
  assert.ok(response.findings.length > 0);
});
