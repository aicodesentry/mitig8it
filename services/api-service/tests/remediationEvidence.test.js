/**
 * The repair service runs on an execution backend whose record does not outlive the
 * instance that ran it. These tests pin what the control plane copies out of a repair
 * response before that happens, what it refuses to copy, and where it truncates.
 */
jest.mock('../src/config/database', () => ({ pool: { query: jest.fn(), connect: jest.fn() } }));

const {
  buildEvidenceRecords, MAX_TRACE_ENTRIES, MAX_OUTPUT_TAIL_BYTES,
} = require('../src/services/remediationWorkflow');

function byKind(records) {
  return Object.fromEntries(records.map((record) => [record.kind, record.payload]));
}

function response(overrides = {}) {
  return {
    state: 'ready',
    candidates: [{
      artifact_digest: 'a'.repeat(64), finding_ids: ['finding-1'],
      preview: { changes: [{ path: 'src/app.js', contents_base64: 'c2VjcmV0' }],
        evidence: { status: 'passed', verification_level: 'independent_sandbox', evidence_digest: 'e'.repeat(64),
          verified_tree_oid: 'f'.repeat(40), summary: ['Regression test t.js failed on the original code and passed on the fix.'],
          limitations: ['Not run: repository test suite.'] } },
    }],
    skipped: [{ finding_id: 'finding-2', code: 'not_repaired', message: 'No candidate proved this finding.' }],
    evidence: {
      agent_trace: [
        { sequence: 1, tool: 'read_file', arguments_digest_only: { path_digest: 'abc' }, outcome: 'ok', reason: null, result_bytes: 412 },
        { sequence: 2, tool: 'propose_patch', outcome: 'rejected', reason: 'patch_context_mismatch', result_bytes: 88 },
      ],
      usage: { input_tokens: 1200, output_tokens: 340, provider_request_ids: ['req_1', 'req_2'] },
      budget_reservation: { settled_calls: 2, overage_calls: 1, overage_tokens: 40, overage_usd: 0.002,
        settlements: [{ call_index: 1, reserved_tokens: 900, reserved_usd: 0.01, actual_tokens: 940, actual_usd: 0.012, overage_tokens: 40, overage_usd: 0.002 }] },
      groups: [{ group_index: 0, finding_ids: ['finding-1', 'finding-2'], state: 'ready', reason: null,
        candidate_ids: ['cand-1'], repaired_finding_ids: ['finding-1'], language: 'javascript',
        coverage: { revisions_used: 1, max_revisions: 2, proven_finding_ids: ['finding-1'], stopped: 'revision_budget_spent' },
        unproven_findings: [{ finding_id: 'finding-2', code: 'not_repaired', message: 'no test' }] }],
      verification_level: 'independent_sandbox',
      verified_tree_oid: 'f'.repeat(40),
      limitations: ['Not run: repository test suite.'],
      verification_run: {
        outcome: 'passed', reason_code: null,
        checks: [{ check_id: 'generated_regression', kind: 'generated_test', finding_id: 'finding-1',
          baseline: { completed: true, status: 'failed', exit_code: 1, duration_ms: 90, output_tail: 'AssertionError: expected safe query' },
          candidate: { completed: true, status: 'passed', exit_code: 0, duration_ms: 84, output_tail: null } }],
        coverage_gaps: [],
      },
    },
    ...overrides,
  };
}

describe('repair evidence shape', () => {
  test('every durable kind is produced from one repair response', () => {
    const kinds = buildEvidenceRecords(response(), { cost: 0.0123 }).map((record) => record.kind).sort();
    expect(kinds).toEqual(['agent_trace', 'budget_reservation', 'candidate_evidence', 'groups', 'usage', 'verification']);
  });

  test('a trace entry keeps the tool, sequence, outcome, reason and size, and nothing else', () => {
    const { agent_trace: trace } = byKind(buildEvidenceRecords(response()));
    expect(trace.total).toBe(2);
    expect(trace.truncated).toBe(false);
    expect(Object.keys(trace.items[0]).sort()).toEqual(['outcome', 'reason', 'result_bytes', 'sequence', 'tool']);
    expect(trace.items[0]).toEqual({ sequence: 1, tool: 'read_file', outcome: 'ok', reason: null, result_bytes: 412 });
    expect(trace.items[1].reason).toBe('patch_context_mismatch');
  });

  test('tool arguments never enter the trace', () => {
    const serialized = JSON.stringify(buildEvidenceRecords(response()));
    expect(serialized).not.toContain('arguments_digest_only');
    expect(serialized).not.toContain('path_digest');
  });

  test('file contents never enter the evidence', () => {
    const serialized = JSON.stringify(buildEvidenceRecords(response()));
    expect(serialized).not.toContain('contents_base64');
    expect(serialized).not.toContain('c2VjcmV0');
  });

  test('the trace is truncated at the bounded entry count and says so', () => {
    const long = response();
    long.evidence.agent_trace = Array.from({ length: MAX_TRACE_ENTRIES + 37 },
      (_, index) => ({ sequence: index + 1, tool: 'read_file', outcome: 'ok', reason: null, result_bytes: 1 }));
    const { agent_trace: trace } = byKind(buildEvidenceRecords(long));
    expect(trace.items).toHaveLength(MAX_TRACE_ENTRIES);
    expect(trace.total).toBe(MAX_TRACE_ENTRIES + 37);
    expect(trace.truncated).toBe(true);
  });

  test('a check output tail is truncated to the bound and keeps the end, where the failure is', () => {
    const long = response();
    const output = `${'x'.repeat(MAX_OUTPUT_TAIL_BYTES * 3)}AssertionError at the very end`;
    long.evidence.verification_run.checks[0].baseline.output_tail = output;
    const { verification } = byKind(buildEvidenceRecords(long));
    const kept = verification.checks.items[0].baseline;
    expect(Buffer.byteLength(kept.output_tail, 'utf8')).toBe(MAX_OUTPUT_TAIL_BYTES);
    expect(kept.output_tail.endsWith('AssertionError at the very end')).toBe(true);
    expect(kept.output_truncated).toBe(true);
  });

  test('a short output tail is kept whole and not marked truncated', () => {
    const { verification } = byKind(buildEvidenceRecords(response()));
    expect(verification.checks.items[0].baseline.output_tail).toBe('AssertionError: expected safe query');
    expect(verification.checks.items[0].baseline.output_truncated).toBe(false);
    expect(verification.checks.items[0].candidate.status).toBe('passed');
    expect(verification.verification_level).toBe('independent_sandbox');
  });

  test('usage carries the tokens and the settled cost the control plane computed', () => {
    const { usage } = byKind(buildEvidenceRecords(response(), { cost: 0.0123 }));
    expect(usage).toEqual({ input_tokens: 1200, output_tokens: 340, cost_usd: 0.0123, provider_request_ids: ['req_1', 'req_2'] });
  });

  test('budget settlements are kept so an overage stays visible after the job ends', () => {
    const { budget_reservation: reservation } = byKind(buildEvidenceRecords(response()));
    expect(reservation.overage_calls).toBe(1);
    expect(reservation.settlements.items[0]).toMatchObject({ call_index: 1, actual_tokens: 940, overage_usd: 0.002 });
  });

  test('groups record coverage, the candidate ids and why a finding was skipped', () => {
    const { groups } = byKind(buildEvidenceRecords(response()));
    expect(groups.groups.items[0].coverage).toEqual({ revisions_used: 1, max_revisions: 2, proven_finding_ids: ['finding-1'], stopped: 'revision_budget_spent' });
    expect(groups.groups.items[0].candidate_ids).toEqual(['cand-1']);
    expect(groups.groups.items[0].unproven_findings[0]).toMatchObject({ finding_id: 'finding-2', code: 'not_repaired' });
    expect(groups.skipped.items[0]).toMatchObject({ finding_id: 'finding-2', code: 'not_repaired' });
  });

  test("each candidate's own preview evidence is kept alongside its digest", () => {
    const { candidate_evidence: candidates } = byKind(buildEvidenceRecords(response()));
    expect(candidates.items[0].artifact_digest).toBe('a'.repeat(64));
    expect(candidates.items[0].finding_ids).toEqual(['finding-1']);
    expect(candidates.items[0].evidence.verification_level).toBe('independent_sandbox');
    expect(candidates.items[0].evidence.summary.items[0]).toMatch(/Regression test/);
  });

  test('a response that repaired nothing still records why', () => {
    const failed = response({ state: 'inconclusive', candidates: [] });
    failed.evidence.verification = { outcome: 'failed', reason_code: 'regression_test_not_reproducing', checks: [], coverage_gaps: [] };
    delete failed.evidence.verification_run;
    const records = byKind(buildEvidenceRecords(failed));
    expect(records.candidate_evidence).toBeUndefined();
    expect(records.verification.outcome).toBe('failed');
    expect(records.verification.reason_code).toBe('regression_test_not_reproducing');
    expect(records.groups.skipped.items[0].code).toBe('not_repaired');
    expect(records.agent_trace.total).toBe(2);
  });

  test('an empty or malformed response yields no evidence rather than throwing', () => {
    expect(buildEvidenceRecords(undefined)).toEqual([]);
    expect(buildEvidenceRecords({})).toEqual([]);
    expect(buildEvidenceRecords({ evidence: { agent_trace: 'not a list', groups: 7 } })).toEqual([]);
  });
});
