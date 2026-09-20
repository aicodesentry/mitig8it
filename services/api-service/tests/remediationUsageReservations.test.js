const mockConnect = jest.fn();
jest.mock('../src/config/database', () => ({ pool: { connect: mockConnect }, transaction: jest.fn() }));

const remediationDb = require('../src/db/remediation');

const connect = mockConnect;

const JOB_ID = '11111111-1111-4111-8111-111111111111';
const REPO_ID = '22222222-2222-4222-8222-222222222222';

function jobRow(overrides = {}) {
  return {
    id: JOB_ID,
    installation_id: '128402824',
    repository_id: REPO_ID,
    fencing_token: 7,
    lease_owner: 'worker-a',
    state_version: 3,
    head_sha: 'a'.repeat(40),
    base_sha: 'b'.repeat(40),
    policy_version: 'policy-1',
    attempt_count: 0,
    policy_manifest: { max_spend_usd: 2, input_usd_per_million_tokens: 2.5, output_usd_per_million_tokens: 10 },
    ...overrides,
  };
}

/** A pg client that answers by SQL shape and records every statement it was given. */
function fakeClient({ jobSelect = jobRow(), jobUpdateRows = 1, reservedRows = [], existingReservation = [] } = {}) {
  const queries = [];
  const query = jest.fn(async (text, params) => {
    queries.push({ text, params });
    if (/SELECT \* FROM remediation_jobs WHERE id=\$1 FOR UPDATE/.test(text)) {
      return { rows: jobSelect ? [jobSelect] : [], rowCount: jobSelect ? 1 : 0 };
    }
    if (/UPDATE remediation_jobs SET state=/.test(text)) return { rows: [], rowCount: jobUpdateRows };
    if (/UPDATE usage_reservations (u )?SET state='released'/.test(text)) {
      return { rows: reservedRows, rowCount: reservedRows.length };
    }
    if (/SELECT \* FROM usage_reservations/.test(text)) {
      return { rows: existingReservation, rowCount: existingReservation.length };
    }
    if (/COALESCE\(SUM\(r\.reserved_amount\)/.test(text)) return { rows: [{ amount: '0' }], rowCount: 1 };
    if (/INSERT INTO usage_reservations/.test(text)) {
      return { rows: [{ id: 'res-new', job_id: JOB_ID, stage: params[3], state: 'reserved' }], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  });
  connect.mockResolvedValue({ query, release: jest.fn() });
  return { queries, query };
}

const TERMINAL_STATES = ['ready', 'unsupported', 'inconclusive', 'failed', 'cancelled', 'superseded', 'dead_letter'];

beforeEach(() => { connect.mockReset(); });

describe('usage reservations are released when a job ends', () => {
  test.each(TERMINAL_STATES)('completeStage releases outstanding reservations on %s', async (state) => {
    const reserved = [{ id: 'res-1', stage: 'generating', reserved_amount: '0.05', repository_id: REPO_ID, job_id: JOB_ID }];
    const client = fakeClient({ reservedRows: reserved });

    const done = await remediationDb.completeStage(jobRow(), { state, stage: state, outcome: state });

    expect(done).toBe(true);
    const release = client.queries.find((entry) => /UPDATE usage_reservations SET state='released'/.test(entry.text));
    expect(release).toBeDefined();
    // Only rows that were never settled are freed, and they are freed at zero.
    expect(release.text).toMatch(/actual_amount=0/);
    expect(release.text).toMatch(/state='reserved'/);
    expect(release.params).toEqual([JOB_ID]);
    // The release is on the audit trail with the reason and the amount returned.
    const audit = client.queries.find((entry) => /INSERT INTO audit_logs/.test(entry.text)
      && entry.params[2] === 'remediation.usage_released');
    expect(audit).toBeDefined();
    expect(JSON.parse(audit.params[5])).toMatchObject({ reason: `job_${state}`, released: 1, amount: 0.05 });
  });

  test('a non-terminal stage transition keeps the reservation outstanding', async () => {
    const client = fakeClient({ reservedRows: [] });

    await remediationDb.completeStage(jobRow(), { state: 'queued', stage: 'generating', outcome: 'retry' });

    expect(client.queries.some((entry) => /UPDATE usage_reservations SET state='released'/.test(entry.text))).toBe(false);
  });

  test('nothing outstanding means no audit noise', async () => {
    const client = fakeClient({ reservedRows: [] });

    await remediationDb.completeStage(jobRow(), { state: 'ready', stage: 'ready', outcome: 'ready' });

    expect(client.queries.some((entry) => /INSERT INTO audit_logs/.test(entry.text)
      && entry.params[2] === 'remediation.usage_released')).toBe(false);
  });

  test('a job whose fencing token moved on releases nothing', async () => {
    const client = fakeClient({ jobSelect: jobRow({ fencing_token: 8 }) });

    const done = await remediationDb.completeStage(jobRow({ fencing_token: 7 }), { state: 'failed', stage: 'failed', outcome: 'failed' });

    expect(done).toBe(false);
    expect(client.queries.some((entry) => /UPDATE usage_reservations SET state='released'/.test(entry.text))).toBe(false);
  });
});

describe('a settled stage is charged what it actually cost', () => {
  test('usageCost prices the reported tokens with the job policy', () => {
    const result = { evidence: { usage: { input_tokens: 6129, output_tokens: 472 } } };
    // (6129 * 2.50 + 472 * 10.00) / 1e6, the live gpt-4o run's reported usage.
    expect(remediationDb.usageCost(jobRow(), result)).toBeCloseTo(0.0200425, 7);
  });

  test('a response that reports no usage settles at zero, not at the estimate', () => {
    expect(remediationDb.usageCost(jobRow(), { evidence: {} })).toBe(0);
    expect(remediationDb.usageCost(jobRow(), {})).toBe(0);
  });

  test('a response carrying an explicit actual_usd is honoured', () => {
    expect(remediationDb.usageCost(jobRow(), { usage: { actual_usd: 0.42 } })).toBeCloseTo(0.42, 6);
  });

  test('settleUsage charges the actual amount and never a negative one', async () => {
    const client = fakeClient();
    await remediationDb.settleUsage(jobRow(), { id: 'res-1' }, -5, 'chatcmpl-1');
    const settle = client.queries.find((entry) => /state='settled'/.test(entry.text));
    expect(settle.params[0]).toBe(0);
    expect(settle.params[1]).toBe('chatcmpl-1');
  });

  test('settleUsage without a reservation is a no-op', async () => {
    fakeClient();
    await remediationDb.settleUsage(jobRow(), null, 1, null);
    expect(connect).not.toHaveBeenCalled();
  });
});

describe('a retry of a stage reuses its reservation', () => {
  test('an existing row for the job and stage is returned without a second charge', async () => {
    const existing = { id: 'res-1', job_id: JOB_ID, stage: 'generating', state: 'reserved' };
    const client = fakeClient({ existingReservation: [existing] });

    const reservation = await remediationDb.reserveUsage(jobRow({ fencing_token: 99 }), 'generating', 0.05);

    expect(reservation).toEqual(existing);
    expect(client.queries.some((entry) => /INSERT INTO usage_reservations/.test(entry.text))).toBe(false);
  });

  test('the reservation key is the job and stage, so a new fencing token is not a new charge', async () => {
    const client = fakeClient();

    await remediationDb.reserveUsage(jobRow({ fencing_token: 99 }), 'generating', 0.05);

    const insert = client.queries.find((entry) => /INSERT INTO usage_reservations/.test(entry.text));
    expect(insert.params[4]).toBe(`${JOB_ID}:generating`);
    expect(insert.params[4]).not.toContain('99');
  });
});

describe('the ceiling counts only work that can still spend', () => {
  test('budgetSnapshot excludes reservations belonging to terminal jobs', async () => {
    const client = fakeClient();

    const snapshot = await remediationDb.budgetSnapshot('128402824', 2);

    const used = client.queries.find((entry) => /COALESCE\(SUM\(r\.reserved_amount\)/.test(entry.text));
    expect(used.text).toMatch(/JOIN remediation_jobs j ON j\.id = r\.job_id/);
    expect(used.text).toMatch(/NOT \(j\.state = ANY\(\$2\)\)/);
    expect(used.params[1]).toEqual(expect.arrayContaining(TERMINAL_STATES));
    expect(snapshot).toEqual({ reserved: 0, ceiling: 2, available: 2 });
  });
});

describe('the reconciler sweep', () => {
  test('releases reservations whose job is terminal or gone, bounded per tick', async () => {
    const stranded = [
      { id: 'res-1', installation_id: '128402824', repository_id: REPO_ID, job_id: JOB_ID, stage: 'snapshotting', reserved_amount: '0.05' },
    ];
    const client = fakeClient({ reservedRows: stranded });

    const released = await remediationDb.releaseStrandedReservations(25);

    expect(released).toHaveLength(1);
    const sweep = client.queries.find((entry) => /UPDATE usage_reservations u SET state='released'/.test(entry.text));
    expect(sweep.text).toMatch(/j\.id IS NULL OR j\.state = ANY/);
    expect(sweep.text).toMatch(/SKIP LOCKED LIMIT \$2/);
    expect(sweep.params[1]).toBe(25);
    const audit = client.queries.find((entry) => /INSERT INTO audit_logs/.test(entry.text)
      && entry.params[2] === 'remediation.usage_released');
    expect(JSON.parse(audit.params[5])).toMatchObject({ reason: 'reconciler_stranded', amount: 0.05 });
  });
});
