// The control plane builds the fix sections; the GitHub adapter's publication gate decides
// whether they may be posted. Each side was tested alone, so a section shape one side
// produces and the other rejects only failed in production. This test feeds the api's
// buildSections output straight into the github-service gate under the same verified
// release fixture.
//
// The case that broke: two proven candidates on the same line. The fold keeps one
// suggestion and rewrites the other section as covered by it. That covered section still
// names a candidate, so the gate checks its release identity; when the fold blanked the
// identity fields, the gate rejected the whole batch and the winner's verified suggestion
// was never posted either.
const crypto = require('crypto');

jest.mock('../src/quality-release.json', () => require('../../../tests/fixtures/verified-quality-release.json'));
jest.mock('../../github-service/src/quality-release.json', () => require('../../../tests/fixtures/verified-quality-release.json'));

const release = require('../../../tests/fixtures/verified-quality-release.json');
const { buildSections } = require('../src/services/remediationInlineFixes');
const gate = require('../../github-service/src/services/qualityPublication');

const ORIGINAL = [
  'const db = require("./db");',
  'async function order(id) {',
  '  const rows = await db.query(`SELECT * FROM orders WHERE id = ${id}`);',
  '  return rows[0];',
  '}',
  'module.exports = { order };',
].join('\n') + '\n';
const FIXED = ORIGINAL.replace('db.query(`SELECT * FROM orders WHERE id = ${id}`)', "db.query('SELECT * FROM orders WHERE id = $1', [id])");
const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

function candidate(id, findingId) {
  const changes = [{ path: 'services/orders.js', original: ORIGINAL, replacement: FIXED, unified_diff: '@@ -3 +3 @@' }];
  return {
    id, finding_snapshot_ids: [findingId], rejection_reason: null, verification_level: 'independent_sandbox',
    preview: {
      changes,
      evidence: {
        status: 'passed', evidence_digest: 'c'.repeat(64), verification_level: 'independent_sandbox',
        verified_tree_oid: 'e'.repeat(40), repair_model: release.provider.model_id,
        sandbox_image_digest: release.sandbox.image_digest, repair_service_image: release.service.image_digest,
        limitations: [],
      },
    },
    file_manifest: {
      verified_tree_oid: 'e'.repeat(40),
      files: changes.map((change) => ({
        path: change.path, base_sha256: sha(change.original), new_sha256: sha(change.replacement),
        contents_base64: Buffer.from(change.replacement).toString('base64'),
      })),
    },
  };
}

const FINDINGS = [
  { id: 'f1', rule_id: 'sql.a', severity: 'high', file_path: 'services/orders.js', line_start: 3, line_end: 3, fingerprint: 'fp-sql' },
  { id: 'f2', rule_id: 'sql.b', severity: 'high', file_path: 'services/orders.js', line_start: 3, line_end: 3, fingerprint: 'fp-sql-2' },
];
const JOB = { id: 'job-1', failure_reason: { skipped: [] } };

// The sections cross the transport as JSON; the gate sees what survives that.
const overTheWire = (sections) => JSON.parse(JSON.stringify(sections));

test('the verified release fixture is a valid identity for the gate', () => {
  expect(gate.releaseIdentity()).not.toBeNull();
});

test('one proven candidate passes the gate', () => {
  const sections = buildSections({ job: JOB, candidates: [candidate(crypto.randomUUID(), 'f1')], findings: [FINDINGS[0]] });
  expect(() => gate.assertRemediationPublicationReady(overTheWire(sections))).not.toThrow();
});

test('two proven candidates on the same line fold into one suggestion that the gate accepts', () => {
  const sections = buildSections({
    job: JOB,
    candidates: [candidate(crypto.randomUUID(), 'f1'), candidate(crypto.randomUUID(), 'f2')],
    findings: FINDINGS,
  });
  const withHunk = sections.filter((section) => section.hunk);
  const covered = sections.filter((section) => section.covered_by);
  expect(withHunk).toHaveLength(1);
  expect(covered).toHaveLength(1);
  expect(covered[0].candidate_id).toBe(withHunk[0].candidate_id);
  expect(() => gate.assertRemediationPublicationReady(overTheWire(sections))).not.toThrow();
});
