jest.mock('../src/quality-release.json', () => ({
  ...require('../../../tests/fixtures/verified-quality-release.json'),
  provider: { ...require('../../../tests/fixtures/verified-quality-release.json').provider },
  sandbox: { ...require('../../../tests/fixtures/verified-quality-release.json').sandbox },
  service: { ...require('../../../tests/fixtures/verified-quality-release.json').service },
  authenticated_reviewers: [...require('../../../tests/fixtures/verified-quality-release.json').authenticated_reviewers],
}));

const release = require('../src/quality-release.json');
const policy = require('../src/services/remediationPolicy');

const SANDBOX = `registry.example/runner@sha256:${'d'.repeat(64)}`;

afterEach(() => {
  release.expires_at = '2999-01-01T00:00:00Z';
  release.provider.model_id = 'test-reviewed-model';
  release.sandbox.image_digest = SANDBOX;
  release.authenticated_reviewers = ['test-reviewer'];
  delete process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST;
  delete process.env.REMEDIATION_SERVICE_IMAGE_DIGEST;
});

test('the release lease exposes the exact reviewed model and sandbox only before expiry', () => {
  expect(policy.releaseEvidenceIdentity(Date.parse('2027-01-01T00:00:00Z'))).toMatchObject({
    model_id: 'test-reviewed-model',
    verification_level: 'independent_sandbox',
    sandbox_image_digest: SANDBOX,
  });
  expect(policy.releaseEvidenceIdentity(Date.parse('3000-01-01T00:00:00Z'))).toBeNull();
});

test('malformed identity and non-independent review evidence fail closed', () => {
  release.provider.model_id = '';
  expect(policy.releaseEvidenceIdentity()).toBeNull();
  release.provider.model_id = 'test-reviewed-model';
  release.authenticated_reviewers = ['same-reviewer', 'same-reviewer'];
  expect(policy.releaseEvidenceIdentity()).toBeNull();
});

test('runtime sandbox identity must exactly match the signed release lease', () => {
  process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = 'registry.example/runner@sha256:' + 'f'.repeat(64);
  expect(policy.getPolicy().release_evidence_ready).toBe(false);
  process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = SANDBOX;
  process.env.REMEDIATION_SERVICE_IMAGE_DIGEST = release.service.image_digest;
  expect(policy.getPolicy().release_evidence_ready).toBe(true);
});

test('runtime service binary must exactly match the signed release lease', () => {
  process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST = SANDBOX;
  expect(policy.getPolicy().release_evidence_ready).toBe(false);
  process.env.REMEDIATION_SERVICE_IMAGE_DIGEST = 'registry.example/other@sha256:' + 'f'.repeat(64);
  expect(policy.getPolicy().release_evidence_ready).toBe(false);
  process.env.REMEDIATION_SERVICE_IMAGE_DIGEST = release.service.image_digest;
  expect(policy.getPolicy().release_evidence_ready).toBe(true);
});
