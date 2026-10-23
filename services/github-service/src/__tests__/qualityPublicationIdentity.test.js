jest.mock('../quality-release.json', () => require('../../../../tests/fixtures/verified-quality-release.json'));

const quality = require('../services/qualityPublication');

const exactSection = {
  candidate_id: 'candidate-1',
  verification_level: 'independent_sandbox',
  repair_model: 'test-reviewed-model',
  repair_service_image: `registry.example/remediation@sha256:${'e'.repeat(64)}`,
  sandbox_image_digest: `registry.example/runner@sha256:${'d'.repeat(64)}`,
};

test('publication accepts only the exact model and sandbox authenticated by the release lease', () => {
  expect(() => quality.assertRemediationPublicationReady([exactSection])).not.toThrow();
  for (const changed of [
    { repair_model: 'different-model' },
    { repair_service_image: '' },
    { repair_service_image: `registry.example/remediation@sha256:${'f'.repeat(64)}` },
    { verification_level: 'isolated_job' },
    { sandbox_image_digest: `registry.example/runner@sha256:${'f'.repeat(64)}` },
  ]) {
    expect(() => quality.assertRemediationPublicationReady([{ ...exactSection, ...changed }]))
      .toThrow(/independently verified release evidence/);
  }
});

test('an otherwise valid release lease is invalid after its expiry', () => {
  expect(quality.releaseIdentity(Date.parse('3000-01-01T00:00:00Z'))).toBeNull();
});
