/**
 * The rotation sentence reaches the reviewer unchanged.
 *
 * A committed credential is the one finding where removing the line is not the fix: the value
 * is in the history, so it has to be rotated as well. The analysis service puts that sentence
 * on the finding's `remediation`, and both publishers render that field, which is what makes
 * the App and the Action say the same thing.
 *
 * `buildRepoAwareRemediation` is the one thing in the App that can replace `remediation` with
 * copy of its own, per `evidence_details.missing_control_type`. A secrets finding carries
 * `secret_manager_or_environment_variable`, and if a branch for that control type were ever
 * added without the rotation sentence in it, the App would quietly stop telling a maintainer
 * to rotate a leaked key while the Action carried on telling them to. This test fails first.
 */

const { buildRepoAwareRemediation } = require('../src/services/suggestedFixValidator').__private;
const { buildReviewComment } = require('../src/services/prAnalysisOrchestrator').__private;

const ROTATION_SENTENCE_START = 'Rotate this credential now';
const ROTATION_REASON = 'does not un-leak it';

// The fixture key is joined rather than written out. `sk_live_` followed by twenty-four
// base62 characters is the shape GitHub's push protection blocks, and it blocked this
// branch; a repository whose own product exists to stop people committing keys does not
// ask to be allowlisted past that. Only the shape is under test here.
const STRIPE_LIVE_KEY = 'sk_live' + '_k8Rm2QpLzV4nB7xW1sT6yU3h';

const SECRET_FINDING = {
  rule_id: 'secret.format.known_key',
  title: 'Stripe live secret key committed in this change',
  description:
    'Stripe live secret key appears on a line this pull request adds. Verified structure: '
    + 'the `sk_live_`/`rk_live_` prefix Stripe reserves for live secret keys, and at least 24 base62 characters.',
  category: 'hardcoded secrets',
  cwe_id: 'CWE-798',
  severity: 'critical',
  confidence: 0.95,
  file_path: 'src/billing.js',
  line_start: 12,
  line_end: 12,
  code_snippet: `const stripeKey = "${STRIPE_LIVE_KEY}";`,
  evidence: 'Stripe live secret key on an added line: `sk_l…******… (32 characters)`.',
  remediation:
    'Rotate this credential now, then replace the literal with a read from the environment '
    + 'or a secret manager. Rotating matters as much as removing: the value is in the commit '
    + 'history, so deleting the line does not un-leak it.',
  remediation_patch: 'const stripeKey = process.env.STRIPE_KEY;',
  fingerprint: 'f'.repeat(64),
  evidence_details: {
    reviewability: 'changed-lines-only',
    fix_scope: 'line',
    fix_target_line: 12,
    missing_control_type: 'secret_manager_or_environment_variable',
    auto_fix_eligible: true,
    extra: { signal: 'key_format', secret_type: 'stripe_live_key', rotation_required: true },
  },
};

const ROTATION_ONLY_FINDING = {
  ...SECRET_FINDING,
  title: 'Private key PEM block committed in this change',
  code_snippet: '-----BEGIN RSA PRIVATE KEY-----',
  remediation:
    'Rotate this credential now, then remove it from the repository. Rotating matters as '
    + 'much as removing: the value is in the commit history, so deleting the line does not '
    + 'un-leak it. No automatic fix is offered for this shape, because the literal is not '
    + 'bound to a constant a template can rewrite.',
  remediation_patch: '',
  evidence_details: {
    extra: {
      signal: 'key_format',
      secret_type: 'private_key_pem',
      rotation_required: true,
      fix_offered: false,
    },
  },
};

const REPO_PROFILES = [
  ['no profile', null],
  ['a profile with security libraries', {
    deterministic: { framework: 'express', security_libraries: [{ name: 'dompurify', purpose: 'html sanitization' }] },
    interpreted: { validation_approach: 'zod schemas', database_pattern: 'parameterized' },
  }],
  ['a profile with a validation library', {
    deterministic: { framework: 'django', security_libraries: [{ name: 'cerberus', purpose: 'input validation' }] },
    interpreted: {},
  }],
];

describe('secret rotation copy', () => {
  describe.each(REPO_PROFILES)('with %s', (_label, repoProfile) => {
    test('the repo-aware override does not replace the rotation sentence', () => {
      const copy = buildRepoAwareRemediation(SECRET_FINDING, repoProfile);
      expect(copy).toContain(ROTATION_SENTENCE_START);
      expect(copy).toContain(ROTATION_REASON);
    });

    test('the rotation-only finding keeps its "no automatic fix" sentence', () => {
      const copy = buildRepoAwareRemediation(ROTATION_ONLY_FINDING, repoProfile);
      expect(copy).toContain(ROTATION_SENTENCE_START);
      expect(copy).toContain('No automatic fix is offered for this shape');
    });
  });

  test('the published comment carries the rotation sentence verbatim', () => {
    const body = buildReviewComment(SECRET_FINDING, { repoProfile: null });
    expect(body).toContain(SECRET_FINDING.remediation);
  });

  test('the rotation-only comment carries its sentence and offers no suggestion block', () => {
    const body = buildReviewComment(ROTATION_ONLY_FINDING, { repoProfile: null });
    expect(body).toContain(ROTATION_ONLY_FINDING.remediation);
    expect(body).not.toContain('```suggestion');
  });
});
