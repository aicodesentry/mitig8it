const release = require('../quality-release.json');

const SHA256_DIGEST = /^sha256:[a-f0-9]{64}$/;
const IMAGE_DIGEST = /^[A-Za-z0-9][A-Za-z0-9./_:-]*@sha256:[a-f0-9]{64}$/;
const SOURCE_REVISION = /^[a-f0-9]{40}$/;
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

function releaseIdentity(nowMs = Date.now()) {
  const expiresAt = release?.expires_at;
  const expiresMs = typeof expiresAt === 'string' && UTC_SECOND.test(expiresAt) ? Date.parse(expiresAt) : NaN;
  const reviewers = release?.authenticated_reviewers;
  if (release?.schema_version !== 'v1' || release?.remediation_release_verified !== true
      || !SOURCE_REVISION.test(release?.source_revision || '') || !SHA256_DIGEST.test(release?.receipt_digest || '')
      || release?.provider?.kind !== 'live-provider' || typeof release?.provider?.model_id !== 'string'
      || !release.provider.model_id || !SHA256_DIGEST.test(release.provider.configuration_digest || '')
      || release?.sandbox?.verification_level !== 'independent_sandbox'
      || !IMAGE_DIGEST.test(release?.sandbox?.image_digest || '')
      || !IMAGE_DIGEST.test(release?.service?.image_digest || '')
      || !Number.isFinite(expiresMs) || expiresMs <= nowMs
      || !Array.isArray(reviewers) || !reviewers.length || new Set(reviewers).size !== reviewers.length
      || reviewers.some((item) => typeof item !== 'string' || !item || item.trim() !== item)) return null;
  return { model_id: release.provider.model_id, verification_level: release.sandbox.verification_level,
    sandbox_image_digest: release.sandbox.image_digest, service_image_digest: release.service.image_digest,
    expires_at: expiresAt };
}

function remediationPublicationReady() {
  return releaseIdentity() !== null;
}

function assertRemediationPublicationReady(sections = []) {
  const identity = releaseIdentity();
  const mismatched = sections.some((section) => section?.candidate_id
    && (section.verification_level !== identity?.verification_level
      || section.repair_model !== identity?.model_id
      || section.repair_service_image !== identity?.service_image_digest
      || section.sandbox_image_digest !== identity?.sandbox_image_digest));
  if (!identity || mismatched) {
    const error = new Error('Remediation publication requires independently verified release evidence');
    error.statusCode = 422;
    error.code = 'REMEDIATION_RELEASE_EVIDENCE_MISSING';
    throw error;
  }
}

function assertReviewBodyReady(body) {
  const text = String(body || '');
  const suggestion = /```suggestion(?:\s|$)/i.test(text);
  // A model-generated Tier 3 snippet is advisory. Only the remediation pipeline
  // may call the dedicated publishFindingFixSections operation after per-candidate
  // sandbox verification. Generic review/comment operations never carry suggestion
  // blocks, even if untrusted text spoofs a candidate marker. Keep this invariant
  // at the final GitHub write boundary so a broad release flag cannot promote prose.
  if (suggestion) {
    const error = new Error('GitHub suggestions require a sandbox-verified remediation candidate');
    error.statusCode = 422;
    error.code = 'UNVERIFIED_SUGGESTION_PROHIBITED';
    throw error;
  }
  if (/(?:<!--\s*mitig8it-fix:|\*\*(?:Recommended|Suggested) fix)/i.test(text)) {
    assertRemediationPublicationReady();
  }
}

module.exports = { releaseIdentity, remediationPublicationReady, assertRemediationPublicationReady, assertReviewBodyReady };
