const DEFAULT_POLICY = Object.freeze({
  version: 'remediation-v1-disabled', max_files: 5, max_changed_lines: 200,
  max_attempts: 3, max_tool_calls: 20, max_context_tokens: 32000,
  max_spend_usd: 2, max_runtime_minutes: 15, max_snapshot_files: 120,
  max_file_bytes: 500000, max_snapshot_bytes: 500000, max_context_chars: 128000,
  max_output_chars: 64000, max_total_tokens: 120000, max_output_tokens_per_call: 16000,
  max_revisions: 2,
  repair_memory_expiry_days: 90,
  request_timeout_seconds: 45, supported_platform: 'node',
  forbidden_path_prefixes: ['.github/', 'infra/', 'infrastructure/', 'deploy/', 'migrations/'],
  forbidden_filenames: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
  // Per-stage reservations. Reserving the whole ceiling for every stage would
  // report a legitimate second stage as quota exhaustion.
  stage_spend_estimates: Object.freeze({
    snapshotting: 0.05, retrieving: 0.15, planning: 0.3, generating: 0.8, verifying: 0.4,
  }),
});

const STAGE_SEQUENCE = Object.freeze(['snapshotting', 'retrieving', 'planning', 'generating', 'verifying']);

function jsonEnv(name) { try { return JSON.parse(process.env[name] || ''); } catch (_) { return null; } }
function flagEnv(name) { return process.env[name] === 'true'; }

function getPolicy() {
  const verificationChecks = jsonEnv('REMEDIATION_VERIFICATION_CHECKS_JSON');
  const allowedRuleFamilies = jsonEnv('REMEDIATION_ALLOWED_RULE_FAMILIES_JSON');
  const protectedBranchPatterns = jsonEnv('REMEDIATION_PROTECTED_BRANCH_PATTERNS_JSON');
  const sandboxImage = process.env.REMEDIATION_SANDBOX_IMAGE_DIGEST;
  return {
    ...DEFAULT_POLICY,
    version: process.env.REMEDIATION_POLICY_VERSION || DEFAULT_POLICY.version,
    enabled: flagEnv('REMEDIATION_ENABLED'),
    generate_enabled: flagEnv('REMEDIATION_GENERATE_ENABLED'),
    publish_enabled: flagEnv('REMEDIATION_PUBLISH_ENABLED'),
    apply_enabled: flagEnv('REMEDIATION_APPLY_ENABLED'),
    merge_enabled: flagEnv('REMEDIATION_MERGE_ENABLED'),
    policy_version: process.env.REMEDIATION_POLICY_VERSION || DEFAULT_POLICY.version,
    sandbox_image_digest: sandboxImage,
    verification_checks: verificationChecks,
    allowed_rule_families: allowedRuleFamilies,
    // Default allow: an empty or absent list never blocks a branch.
    protected_branch_patterns: Array.isArray(protectedBranchPatterns) ? protectedBranchPatterns.filter((p) => typeof p === 'string' && p) : [],
    input_usd_per_million_tokens: Number(process.env.REMEDIATION_INPUT_USD_PER_MILLION_TOKENS),
    output_usd_per_million_tokens: Number(process.env.REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS),
    repair_service_configured: Boolean(process.env.REMEDIATION_SERVICE_URL && process.env.REMEDIATION_SERVICE_INTERNAL_SECRET && process.env.GITHUB_SERVICE_URL && process.env.GITHUB_SERVICE_INTERNAL_SECRET && sandboxImage && Array.isArray(verificationChecks) && Array.isArray(allowedRuleFamilies) && Number.isFinite(Number(process.env.REMEDIATION_INPUT_USD_PER_MILLION_TOKENS)) && Number.isFinite(Number(process.env.REMEDIATION_OUTPUT_USD_PER_MILLION_TOKENS))),
    github_write_configured: Boolean(process.env.GITHUB_SERVICE_URL && process.env.GITHUB_SERVICE_INTERNAL_SECRET),
  };
}

// Each capability is an independent flag gated by the global kill switch and by
// the dependency it actually needs. merge is never an alias of apply.
function capabilities() {
  const policy = getPolicy();
  return {
    generate: policy.enabled && policy.generate_enabled && policy.repair_service_configured,
    publish: policy.enabled && policy.publish_enabled && policy.repair_service_configured,
    apply: policy.enabled && policy.apply_enabled && policy.github_write_configured,
    merge: policy.enabled && policy.merge_enabled && policy.github_write_configured,
  };
}

// The reason is exposed so the UI can explain why a button is unavailable.
function capabilityReasons() {
  const policy = getPolicy();
  const reason = (flag, dependency) => {
    if (!policy.enabled) return 'global_kill_switch_off';
    if (!flag) return 'feature_flag_off';
    if (!dependency) return 'dependency_not_configured';
    return null;
  };
  return {
    generate: reason(policy.generate_enabled, policy.repair_service_configured),
    publish: reason(policy.publish_enabled, policy.repair_service_configured),
    apply: reason(policy.apply_enabled, policy.github_write_configured),
    merge: reason(policy.merge_enabled, policy.github_write_configured),
  };
}

function capabilityReport() {
  const enabled = capabilities();
  const reasons = capabilityReasons();
  const report = Object.fromEntries(Object.keys(enabled).map((name) => [name, { enabled: enabled[name], reason: reasons[name] }]));
  report.development_verification_allowed = allowDevelopmentVerification();
  return report;
}

function denial(message, code, status) {
  const error = new Error(message);
  error.code = code; error.status = status;
  return error;
}

function assertGenerateEnabled() {
  if (!capabilities().generate) {
    throw denial('Automated remediation is not enabled or its repair dependency is unavailable', 'REMEDIATION_UNAVAILABLE', 422);
  }
}

function assertPublishEnabled() {
  if (!capabilities().publish) {
    throw denial('Publishing remediation proposals is not enabled', 'REMEDIATION_PUBLISH_UNAVAILABLE', 422);
  }
}

function assertApplyEnabled() {
  if (!capabilities().apply) {
    throw denial('Verified remediation application is not enabled or its GitHub dependency is unavailable', 'REMEDIATION_APPLY_UNAVAILABLE', 422);
  }
}

function assertMergeEnabled() {
  if (!capabilities().merge) {
    throw denial('Automatic remediation merge is not enabled or its GitHub dependency is unavailable', 'REMEDIATION_MERGE_UNAVAILABLE', 422);
  }
}

// A stage reserves its own estimate. The ceiling still bounds the job as a whole.
function stageEstimate(policyManifest, stage) {
  const estimates = policyManifest?.stage_spend_estimates || DEFAULT_POLICY.stage_spend_estimates;
  const ceiling = Number(policyManifest?.max_spend_usd || DEFAULT_POLICY.max_spend_usd);
  const estimate = Number(estimates?.[stage]);
  if (Number.isFinite(estimate) && estimate > 0) return Math.min(estimate, ceiling);
  return Math.min(ceiling / STAGE_SEQUENCE.length, ceiling);
}

// Observed feedback expires; an unreviewed observation never influences generation and
// never outlives its retention window.
const PRODUCTION_VERIFICATION_LEVEL = 'independent_sandbox';

// Development verification (local subprocess sandbox) never satisfies the production
// gate. It is accepted for apply only when an operator opts in explicitly.
function allowDevelopmentVerification() { return flagEnv('REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION'); }
function verificationLevelPermitted(level) {
  if (level === PRODUCTION_VERIFICATION_LEVEL) return true;
  return level === 'development_unverified' && allowDevelopmentVerification();
}

function repairMemoryExpiryDays() {
  const configured = Number(process.env.REMEDIATION_REPAIR_MEMORY_EXPIRY_DAYS);
  return Number.isInteger(configured) && configured > 0 ? configured : DEFAULT_POLICY.repair_memory_expiry_days;
}

function branchAllowed(branch) {
  const patterns = getPolicy().protected_branch_patterns;
  if (!patterns.length || typeof branch !== 'string' || !branch) return true;
  return !patterns.some((pattern) => matchesBranchPattern(pattern, branch));
}

function matchesBranchPattern(pattern, branch) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`).test(branch);
}

module.exports = {
  DEFAULT_POLICY, STAGE_SEQUENCE, getPolicy, capabilities, capabilityReasons, capabilityReport,
  assertGenerateEnabled, assertPublishEnabled, assertApplyEnabled, assertMergeEnabled,
  // Retained name so existing callers keep the same behaviour.
  assertGenerationEnabled: assertGenerateEnabled,
  stageEstimate, branchAllowed, repairMemoryExpiryDays,
  PRODUCTION_VERIFICATION_LEVEL, allowDevelopmentVerification, verificationLevelPermitted,
};
