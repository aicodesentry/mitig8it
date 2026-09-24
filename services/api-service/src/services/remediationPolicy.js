const DEFAULT_POLICY = Object.freeze({
  version: 'remediation-v1-disabled', max_files: 5, max_changed_lines: 200,
  max_attempts: 3, max_tool_calls: 20, max_context_tokens: 32000,
  max_spend_usd: 2, max_runtime_minutes: 15, max_snapshot_files: 120,
  max_file_bytes: 500000, max_snapshot_bytes: 500000, max_context_chars: 128000,
  max_output_chars: 64000, max_total_tokens: 120000, max_output_tokens_per_call: 16000,
  max_revisions: 2,
  // The repair service requires an agent-generated regression test per candidate, which is
  // what lets a repository with no verification fixture still produce an applicable fix.
  require_generated_regression_test: true,
  run_repository_tests: false,
  // The families the repair service can repair and prove: the three JavaScript families plus
  // the two Python-only ones (hardcoded credentials moved to the environment, eval replaced
  // by ast.literal_eval). REMEDIATION_ALLOWED_RULE_FAMILIES_JSON narrows or overrides this.
  allowed_rule_families: Object.freeze([
    'sql_parameterization', 'command_arguments', 'path_containment', 'hardcoded_credential', 'code_injection_eval',
  ]),
  repair_memory_expiry_days: 90,
  // The sandbox deadline for one verification, enforced by the broker across every
  // baseline and candidate check. This is the single source: the repair service uses it
  // as the broker's deadline_seconds and waits a fixed margin longer for the response.
  // A verification runs each check on the baseline tree and on the candidate tree in
  // separate sandbox pods (tens of seconds each to schedule), the generated regression
  // test has a 60 s budget per run, the syntax check 30 s, and repository tests, when
  // enabled, 300 s per run. The previous 45 s could not cover one pod pair, so long
  // verifications timed out client-side and were reported as the broker being
  // unavailable. 900 s is the 15 minute job runtime ceiling above, and matches the
  // repair service's own default, so one verification may use the whole job budget
  // and the job's runtime limit is what bounds it.
  request_timeout_seconds: 900, supported_platform: 'linux',
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

// Default true: the repair service also defaults it to true, and the two must agree.
function requireGeneratedRegressionTest() { return process.env.REMEDIATION_REQUIRE_GENERATED_REGRESSION_TEST !== 'false'; }

function getPolicy() {
  const declaredChecks = jsonEnv('REMEDIATION_VERIFICATION_CHECKS_JSON');
  const requireGeneratedTest = requireGeneratedRegressionTest();
  // A repository-specific verification profile is optional once the candidate must ship its
  // own reproducer. An absent profile becomes an empty list rather than "not configured", so
  // the repair service runs the generated regression test and its generic behavior checks.
  const verificationChecks = Array.isArray(declaredChecks) ? declaredChecks : (requireGeneratedTest ? [] : null);
  const declaredFamilies = jsonEnv('REMEDIATION_ALLOWED_RULE_FAMILIES_JSON');
  // An explicit list is the operator's choice, even a narrower one; an absent or unparseable
  // list takes the service default rather than leaving the repair service unconfigured.
  const allowedRuleFamilies = Array.isArray(declaredFamilies)
    ? declaredFamilies.filter((family) => typeof family === 'string' && family)
    : [...DEFAULT_POLICY.allowed_rule_families];
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
    require_generated_regression_test: requireGeneratedTest,
    run_repository_tests: flagEnv('REMEDIATION_RUN_REPOSITORY_TESTS'),
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
    // Generation after analysis is only useful when the result can be published under
    // the findings, so it requires both flags and both dependencies.
    auto_generate: policy.enabled && policy.generate_enabled && policy.publish_enabled
      && policy.repair_service_configured && policy.github_write_configured,
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
    auto_generate: reason(policy.generate_enabled && policy.publish_enabled,
      policy.repair_service_configured && policy.github_write_configured),
  };
}

function capabilityReport() {
  const enabled = capabilities();
  const reasons = capabilityReasons();
  const report = Object.fromEntries(Object.keys(enabled).map((name) => [name, { enabled: enabled[name], reason: reasons[name] }]));
  report.development_verification_allowed = allowDevelopmentVerification();
  report.isolated_job_verification_allowed = allowIsolatedJobVerification();
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
// The Cloud Run job sandbox: separate containers, an unprivileged check user holding none of
// the job's credentials, and a network the job's own probes measured as unreachable before
// each check ran. Weaker than the Kubernetes/gVisor level, which also pins a read-only root
// filesystem and a gVisor runtime class, and not comparable to the development level, where
// repository code runs in the service's own container.
const ISOLATED_JOB_VERIFICATION_LEVEL = 'isolated_job';

// Development verification (local subprocess sandbox) never satisfies the production
// gate. It is accepted for apply only when an operator opts in explicitly.
function allowDevelopmentVerification() { return flagEnv('REMEDIATION_ALLOW_DEVELOPMENT_VERIFICATION'); }
// Default true, and the repair service defaults its policy field the same way; the two must
// agree. An operator who will accept nothing below the gVisor sandbox sets this to 'false'.
function allowIsolatedJobVerification() { return process.env.REMEDIATION_ALLOW_ISOLATED_JOB_VERIFICATION !== 'false'; }
function verificationLevelPermitted(level) {
  if (level === PRODUCTION_VERIFICATION_LEVEL) return true;
  if (level === ISOLATED_JOB_VERIFICATION_LEVEL) return allowIsolatedJobVerification();
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
  PRODUCTION_VERIFICATION_LEVEL, ISOLATED_JOB_VERIFICATION_LEVEL,
  allowDevelopmentVerification, allowIsolatedJobVerification, verificationLevelPermitted,
  requireGeneratedRegressionTest,
};
