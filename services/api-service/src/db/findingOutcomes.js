const { pool } = require('../config/database');
const logger = require('../utils/logger');

// The single writer for finding_outcomes. Every producer goes through it; nothing
// inserts into the table inline. The insert is ON CONFLICT DO NOTHING against the
// replay key, so a redelivered webhook, a retried reconciler step, or a re-run
// analysis records the same fact once.

const OUTCOMES = new Set([
  'fix_published', 'applied_in_app', 'applied_on_github', 'dismissed', 'accepted_risk',
  'suppressed', 'thread_resolved', 'thread_unresolved', 'fixed_by_reanalysis', 'reopened',
  'marked_fixed', 'residual_after_apply',
]);

const SOURCES = new Set([
  'workspace', 'github_thread', 'github_push', 'reanalysis', 'remediation', 'suppression',
]);

const DISMISSAL_REASONS = ['not_exploitable', 'test_or_sample_code', 'wrong_rule_match', 'other'];

// Reasons the workspace wrote before the enum existed, and the phrasings a GitHub reply
// uses. Anything unrecognised becomes 'other' rather than being stored free-text.
const REASON_ALIASES = new Map([
  ['false_positive', 'not_exploitable'],
  ['false positive', 'not_exploitable'],
  ['not_exploitable', 'not_exploitable'],
  ['not exploitable', 'not_exploitable'],
  ['not_an_issue', 'not_exploitable'],
  ['not an issue', 'not_exploitable'],
  ['test_or_sample_code', 'test_or_sample_code'],
  ['test code', 'test_or_sample_code'],
  ['sample code', 'test_or_sample_code'],
  ['test_code', 'test_or_sample_code'],
  ['wrong_rule_match', 'wrong_rule_match'],
  ['wrong rule', 'wrong_rule_match'],
  ['wrong rule match', 'wrong_rule_match'],
  ['other', 'other'],
]);

function normalizeDismissalReason(reason, fallback = 'other') {
  if (reason == null || reason === '') return fallback;
  const key = String(reason).trim().toLowerCase();
  return REASON_ALIASES.get(key) || fallback;
}

function isDismissalReason(reason) {
  return DISMISSAL_REASONS.includes(String(reason || '').trim().toLowerCase());
}

const INSERT_SQL = `
  INSERT INTO finding_outcomes (
    installation_id, repository_id, pull_request_id, finding_id, fingerprint, rule_id,
    cwe_id, severity, confidence, family, outcome, source, reason, actor_login,
    candidate_id, action_id, job_id, commit_sha, external_id, details
  ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
  ON CONFLICT DO NOTHING
  RETURNING id`;

function numberOrNull(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function textOrNull(value) {
  if (value == null) return null;
  const text = String(value).trim();
  return text === '' ? null : text;
}

// An installation is the tenant boundary and the row's composite foreign key needs it,
// so a missing one is resolved from the repository before the insert is attempted.
async function resolveInstallationId(executor, repositoryId, installationId) {
  if (installationId != null && installationId !== '') return String(installationId);
  if (!repositoryId) return null;
  const result = await executor.query('SELECT installation_id FROM repositories WHERE id = $1', [repositoryId]);
  const resolved = result.rows[0]?.installation_id;
  return resolved == null ? null : String(resolved);
}

/**
 * Append one outcome. `client` may be a transaction client, so the outcome commits with
 * the state change it describes; pass null to use the pool.
 * Returns the new row id, or null when the row already existed or could not be placed.
 */
async function recordOutcome(client, outcome = {}) {
  const executor = client || pool;

  if (!OUTCOMES.has(outcome.outcome)) {
    throw new Error(`Unknown finding outcome: ${outcome.outcome}`);
  }
  if (!SOURCES.has(outcome.source)) {
    throw new Error(`Unknown finding outcome source: ${outcome.source}`);
  }

  const fingerprint = textOrNull(outcome.fingerprint);
  const repositoryId = outcome.repositoryId || null;
  if (!fingerprint || !repositoryId) {
    logger.warn('Finding outcome skipped: it carries no repository or fingerprint', {
      outcome: outcome.outcome, source: outcome.source, finding_id: outcome.findingId || null,
    });
    return null;
  }

  const installationId = await resolveInstallationId(executor, repositoryId, outcome.installationId);
  if (installationId == null) {
    logger.warn('Finding outcome skipped: the repository has no installation', {
      outcome: outcome.outcome, source: outcome.source, repository_id: repositoryId,
    });
    return null;
  }

  const result = await executor.query(INSERT_SQL, [
    installationId,
    repositoryId,
    outcome.pullRequestId || null,
    outcome.findingId || null,
    fingerprint,
    textOrNull(outcome.ruleId),
    textOrNull(outcome.cweId),
    textOrNull(outcome.severity),
    numberOrNull(outcome.confidence),
    textOrNull(outcome.family),
    outcome.outcome,
    outcome.source,
    textOrNull(outcome.reason),
    textOrNull(outcome.actorLogin),
    outcome.candidateId || null,
    outcome.actionId || null,
    outcome.jobId || null,
    textOrNull(outcome.commitSha),
    textOrNull(outcome.externalId),
    JSON.stringify(outcome.details || {}),
  ]);

  return result.rows[0]?.id || null;
}

// The identity a finding row (or an analysis snapshot of one) contributes to an outcome.
function identityOf(finding = {}) {
  return {
    findingId: finding.id || finding.finding_id || null,
    fingerprint: finding.fingerprint || null,
    ruleId: finding.rule_id || null,
    cweId: finding.cwe_id || null,
    severity: finding.severity || null,
    confidence: finding.confidence ?? null,
    family: finding.family || finding.category || null,
    repositoryId: finding.repository_id || null,
    installationId: finding.installation_id ?? null,
    pullRequestId: finding.pull_request_id || null,
  };
}

/**
 * Append the same outcome for a set of findings. `common` supplies everything the
 * finding rows do not carry (outcome, source, actor, external id and so on) and
 * overrides any identity field it names.
 */
async function recordOutcomesForFindings(client, findings = [], common = {}) {
  // An absent key in `common` must not blank out what the finding row carries.
  const overrides = Object.fromEntries(Object.entries(common).filter(([, value]) => value !== undefined));
  const recorded = [];
  for (const finding of findings) {
    if (!finding) continue;
    const id = await recordOutcome(client, { ...identityOf(finding), ...overrides });
    if (id) recorded.push(id);
  }
  return recorded;
}

module.exports = {
  recordOutcome,
  recordOutcomesForFindings,
  normalizeDismissalReason,
  isDismissalReason,
  identityOf,
  OUTCOMES,
  SOURCES,
  DISMISSAL_REASONS,
};
