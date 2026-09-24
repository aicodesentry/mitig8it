const client = require('prom-client');

// Registry is deliberately the global application registry so the API's existing
// /metrics endpoint exports these counters without creating a second collector.
const stageAttempts = new client.Counter({ name: 'mitig8it_remediation_stage_attempts_total', help: 'Remediation stage attempts', labelNames: ['stage', 'outcome'] });
const leaseReclaims = new client.Counter({ name: 'mitig8it_remediation_lease_reclaims_total', help: 'Remediation jobs reclaimed after lease expiry' });
const actionTransitions = new client.Counter({ name: 'mitig8it_remediation_action_transitions_total', help: 'Remediation action state transitions', labelNames: ['state'] });
const usageReleases = new client.Counter({ name: 'mitig8it_remediation_usage_releases_total', help: 'Remediation spend reservations released back to the installation budget', labelNames: ['reason'] });
const stageDuration = new client.Histogram({ name: 'mitig8it_remediation_stage_duration_seconds', help: 'Bounded remediation stage duration', labelNames: ['stage', 'outcome'], buckets: [0.1, 1, 5, 15, 30, 60, 120] });

// The three quality rates, set by the reconciler's quality_metrics step from the daily
// roll-up. They are gauges, not counters: each pass replaces the value rather than adding
// to it. A rate with no denominator is not exported at all, because a gauge has no way to
// say "unknown" and zero would be read as a real answer.
const qualityApplyRate = new client.Gauge({ name: 'mitig8it_quality_apply_rate', help: 'Share of published fixes that were applied', labelNames: ['installation_id', 'window'] });
const qualityDismissRate = new client.Gauge({ name: 'mitig8it_quality_dismiss_rate', help: 'Share of new findings that were dismissed, suppressed, or resolved without a fix', labelNames: ['installation_id', 'window'] });
const qualityResidualRate = new client.Gauge({ name: 'mitig8it_quality_residual_rate', help: 'Share of applied fixes that left a blocking finding behind', labelNames: ['installation_id', 'window'] });

module.exports = {
  stageAttempts, leaseReclaims, actionTransitions, stageDuration, usageReleases,
  qualityApplyRate, qualityDismissRate, qualityResidualRate,
};
