const client = require('prom-client');

// Registry is deliberately the global application registry so the API's existing
// /metrics endpoint exports these counters without creating a second collector.
const stageAttempts = new client.Counter({ name: 'mitig8it_remediation_stage_attempts_total', help: 'Remediation stage attempts', labelNames: ['stage', 'outcome'] });
const leaseReclaims = new client.Counter({ name: 'mitig8it_remediation_lease_reclaims_total', help: 'Remediation jobs reclaimed after lease expiry' });
const actionTransitions = new client.Counter({ name: 'mitig8it_remediation_action_transitions_total', help: 'Remediation action state transitions', labelNames: ['state'] });
const stageDuration = new client.Histogram({ name: 'mitig8it_remediation_stage_duration_seconds', help: 'Bounded remediation stage duration', labelNames: ['stage', 'outcome'], buckets: [0.1, 1, 5, 15, 30, 60, 120] });

module.exports = { stageAttempts, leaseReclaims, actionTransitions, stageDuration };
