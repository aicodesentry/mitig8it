const client = require('prom-client');

// Registry is deliberately the global application registry so the API's existing
// /metrics endpoint exports these counters without creating a second collector.
const stageAttempts = new client.Counter({ name: 'mitig8it_remediation_stage_attempts_total', help: 'Remediation stage attempts', labelNames: ['stage', 'outcome'] });
const leaseReclaims = new client.Counter({ name: 'mitig8it_remediation_lease_reclaims_total', help: 'Remediation jobs reclaimed after lease expiry' });
const actionTransitions = new client.Counter({ name: 'mitig8it_remediation_action_transitions_total', help: 'Remediation action state transitions', labelNames: ['state'] });
const usageReleases = new client.Counter({ name: 'mitig8it_remediation_usage_releases_total', help: 'Remediation spend reservations released back to the installation budget', labelNames: ['reason'] });
const stageDuration = new client.Histogram({ name: 'mitig8it_remediation_stage_duration_seconds', help: 'Bounded remediation stage duration', labelNames: ['stage', 'outcome'], buckets: [0.1, 1, 5, 15, 30, 60, 120] });
// Stage attempts say what the worker tried. This says how jobs actually ended, which is
// the number a dashboard needs to answer "how many remediations failed today".
const jobTerminalStates = new client.Counter({ name: 'mitig8it_remediation_jobs_terminal_total', help: 'Remediation jobs that reached a terminal state, by state', labelNames: ['state'] });

module.exports = { stageAttempts, leaseReclaims, actionTransitions, stageDuration, usageReleases, jobTerminalStates };
