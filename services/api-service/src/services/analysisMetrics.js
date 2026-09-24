const client = require('prom-client');

// These use the default prom-client registry, the same one the /metrics route merges
// into its response, so the managed Prometheus sidecar scrapes them with no extra wiring.

// "Did reviews run in the last hour" is answered by this counter alone.
const runsStarted = new client.Counter({
  name: 'mitig8it_analysis_runs_started_total',
  help: 'Analysis runs claimed from the queue and started',
  labelNames: ['trigger'],
});

const runsCompleted = new client.Counter({
  name: 'mitig8it_analysis_runs_completed_total',
  help: 'Analysis runs that published a review and reached the completed state',
});

// `reason` is a bounded classification, never an error message: an unbounded label
// would multiply the series until the scrape itself becomes the incident.
const runsFailed = new client.Counter({
  name: 'mitig8it_analysis_runs_failed_total',
  help: 'Analysis runs that ended without publishing a result, by failure classification',
  labelNames: ['reason'],
});

const runDuration = new client.Histogram({
  name: 'mitig8it_analysis_run_duration_seconds',
  help: 'Wall-clock duration of an analysis run from claim to terminal state',
  labelNames: ['outcome'],
  buckets: [5, 10, 20, 30, 60, 120, 300, 600],
});

const findingsPosted = new client.Counter({
  name: 'mitig8it_analysis_findings_posted_total',
  help: 'Findings published onto a pull request review, by severity',
  labelNames: ['severity'],
});

const queueDepth = new client.Gauge({
  name: 'mitig8it_analysis_queue_depth',
  help: 'Analysis runs currently in each non-terminal queue status',
  labelNames: ['status'],
});

const queueOldestPendingSeconds = new client.Gauge({
  name: 'mitig8it_analysis_queue_oldest_pending_seconds',
  help: 'Age of the oldest pending analysis run in seconds, 0 when the queue is empty',
});

const secondsSinceLastRunStarted = new client.Gauge({
  name: 'mitig8it_analysis_seconds_since_last_run_started',
  help: 'Seconds since any analysis run last moved into the running state, -1 when none ever has',
});

// A derived 0/1 gauge rather than a PromQL expression: the stall condition joins a
// queue age to the absence of starts, and an alert that has to reconstruct that join
// from two raw series is the kind of rule nobody trusts at 3am.
const runsStalled = new client.Gauge({
  name: 'mitig8it_analysis_runs_stalled',
  help: 'One when pending analysis runs are older than the stall threshold and nothing has started within it',
});

const STALL_THRESHOLD_SECONDS = 600;

// Called from the queue observer and from the remediation reconciler, so the gauges
// exist in both deployment topologies: API alone, and API plus the in-process worker.
function observeQueue(stats = {}, { stallThresholdSeconds = STALL_THRESHOLD_SECONDS } = {}) {
  const pending = Number(stats.pending || 0);
  const running = Number(stats.running || 0);
  const oldestPending = Number(stats.oldest_pending_seconds || 0);
  const sinceLastStart = stats.seconds_since_last_start == null
    ? null
    : Number(stats.seconds_since_last_start);

  queueDepth.labels('pending').set(pending);
  queueDepth.labels('running').set(running);
  queueOldestPendingSeconds.set(oldestPending);
  secondsSinceLastRunStarted.set(sinceLastStart == null ? -1 : sinceLastStart);

  // A backlog that nothing is picking up. A service that has never started a run while
  // work waits counts as stalled too: from the outside those are the same outage.
  const nothingStartedRecently = sinceLastStart == null || sinceLastStart > stallThresholdSeconds;
  const stalled = pending > 0 && oldestPending > stallThresholdSeconds && nothingStartedRecently;
  runsStalled.set(stalled ? 1 : 0);
  return stalled;
}

module.exports = {
  runsStarted,
  runsCompleted,
  runsFailed,
  runDuration,
  findingsPosted,
  queueDepth,
  queueOldestPendingSeconds,
  secondsSinceLastRunStarted,
  runsStalled,
  observeQueue,
  STALL_THRESHOLD_SECONDS,
};
