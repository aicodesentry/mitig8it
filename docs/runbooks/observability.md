# Observability runbook

How to answer "did reviews run in the last hour and how many failed" without reading
logs, what pages when they stop, and what to do when it does.

For the state of the older local Prometheus and Grafana Agent configurations, see
[operations/observability.md](../operations/observability.md).

## How a metric gets from the service to an alert

1. The API registers its counters on the prom-client default registry. The product
   metrics are loaded eagerly by `src/utils/metricsRegistry.js`, so every series is
   present at zero from the first scrape. A counter that appears only after the first
   event is indistinguishable from a service that stopped reporting.
2. Two endpoints serve the same registry. `GET /metrics` on the ingress port stays
   gated by `x-internal-secret` in production. A second listener, bound to `127.0.0.1`
   on port 9091, serves the same body with no header at all and is started only when
   `METRICS_LOOPBACK_ENABLED=true`.
3. The Google Managed Service for Prometheus sidecar runs in the same Cloud Run
   instance as a second container named `collector`, reads
   `/etc/rungmp/config.yaml`, and scrapes `127.0.0.1:9091/metrics` every 30 seconds.
   The config lives at `infrastructure/monitoring/runmonitoring.yaml`.
4. The sidecar writes the series to Cloud Monitoring under the
   `prometheus.googleapis.com/<metric>/counter` metric types, labelled with the Cloud
   Run service name, which is what separates staging from production.
5. The alert policies in `infrastructure/monitoring/*.tf` evaluate PromQL against those
   series and notify the email channel.

The sidecar cannot hold the internal secret, which is the only reason the loopback
listener exists. Nothing outside the instance can reach it: it is bound to the loopback
address, and Cloud Run's ingress only ever forwards to the ingress container's port.

## One-time owner setup

Run once per project. None of it is in a workflow, because none of it should change on
a deploy.

```sh
# 1. The scrape config the sidecar mounts. It holds nothing sensitive; Secret Manager
#    is simply the mount Cloud Run offers for a file.
gcloud secrets create codesentry-gmp-config --replication-policy=automatic \
  --project codesentry-260311-9f2b
gcloud secrets versions add codesentry-gmp-config \
  --data-file=infrastructure/monitoring/runmonitoring.yaml \
  --project codesentry-260311-9f2b

# 2. The Cloud Run runtime service account must be allowed to read that secret and to
#    write the metrics the sidecar collects.
RUNTIME_SA=$(gcloud run services describe codesentry-api \
  --region us-central1 --project codesentry-260311-9f2b \
  --format='value(spec.template.spec.serviceAccountName)')
gcloud secrets add-iam-policy-binding codesentry-gmp-config \
  --member="serviceAccount:${RUNTIME_SA}" --role=roles/secretmanager.secretAccessor \
  --project codesentry-260311-9f2b
gcloud projects add-iam-policy-binding codesentry-260311-9f2b \
  --member="serviceAccount:${RUNTIME_SA}" --role=roles/monitoring.metricWriter
```

Then apply the alert policies:

```sh
cd infrastructure/monitoring
cp terraform.tfvars.example terraform.tfvars   # set project_id and alert_email
terraform init
terraform plan
terraform apply
```

The apply creates one email notification channel and the alert policies, nothing else.
Google sends a confirmation mail to the address; the channel does not deliver until it
is confirmed.

## Grafana, if you want dashboards

Grafana is optional. The alert policies do not need it. If you want the dashboards:

1. In Grafana, add a **Google Cloud Monitoring** data source.
2. Authenticate with a service account that holds `roles/monitoring.viewer` on
   `codesentry-260311-9f2b`, either by uploading a JSON key or with GCE default
   credentials when Grafana runs inside the project.
3. Enable the **Prometheus** query editor on the data source. Managed Prometheus series
   are queried as PromQL through this data source, so the expressions in
   `infrastructure/remediation/grafana/alerts/remediation-rules.yaml` and the dashboard
   in `infrastructure/remediation/grafana/dashboards/remediation-overview.json` work
   unchanged.
4. Import the alert rules only if Grafana is the paging path. Running both Grafana
   rules and the Cloud Monitoring policies means every incident pages twice. Pick one
   and delete the other; the two files are kept in step so either can be the survivor.

## The metrics

Analysis, emitted by the API:

| Metric | Type | Labels | What it answers |
| --- | --- | --- | --- |
| `mitig8it_analysis_runs_started_total` | counter | `trigger` | Did reviews run at all? |
| `mitig8it_analysis_runs_completed_total` | counter | | How many published a review? |
| `mitig8it_analysis_runs_failed_total` | counter | `reason` | How many failed, and whose fault? |
| `mitig8it_analysis_run_duration_seconds` | histogram | `outcome` | How long does a review take? |
| `mitig8it_analysis_findings_posted_total` | counter | `severity` | What are we telling people? |
| `mitig8it_analysis_queue_depth` | gauge | `status` | How much work is waiting? |
| `mitig8it_analysis_queue_oldest_pending_seconds` | gauge | | How long has the oldest waited? |
| `mitig8it_analysis_seconds_since_last_run_started` | gauge | | When did anything last start? `-1` means never. |
| `mitig8it_analysis_runs_stalled` | gauge | | 1 when work is waiting and nothing is picking it up. |

`reason` is a closed set: `analysis_incomplete`, `github_files_invalid`,
`publication_incomplete`, `publication_failed`, `infrastructure`, `unhandled`, and
`transient_retried`. The last one is counted apart from the rest and excluded from the
failure-ratio alert: that run has not failed for the pull request author yet.

Remediation, also emitted by the API:

| Metric | Type | Labels |
| --- | --- | --- |
| `mitig8it_remediation_jobs_terminal_total` | counter | `state` |
| `mitig8it_remediation_stage_attempts_total` | counter | `stage`, `outcome` |
| `mitig8it_remediation_stage_duration_seconds` | histogram | `stage`, `outcome` |
| `mitig8it_remediation_lease_reclaims_total` | counter | |
| `mitig8it_remediation_action_transitions_total` | counter | `state` |
| `mitig8it_remediation_usage_releases_total` | counter | `reason` |

## The alerts

Two policies page. One warns. Everything else that used to be in the rules file queried
metrics nothing emitted, and has been deleted.

### mitig8it_reviews_failing

Fires when, over 15 minutes, at least 3 analysis runs started and more than 30 percent
of them ended without publishing a review.

**No data**: inactive. No runs started means the ratio has no denominator, and "nothing
ran" is the other alert's question.

When it fires, break the failures down by reason:

```promql
sum by (reason) (increase(mitig8it_analysis_runs_failed_total[15m]))
```

- `analysis_incomplete`: one of our analysis tiers returned an unusable response. Ours.
- `github_files_invalid`, `publication_incomplete`, `publication_failed`: GitHub
  returned something unusable, or the review could not be published. Check GitHub
  status and the installation token.
- `infrastructure`: network, or a downstream that is cold and slow. Check whether
  codesentry-github and codesentry-analysis are scaled to zero.
- `unhandled`: a bug. Find the failing runs and read their lines:
  `severity="ERROR" AND jsonPayload.analysis_run_id="<id>"` in Cloud Logging.

### mitig8it_reviews_stalled

Fires when pending analysis runs are older than 10 minutes and nothing has started for
10 minutes. The service derives that join into the `mitig8it_analysis_runs_stalled`
gauge; the alert reads one series.

**No data**: firing. An API that is down reports neither a backlog nor a start, so the
Cloud Monitoring policy carries a second, absence condition on
`mitig8it_analysis_runs_started_total`: if the series stops arriving for 15 minutes,
the policy fires. Silence is the outage.

When it fires:

1. Is an instance serving?
   `gcloud run services describe codesentry-api --region us-central1 --project codesentry-260311-9f2b`
2. Did the queue worker start? Look for `Analysis queue worker started` on the newest
   instance.
3. Is the database reachable? The claim query is the first thing a database outage
   stops, and it fails quietly into the queue rather than into the request path.
4. If the gauge itself is missing rather than 1, the scrape stopped. Confirm the
   revision still has the `collector` container; the API deploy asserts this, but a
   manual `gcloud run deploy` without `--container` flags would drop it.

### mitig8it_remediation_lease_reclaim

A warning. One reclaim is normal recovery after an instance restart. More than three in
half an hour means workers are being killed mid-job, which usually precedes an outage.
See [remediation.md](remediation.md#expired-worker-lease).

## Correlated logs

Every log line from the API, the github service and the analysis service is one JSON
object with `severity`, `message`, and whichever of `delivery_id`, `analysis_run_id`,
`job_id` and `correlation_id` are known. Cloud Logging promotes `severity` and
`message` onto the entry and keeps the rest under `jsonPayload`.

The identifiers are held in an AsyncLocalStorage context in Node and contextvars in
Python, adopted once per request from HTTP headers (`x-github-delivery`,
`x-analysis-run-id`, `x-job-id`, `x-correlation-id`) or the equivalent gRPC metadata,
and passed on automatically to every downstream call. No call site passes them by hand.

The analysis queue breaks the request scope, so the delivery is stored on the
`analysis_runs` row and the context is re-established when a run is claimed. An
automatic retry inherits the delivery of the run it replaces.

To follow one webhook end to end:

```
jsonPayload.delivery_id="<the delivery id GitHub shows>"
```

To follow one review across all three services:

```
jsonPayload.analysis_run_id="<run id>"
```

## What to measure after the next deploy

Nothing below has been measured against the deployed service. Measure it once the
min-instance change and the sidecar are live, and record the numbers here.

- **First review latency after idle.** Leave the service untouched for an hour, then
  open a pull request and time from the webhook delivery timestamp GitHub shows to the
  check run appearing. Compare with `mitig8it_analysis_run_duration_seconds`: the gap
  between them is queue wait plus cold start, which is what `--min-instances 1` and the
  start-up warm-up are meant to remove.
- **Whether the warm-up actually paid.** On a fresh instance, the `Warm-up finished`
  line carries `durationMs` and which downstreams answered. If `failed` is non-zero on
  every start, the warm-up is not buying anything and the reason is worth finding.
- **Scrape health.** In Cloud Monitoring, confirm
  `prometheus.googleapis.com/mitig8it_analysis_runs_started_total/counter` has points
  for the `codesentry-api` service and that the gap between points is about 30 seconds.
  An irregular gap means the sidecar is being starved of CPU.
- **Alert thresholds.** After a week of real traffic, check what the failure ratio
  actually is on a normal day. If it sits near 0.3, the threshold is wrong for this
  service and should move, rather than being silenced.

The sidecar is opt-in. After the `codesentry-gmp-config` secret exists and the service account can read it, set the repository variable `METRICS_SIDECAR_ENABLED` to `true` and re-run the API deploy. Without the variable the API deploys as a single container and the loopback metrics listener stays off, so a missing secret can never block a production deploy.
